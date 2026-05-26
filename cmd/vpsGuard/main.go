package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/vpsik-lab/vpsGuard/internal/api"
	"github.com/vpsik-lab/vpsGuard/internal/bootstrap"
	"github.com/vpsik-lab/vpsGuard/internal/config"
	"github.com/vpsik-lab/vpsGuard/internal/engine"
	"github.com/vpsik-lab/vpsGuard/internal/firewall"
	"github.com/vpsik-lab/vpsGuard/internal/monitor"
	"github.com/vpsik-lab/vpsGuard/internal/notify"
	"github.com/vpsik-lab/vpsGuard/internal/pipeline"
	"github.com/vpsik-lab/vpsGuard/internal/rules"
	"github.com/vpsik-lab/vpsGuard/internal/selfprotect"
	"github.com/vpsik-lab/vpsGuard/internal/threat"
)

var (
	version = "0.3.0"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	configPath := flag.String("config", "/etc/vpsGuard/config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "show version and exit")
	genChecksum := flag.Bool("gen-checksum", false, "compute and print SHA256 of config file")
	healthAddr := flag.String("health-addr", "127.0.0.1:9090", "health endpoint listen address")
	flag.Parse()

	if *showVersion {
		fmt.Printf("vpsGuard version %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	if *genChecksum {
		f, err := os.Open(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		f.Close()
		fmt.Println(hex.EncodeToString(h.Sum(nil)))
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	os.MkdirAll(cfg.LogDir, 0750)
	os.MkdirAll(cfg.CacheDir, 0750)

	logger, err := newLogger(cfg.LogDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger error: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("starting vpsGuard agent",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("config_path", *configPath),
	)

	if cfg.Bootstrap.Enabled {
		logger.Info("running system hardening")
		bootstrap.RunHardening(cfg, logger)
	}

	bus := pipeline.NewBus(logger)
	intelClient := threat.NewIntelClient(cfg, logger)

	var fw *firewall.NftablesManager
	if fwInstance, err := firewall.NewNftables(cfg, logger); err != nil {
		logger.Warn("firewall unavailable, running without blocking", zap.Error(err))
	} else {
		fw = fwInstance
	}

	blockStore := firewall.NewBlockStore(filepath.Join(cfg.CacheDir, "blocks.json"))
	if fw != nil {
		entries, err := blockStore.Load()
		if err != nil {
			logger.Warn("cannot load persisted blocks", zap.Error(err))
		} else {
			for _, entry := range entries {
				duration := time.Until(entry.ExpiresAt)
				if duration > 0 {
					if err := fw.BlockIP(context.Background(), entry.IP, duration); err != nil {
						logger.Warn("failed to restore persisted block",
							zap.String("ip", entry.IP), zap.Error(err),
						)
					}
				}
			}
			logger.Info("restored persisted blocks", zap.Int("count", len(entries)))
		}
	}

	auditLog := engine.NewAuditLogger(filepath.Join(cfg.LogDir, "audit.jsonl"))
	scorer := engine.NewScorer(cfg, logger)
	decision := engine.NewDecision(cfg, fw, logger)
	notifier := notify.NewNotifier(cfg, logger)
	rulesEngine := rules.NewEngine(cfg, logger)
	rulesEngine.LoadDefaults()
	pullClient := api.NewPullClient(cfg, logger, intelClient)
	watchdog := selfprotect.NewWatchdog(logger, *configPath, time.Duration(cfg.SelfProtect.WatchdogInterval)*time.Second, cfg.SelfProtect.ConfigChecksum)
	journalMon := monitor.NewJournalMonitor(cfg, logger, bus)

	healthSrv := api.NewHealthServer(logger, version)
	healthSrv.RegisterComponent("watchdog", func(ctx context.Context) api.ComponentStatus {
		uptime := watchdog.Uptime()
		if uptime > 2*time.Duration(cfg.SelfProtect.WatchdogInterval)*time.Second {
			return api.ComponentStatus{Status: "degraded", Message: fmt.Sprintf("last health check %s ago", uptime.Round(time.Second))}
		}
		if watchdog.TamperWarnings() > 0 {
			return api.ComponentStatus{Status: "degraded", Message: fmt.Sprintf("%d tamper warnings", watchdog.TamperWarnings())}
		}
		return api.ComponentStatus{Status: "ok"}
	})
	if fw != nil {
		healthSrv.RegisterComponent("firewall", func(ctx context.Context) api.ComponentStatus {
			return api.ComponentStatus{Status: "ok"}
		})
	} else {
		healthSrv.RegisterComponent("firewall", func(ctx context.Context) api.ComponentStatus {
			return api.ComponentStatus{Status: "degraded", Message: "not available"}
		})
	}

	eventCh := bus.Subscribe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go journalMon.Run(ctx)
	go pullClient.Start(ctx)
	go watchdog.Run(ctx)
	go healthSrv.ListenAndServe(ctx, *healthAddr)

	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				logger.Debug("running periodic cleanup")
				scorer.Cleanup()
				intelClient.CacheCleanup()
				if err := blockStore.Cleanup(); err != nil {
					logger.Warn("block store cleanup failed", zap.Error(err))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			select {
			case evt := <-eventCh:
				processEvent(ctx, cfg, logger, scorer, decision, notifier, rulesEngine, intelClient, fw, blockStore, auditLog, evt)
			case <-ctx.Done():
				return
			}
		}
	}()

	<-sigCh
	logger.Info("shutting down")
	cancel()
	time.Sleep(1 * time.Second)
}

func processEvent(
	ctx context.Context,
	cfg *config.Config,
	logger *zap.Logger,
	scorer *engine.Scorer,
	decision *engine.DecisionEngine,
	notifier *notify.Notifier,
	rulesEngine *rules.Engine,
	intelClient *threat.IntelClient,
	fw *firewall.NftablesManager,
	blockStore *firewall.BlockStore,
	auditLog *engine.AuditLogger,
	evt pipeline.Envelope,
) {
	logger.Debug("processing event",
		zap.String("ip", evt.SourceIP()),
		zap.String("type", string(evt.Event.EventType())),
		zap.String("trace_id", evt.TraceID),
	)

	scorer.RecordEvent(evt)
	scores := scorer.Evaluate(ctx, evt, intelClient)
	actions := decision.Evaluate(ctx, evt, scores, rulesEngine)

	for _, action := range actions {
		if action.Block && fw != nil {
			if err := fw.BlockIP(ctx, evt.SourceIP(), action.Duration); err != nil {
				logger.Error("block failed",
					zap.String("ip", evt.SourceIP()),
					zap.Error(err),
				)
			}
			blockStore.Save(evt.SourceIP(), time.Now().Add(action.Duration), action.Reason)
			intelClient.ReportIP(ctx, evt.SourceIP())
		}
		if action.Notify {
			notifier.Send(ctx, evt, scores, action)
		}
	}

	if action := firstBlockAction(actions); action != nil {
		auditLog.Log(engine.AuditEntry{
			Timestamp: time.Now(),
			IP:        evt.SourceIP(),
			TraceID:   evt.TraceID,
			EventType: string(evt.Event.EventType()),
			Score:     action.Score,
			Verdict:   scores.Verdict(),
			Action:    action.Type,
			Reason:    action.Reason,
			Duration:  action.Duration.String(),
			Sources:   scores.Sources,
		})
	}
}

func firstBlockAction(actions []engine.Action) *engine.Action {
	for _, a := range actions {
		if a.Block {
			return &a
		}
	}
	if len(actions) > 0 {
		return &actions[0]
	}
	return nil
}

func newLogger(logDir string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.DisableStacktrace = true
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	cfg.OutputPaths = []string{"stdout"}
	if logDir != "" {
		cfg.OutputPaths = append(cfg.OutputPaths, filepath.Join(logDir, "vpsGuard.log"))
	}
	return cfg.Build()
}
