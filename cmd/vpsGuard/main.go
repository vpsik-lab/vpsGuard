package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/vpsik-lab/vpsGuard/internal/api"
	"github.com/vpsik-lab/vpsGuard/internal/config"
	"github.com/vpsik-lab/vpsGuard/internal/engine"
	"github.com/vpsik-lab/vpsGuard/internal/firewall"
	"github.com/vpsik-lab/vpsGuard/internal/monitor"
	"github.com/vpsik-lab/vpsGuard/internal/notify"
	"github.com/vpsik-lab/vpsGuard/internal/pipeline"
	"github.com/vpsik-lab/vpsGuard/internal/reporting"
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
	configPath  := flag.String("config", "/etc/vpsGuard/config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "show version and exit")
	genChecksum := flag.Bool("gen-checksum", false, "compute and print SHA256 of config file")
	hashChainDir := flag.String("hash-chain", "", "append hash chain entry for logs in directory")
	healthAddr  := flag.String("health-addr", "127.0.0.1:9090", "health endpoint listen address")
	listBlocked := flag.Bool("list-blocked", false, "list currently blocked IPs")
	unblockIP   := flag.String("unblock", "", "immediately unblock an IP address")
	showStatus  := flag.Bool("status", false, "show agent health status (requires agent to be running)")
	flag.Parse()

	if *hashChainDir != "" {
		runHashChain(*hashChainDir)
		return
	}

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

	// ── CLI utility commands (no daemon needed) ──────────────────────────
	if *listBlocked {
		runListBlocked(cfg)
		return
	}
	if *unblockIP != "" {
		runUnblockIP(cfg, *unblockIP)
		return
	}
	if *showStatus {
		runStatus(*healthAddr)
		return
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

	// NOTE: bootstrap hardening is intentionally NOT run here.
	// The daemon runs as user 'vpsGuard' with only CAP_NET_ADMIN+CAP_SYSLOG;
	// apt-get / sshd_config edits require full root and belong in
	// deploy/install.sh and deploy/harden.sh (run once at install time).

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
	reporter := reporting.NewDailyReporter(cfg, logger, notifier)
	rulesEngine := rules.NewEngine(cfg, logger)
	rulesEngine.LoadDefaults()
	pullClient := api.NewPullClient(cfg, logger, intelClient)
	watchdog := selfprotect.NewWatchdog(logger, *configPath, time.Duration(cfg.SelfProtect.WatchdogInterval)*time.Second, cfg.SelfProtect.ConfigChecksum)
	// Wire tamper callback: fire an immediate alert via all configured channels
	watchdog.OnTamper(func(msg string) {
		logger.Error("TAMPER ALERT — sending emergency notification", zap.String("detail", msg))
		notifier.SendRaw(context.Background(), "\u26a0\ufe0f *vpsGuard TAMPER ALERT*\n"+msg)
	})
	journalMon := monitor.NewJournalMonitor(cfg, logger, bus)

	agentMetrics := api.NewAgentMetrics()
	healthSrv := api.NewHealthServer(logger, version)
	healthSrv.RegisterMetrics(agentMetrics)
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
	go reporter.Run(ctx)

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
				processEvent(ctx, cfg, logger, scorer, decision, notifier, reporter, rulesEngine, intelClient, fw, blockStore, auditLog, agentMetrics, evt)
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
	reporter *reporting.DailyReporter,
	rulesEngine *rules.Engine,
	intelClient *threat.IntelClient,
	fw *firewall.NftablesManager,
	blockStore *firewall.BlockStore,
	auditLog *engine.AuditLogger,
	metrics *api.AgentMetrics,
	evt pipeline.Envelope,
) {
	logger.Debug("processing event",
		zap.String("ip", evt.SourceIP()),
		zap.String("type", string(evt.Event.EventType())),
		zap.String("trace_id", evt.TraceID),
	)

	reporter.IncrementEventCount()
	metrics.EventsTotal.Add(1)

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
			metrics.BlocksTotal.Add(1)
		}
		if action.Notify {
			notifier.Send(ctx, evt, scores, action)
		}
		// Update action-type counters
		switch action.Type {
		case "quarantine":
			metrics.QuarantTotal.Add(1)
		case "rate_limit":
			metrics.RateLimTotal.Add(1)
		case "monitor":
			metrics.MonitorTotal.Add(1)
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

// ── CLI utility helpers ───────────────────────────────────────────────────────

// runListBlocked prints all currently blocked IPs.
// It merges two sources:
//  1. blocks.json (the persistent block store written by the daemon)
//  2. nftables live set (captures IPs blocked outside the store, e.g. after
//     blocks.json was manually deleted or by a direct nft command)
func runListBlocked(cfg *config.Config) {
	// ── Source 1: block store ────────────────────────────────────────────
	type row struct {
		ip      string
		expires string
		reason  string
	}
	seen := make(map[string]struct{})
	var rows []row

	store := firewall.NewBlockStore(filepath.Join(cfg.CacheDir, "blocks.json"))
	if entries, err := store.Load(); err == nil {
		for _, e := range entries {
			remaining := time.Until(e.ExpiresAt).Round(time.Second)
			expiry := e.ExpiresAt.Format(time.RFC3339)
			if remaining <= 0 {
				expiry += " (expired)"
			} else {
				expiry += fmt.Sprintf(" (in %s)", remaining)
			}
			rows = append(rows, row{e.IP, expiry, e.Reason})
			seen[e.IP] = struct{}{}
		}
	} else {
		fmt.Fprintf(os.Stderr, "warn: could not read block store: %v\n", err)
	}

	// ── Source 2: live nftables set ──────────────────────────────────────
	fw, fwErr := firewall.NewNftables(cfg, zap.NewNop())
	if fwErr == nil {
		ctx := context.Background()
		// IPv4 set
		if ips, err := fw.ListBlocked(ctx, false); err == nil {
			for _, ip := range ips {
				if _, exists := seen[ip]; !exists {
					rows = append(rows, row{ip, "(nftables only — no store entry)", ""})
					seen[ip] = struct{}{}
				}
			}
		}
		// IPv6 set
		if ips, err := fw.ListBlocked(ctx, true); err == nil {
			for _, ip := range ips {
				if _, exists := seen[ip]; !exists {
					rows = append(rows, row{ip, "(nftables only — no store entry)", ""})
					seen[ip] = struct{}{}
				}
			}
		}
	}

	if len(rows) == 0 {
		fmt.Println("No IPs currently blocked.")
		return
	}
	fmt.Printf("%-20s  %-42s  %s\n", "IP", "EXPIRES", "REASON")
	fmt.Println(strings.Repeat("-", 82))
	for _, r := range rows {
		fmt.Printf("%-20s  %-42s  %s\n", r.ip, r.expires, r.reason)
	}
	if fwErr != nil {
		fmt.Fprintf(os.Stderr, "\nnote: nftables unavailable (%v) — showing block store only\n", fwErr)
	}
}

// runUnblockIP removes an IP from the block store and from nftables if available.
func runUnblockIP(cfg *config.Config, ip string) {
	// 1. Remove from persistent block store.
	store := firewall.NewBlockStore(filepath.Join(cfg.CacheDir, "blocks.json"))
	if err := store.Remove(ip); err != nil {
		fmt.Fprintf(os.Stderr, "warn: block store removal: %v\n", err)
	} else {
		fmt.Printf("✅ %s removed from block store\n", ip)
	}

	// 2. Best-effort nftables removal (requires CAP_NET_ADMIN / root).
	// Use zap.NewNop() — never pass nil to avoid a potential nil-dereference
	// inside nftables.go if nft returns an unexpected error.
	fw, err := firewall.NewNftables(cfg, zap.NewNop())
	if err != nil {
		fmt.Println("note: nftables unavailable — block store entry removed only.")
		return
	}
	ctx := context.Background()
	if err2 := fw.UnblockIP(ctx, ip); err2 != nil {
		fmt.Fprintf(os.Stderr, "warn: nftables unblock failed (may need root): %v\n", err2)
	} else {
		fmt.Printf("✅ %s unblocked from nftables\n", ip)
	}
}

// runStatus queries the running agent's /health endpoint and prints a summary.
func runStatus(healthAddr string) {
	url := "http://" + healthAddr + "/health"
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot reach agent at %s: %v\n", url, err)
		fmt.Println("Is the agent running?  →  systemctl status vpsGuard")
		os.Exit(1)
	}
	defer resp.Body.Close()
	var body map[string]interface{}
	if err2 := json.NewDecoder(resp.Body).Decode(&body); err2 != nil {
		fmt.Fprintf(os.Stderr, "invalid response: %v\n", err2)
		os.Exit(1)
	}
	fmt.Printf("Status:  %v\n", body["status"])
	fmt.Printf("Version: %v\n", body["version"])
	fmt.Printf("Uptime:  %v\n", body["uptime"])
	if comps, ok := body["components"].(map[string]interface{}); ok {
		fmt.Println("\nComponents:")
		for name, val := range comps {
			fmt.Printf("  %-20s %v\n", name, val)
		}
	}
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

func runHashChain(dir string) {
	chainFile := filepath.Join(dir, "log-hashes.yaml")

	var existing []byte
	if data, err := os.ReadFile(chainFile); err == nil {
		existing = data
	}

	prevHash := ""
	lines := strings.Split(strings.TrimSpace(string(existing)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "  sha256: ") {
			prevHash = strings.TrimPrefix(lines[i], "  sha256: ")
			break
		}
	}

	now := time.Now().UTC().Format("2006-01-02")
	var newHash string

	files, _ := filepath.Glob(filepath.Join(dir, "*.log.*"))
	jsonlFiles, _ := filepath.Glob(filepath.Join(dir, "*.jsonl.*"))
	files = append(files, jsonlFiles...)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		h := sha256.Sum256(data)
		newHash = hex.EncodeToString(h[:])
	}

	if newHash == "" {
		os.Exit(0)
	}

	var chainData string
	if len(existing) == 0 {
		chainData = fmt.Sprintf("chain:\n  - date: %s\n    file: %s\n    sha256: %s\n    prev: \"\"\n",
			now, filepath.Base(files[0]), newHash)
	} else {
		chainData = fmt.Sprintf("%s  - date: %s\n    file: %s\n    sha256: %s\n    prev: %s\n",
			string(existing), now, filepath.Base(files[0]), newHash, prevHash)
	}
	os.WriteFile(chainFile, []byte(chainData), 0644)
}
