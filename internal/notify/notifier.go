package notify

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vpsik-lab/vpsGuard/internal/config"
	"github.com/vpsik-lab/vpsGuard/internal/engine"
	"github.com/vpsik-lab/vpsGuard/internal/pipeline"
)

type Notifier struct {
	telegram *TelegramNotifier
	email    *EmailNotifier
	logger   *zap.Logger

	cooldown     time.Duration
	cooldownMu   sync.Mutex
	cooldownSent map[string]time.Time
}

func NewNotifier(cfg *config.Config, logger *zap.Logger) *Notifier {
	n := &Notifier{
		logger:       logger,
		cooldown:     time.Duration(cfg.Notify.CooldownMinutes) * time.Minute,
		cooldownSent: make(map[string]time.Time),
	}

	if cfg.Notify.TelegramToken != "" && cfg.Notify.TelegramChatID != "" {
		n.telegram = NewTelegramNotifier(cfg.Notify.TelegramToken, cfg.Notify.TelegramChatID, logger)
	}
	if cfg.Notify.SMTPHost != "" && cfg.Notify.EmailTo != "" {
		n.email = NewEmailNotifier(
			cfg.Notify.SMTPHost, cfg.Notify.SMTPPort,
			cfg.Notify.SMTPUser, cfg.Notify.SMTPPass,
			cfg.Notify.EmailFrom, cfg.Notify.EmailTo,
			logger,
		)
	}

	return n
}

func (n *Notifier) Send(ctx context.Context, evt pipeline.Envelope, scores *engine.ScoreResult, action engine.Action) {
	ip := evt.SourceIP()

	if n.onCooldown(ip) {
		n.logger.Debug("notification skipped (cooldown)", zap.String("ip", ip))
		return
	}

	msg := formatAlert(evt, scores, action)

	if n.telegram != nil {
		if err := n.telegram.Send(ctx, msg); err != nil {
			n.logger.Error("telegram send failed", zap.Error(err))
		}
	}

	if n.email != nil {
		if err := n.email.Send(ctx, "vpsGuard Alert - "+scores.IP, msg); err != nil {
			n.logger.Error("email send failed", zap.Error(err))
		}
	}

	n.markSent(ip)
}

func (n *Notifier) SendReport(ctx context.Context, text string, useTelegram bool, useEmail bool) {
	if n.telegram != nil && useTelegram {
		if err := n.telegram.Send(ctx, text); err != nil {
			n.logger.Error("telegram report send failed", zap.Error(err))
		}
	}
	if n.email != nil && useEmail {
		if err := n.email.Send(ctx, "vpsGuard Daily Report", text); err != nil {
			n.logger.Error("email report send failed", zap.Error(err))
		}
	}
}

func (n *Notifier) onCooldown(ip string) bool {
	if n.cooldown <= 0 {
		return false
	}
	n.cooldownMu.Lock()
	defer n.cooldownMu.Unlock()
	last, ok := n.cooldownSent[ip]
	if !ok {
		return false
	}
	return time.Since(last) < n.cooldown
}

func (n *Notifier) markSent(ip string) {
	if n.cooldown <= 0 {
		return
	}
	n.cooldownMu.Lock()
	defer n.cooldownMu.Unlock()
	n.cooldownSent[ip] = time.Now()
}

func formatAlert(evt pipeline.Envelope, scores *engine.ScoreResult, action engine.Action) string {
	now := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	verdict := scores.Verdict()

	verdictEmoji := map[string]string{
		"critical":    "🚨",
		"high":        "⚠️",
		"suspicious":  "🔶",
		"low":         "🔵",
		"clean":       "✅",
	}

	emoji := verdictEmoji[verdict]
	if emoji == "" {
		emoji = "❓"
	}

	return fmt.Sprintf(`%s <b>vpsGuard Alert</b>

<b>IP:</b> %s
<b>Score:</b> %d/100 (%s)
<b>Action:</b> %s
<b>Reason:</b> %s
<b>Sources:</b> %v

┌─ <b>Score Breakdown</b>
├ AbuseIPDB: %d
├ AlienVault OTX: %d
├ Central Feed: %d (conf: %d)
├ Behavioral: %d
└ Temporal: %d

<b>Time:</b> %s
	`, emoji, scores.IP, scores.FinalScore, verdict,
		action.Type, action.Reason, scores.Sources,
		scores.AbuseScore, scores.OTXScore,
		scores.CentralScore, scores.CentralConf,
		scores.Behavioral, scores.Temporal, now)
}
