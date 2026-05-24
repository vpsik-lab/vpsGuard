package notify

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/vps-guard/vps-guard/internal/config"
	"github.com/vps-guard/vps-guard/internal/engine"
	"github.com/vps-guard/vps-guard/internal/pipeline"
)

type Notifier struct {
	telegram *TelegramNotifier
	email    *EmailNotifier
	logger   *zap.Logger
}

func NewNotifier(cfg *config.Config, logger *zap.Logger) *Notifier {
	n := &Notifier{logger: logger}

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
	msg := formatAlert(evt, scores, action)

	if n.telegram != nil {
		if err := n.telegram.Send(ctx, msg); err != nil {
			n.logger.Error("telegram send failed", zap.Error(err))
		}
	}

	if n.email != nil {
		if err := n.email.Send(ctx, "VPS-Guard Alert - "+scores.IP, msg); err != nil {
			n.logger.Error("email send failed", zap.Error(err))
		}
	}
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

	return fmt.Sprintf(`%s <b>VPS-Guard Alert</b>

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
