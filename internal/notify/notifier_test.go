package notify

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vpsik-lab/vpsGuard/internal/config"
	"github.com/vpsik-lab/vpsGuard/internal/engine"
	"github.com/vpsik-lab/vpsGuard/internal/pipeline"
)

func TestNewNotifierEmpty(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	n := NewNotifier(cfg, logger)
	if n == nil {
		t.Fatal("NewNotifier returned nil")
	}
	if n.telegram != nil {
		t.Error("expected telegram to be nil when no config")
	}
	if n.email != nil {
		t.Error("expected email to be nil when no config")
	}
}

func TestNewNotifierTelegramOnly(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.Notify.TelegramToken = "test-token"
	cfg.Notify.TelegramChatID = "test-chat"
	logger := zap.NewNop()

	n := NewNotifier(cfg, logger)
	if n.telegram == nil {
		t.Error("expected telegram to be non-nil when configured")
	}
	if n.email != nil {
		t.Error("expected email to be nil")
	}
}

func TestNewNotifierEmailOnly(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.Notify.SMTPHost = "smtp.test.com"
	cfg.Notify.EmailTo = "test@test.com"
	cfg.Notify.EmailFrom = "agent@test.com"
	logger := zap.NewNop()

	n := NewNotifier(cfg, logger)
	if n.email == nil {
		t.Error("expected email to be non-nil when configured")
	}
	if n.telegram != nil {
		t.Error("expected telegram to be nil")
	}
}

func TestFormatAlertAllVerdicts(t *testing.T) {
	now := time.Now()
	evt := pipeline.Envelope{
		Timestamp: now,
		Source:    "test",
		TraceID:   "trace-123",
		Event:     pipeline.BaseEvent{IP: "1.2.3.4"},
	}

	tests := []struct {
		score int
		verdict string
	}{
		{85, "critical"},
		{60, "high"},
		{35, "suspicious"},
		{10, "low"},
		{0, "clean"},
	}

	for _, tt := range tests {
		scores := &engine.ScoreResult{
			IP: "1.2.3.4", FinalScore: tt.score,
			AbuseScore: 50, OTXScore: 30, CentralScore: 20,
			CentralConf: 80, Behavioral: 40, Temporal: 10,
		}
		action := engine.Action{
			Type: "block", Score: tt.score,
			Block: true, Notify: true,
			Reason: "test_reason",
		}

		msg := formatAlert(evt, scores, action)
		if msg == "" {
			t.Fatalf("formatAlert returned empty for score %d", tt.score)
		}
		if !strings.Contains(msg, "1.2.3.4") {
			t.Error("alert missing IP")
		}
		if !strings.Contains(msg, tt.verdict) {
			t.Errorf("alert missing verdict %q for score %d", tt.verdict, tt.score)
		}
		if !strings.Contains(msg, "block") {
			t.Error("alert missing action")
		}
	}
}

func TestFormatAlertActionTypes(t *testing.T) {
	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{IP: "1.2.3.4"},
	}
	scores := &engine.ScoreResult{
		IP: "1.2.3.4", FinalScore: 75,
	}

	actionTypes := []string{"block", "quarantine", "monitor", "ignore"}
	for _, at := range actionTypes {
		action := engine.Action{Type: at, Score: 75, Reason: "test"}
		msg := formatAlert(evt, scores, action)
		if !strings.Contains(msg, at) {
			t.Errorf("alert missing action type %q", at)
		}
	}
}

func TestFormatAlertScoreBreakdown(t *testing.T) {
	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{IP: "1.2.3.4"},
	}
	scores := &engine.ScoreResult{
		IP: "1.2.3.4", FinalScore: 72,
		AbuseScore: 80, OTXScore: 60, CentralScore: 50,
		CentralConf: 95, Behavioral: 70, Temporal: 30,
		Sources: []string{"abuseipdb", "alienvault", "behavioral"},
	}
	action := engine.Action{Type: "block", Score: 72, Reason: "score_exceeded"}

	msg := formatAlert(evt, scores, action)
	if !strings.Contains(msg, "80") {
		t.Error("alert missing AbuseIPDB score")
	}
	if !strings.Contains(msg, "60") {
		t.Error("alert missing OTX score")
	}
	if !strings.Contains(msg, "50") {
		t.Error("alert missing Central score")
	}
	if !strings.Contains(msg, "95") {
		t.Error("alert missing Central confidence")
	}
}

func TestSendWithNoNotifiers(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	n := NewNotifier(cfg, logger)
	evt := pipeline.Envelope{Event: pipeline.BaseEvent{IP: "1.2.3.4"}}
	scores := &engine.ScoreResult{IP: "1.2.3.4", FinalScore: 50}
	action := engine.Action{Type: "block", Score: 50, Reason: "test"}

	n.Send(context.Background(), evt, scores, action)
}

func TestCooldownBlocksDuplicate(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.Notify.CooldownMinutes = 10
	logger := zap.NewNop()

	n := NewNotifier(cfg, logger)

	if n.onCooldown("1.2.3.4") {
		t.Error("IP should not be on cooldown before first send")
	}

	n.markSent("1.2.3.4")

	if !n.onCooldown("1.2.3.4") {
		t.Error("IP should be on cooldown after send")
	}
}

func TestCooldownDifferentIPs(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.Notify.CooldownMinutes = 10
	logger := zap.NewNop()

	n := NewNotifier(cfg, logger)

	n.markSent("1.1.1.1")

	if n.onCooldown("2.2.2.2") {
		t.Error("different IP should not be on cooldown")
	}
}

func TestCooldownExpires(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.Notify.CooldownMinutes = 0
	logger := zap.NewNop()

	n := NewNotifier(cfg, logger)

	n.markSent("1.2.3.4")

	if n.onCooldown("1.2.3.4") {
		t.Error("cooldown should be disabled when CooldownMinutes = 0")
	}
}

func TestNewNotifierCooldownConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.Notify.CooldownMinutes = 30
	logger := zap.NewNop()

	n := NewNotifier(cfg, logger)
	if n.cooldown != 30*time.Minute {
		t.Errorf("expected 30m cooldown, got %v", n.cooldown)
	}
}
