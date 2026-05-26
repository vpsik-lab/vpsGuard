package reporting

import (
	"context"
	"testing"
	"time"

	"github.com/vpsik-lab/vpsGuard/internal/config"

	"go.uber.org/zap"
)

func TestNewDailyReporter(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	r := NewDailyReporter(cfg, logger, nil)
	if r == nil {
		t.Fatal("NewDailyReporter returned nil")
	}
}

func TestDailyReporterDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	r := NewDailyReporter(cfg, logger, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r.Run(ctx) // should return immediately since disabled
}

func TestDailyReporterEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.Report.Enabled = true
	cfg.Report.IntervalHours = 1
	logger := zap.NewNop()

	r := NewDailyReporter(cfg, logger, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r.Run(ctx) // should exit cleanly on cancel
}

func TestIncrementEventCount(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	r := NewDailyReporter(cfg, logger, nil)
	r.IncrementEventCount()
	r.IncrementEventCount()
	r.IncrementEventCount()

	r.mu.Lock()
	count := r.eventCount24h
	r.mu.Unlock()

	if count != 3 {
		t.Errorf("event count = %d, want 3", count)
	}
}

func TestFormatReport(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	r := NewDailyReporter(cfg, logger, nil)
	msg := r.formatReport(100, 10, 5, 2, 200, "valid (3 entries)", "14d 6h")

	if msg == "" {
		t.Fatal("formatReport returned empty string")
	}

	if !contains(msg, "Daily Report") {
		t.Error("report missing Daily Report header")
	}
	if !contains(msg, "Blocked: 10") {
		t.Error("report missing Blocked count")
	}
	if !contains(msg, "Rate Limited: 5") {
		t.Error("report missing Rate Limited count")
	}
	if !contains(msg, "Quarantined: 2") {
		t.Error("report missing Quarantined count")
	}
	if !contains(msg, "Events processed: 100") {
		t.Error("report missing events count")
	}
	if !contains(msg, "valid (3 entries)") {
		t.Error("report missing hash chain status")
	}
}

func TestReadBlockStatsEmptyFile(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.LogDir = t.TempDir()
	logger := zap.NewNop()

	r := NewDailyReporter(cfg, logger, nil)
	blocks, rateLimits, quarantines := r.readBlockStats()
	if blocks != 0 || rateLimits != 0 || quarantines != 0 {
		t.Errorf("expected 0, got blocks=%d rate=%d quar=%d", blocks, rateLimits, quarantines)
	}
}

func TestCountAuditEventsEmptyFile(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.LogDir = t.TempDir()
	logger := zap.NewNop()

	r := NewDailyReporter(cfg, logger, nil)
	count := r.countAuditEvents()
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestUptime(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	r := NewDailyReporter(cfg, logger, nil)
	uptime := r.uptime()
	if uptime == "" {
		t.Fatal("uptime returned empty")
	}
	if uptime == "unknown" {
		t.Log("uptime parsing failed (not critical)")
	}
}

func TestVerifyHashChainNoFile(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.LogDir = t.TempDir()
	logger := zap.NewNop()

	r := NewDailyReporter(cfg, logger, nil)
	status := r.verifyHashChain()
	if status != "no chain file" {
		t.Errorf("expected 'no chain file', got %q", status)
	}
}

func TestFormatReportTimeRange(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.Report.IntervalHours = 24
	logger := zap.NewNop()

	r := NewDailyReporter(cfg, logger, nil)
	msg := r.formatReport(0, 0, 0, 0, 0, "empty", "1d 0h")

	nextReport := time.Now().Add(24 * time.Hour).Format("2006-01-02")
	if !contains(msg, nextReport[:10]) {
		t.Errorf("report missing next day date %s", nextReport[:10])
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
