package selfprotect

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNewWatchdog(t *testing.T) {
	logger := zap.NewNop()
	w := NewWatchdog(logger)
	if w == nil {
		t.Fatal("NewWatchdog returned nil")
	}
	if w.configPath != "/etc/vps-guard/config.yaml" {
		t.Errorf("configPath = %q", w.configPath)
	}
}

func TestWatchdogPing(t *testing.T) {
	logger := zap.NewNop()
	w := NewWatchdog(logger)

	time.Sleep(10 * time.Millisecond)
	w.Ping()

	uptime := w.Uptime()
	if uptime < 0 {
		t.Error("Uptime should be positive")
	}
	if uptime > 5*time.Second {
		t.Errorf("Uptime too large: %v", uptime)
	}
}

func TestWatchdogUptime(t *testing.T) {
	logger := zap.NewNop()
	w := NewWatchdog(logger)

	time.Sleep(5 * time.Millisecond)
	uptime := w.Uptime()

	if uptime < 5*time.Millisecond {
		t.Errorf("expected uptime >= 5ms, got %v", uptime)
	}
}

func TestWatchdogTickCount(t *testing.T) {
	logger := zap.NewNop()
	w := NewWatchdog(logger)

	if w.tickCount != 0 {
		t.Errorf("initial tickCount = %d, want 0", w.tickCount)
	}
}
