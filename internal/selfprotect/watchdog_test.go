package selfprotect

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNewWatchdog(t *testing.T) {
	logger := zap.NewNop()
	w := NewWatchdog(logger, "/etc/vps-guard/config.yaml", 30*time.Second, "")
	if w == nil {
		t.Fatal("NewWatchdog returned nil")
	}
	if w.configPath != "/etc/vps-guard/config.yaml" {
		t.Errorf("configPath = %q", w.configPath)
	}
	if w.interval != 30*time.Second {
		t.Errorf("interval = %v, want 30s", w.interval)
	}
}

func TestWatchdogPing(t *testing.T) {
	logger := zap.NewNop()
	w := NewWatchdog(logger, "/etc/vps-guard/config.yaml", 30*time.Second, "")

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
	w := NewWatchdog(logger, "/etc/vps-guard/config.yaml", 30*time.Second, "")

	time.Sleep(5 * time.Millisecond)
	uptime := w.Uptime()

	if uptime < 5*time.Millisecond {
		t.Errorf("expected uptime >= 5ms, got %v", uptime)
	}
}

func TestWatchdogTickCount(t *testing.T) {
	logger := zap.NewNop()
	w := NewWatchdog(logger, "/etc/vps-guard/config.yaml", 30*time.Second, "")

	if w.tickCount != 0 {
		t.Errorf("initial tickCount = %d, want 0", w.tickCount)
	}
}

func TestWatchdogChecksumEmpty(t *testing.T) {
	logger := zap.NewNop()
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("key: value\n")
	tmpFile.Close()

	w := NewWatchdog(logger, tmpFile.Name(), 30*time.Second, "")
	w.healthCheck()

	if w.TamperWarnings() != 0 {
		t.Error("expected no tamper warnings with empty checksum")
	}
}

func TestWatchdogChecksumMatch(t *testing.T) {
	logger := zap.NewNop()
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	content := "key: value\n"
	tmpFile.WriteString(content)
	tmpFile.Close()

	h := sha256.Sum256([]byte(content))
	expected := hex.EncodeToString(h[:])

	w := NewWatchdog(logger, tmpFile.Name(), 30*time.Second, expected)
	w.healthCheck()

	if w.TamperWarnings() != 0 {
		t.Errorf("expected 0 tamper warnings, got %d", w.TamperWarnings())
	}
}

func TestWatchdogChecksumMismatch(t *testing.T) {
	logger := zap.NewNop()
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("key: value\n")
	tmpFile.Close()

	w := NewWatchdog(logger, tmpFile.Name(), 30*time.Second, "0000000000000000000000000000000000000000000000000000000000000000")
	w.healthCheck()

	if w.TamperWarnings() != 1 {
		t.Errorf("expected 1 tamper warning, got %d", w.TamperWarnings())
	}
}

func TestWatchdogChecksumConsecutiveWarnings(t *testing.T) {
	logger := zap.NewNop()
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("key: value\n")
	tmpFile.Close()

	w := NewWatchdog(logger, tmpFile.Name(), 30*time.Second, "0000000000000000000000000000000000000000000000000000000000000000")

	w.healthCheck()
	if w.TamperWarnings() != 1 {
		t.Fatalf("expected 1 warning after first check, got %d", w.TamperWarnings())
	}

	w.healthCheck()
	if w.TamperWarnings() != 2 {
		t.Errorf("expected 2 warnings after second check, got %d", w.TamperWarnings())
	}
}

func TestWatchdogChecksumMatchResetsCounter(t *testing.T) {
	logger := zap.NewNop()
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	content := "key: value\n"
	tmpFile.WriteString(content)
	tmpFile.Close()

	h := sha256.Sum256([]byte(content))
	expected := hex.EncodeToString(h[:])

	w := NewWatchdog(logger, tmpFile.Name(), 30*time.Second, expected)

	w.healthCheck()
	if w.TamperWarnings() != 0 {
		t.Fatalf("expected 0 warnings with matching hash, got %d", w.TamperWarnings())
	}

	w.healthCheck()
	if w.TamperWarnings() != 0 {
		t.Errorf("expected 0 warnings after second match, got %d", w.TamperWarnings())
	}
}
