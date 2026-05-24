package firewall

import (
	"context"
	"os"
	"testing"

	"github.com/vps-guard/vps-guard/internal/config"
)

func TestNewNftables(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root privileges")
	}

	cfg := &config.Config{}
	cfg.SetDefaults()

	mgr, err := NewNftables(cfg, nil)
	if err != nil {
		t.Fatalf("NewNftables() error = %v", err)
	}
	if mgr == nil {
		t.Fatal("NewNftables() returned nil")
	}

	defer func() {
		mgr.UnblockIP(context.Background(), "1.2.3.4")
	}()
}

func TestBlockUnblockIP(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root privileges")
	}

	cfg := &config.Config{}
	cfg.SetDefaults()

	mgr, err := NewNftables(cfg, nil)
	if err != nil {
		t.Fatalf("NewNftables() error = %v", err)
	}

	ip := "10.0.0.1"

	if err := mgr.BlockIP(context.Background(), ip, 60); err != nil {
		t.Fatalf("BlockIP() error = %v", err)
	}

	blocked, err := mgr.IsBlocked(context.Background(), ip)
	if err != nil {
		t.Fatalf("IsBlocked() error = %v", err)
	}
	if !blocked {
		t.Error("expected IP to be blocked after BlockIP()")
	}

	if err := mgr.UnblockIP(context.Background(), ip); err != nil {
		t.Fatalf("UnblockIP() error = %v", err)
	}
}

func TestContainsIP(t *testing.T) {
	tests := []struct {
		output string
		ip     string
		want   bool
	}{
		{"elements = { 1.2.3.4, 5.6.7.8 }", "1.2.3.4", true},
		{"elements = { 1.2.3.4, 5.6.7.8 }", "5.6.7.8", true},
		{"elements = { 1.2.3.4 }", "9.9.9.9", false},
		{"", "1.2.3.4", false},
	}

	for _, tt := range tests {
		got := containsIP(tt.output, tt.ip)
		if got != tt.want {
			t.Errorf("containsIP(%q, %q) = %v, want %v", tt.output, tt.ip, got, tt.want)
		}
	}
}
