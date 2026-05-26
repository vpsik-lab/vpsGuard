package config

import (
	"os"
	"testing"
)

func TestSetDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.SetDefaults()

	if cfg.LogDir != "/var/log/vpsGuard" {
		t.Errorf("LogDir = %q, want %q", cfg.LogDir, "/var/log/vpsGuard")
	}
	if cfg.AgentMode != "hybrid" {
		t.Errorf("AgentMode = %q, want %q", cfg.AgentMode, "hybrid")
	}
	if cfg.Monitor.Interval != 5 {
		t.Errorf("Monitor.Interval = %d, want 5", cfg.Monitor.Interval)
	}
	if cfg.Scoring.BlockThreshold != 60 {
		t.Errorf("BlockThreshold = %d, want 60", cfg.Scoring.BlockThreshold)
	}
	if cfg.Scoring.AbuseIPDBWeight != 0.25 {
		t.Errorf("AbuseIPDBWeight = %f, want 0.25", cfg.Scoring.AbuseIPDBWeight)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &Config{
				Monitor: MonitorConfig{Interval: 5, LogPaths: []string{"/var/log/auth.log"}},
				Threat:  ThreatConfig{CacheTTL: 24, RateLimit: 10},
				Scoring: ScoringConfig{
					BlockThreshold: 60, RateLimitScore: 40, QuarantineScore: 30, QuarantineMin: 15,
					AbuseIPDBWeight: 0.25, AlienVaultWeight: 0.20,
					BehaviorWeight: 0.30, TemporalWeight: 0.10, CentralWeight: 0.15,
					CentralBlockThreshold: 80, CentralQuarThreshold: 50,
				},
				Firewall: FirewallConfig{Table: "vpsGuard", SetName: "blacklist", DefaultBlockDuration: 24},
				CentralFeed: CentralFeedConfig{MinConfidence: 50},
			},
			wantErr: false,
		},
		{
			name: "block threshold too high",
			cfg: &Config{
				Scoring: ScoringConfig{BlockThreshold: 200},
			},
			wantErr: true,
		},
		{
			name: "weights sum too high",
			cfg: &Config{
				Monitor: MonitorConfig{Interval: 5},
				Threat: ThreatConfig{CacheTTL: 24},
				Scoring: ScoringConfig{
					BlockThreshold: 50, QuarantineScore: 25,
					AbuseIPDBWeight: 0.5, AlienVaultWeight: 0.5,
					BehaviorWeight: 0.5, TemporalWeight: 0.1, CentralWeight: 0.5,
					CentralBlockThreshold: 80, CentralQuarThreshold: 50,
				},
				Firewall: FirewallConfig{DefaultBlockDuration: 24},
			},
			wantErr: true,
		},
		{
			name: "weights exactly 1.0 passes",
			cfg: &Config{
				Monitor: MonitorConfig{Interval: 5},
				Threat: ThreatConfig{CacheTTL: 24},
				Scoring: ScoringConfig{
					BlockThreshold: 60, QuarantineScore: 30,
					AbuseIPDBWeight: 0.25, AlienVaultWeight: 0.20,
					BehaviorWeight: 0.30, TemporalWeight: 0.10, CentralWeight: 0.15,
					CentralBlockThreshold: 80, CentralQuarThreshold: 50,
				},
				Firewall: FirewallConfig{DefaultBlockDuration: 24},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.SetDefaults()
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	data := []byte(`
log_dir: /tmp/test-logs
agent_mode: local
monitor:
  interval_seconds: 10
threat:
  cache_ttl_hours: 48
  rate_limit_per_min: 5
scoring:
  block_threshold: 70
firewall:
  default_block_hours: 12
`)
	tmpFile, err := os.CreateTemp("", "vpsGuard-test-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(data); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.LogDir != "/tmp/test-logs" {
		t.Errorf("LogDir = %q, want %q", cfg.LogDir, "/tmp/test-logs")
	}
	if cfg.AgentMode != "local" {
		t.Errorf("AgentMode = %q, want %q", cfg.AgentMode, "local")
	}
	if cfg.Monitor.Interval != 10 {
		t.Errorf("Monitor.Interval = %d, want 10", cfg.Monitor.Interval)
	}
	if cfg.Threat.CacheTTL != 48 {
		t.Errorf("CacheTTL = %d, want 48", cfg.Threat.CacheTTL)
	}
	if cfg.Scoring.BlockThreshold != 70 {
		t.Errorf("BlockThreshold = %d, want 70", cfg.Scoring.BlockThreshold)
	}
	if cfg.Firewall.DefaultBlockDuration != 12 {
		t.Errorf("DefaultBlockDuration = %d, want 12", cfg.Firewall.DefaultBlockDuration)
	}
}
