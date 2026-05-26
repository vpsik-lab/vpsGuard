package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LogDir    string `yaml:"log_dir"`
	CacheDir  string `yaml:"cache_dir"`
	Mode      string `yaml:"mode"`
	AgentMode string `yaml:"agent_mode"`
	Bootstrap BootstrapConfig `yaml:"bootstrap"`
	Monitor   MonitorConfig   `yaml:"monitor"`
	Threat    ThreatConfig    `yaml:"threat"`
	Scoring   ScoringConfig   `yaml:"scoring"`
	Firewall  FirewallConfig  `yaml:"firewall"`
	Notify    NotifyConfig    `yaml:"notify"`
	Report    ReportConfig    `yaml:"daily_report"`
	SelfProtect SelfProtectConfig `yaml:"self_protect"`
	CentralFeed CentralFeedConfig `yaml:"central_feed"`
}

type BootstrapConfig struct {
	Enabled    bool   `yaml:"enabled"`
	SSHPort    int    `yaml:"ssh_port"`
	AllowRoot  bool   `yaml:"allow_root"`
}

type MonitorConfig struct {
	Journal    bool     `yaml:"journal"`
	LogPaths   []string `yaml:"log_paths"`
	Interval   int      `yaml:"interval_seconds"`
}

type ThreatConfig struct {
	AbuseIPDBKey  string `yaml:"abuseipdb_key"`
	AlienVaultKey string `yaml:"alienvault_key"`
	CacheTTL      int    `yaml:"cache_ttl_hours"`
	RateLimit     int    `yaml:"rate_limit_per_min"`
}

type ScoringConfig struct {
	AbuseIPDBWeight  float64 `yaml:"abuseipdb_weight"`
	AlienVaultWeight float64 `yaml:"alienvault_weight"`
	BehaviorWeight   float64 `yaml:"behavior_weight"`
	TemporalWeight   float64 `yaml:"temporal_weight"`
	CentralWeight    float64 `yaml:"central_weight"`
	BlockThreshold   int     `yaml:"block_threshold"`
	RateLimitScore   int     `yaml:"rate_limit_score"`
	RateLimitMin     int     `yaml:"rate_limit_minutes"`
	QuarantineScore  int     `yaml:"quarantine_score"`
	QuarantineMin    int     `yaml:"quarantine_minutes"`
	CentralBlockThreshold int `yaml:"central_block_threshold"`
	CentralQuarThreshold  int `yaml:"central_quarantine_threshold"`
	BehaviorWindowMinutes int `yaml:"behavior_window_minutes"`
	BehaviorThreshold     int `yaml:"behavior_threshold"`
	TemporalTTLHours      int `yaml:"temporal_ttl_hours"`
}

type FirewallConfig struct {
	Table    string   `yaml:"table"`
	SetName  string   `yaml:"set_name"`
	SetNameV6 string  `yaml:"set_name_v6"`
	DefaultBlockDuration int `yaml:"default_block_hours"`
	Whitelist []string `yaml:"whitelist"`
}

type NotifyConfig struct {
	TelegramToken    string `yaml:"telegram_token"`
	TelegramChatID   string `yaml:"telegram_chat_id"`
	SMTPHost         string `yaml:"smtp_host"`
	SMTPPort         int    `yaml:"smtp_port"`
	SMTPUser         string `yaml:"smtp_user"`
	SMTPPass         string `yaml:"smtp_pass"`
	EmailFrom        string `yaml:"email_from"`
	EmailTo          string `yaml:"email_to"`
	CooldownMinutes  int    `yaml:"cooldown_minutes"`
}

type SelfProtectConfig struct {
	WatchdogInterval int    `yaml:"watchdog_interval_seconds"`
	EnableFileCheck  bool   `yaml:"enable_file_check"`
	ConfigChecksum   string `yaml:"config_checksum"`
}

type CentralFeedConfig struct {
	Enabled       bool   `yaml:"enabled"`
	APIURL        string `yaml:"api_url"`
	APIToken      string `yaml:"api_token"`
	SyncInterval  int    `yaml:"sync_interval_seconds"`
	MinConfidence int    `yaml:"min_confidence"`
}

type ReportConfig struct {
	Enabled       bool `yaml:"enabled"`
	IntervalHours int  `yaml:"interval_hours"`
	SendTelegram  bool `yaml:"send_telegram"`
	SendEmail     bool `yaml:"send_email"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.SetDefaults()
	cfg.LoadEnvOverrides() // env vars override file values
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadEnvOverrides overrides sensitive config fields from environment variables.
// Environment variables always take precedence over values in config.yaml.
//
// Supported variables:
//
//	VPSGUARD_ABUSEIPDB_KEY    — AbuseIPDB API key
//	VPSGUARD_ALIENVAULT_KEY   — AlienVault OTX API key
//	VPSGUARD_TELEGRAM_TOKEN   — Telegram bot token
//	VPSGUARD_TELEGRAM_CHAT_ID — Telegram chat ID
//	VPSGUARD_SMTP_PASS        — SMTP password
//	VPSGUARD_CENTRAL_TOKEN    — Central Platform API token
func (c *Config) LoadEnvOverrides() {
	if v := os.Getenv("VPSGUARD_ABUSEIPDB_KEY"); v != "" {
		c.Threat.AbuseIPDBKey = v
	}
	if v := os.Getenv("VPSGUARD_ALIENVAULT_KEY"); v != "" {
		c.Threat.AlienVaultKey = v
	}
	if v := os.Getenv("VPSGUARD_TELEGRAM_TOKEN"); v != "" {
		c.Notify.TelegramToken = v
	}
	if v := os.Getenv("VPSGUARD_TELEGRAM_CHAT_ID"); v != "" {
		c.Notify.TelegramChatID = v
	}
	if v := os.Getenv("VPSGUARD_SMTP_PASS"); v != "" {
		c.Notify.SMTPPass = v
	}
	if v := os.Getenv("VPSGUARD_CENTRAL_TOKEN"); v != "" {
		c.CentralFeed.APIToken = v
	}
}

func (c *Config) SetDefaults() {
	if c.LogDir == "" {
		c.LogDir = "/var/log/vpsGuard"
	}
	if c.CacheDir == "" {
		c.CacheDir = "/var/cache/vpsGuard"
	}
	if c.AgentMode == "" {
		c.AgentMode = "hybrid"
	}
	if c.Mode == "" {
		c.Mode = "agent"
	}
	if c.Monitor.Interval <= 0 {
		c.Monitor.Interval = 5
	}
	if len(c.Monitor.LogPaths) == 0 {
		c.Monitor.LogPaths = []string{"/var/log/auth.log", "/var/log/syslog"}
	}
	if c.Threat.CacheTTL <= 0 {
		c.Threat.CacheTTL = 24
	}
	if c.Threat.RateLimit <= 0 {
		c.Threat.RateLimit = 10
	}
	if c.Scoring.BlockThreshold <= 0 {
		c.Scoring.BlockThreshold = 60
	}
	if c.Scoring.BehaviorWindowMinutes <= 0 {
		c.Scoring.BehaviorWindowMinutes = 10
	}
	if c.Scoring.BehaviorThreshold <= 0 {
		c.Scoring.BehaviorThreshold = 5
	}
	if c.Scoring.TemporalTTLHours <= 0 {
		c.Scoring.TemporalTTLHours = 168
	}
	if c.Scoring.RateLimitScore <= 0 {
		c.Scoring.RateLimitScore = 40
	}
	if c.Scoring.RateLimitMin <= 0 {
		c.Scoring.RateLimitMin = 5
	}
	if c.Scoring.QuarantineScore <= 0 {
		c.Scoring.QuarantineScore = 30
	}
	if c.Scoring.QuarantineMin <= 0 {
		c.Scoring.QuarantineMin = 15
	}
	if c.Scoring.AbuseIPDBWeight == 0 {
		c.Scoring.AbuseIPDBWeight = 0.25
	}
	if c.Scoring.AlienVaultWeight == 0 {
		c.Scoring.AlienVaultWeight = 0.20
	}
	if c.Scoring.BehaviorWeight == 0 {
		c.Scoring.BehaviorWeight = 0.30
	}
	if c.Scoring.TemporalWeight == 0 {
		c.Scoring.TemporalWeight = 0.10
	}
	if c.Scoring.CentralWeight == 0 {
		c.Scoring.CentralWeight = 0.15
	}
	if c.Scoring.CentralBlockThreshold <= 0 {
		c.Scoring.CentralBlockThreshold = 80
	}
	if c.Scoring.CentralQuarThreshold <= 0 {
		c.Scoring.CentralQuarThreshold = 50
	}
	if c.Firewall.Table == "" {
		c.Firewall.Table = "vpsGuard"
	}
	if c.Firewall.SetName == "" {
		c.Firewall.SetName = "blacklist"
	}
	if c.Firewall.SetNameV6 == "" {
		c.Firewall.SetNameV6 = "blacklist6"
	}
	if c.Firewall.DefaultBlockDuration <= 0 {
		c.Firewall.DefaultBlockDuration = 24
	}
	if c.Notify.SMTPPort <= 0 {
		c.Notify.SMTPPort = 587
	}
	if c.Notify.CooldownMinutes <= 0 {
		c.Notify.CooldownMinutes = 10
	}
	if c.SelfProtect.WatchdogInterval <= 0 {
		c.SelfProtect.WatchdogInterval = 30
	}
	if c.CentralFeed.SyncInterval <= 0 {
		c.CentralFeed.SyncInterval = 60
	}
	if c.CentralFeed.MinConfidence <= 0 {
		c.CentralFeed.MinConfidence = 50
	}
	if c.Report.IntervalHours <= 0 {
		c.Report.IntervalHours = 24
	}
}

func (f *FirewallConfig) IsWhitelisted(ip string) bool {
	for _, w := range f.Whitelist {
		if w == ip {
			return true
		}
	}
	return false
}

func (c *Config) Validate() error {
	if c.Scoring.BlockThreshold > 100 {
		return fmt.Errorf("block_threshold must be <= 100, got %d", c.Scoring.BlockThreshold)
	}
	if c.Scoring.QuarantineScore > 100 {
		return fmt.Errorf("quarantine_score must be <= 100, got %d", c.Scoring.QuarantineScore)
	}
	totalW := c.Scoring.AbuseIPDBWeight + c.Scoring.AlienVaultWeight +
		c.Scoring.BehaviorWeight + c.Scoring.TemporalWeight + c.Scoring.CentralWeight
	if totalW > 1.0+1e-9 {
		return fmt.Errorf("scoring weights sum must be <= 1.0, got %.4f", totalW)
	}
	if c.Monitor.Interval < 1 {
		return fmt.Errorf("monitor.interval_seconds must be >= 1, got %d", c.Monitor.Interval)
	}
	if c.Threat.CacheTTL < 1 {
		return fmt.Errorf("threat.cache_ttl_hours must be >= 1, got %d", c.Threat.CacheTTL)
	}
	if c.CentralFeed.MinConfidence > 100 {
		return fmt.Errorf("central_feed.min_confidence must be <= 100, got %d", c.CentralFeed.MinConfidence)
	}
	if c.Firewall.DefaultBlockDuration < 1 {
		return fmt.Errorf("firewall.default_block_hours must be >= 1, got %d", c.Firewall.DefaultBlockDuration)
	}
	if c.Scoring.BlockThreshold <= c.Scoring.RateLimitScore {
		return fmt.Errorf("block_threshold (%d) must be > rate_limit_score (%d)", c.Scoring.BlockThreshold, c.Scoring.RateLimitScore)
	}
	if c.Scoring.RateLimitScore <= c.Scoring.QuarantineScore {
		return fmt.Errorf("rate_limit_score (%d) must be > quarantine_score (%d)", c.Scoring.RateLimitScore, c.Scoring.QuarantineScore)
	}
	return nil
}
