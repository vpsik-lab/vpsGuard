package threat

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vpsik-lab/vpsGuard/internal/config"
)

func TestNewIPCache(t *testing.T) {
	cache, err := NewIPCache(":memory:", time.Hour, zap.NewNop())
	if err != nil {
		t.Fatalf("NewIPCache() error = %v", err)
	}
	if cache == nil {
		t.Fatal("NewIPCache returned nil")
	}
}

func TestIPCacheGetSet(t *testing.T) {
	cache, err := NewIPCache(":memory:", time.Hour, zap.NewNop())
	if err != nil {
		t.Fatalf("NewIPCache() error = %v", err)
	}

	entry := cache.Get("1.2.3.4")
	if entry != nil {
		t.Fatal("expected nil for unknown IP")
	}

	cache.Set("1.2.3.4", &CacheEntry{
		IP:          "1.2.3.4",
		AbuseScore:  50,
		OTXScore:    30,
		CentralScore: 80,
		CentralConf:  90,
	})

	entry = cache.Get("1.2.3.4")
	if entry == nil {
		t.Fatal("expected non-nil after Set")
	}
	if entry.AbuseScore != 50 {
		t.Errorf("AbuseScore = %d, want 50", entry.AbuseScore)
	}
	if entry.OTXScore != 30 {
		t.Errorf("OTXScore = %d, want 30", entry.OTXScore)
	}
	if entry.CentralScore != 80 {
		t.Errorf("CentralScore = %d, want 80", entry.CentralScore)
	}
	if entry.CentralConf != 90 {
		t.Errorf("CentralConf = %d, want 90", entry.CentralConf)
	}
}

func TestIPCacheOverwrite(t *testing.T) {
	cache, err := NewIPCache(":memory:", time.Hour, zap.NewNop())
	if err != nil {
		t.Fatalf("NewIPCache() error = %v", err)
	}

	cache.Set("1.2.3.4", &CacheEntry{IP: "1.2.3.4", AbuseScore: 10})
	cache.Set("1.2.3.4", &CacheEntry{IP: "1.2.3.4", AbuseScore: 90})

	entry := cache.Get("1.2.3.4")
	if entry.AbuseScore != 90 {
		t.Errorf("AbuseScore = %d, want 90 after overwrite", entry.AbuseScore)
	}
}

func TestIPCacheIsExpired(t *testing.T) {
	cache, err := NewIPCache(":memory:", 10*time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("NewIPCache() error = %v", err)
	}

	cache.Set("1.2.3.4", &CacheEntry{IP: "1.2.3.4", AbuseScore: 50})

	entry := cache.Get("1.2.3.4")
	if cache.IsExpired(entry) {
		t.Error("expected entry to not be expired immediately")
	}

	entry.TTL = 1 * time.Nanosecond
	if !cache.IsExpired(entry) {
		t.Error("expected entry to be expired with 1ns TTL")
	}
}

func TestIPCacheCleanup(t *testing.T) {
	cache, err := NewIPCache(":memory:", 1*time.Nanosecond, zap.NewNop())
	if err != nil {
		t.Fatalf("NewIPCache() error = %v", err)
	}

	cache.Set("1.2.3.4", &CacheEntry{IP: "1.2.3.4", AbuseScore: 50})
	cache.Set("5.6.7.8", &CacheEntry{IP: "5.6.7.8", AbuseScore: 30})

	time.Sleep(10 * time.Millisecond)

	cache.Cleanup()

	if cache.Get("1.2.3.4") != nil {
		t.Error("expected 1.2.3.4 to be cleaned up")
	}
	if cache.Get("5.6.7.8") != nil {
		t.Error("expected 5.6.7.8 to be cleaned up")
	}
}

func TestIPCacheSetOverwritesTTL(t *testing.T) {
	cache, err := NewIPCache(":memory:", 24*time.Hour, zap.NewNop())
	if err != nil {
		t.Fatalf("NewIPCache() error = %v", err)
	}

	cache.Set("1.2.3.4", &CacheEntry{IP: "1.2.3.4", AbuseScore: 50, TTL: 1 * time.Hour})
	entry := cache.Get("1.2.3.4")
	if entry.TTL != 24*time.Hour {
		t.Errorf("expected TTL to be overridden to 24h, got %v", entry.TTL)
	}
}

func TestNewIntelClient(t *testing.T) {
	cfg := testConfig()
	logger := zap.NewNop()

	client := NewIntelClient(cfg, logger)
	if client == nil {
		t.Fatal("NewIntelClient returned nil")
	}
	if client.abuseipdb != nil {
		t.Error("expected abuseipdb to be nil (no key)")
	}
	if client.alienvault != nil {
		t.Error("expected alienvault to be nil (no key)")
	}
	if client.cache == nil {
		t.Error("expected cache to be initialized")
	}
}

func TestIntelClientWithKeys(t *testing.T) {
	cfg := testConfig()
	cfg.Threat.AbuseIPDBKey = "test-abuse-key"
	cfg.Threat.AlienVaultKey = "test-otx-key"
	logger := zap.NewNop()

	client := NewIntelClient(cfg, logger)
	if client.abuseipdb == nil {
		t.Error("expected abuseipdb to be non-nil when key set")
	}
	if client.alienvault == nil {
		t.Error("expected alienvault to be non-nil when key set")
	}
}

func TestSetCentralScoreNew(t *testing.T) {
	cfg := testConfig()
	logger := zap.NewNop()
	client := NewIntelClient(cfg, logger)

	client.SetCentralScore(nil, "1.2.3.4", 85, 92)

	entry := client.cache.Get("1.2.3.4")
	if entry == nil {
		t.Fatal("expected entry after SetCentralScore")
	}
	if entry.CentralScore != 85 {
		t.Errorf("CentralScore = %d, want 85", entry.CentralScore)
	}
	if entry.CentralConf != 92 {
		t.Errorf("CentralConf = %d, want 92", entry.CentralConf)
	}
}

func TestSetCentralScoreUpdate(t *testing.T) {
	cfg := testConfig()
	logger := zap.NewNop()
	client := NewIntelClient(cfg, logger)

	client.cache.Set("1.2.3.4", &CacheEntry{
		IP: "1.2.3.4", AbuseScore: 50, OTXScore: 30,
	})

	client.SetCentralScore(nil, "1.2.3.4", 90, 95)

	entry := client.cache.Get("1.2.3.4")
	if entry.AbuseScore != 50 {
		t.Errorf("AbuseScore should be preserved, got %d", entry.AbuseScore)
	}
	if entry.CentralScore != 90 {
		t.Errorf("CentralScore = %d, want 90", entry.CentralScore)
	}
	if entry.CentralConf != 95 {
		t.Errorf("CentralConf = %d, want 95", entry.CentralConf)
	}
}

func TestCacheCleanup(t *testing.T) {
	cfg := testConfig()
	logger := zap.NewNop()
	client := NewIntelClient(cfg, logger)

	client.cache.Set("1.2.3.4", &CacheEntry{IP: "1.2.3.4", AbuseScore: 50})
	client.CacheCleanup()
}

func testConfig() *config.Config {
	cfg := &config.Config{}
	cfg.SetDefaults()
	return cfg
}
