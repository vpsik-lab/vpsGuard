package threat

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vpsik-lab/vpsGuard/internal/config"
)

type IntelResult struct {
	IP            string
	AbuseScore    int
	OTXScore      int
	CentralScore  int
	CentralConf   int
	PulseCount    int
	ErrorMessage  string
	Sources       []string
}

type IntelClient struct {
	abuseipdb  *AbuseIPDBClient
	alienvault *AlienVaultClient
	cache      *IPCache
	logger     *zap.Logger
	rateLimit  *time.Ticker
	mu         sync.Mutex
	cfg        *config.Config
}

func NewIntelClient(cfg *config.Config, logger *zap.Logger) *IntelClient {
	rateLimit := cfg.Threat.RateLimit
	if rateLimit <= 0 {
		rateLimit = 1
	}
	client := &IntelClient{
		logger:    logger,
		rateLimit: time.NewTicker(time.Minute / time.Duration(rateLimit)),
		cfg:       cfg,
	}

	if cfg.Threat.AbuseIPDBKey != "" {
		client.abuseipdb = NewAbuseIPDBClient(cfg.Threat.AbuseIPDBKey)
	}
	if cfg.Threat.AlienVaultKey != "" {
		client.alienvault = NewAlienVaultClient(cfg.Threat.AlienVaultKey)
	}

	cachePath := cfg.CacheDir + "/vps-guard-cache.db"
	cache, err := NewIPCache(cachePath, time.Duration(cfg.Threat.CacheTTL)*time.Hour, logger)
	if err != nil {
		logger.Warn("disk cache disabled, using in-memory", zap.Error(err))
		cache, _ = NewIPCache(":memory:", time.Duration(cfg.Threat.CacheTTL)*time.Hour, logger)
	}
	client.cache = cache

	return client
}

func (c *IntelClient) CheckIP(ctx context.Context, ip string) *IntelResult {
	result := &IntelResult{IP: ip}

	if cached := c.cache.Get(ip); cached != nil && !c.cache.IsExpired(cached) {
		result.AbuseScore = cached.AbuseScore
		result.OTXScore = cached.OTXScore
		result.CentralScore = cached.CentralScore
		result.CentralConf = cached.CentralConf
		return result
	}

	var wg sync.WaitGroup

	if c.abuseipdb != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-c.rateLimit.C
			resp, err := c.abuseipdb.Check(ctx, ip)
			if err != nil {
				c.logger.Warn("AbuseIPDB check failed", zap.String("ip", ip), zap.Error(err))
				return
			}
			result.AbuseScore = resp.Data.AbuseConfidenceScore
			result.Sources = append(result.Sources, "abuseipdb")
		}()
	}

	if c.alienvault != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-c.rateLimit.C
			resp, err := c.alienvault.Check(ctx, ip)
			if err != nil {
				c.logger.Warn("AlienVault check failed", zap.String("ip", ip), zap.Error(err))
				return
			}
			result.PulseCount = resp.PulseInfo.Count
			result.OTXScore = OTXPulseToScore(resp.PulseInfo.Count)
			result.Sources = append(result.Sources, "alienvault")
		}()
	}

	wg.Wait()

	c.cache.Set(ip, &CacheEntry{
		IP:           ip,
		AbuseScore:   result.AbuseScore,
		OTXScore:     result.OTXScore,
		CentralScore: result.CentralScore,
		CentralConf:  result.CentralConf,
	})

	return result
}

func (c *IntelClient) CacheCleanup() {
	c.cache.Cleanup()
}

func (c *IntelClient) SetCentralScore(ctx context.Context, ip string, score, confidence int) {
	existing := c.cache.Get(ip)
	if existing != nil {
		existing.CentralScore = score
		existing.CentralConf = confidence
		existing.LastChecked = time.Now()
		c.cache.Set(ip, existing)
		return
	}
	c.cache.Set(ip, &CacheEntry{
		IP:           ip,
		CentralScore: score,
		CentralConf:  confidence,
		LastChecked:  time.Now(),
		TTL:          time.Duration(c.cfg.Threat.CacheTTL) * time.Hour,
	})
}

func (c *IntelClient) CacheGet(ip string) *CacheEntry {
	return c.cache.Get(ip)
}

func (c *IntelClient) ReportIP(ctx context.Context, ip string) {
	if c.abuseipdb == nil {
		return
	}
	<-c.rateLimit.C
	if err := c.abuseipdb.Report(ctx, ip, []int{18, 22}, "SSH brute-force blocked by VPS-Guard"); err != nil {
		c.logger.Warn("AbuseIPDB report failed", zap.String("ip", ip), zap.Error(err))
	}
}
