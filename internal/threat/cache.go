package threat

import (
	"database/sql"
	"sync"
	"time"

	"go.uber.org/zap"
	_ "github.com/mattn/go-sqlite3"
)

type CacheEntry struct {
	IP            string
	AbuseScore    int
	OTXScore      int
	CentralScore  int
	CentralConf   int
	LastChecked   time.Time
	TTL           time.Duration
}

type IPCache struct {
	db      *sql.DB
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]*CacheEntry
	logger  *zap.Logger
}

func NewIPCache(dbPath string, ttl time.Duration, logger *zap.Logger) (*IPCache, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	schema := `CREATE TABLE IF NOT EXISTS ip_cache (
		ip TEXT PRIMARY KEY,
		abuse_score INT DEFAULT 0,
		otx_score INT DEFAULT 0,
		central_score INT DEFAULT 0,
		central_conf INT DEFAULT 0,
		last_checked DATETIME DEFAULT CURRENT_TIMESTAMP,
		ttl_hours INT DEFAULT 24
	);`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	return &IPCache{
		db:      db,
		ttl:     ttl,
		entries: make(map[string]*CacheEntry),
		logger:  logger,
	}, nil
}

func (c *IPCache) Get(ip string) *CacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[ip]
}

func (c *IPCache) Set(ip string, entry *CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry.TTL = c.ttl
	entry.LastChecked = time.Now()
	c.entries[ip] = entry

	if _, err := c.db.Exec(`INSERT OR REPLACE INTO ip_cache 
		(ip, abuse_score, otx_score, central_score, central_conf, last_checked, ttl_hours) 
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ip, entry.AbuseScore, entry.OTXScore, entry.CentralScore,
		entry.CentralConf, entry.LastChecked, int(c.ttl.Hours())); err != nil {
		if c.logger != nil {
			c.logger.Warn("cache write failed", zap.String("ip", ip), zap.Error(err))
		}
	}
}

func (c *IPCache) IsExpired(entry *CacheEntry) bool {
	return time.Since(entry.LastChecked) > entry.TTL
}

func (c *IPCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for ip, entry := range c.entries {
		if c.IsExpired(entry) {
			delete(c.entries, ip)
			if _, err := c.db.Exec("DELETE FROM ip_cache WHERE ip = ?", ip); err != nil {
				if c.logger != nil {
					c.logger.Warn("cache cleanup failed", zap.String("ip", ip), zap.Error(err))
				}
			}
		}
	}
}
