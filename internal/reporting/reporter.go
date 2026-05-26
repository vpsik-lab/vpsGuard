package reporting

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vpsik-lab/vpsGuard/internal/config"
	"github.com/vpsik-lab/vpsGuard/internal/notify"
)

type DailyReporter struct {
	cfg     *config.Config
	logger  *zap.Logger
	notifier *notify.Notifier

	mu           sync.Mutex
	eventCount24h int
	lastReset    time.Time
}

func NewDailyReporter(cfg *config.Config, logger *zap.Logger, notifier *notify.Notifier) *DailyReporter {
	return &DailyReporter{
		cfg:        cfg,
		logger:     logger,
		notifier:   notifier,
		lastReset:  time.Now(),
	}
}

func (r *DailyReporter) IncrementEventCount() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventCount24h++
}

func (r *DailyReporter) Run(ctx context.Context) {
	if !r.cfg.Report.Enabled {
		return
	}

	interval := time.Duration(r.cfg.Report.IntervalHours) * time.Hour
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	r.logger.Info("daily reporter started",
		zap.Duration("interval", interval),
	)

	for {
		select {
		case <-ticker.C:
			r.sendReport(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (r *DailyReporter) sendReport(ctx context.Context) {
	r.mu.Lock()
	events := r.eventCount24h
	r.eventCount24h = 0
	r.lastReset = time.Now()
	r.mu.Unlock()

	blocks, rateLimits, quarantines := r.readBlockStats()
	auditEvents := r.countAuditEvents()
	hashStatus := r.verifyHashChain()
	uptime := r.uptime()

	msg := r.formatReport(events, blocks, rateLimits, quarantines, auditEvents, hashStatus, uptime)
	r.notifier.SendReport(ctx, msg, r.cfg.Report.SendTelegram, r.cfg.Report.SendEmail)
}

func (r *DailyReporter) readBlockStats() (blocks, rateLimits, quarantines int) {
	f, err := os.Open(r.cfg.LogDir + "/audit.jsonl")
	if err != nil {
		return 0, 0, 0
	}
	defer f.Close()

	since := time.Now().Add(-24 * time.Hour)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry struct {
			Timestamp time.Time `json:"timestamp"`
			Action    string    `json:"action"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Timestamp.Before(since) {
			continue
		}
		switch entry.Action {
		case "block":
			blocks++
		case "rate_limit":
			rateLimits++
		case "quarantine":
			quarantines++
		}
	}
	return
}

func (r *DailyReporter) countAuditEvents() int {
	f, err := os.Open(r.cfg.LogDir + "/audit.jsonl")
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	since := time.Now().Add(-24 * time.Hour)
	for scanner.Scan() {
		var entry struct {
			Timestamp time.Time `json:"timestamp"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Timestamp.After(since) {
			count++
		}
	}
	return count
}

func (r *DailyReporter) verifyHashChain() string {
	chainFile := r.cfg.LogDir + "/log-hashes.yaml"
	if _, err := os.Stat(chainFile); os.IsNotExist(err) {
		return "no chain file"
	}

	data, err := os.ReadFile(chainFile)
	if err != nil {
		return "read error: " + err.Error()
	}
	if len(data) == 0 {
		return "empty"
	}

	entries := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(entries) < 2 {
		return "valid (1 entry)"
	}

	var prevHash string
	for i, line := range entries {
		if !strings.HasPrefix(line, "  sha256: ") {
			continue
		}
		currentHash := strings.TrimPrefix(line, "  sha256: ")
		if i > 0 {
			var prevLine string
			for j := i - 1; j >= 0; j-- {
				if strings.HasPrefix(entries[j], "  sha256: ") {
					prevLine = strings.TrimPrefix(entries[j], "  sha256: ")
					break
				}
			}
			if prevHash != "" && prevLine != "" && prevHash != prevLine {
				return "CHAIN BROKEN"
			}
		}
		prevHash = currentHash
	}

	return fmt.Sprintf("valid (%d entries)", len(entries))
}

func (r *DailyReporter) uptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "unknown"
	}
	var uptimeSec float64
	fmt.Sscanf(string(data), "%f", &uptimeSec)
	days := int(math.Floor(uptimeSec / 86400))
	hours := int(math.Floor(math.Mod(uptimeSec, 86400) / 3600))
	return fmt.Sprintf("%dd %dh", days, hours)
}

func (r *DailyReporter) formatReport(events, blocks, rateLimits, quarantines, auditEvents int, hashStatus, uptime string) string {
	hostname, _ := os.Hostname()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return fmt.Sprintf(`📊 <b>vpsGuard Daily Report</b>
📅 %s | %s

━━━ System Health ━━━
🟢 Uptime: %s
💾 Go mem: %d MB

━━━ Security (24h) ━━━
🛡 Blocked: %d
⚠️ Rate Limited: %d
🔒 Quarantined: %d
📥 Events processed: %d
📁 Audit log entries: %d

━━━ Integrity ━━━
🔐 Log hash chain: %s

━━━ Next Report ━━━
⏰ %s

━━━━━━━━━━━━━━━━━━
<i>vpsGuard Security Agent</i>`,
		time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		hostname,
		uptime,
		m.Alloc/1024/1024,
		blocks, rateLimits, quarantines,
		events, auditEvents,
		hashStatus,
		time.Now().Add(time.Duration(r.cfg.Report.IntervalHours)*time.Hour).Format("2006-01-02 15:04 UTC"),
	)
}
