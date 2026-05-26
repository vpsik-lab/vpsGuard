package selfprotect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"go.uber.org/zap"
)

type Watchdog struct {
	logger           *zap.Logger
	lastHealth       time.Time
	configPath       string
	interval         time.Duration
	tickCount        int64
	expectedChecksum string
	tamperWarnings   int
	onTamperFn       func(message string) // called immediately on tamper detection
}

func NewWatchdog(logger *zap.Logger, configPath string, interval time.Duration, expectedChecksum string) *Watchdog {
	return &Watchdog{
		logger:           logger,
		lastHealth:       time.Now(),
		configPath:       configPath,
		interval:         interval,
		expectedChecksum: expectedChecksum,
	}
}

// OnTamper registers a callback invoked immediately when a config-file tamper is detected.
// Use this to wire Telegram/Email alerts from outside the selfprotect package.
// The callback receives a human-readable description of the tamper event.
func (w *Watchdog) OnTamper(fn func(message string)) {
	w.onTamperFn = fn
}

func (w *Watchdog) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	w.logger.Info("watchdog started")

	for {
		select {
		case <-ticker.C:
			w.tickCount++
			w.healthCheck()
		case <-ctx.Done():
			w.logger.Info("watchdog stopped", zap.Int64("ticks", w.tickCount))
			return
		}
	}
}

func (w *Watchdog) healthCheck() {
	if _, err := os.Stat(w.configPath); os.IsNotExist(err) {
		w.logger.Error("config file missing - possible tamper",
			zap.String("path", w.configPath),
		)
		w.lastHealth = time.Now()
		return
	}

	if w.expectedChecksum != "" {
		f, err := os.Open(w.configPath)
		if err != nil {
			w.logger.Error("cannot open config for checksum",
				zap.String("path", w.configPath),
				zap.Error(err),
			)
			w.lastHealth = time.Now()
			return
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			w.logger.Error("cannot read config for checksum",
				zap.String("path", w.configPath),
				zap.Error(err),
			)
			w.lastHealth = time.Now()
			return
		}
		f.Close()
		got := hex.EncodeToString(h.Sum(nil))
		if got != w.expectedChecksum {
			w.tamperWarnings++
			msg := fmt.Sprintf(
				"config checksum mismatch on %s (warning #%d) — expected ...%s got ...%s",
				w.configPath, w.tamperWarnings,
				w.expectedChecksum[max(0, len(w.expectedChecksum)-8):],
				got[max(0, len(got)-8):],
			)
			w.logger.Error("config file checksum mismatch - possible tamper",
				zap.String("path", w.configPath),
				zap.String("expected", w.expectedChecksum),
				zap.String("got", got),
				zap.Int("consecutive_warnings", w.tamperWarnings),
			)
			if w.onTamperFn != nil {
				w.onTamperFn(msg)
			}
			w.lastHealth = time.Now()
			return
		}
		w.tamperWarnings = 0
	}

	w.lastHealth = time.Now()
}

func (w *Watchdog) TamperWarnings() int {
	return w.tamperWarnings
}

func (w *Watchdog) Ping() {
	w.lastHealth = time.Now()
}

func (w *Watchdog) Uptime() time.Duration {
	return time.Since(w.lastHealth)
}
