package selfprotect

import (
	"context"
	"os"
	"time"

	"go.uber.org/zap"
)

type Watchdog struct {
	logger     *zap.Logger
	lastHealth time.Time
	configPath string
	tickCount  int64
}

func NewWatchdog(logger *zap.Logger) *Watchdog {
	return &Watchdog{
		logger:     logger,
		lastHealth: time.Now(),
		configPath: "/etc/vps-guard/config.yaml",
	}
}

func (w *Watchdog) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
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
	}
	w.lastHealth = time.Now()
}

func (w *Watchdog) Ping() {
	w.lastHealth = time.Now()
}

func (w *Watchdog) Uptime() time.Duration {
	return time.Since(w.lastHealth)
}
