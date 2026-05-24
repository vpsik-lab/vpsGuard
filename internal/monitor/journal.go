package monitor

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/vps-guard/vps-guard/internal/config"
	"github.com/vps-guard/vps-guard/internal/pipeline"
)

type JournalMonitor struct {
	cfg     *config.Config
	logger  *zap.Logger
	bus     *pipeline.Bus
	parser  *LogParser
	tailers map[string]*FileTailer
}

func NewJournalMonitor(cfg *config.Config, logger *zap.Logger, bus *pipeline.Bus) *JournalMonitor {
	return &JournalMonitor{
		cfg:     cfg,
		logger:  logger,
		bus:     bus,
		parser:  NewLogParser(),
		tailers: make(map[string]*FileTailer),
	}
}

func (m *JournalMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(m.cfg.Monitor.Interval) * time.Second)
	defer ticker.Stop()

	for _, path := range m.cfg.Monitor.LogPaths {
		tailer, err := NewFileTailer(path)
		if err != nil {
			m.logger.Warn("cannot open log file", zap.String("path", path), zap.Error(err))
			continue
		}
		m.tailers[path] = tailer
		defer tailer.Close()
	}

	m.logger.Info("journal monitor started",
		zap.Int("interval", m.cfg.Monitor.Interval),
		zap.Int("files", len(m.tailers)),
	)

	for {
		select {
		case <-ticker.C:
			m.poll(ctx)
		case <-ctx.Done():
			m.logger.Info("journal monitor stopped")
			return
		}
	}
}

func (m *JournalMonitor) poll(ctx context.Context) {
	for _, tailer := range m.tailers {
		lines := tailer.ReadNewLines()
		for _, line := range lines {
			parsed := m.parser.Parse(line)
			if parsed != nil {
				evt := m.parser.ToEvent(parsed)
			traceID := generateID()
			env := pipeline.Envelope{
				Timestamp: time.Now(),
				Source:    "journal",
				Version:   "1.0",
				TraceID:   traceID,
				Event:     evt,
			}
				m.bus.Publish(ctx, env)
			}
		}
	}
}
