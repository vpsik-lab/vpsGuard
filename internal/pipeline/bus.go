package pipeline

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

type Bus struct {
	mu        sync.RWMutex
	listeners []chan Envelope
	logger    *zap.Logger
}

func NewBus(logger *zap.Logger) *Bus {
	return &Bus{
		listeners: make([]chan Envelope, 0),
		logger:    logger,
	}
}

func (b *Bus) Publish(ctx context.Context, evt Envelope) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.listeners {
		select {
		case ch <- evt:
		case <-ctx.Done():
			return
		default:
			b.logger.Warn("dropped event",
				zap.String("ip", evt.SourceIP()),
				zap.String("trace_id", evt.TraceID),
			)
		}
	}
}

func (b *Bus) Subscribe() chan Envelope {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan Envelope, 1000)
	b.listeners = append(b.listeners, ch)
	return ch
}

func (b *Bus) FanOut(ctx context.Context, output chan Envelope) {
	ch := b.Subscribe()

	for {
		select {
		case evt := <-ch:
			select {
			case output <- evt:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (b *Bus) Run(ctx context.Context) {
	<-ctx.Done()
}
