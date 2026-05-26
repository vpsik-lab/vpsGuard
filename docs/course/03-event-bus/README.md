# Lesson 03: Event Bus

**Backtrack: our simple loop doesn't scale. We need a pipeline.**

---

## The Problem

In Lesson 02, our main loop was:

```go
for {
    lines := tailer.ReadNewLines()
    for _, line := range lines {
        parsed := parser.Parse(line)
        if parsed != nil {
            event := parser.ToEvent(parsed)
            fmt.Println(event)
        }
    }
    time.Sleep(1 * time.Second)
}
```

This works for a demo. But what happens when we add:
- **Scoring** — need to look up reputation data
- **Blocking** — need to call nftables
- **Notifications** — need to send Telegram messages
- **Audit logging** — need to write to a file
- **Threat intelligence** — need to call external APIs

All in the same loop? That's a nightmare. If blocking takes 100ms and Telegram takes 500ms, each event blocks the parser for 600ms. At 3 events/second we're already behind.

**We need to decouple the producer (parser) from the consumers (scorer, blocker, notifier).**

---

## The Solution: Event Bus (Pub/Sub)

```
                    ┌──────────┐
                    │  Parser  │
                    └────┬─────┘
                         │ Publish
                         ▼
              ┌──────────────────┐
              │    Event Bus     │  ← buffered channel per subscriber
              │  (fan-out, no   │
              │   block on pub) │
              └──┬────┬────┬────┘
                 │    │    │     Subscribe
                 ▼    ▼    ▼
           ┌────┐┌────┐┌────┐
           │S1  ││S2  ││S3  │   ← independent goroutines
           └────┘└────┘└────┘
```

Each subscriber gets its own buffered channel. The publisher never blocks — if a subscriber is slow, its messages are dropped (with a warning counter), not the entire pipeline.

---

## The Code

### Envelope — the message wrapper

Every event travels in an `Envelope` that adds metadata:

```go
type Envelope struct {
    Timestamp time.Time
    Source    string        // "auth.log", "journal", "api"
    Version   string        // event schema version
    TraceID   string        // unique ID for tracing
    Event     Event         // the actual event (interface)
}
```

**Why an envelope?**
- **TraceID**: lets us follow a single event through the entire pipeline
- **Version**: future-proofing for schema evolution
- **Source**: debugging — where did this event originate?

### Event interface

All events implement this contract:

```go
type Event interface {
    EventType() EventType
    SourceIP() string
    Severity() int
    Priority() Priority
    Timestamp() time.Time
}
```

### Bus — the core

```go
type Bus struct {
    listeners    []chan Envelope
    logger       *zap.Logger
    droppedCount atomic.Uint64
}
```

**Subscribe** — each consumer gets its own channel:

```go
func (b *Bus) Subscribe() chan Envelope {
    ch := make(chan Envelope, 10000)
    b.listeners = append(b.listeners, ch)
    return ch
}
```

Buffer of 10,000 means a slow consumer has ~10 seconds to catch up before dropping events.

**Publish** — fan-out to all subscribers, never block:

```go
func (b *Bus) Publish(ctx context.Context, evt Envelope) {
    for _, ch := range b.listeners {
        select {
        case ch <- evt:          // subscriber gets it
        case <-ctx.Done():       // context cancelled
            return
        default:                 // subscriber is full — drop
            count := b.droppedCount.Add(1)
            logger.Warn("dropped event", zap.Uint64("total_dropped", count))
        }
    }
}
```

Three cases in the `select`:
1. **Send succeeds** — normal flow
2. **Context cancelled** — shut down gracefully
3. **Channel full** — drop, warn, count. Don't block the entire pipeline.

---

## Putting It Together

```go
func main() {
    bus := pipeline.NewBus(logger)
    parser := monitor.NewLogParser()
    tailer, _ := monitor.NewFileTailer("/var/log/auth.log")

    // Subscribers each get their own goroutine
    subscriber1 := bus.Subscribe()
    go func() {
        for evt := range subscriber1 {
            fmt.Println("Consumer 1:", evt.SourceIP())
        }
    }()

    subscriber2 := bus.Subscribe()
    go func() {
        for evt := range subscriber2 {
            fmt.Println("Consumer 2:", evt.SourceIP())
        }
    }()

    // Publisher loop
    for {
        lines := tailer.ReadNewLines()
        for _, line := range lines {
            if parsed := parser.Parse(line); parsed != nil {
                event := parser.ToEvent(parsed)
                envelope := pipeline.Envelope{
                    Timestamp: time.Now(),
                    Source:    "auth.log",
                    TraceID:   generateID(),
                    Event:     event,
                }
                bus.Publish(context.Background(), envelope)
            }
        }
        time.Sleep(1 * time.Second)
    }
}
```

---

## What We Learned

| Concept | Why It Matters |
|---------|---------------|
| **Pub/Sub decoupling** | Producers don't wait for consumers |
| **Buffered channels** | Absorb bursts — 10,000 gives ~10 seconds of slack |
| **Non-blocking publish** | One slow consumer doesn't stall the system |
| **Dropped event counter** | Visibility into overload instead of silent data loss |
| **Envelope pattern** | Metadata (TraceID, Source, Version) doesn't pollute the event |

## Design Decisions

1. **Why not a message queue (RabbitMQ, NATS, Redis)?** For a single-node agent, an in-process channel is faster (microseconds vs milliseconds). No network, no serialization, no daemon to manage.

2. **Why `select` with `default` for non-blocking?** Classic Go pattern. The `default` case fires when the channel is full, letting us log and continue instead of blocking.

3. **Why `sync.RWMutex` instead of a lock-free list?** Subscriptions change rarely (once at startup). A mutex is simple, correct, and fast enough for our use case.

4. **Why is `FanOut` a separate method?** Convenience: some consumers want their own goroutine but share a single channel. `FanOut` bridges a subscriber to a shared output channel.

---

## What's Still Missing

We now have a real pipeline. But:
- **Scoring?** Not yet — next lesson
- **Blocking?** After scoring
- **Graceful shutdown?** We'll add context propagation later
- **Metrics?** Not yet — but the `droppedCount` is our first telemetry

---

## Check Your Understanding

1. What happens if a subscriber's channel buffer fills up?
2. Why does `Publish` use `select` with three cases?
3. What's the purpose of `TraceID` in the envelope?
4. Why not use an external message queue?
