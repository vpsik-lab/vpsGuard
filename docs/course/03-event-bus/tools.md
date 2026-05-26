# Tools: Lesson 03

## New Tools

### Go Channels

Built-in concurrency primitive. A channel is a typed conduit — send values in one goroutine, receive in another.

```go
ch := make(chan Envelope, 10000)  // buffered channel
ch <- evt                         // send (blocks if full)
evt := <-ch                       // receive (blocks if empty)
```

**Why channels over shared memory?** "Don't communicate by sharing memory; share memory by communicating." — Go proverb. Channels make concurrency composable and safe by design.

### select statement

Go's control structure for channel operations:

```go
select {
case ch <- evt:     // send succeeded
    // normal path
case <-ctx.Done():  // context cancelled
    return
default:            // channel full
    log.Warn("drop")
}
```

**Why `select`?** It lets us handle multiple channel operations in a single goroutine — including the all-important "non-blocking" case via `default`.

### sync.RWMutex

Reader/writer mutex. Multiple readers can hold the lock simultaneously; writers get exclusive access.

**Why RWMutex and not Mutex?** Subscribers are read far more often than written (published continuously, subscribed once). RWMutex lets parallel publishers proceed without contention.

### atomic.Uint64

Lock-free counter from `sync/atomic`. Used for the dropped event counter.

**Why atomic?** Incrementing a counter in a hot path with a mutex would add contention. Atomic operations are CPU-level — no OS lock needed.

## Reference: Channel Capacity

| Buffer size | Time to fill at 1000 events/sec |
|-------------|--------------------------------|
| 0 (unbuffered) | 0ms — blocks immediately |
| 100 | 100ms — brief bursts OK |
| 1,000 | 1 second — typical bursts |
| **10,000** | **10 seconds — generous** |

10,000 is our choice: enough for any realistic burst, but bounded so memory doesn't grow unbounded.
