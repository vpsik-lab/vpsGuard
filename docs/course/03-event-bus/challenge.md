# Challenge: Event Bus

**Difficulty levels — pick your path.**

---

## ⭐ Level 1: Test the Bus

Write a test that:
1. Creates a Bus
2. Subscribes two listeners
3. Publishes 10 events
4. Verifies both listeners receive all 10 events

```go
func TestBusFanOut(t *testing.T) {
    bus := pipeline.NewBus(zap.NewNop())
    
    ch1 := bus.Subscribe()
    ch2 := bus.Subscribe()
    
    go bus.Publish(context.Background(), makeEnvelope("1.2.3.4"))
    // ... receive and verify
}
```

**Hint:** The actual test file is at `internal/pipeline/bus_test.go`.

---

## ⭐⭐ Level 2: Priority Fan-Out

Modify the Bus so events with `PriorityCritical` are never dropped — they always block the publisher until delivered.

**Hint:** Check `evt.Event.Priority()` inside `Publish`. For critical events, skip the `default` case.

---

## ⭐⭐⭐ Level 3: The Slow Consumer Problem

Create a subscriber that processes events at 1/10th the speed of the publisher. Demonstrate that:
1. The fast subscriber never drops events
2. The slow subscriber drops events after ~10 seconds
3. The publisher never blocks

Write a test that proves all three.

---

## Solution

<details>
<summary>Click for Level 1 solution</summary>

```go
func TestBusFanOut(t *testing.T) {
    bus := pipeline.NewBus(zap.NewNop())
    
    ch1 := bus.Subscribe()
    ch2 := bus.Subscribe()
    
    ctx := context.Background()
    for i := 0; i < 10; i++ {
        bus.Publish(ctx, pipeline.Envelope{
            Timestamp: time.Now(),
            TraceID:   fmt.Sprintf("evt_%d", i),
        })
    }
    
    for i := 0; i < 10; i++ {
        <-ch1  // blocks until received
        <-ch2
    }
}
```

Check `internal/pipeline/bus_test.go` for the real comprehensive tests.
</details>
