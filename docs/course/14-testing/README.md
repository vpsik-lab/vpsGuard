# Lesson 14: Testing

**How we know it works — even when we change everything.**

---

## The Problem

This agent processes real SSH attacks. If a bug slips in, attackers get through. If a regression happens, blocks stop working.

**How do you ship changes with confidence?**

The answer: **automated tests at every level.**

```
Test Pyramid for vpsGuard:
       ╱╲
      ╱  ╲         Integration tests   (10 tests)
     ╱    ╲
    ╱──────╲
   ╱        ╲      Unit tests          (136 tests)
  ╱──────────╲
 ╱            ╲
╱──────────────╲
                 Lint + build + race    (CI enforces)
```

**146 test functions across 20 files in 12 packages.** Every one runs on every commit.

---

## Level 1: Unit Tests

### The Basics

Every Go package has a `_test.go` file. Tests are just functions starting with `Test`:

```go
func TestParseFailedPassword(t *testing.T) {
    p := NewLogParser()
    line := "Failed password for root from 1.2.3.4 port 51234 ssh2"
    result := p.Parse(line)
    if result.IP != "1.2.3.4" {
        t.Errorf("expected 1.2.3.4, got %s", result.IP)
    }
}
```

**Table-driven tests** — test multiple cases in one function:

```go
func TestOTXPulseToScore(t *testing.T) {
    tests := []struct {
        pulses int
        want   int
    }{
        {0, 0},     // no pulses → clean
        {1, 15},    // 1 pulse → low
        {5, 35},    // 5 pulses → medium
        {30, 90},   // 30 pulses → critical
    }
    for _, tt := range tests {
        got := OTXPulseToScore(tt.pulses)
        if got != tt.want {
            t.Errorf("OTXPulseToScore(%d) = %d, want %d", tt.pulses, got, tt.want)
        }
    }
}
```

### Testing Concurrency

Our code uses goroutines and channels. Test them with timeouts:

```go
func TestBusFanOut(t *testing.T) {
    bus := pipeline.NewBus(zap.NewNop())
    ch := bus.Subscribe()

    ctx := context.Background()
    bus.Publish(ctx, makeEnvelope("1.2.3.4"))

    select {
    case evt := <-ch:
        assert.Equal(t, "1.2.3.4", evt.SourceIP())
    case <-time.After(100 * time.Millisecond):
        t.Fatal("timeout waiting for event")
    }
}
```

### Testing with Temp Files

For persistence tests:

```go
func TestBlockStoreSaveAndLoad(t *testing.T) {
    f, _ := os.CreateTemp("", "blocks-*.json")
    defer os.Remove(f.Name())

    store := NewBlockStore(f.Name())
    store.Save("1.2.3.4", time.Now().Add(24*time.Hour), "test")
    store.Save("5.6.7.8", time.Now().Add(-1*time.Hour), "expired")

    entries, _ := store.Load()
    assert.Len(t, entries, 1)  // only non-expired
}
```

---

## Level 2: Integration Tests

Some packages depend on each other. Integration tests verify the **full flow**:

```go
func TestPipelineRecordScoreDecide(t *testing.T) {
    scorer := NewScorer(cfg, logger)
    decision := NewDecision(cfg, nil, logger)

    // Create and process events
    for i := 0; i < 15; i++ {
        evt := makeSSHEvent("1.2.3.4", "root")
        scorer.RecordEvent(evt)
    }

    // Score
    scores := scorer.Evaluate(ctx, evt, intelClient)

    // Decide
    actions := decision.Evaluate(ctx, evt, scores, rulesEngine)

    // Assert: 15 attempts → score > 50 → action is "block"
    assert.True(t, actions[0].Block)
    assert.Equal(t, "block", actions[0].Type)
}
```

---

## Level 3: Race Detection

Go's race detector catches concurrent data races:

```bash
go test -race ./...
```

Every CI run uses `-race`. If any goroutine reads and writes the same variable without synchronization, the test **panics with a race report**.

---

## Level 4: Static Analysis

```bash
go vet ./...
```

Go's built-in static analyzer catches:
- Unreachable code
- Mismatched printf arguments
- Lock mistakes
- Structural issues

---

## Level 5: Build Verification

```bash
go build ./...
```

Every package must compile. The CI also cross-compiles for amd64, arm64, and arm:

```makefile
cross-amd64:
    GOOS=linux GOARCH=amd64 go build -o dist/vpsGuard-linux-amd64 ./cmd/vpsGuard
```

---

## The CI Pipeline

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go vet ./...
      - run: go test -race ./...
      - run: go build ./...
```

Every PR must pass this before merging. No exceptions.

---

## Testing Philosophy

1. **Test behavior, not implementation** — test that `1.2.3.4` gets blocked, not that `BlockIP` calls `exec.Command` with specific args.
2. **Table-driven tests** — one test function, many cases. Easy to add new cases when bugs are found.
3. **No external dependencies** — tests don't call AbuseIPDB, Telegram, or nftables. APIs are tested with mocks; nftables tests require root and are skipped in CI.
4. **Parallel by package** — `go test -count=1 ./...` runs packages sequentially but tests within a package can be parallel.

---

## What We Learned

| Level | Tool | What It Catches |
|-------|------|-----------------|
| Unit | `go test` | Logic bugs, edge cases |
| Integration | `go test` with mocks | Component interaction bugs |
| Race | `go test -race` | Concurrent data races |
| Static | `go vet` | Suspicious code patterns |
| Build | `go build` | Compilation errors |
| CI | GitHub Actions | Regressions before merge |

## Design Decisions

1. **Why skip nftables tests in CI?** nftables requires root + kernel modules. GitHub Actions runners don't have them. We test the nftables manager's logic; the actual nft commands are tested manually.

2. **Why `count=1`?** Go's test cache (`-count=1` disables it) can mask flaky tests. Always disable cache in CI.

3. **Why no mock framework?** Go interfaces are simple enough that hand-written mocks are clearer than generated mocks. No dependency needed.

---

## Check Your Understanding

1. What's the difference between a unit test and an integration test in this project?
2. Why is `-race` important for a concurrent agent?
3. What does `go vet` catch that `go build` doesn't?
4. Why do we use `os.CreateTemp` in persistence tests?
