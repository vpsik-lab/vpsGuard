# Challenge: Reports

---

## ⭐ Level 1: Test the Format Report

Write a test that calls `formatReport()` with sample data and verifies the output contains expected strings:

```go
func TestFormatReport(t *testing.T) {
    r := NewDailyReporter(...)
    msg := r.formatReport(100, 50, 10, 5, 60, "valid (10 entries)", "5d 3h")
    assert.Contains(t, msg, "100")
    assert.Contains(t, msg, "50")
    assert.Contains(t, msg, "valid (10 entries)")
}
```

**Hint:** Look at `internal/reporting/reporter_test.go`.

---

## ⭐⭐ Level 2: Integrate Prometheus Metrics

Add Prometheus counters to the daily report. The report should include values from the `/metrics` endpoint:

```go
// readMetrics() fetches http://127.0.0.1:9090/metrics?format=json
// and returns the counters
```

**Hint:** Use `net/http` to query the agent's own metrics endpoint.

---

## ⭐⭐⭐ Level 3: Alert on Zero Events

If the daily report shows 0 events processed, it might mean:
1. Quiet day (unlikely for a public VPS)
2. Agent crashed (most likely)
3. Logs rotated away (possible)

Add an **anomaly detection**: if events < 10 for 24h, fire an additional alert.

**Hint:** This is a heuristic. Don't make it too sensitive — 0 events is suspicious, 5 may not be.

---

## Solution

<details>
<summary>Click for Level 1 test solution</summary>

```go
func TestFormatReport(t *testing.T) {
    cfg := &config.Config{}
    cfg.Report.IntervalHours = 24
    logger := zap.NewNop()
    notifier := notify.NewNotifier(&config.NotifyConfig{}, logger)
    r := NewDailyReporter(cfg, logger, notifier)

    msg := r.formatReport(100, 50, 10, 5, 60, "valid (10 entries)", "5d 3h")

    assert.Contains(t, msg, "100")      // events
    assert.Contains(t, msg, "50")       // blocks
    assert.Contains(t, msg, "5d 3h")    // uptime
    assert.Contains(t, msg, "valid")    // chain status
}
```

Check `internal/reporting/reporter_test.go` for the complete test suite.
</details>
