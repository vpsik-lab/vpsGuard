# Challenge: Metrics

---

## ⭐ Level 1: Query the Metrics

With the agent running, query:

```bash
# Health check
curl http://127.0.0.1:9090/health

# Prometheus metrics
curl http://127.0.0.1:9090/metrics

# JSON metrics
curl http://127.0.0.1:9090/metrics?format=json
```

**Task:** What's the uptime? How many events processed?

---

## ⭐⭐ Level 2: Test the Metrics Endpoint

Write a test that:
1. Creates a `HealthServer` with `AgentMetrics`
2. Starts the server
3. Queries `/metrics` and `/metrics?format=json`
4. Verifies the response

```go
func TestMetricsEndpoint(t *testing.T) {
    srv := NewHealthServer(zap.NewNop(), "test")
    metrics := NewAgentMetrics()
    metrics.EventsTotal.Store(100)
    metrics.BlocksTotal.Store(50)
    srv.RegisterMetrics(metrics)
    
    // Start, query, assert...
}
```

**Hint:** Look at `internal/api/health_test.go`.

---

## ⭐⭐⭐ Level 3: Add a Custom Metric

Add `vpsguard_unique_attackers_total` — the number of unique IPs seen in the last 24h. This requires maintaining a set of IPs with timestamps.

**Hint:** Use a `map[string]time.Time` with periodic cleanup. Register a new atomic counter and increment it.

---

## Solution

<details>
<summary>Click for Level 2 test solution</summary>

```go
func TestMetricsEndpoint(t *testing.T) {
    logger := zap.NewNop()
    srv := NewHealthServer(logger, "test")
    metrics := NewAgentMetrics()
    metrics.EventsTotal.Store(100)
    metrics.BlocksTotal.Store(50)
    srv.RegisterMetrics(metrics)

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    go srv.ListenAndServe(ctx, "127.0.0.1:0")
    time.Sleep(50 * time.Millisecond)

    url := fmt.Sprintf("http://%s/metrics", srv.Addr)
    resp, _ := http.Get(url)
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    assert.Contains(t, string(body), "vpsguard_events_total 100")
    assert.Contains(t, string(body), "vpsguard_blocks_total 50")
}
```

Check `internal/api/health_test.go` for the full test suite.
</details>
