# Tools: Lesson 12

## New Tools

### sync/atomic (stdlib)

Lock-free concurrent counters:

```go
var count atomic.Int64
count.Add(1)
value := count.Load()
```

**Why atomic over mutex?** For simple integer counters, atomics are 10-100x faster than mutexes. They compile to a single CPU instruction.

### net/http.ServeMux (stdlib)

Go's default HTTP request multiplexer (router):

```go
mux := http.NewServeMux()
mux.HandleFunc("/health", handleHealth)
mux.HandleFunc("/metrics", handleMetrics)
```

**Why not gorilla/mux or chi?** For 2 routes, stdlib is fine. No need for a framework.

### Prometheus text format

Simple exposition format for metrics:

```
# HELP metric_name Description
# TYPE metric_name counter|gauge|histogram|summary
metric_name value
```

## Reference: Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `vpsguard_uptime_seconds` | gauge | Time since agent start |
| `vpsguard_events_total` | counter | Total SSH events processed |
| `vpsguard_blocks_total` | counter | Total IPs blocked |
| `vpsguard_quarantine_total` | counter | Total IPs quarantined |
| `vpsguard_rate_limit_total` | counter | Total IPs rate-limited |
| `vpsguard_monitor_total` | counter | Total IPs monitored |
| `vpsguard_tamper_alerts_total` | counter | Config tamper alerts |
