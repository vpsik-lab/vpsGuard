# Lesson 12: Metrics

**Is the agent healthy? Query it.**

---

## The Problem

The agent is running on a headless VPS. How do you know it's healthy?

You could SSH in and check:
```bash
systemctl status vpsGuard
journalctl -u vpsGuard --since "1 hour ago" | grep ERROR
```

But that doesn't scale. You need:
- An **HTTP health endpoint** for monitoring tools (UptimeRobot, Better Uptime, etc.)
- **Prometheus metrics** for Grafana dashboards
- **CLI commands** for quick checks

---

## The Health Endpoint

`GET /health` returns JSON:

```json
{
  "status": "ok",
  "version": "v0.3.0",
  "uptime": "14h3m12s",
  "components": {
    "watchdog": { "status": "ok" },
    "event_bus": { "status": "ok" }
  }
}
```

Each component registers a checker:

```go
healthSrv.RegisterComponent("watchdog", func(ctx context.Context) api.ComponentStatus {
    uptime := watchdog.Uptime()
    if uptime > 2*watchdogInterval {
        return api.ComponentStatus{Status: "degraded", Message: "watchdog not running"}
    }
    return api.ComponentStatus{Status: "ok"}
})
```

If any component reports "degraded", the overall status becomes "degraded".

---

## Prometheus Metrics

`GET /metrics` returns Prometheus text format:

```
# HELP vpsguard_events_total Total SSH events processed
# TYPE vpsguard_events_total counter
vpsguard_events_total 12847

# HELP vpsguard_blocks_total Total IPs blocked
# TYPE vpsguard_blocks_total counter
vpsguard_blocks_total 1234

# HELP vpsguard_uptime_seconds Time the agent has been running
# TYPE vpsguard_uptime_seconds gauge
vpsguard_uptime_seconds 50988.00
```

`GET /metrics?format=json` returns JSON:

```json
{
  "uptime_seconds": 50988,
  "events_total": 12847,
  "blocks_total": 1234
}
```

### How Counters Are Updated

The `processEvent` function increments counters atomically:

```go
func processEvent(..., metrics *api.AgentMetrics, ...) {
    metrics.EventsTotal.Add(1)

    if action.Block {
        fw.BlockIP(ctx, ip, duration)
        metrics.BlocksTotal.Add(1)
    }

    switch action.Type {
    case "quarantine":  metrics.QuarantTotal.Add(1)
    case "rate_limit":  metrics.RateLimTotal.Add(1)
    case "monitor":     metrics.MonitorTotal.Add(1)
    }
}
```

**Why `atomic.Int64`?** No locks, no contention. Multiple goroutines can increment safely.

---

## CLI Commands

Three ways to interact with the agent without HTTP:

```bash
# List all blocked IPs
sudo vpsGuard --list-blocked
IP                   EXPIRES                                      REASON
1.2.3.4              2025-03-13T10:00:00Z (in 23h59m)            score_exceeded_block_threshold
5.6.7.8              2025-03-13T08:00:00Z (in 21h59m)            central_feed_confirmed

# Unblock an IP
sudo vpsGuard --unblock 1.2.3.4
✅ 1.2.3.4 removed from block store
✅ 1.2.3.4 unblocked from nftables

# Check agent health
vpsGuard --status
Status:  ok
Version: v0.3.0
Uptime:  14h3m12s

Components:
  watchdog           ok
  event_bus          ok
```

These commands connect to the running agent via its health endpoint, or directly query nftables and the block store.

**They run BEFORE the daemon starts:**

```go
func main() {
    // Parse flags
    if *listBlocked {
        runListBlocked(cfg)
        return  // exit before starting the agent
    }
    if *unblockIP != "" {
        runUnblockIP(cfg, *unblockIP)
        return
    }
    if *showStatus {
        runStatus(*healthAddr)
        return
    }
    // ... start the daemon
}
```

---

## What We Learned

| Concept | Why It Matters |
|---------|---------------|
| **Health endpoint** | Integration with monitoring tools |
| **Prometheus metrics** | Industry standard — Grafana, alerting |
| **Atomic counters** | Lock-free concurrency for hot path |
| **CLI before daemon** | Clean separation — CLI exits, doesn't start agent |

## Design Decisions

1. **Why both Prometheus and JSON formats?** Prometheus is for collectors; JSON is for humans and scripts. Same data, two views.

2. **Why `--status` hits the health endpoint instead of reading local state?** It lets you check a running agent from anywhere. The CLI doesn't need root — just network access to localhost:9090.

3. **Why `--list-blocked` merges two sources (blocks.json + nftables)?** They can get out of sync (manual nft commands, file deletion). Merging gives the full picture.

---

## What's Next

The agent is operational. One last security fix: **secrets management**.

## Check Your Understanding

1. What happens to the counters if the agent restarts?
2. Why does `--list-blocked` need root (sudo)?
3. What's the difference between `counter` and `gauge` in Prometheus?
4. Why do CLI commands run before the daemon starts?
