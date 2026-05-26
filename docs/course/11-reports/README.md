# Lesson 11: Reports

**What happened while you were asleep?**

---

## The Problem

You wake up. You check Telegram. No alerts — good, no attacks?

Or... maybe the agent crashed at 2 AM and you missed everything?

You need a **daily summary**:
- How many attacks were blocked?
- Is the agent still running?
- Are the logs intact?
- Memory usage?

---

## The Daily Reporter

```go
type DailyReporter struct {
    eventCount24h int       // reset every report
    lastReset     time.Time
    notifier      *notify.Notifier
}
```

It runs as a goroutine, firing every `interval_hours` (default 24):

```go
func (r *DailyReporter) Run(ctx context.Context) {
    if !r.cfg.Report.Enabled {
        return  // no report configured — silent
    }

    interval := time.Duration(r.cfg.Report.IntervalHours) * time.Hour
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            r.sendReport(ctx)
        case <-ctx.Done():
            return
        }
    }
}
```

---

## What's in the Report

```
📊 vpsGuard Daily Report
📅 2025-03-12 10:00 UTC | my-vps

━━━ System Health ━━━
🟢 Uptime: 14d 3h
💾 Go mem: 8 MB

━━━ Security (24h) ━━━
🛡 Blocked: 1,234
⚠️ Rate Limited: 456
🔒 Quarantined: 89
📥 Events processed: 12,847
📁 Audit log entries: 11,500

━━━ Integrity ━━━
🔐 Log hash chain: valid (42 entries)

━━━ Next Report ━━━
⏰ 2025-03-13 10:00 UTC
━━━━━━━━━━━━━━━━━━
vpsGuard Security Agent
```

Three sections:
1. **System Health** — uptime, memory (is the agent healthy?)
2. **Security** — blocks, rate-limits, quarantines (what happened?)
3. **Integrity** — log hash chain status (were logs tampered with?)

---

## Log Hash Chain

Logs can be tampered with: an attacker deletes evidence from audit logs.

**Solution:** A hash chain that links every log entry to the previous one.

```yaml
# /var/log/vpsGuard/log-hashes.yaml
- timestamp: "2025-03-11T10:00:00Z"
  sha256: "a1b2c3..."
  prev: "000000..."

- timestamp: "2025-03-12T10:00:00Z"
  sha256: "d4e5f6..."
  prev: "a1b2c3..."   # ← links to previous hash
```

Each entry is:
```
sha256(prev_hash + log_file_content)
```

If someone modifies yesterday's audit log, the hash changes — and it won't match the `prev` field in today's entry. **Chain broken.**

The hash is appended via the `-hash-chain` CLI flag, called by logrotate:

```bash
# postrotate script
/usr/local/bin/vpsGuard -hash-chain /var/log/vpsGuard
```

The daily report verifies the chain:

```go
func (r *DailyReporter) verifyHashChain() string {
    entries := readChainFile()
    for i, entry := range entries {
        if entry.prev != entries[i-1].sha256 {
            return "CHAIN BROKEN"  // tamper detected!
        }
    }
    return "valid (N entries)"
}
```

---

## Configurable Reporting

```yaml
daily_report:
  enabled: true
  interval_hours: 24
  send_telegram: true    # report via Telegram
  send_email: false      # skip email
```

Independent toggles for each channel. You might want Telegram reports but not email spam.

---

## What We Learned

| Concept | Why It Matters |
|---------|---------------|
| **Daily summary** | See attack patterns over time |
| **Event counting** | Know the volume — 100 vs 10k attacks/day is different |
| **Hash chain** | Prove logs haven't been tampered with |
| **Per-channel toggles** | Telegram for mobile, email for archive |

## Design Decisions

1. **Why a ticker instead of cron?** The agent already runs 24/7. A goroutine with a ticker is simpler than managing cron jobs. No external dependency.

2. **Why SHA256 for the hash chain?** Standard, fast, available in Go stdlib. Not for cryptography — for tamper *detection* (if someone modifies logs, the chain breaks).

3. **Why `copytruncate` in logrotate?** The agent keeps file handles open. `copytruncate` copies the file then truncates the original, so the agent can keep writing without reopening.

---

## What's Next

The agent runs, blocks, reports. Now we need **operations**: metrics, monitoring, and management. Next lesson.

---

## Check Your Understanding

1. How does the daily report know how many events were processed?
2. What breaks the hash chain if someone modifies audit logs?
3. Why `send_telegram` and `send_email` as separate config options?
4. What happens if the agent restarts between reports?
