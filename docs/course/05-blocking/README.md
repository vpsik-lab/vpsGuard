# Lesson 05: Blocking

**From scores to action — block attackers at the firewall level.**

---

## The Problem

We have scores. Now what?

An IP with score 85 should be **blocked immediately** — not rate-limited, not monitored. We need to reach into the Linux kernel and tell it: "Drop every packet from this IP."

This is where **nftables** comes in.

---

## The Architecture

```
Scorer → ScoreResult (score: 85, verdict: "critical")
    ↓
DecisionEngine.Evaluate()
    ↓
Action{Type: "block", Block: true, Duration: 24h}
    ↓
processEvent() → fw.BlockIP(ctx, "1.2.3.4", 24h)
    ↓
nft add element inet vpsGuard blacklist { 1.2.3.4 timeout 86400s }
```

---

## The Decision Engine

The `DecisionEngine` takes a score and maps it to an action:

```go
func (d *DecisionEngine) Evaluate(scores *ScoreResult) []Action {
    switch {
    case scores.FinalScore >= blockThreshold:
        // BLOCK — high confidence malicious
        return Action{Type: "block", Block: true, Duration: 24h}

    case scores.FinalScore >= rateLimitScore:
        // RATE-LIMIT — suspicious, short block
        return Action{Type: "rate_limit", Block: true, Duration: 30min}

    case scores.FinalScore >= quarantineScore:
        // QUARANTINE — mildly suspicious, monitor
        return Action{Type: "quarantine", Block: true, Duration: 15min}
    }

    // Fallback: monitor if any behavioral signal exists
    if scores.Behavioral > 0 {
        return Action{Type: "monitor", Block: false}
    }
    return nil
}
```

Three tiers — three thresholds. Configurable in `config.yaml`.

---

## nftables: The Modern Firewall

nftables is the successor to iptables. Same kernel subsystem, better syntax, better performance.

### Key Concept: Sets

A **set** is a named collection of IPs with optional timeouts:

```bash
# Create a set
nft add set inet vpsGuard blacklist { type ipv4_addr; flags timeout; }

# Add an IP with auto-expiry
nft add element inet vpsGuard blacklist { 1.2.3.4 timeout 86400s }

# The drop rule references the set
nft add rule inet vpsGuard input ip saddr @blacklist drop
```

**Why sets?** They're O(1) lookup, auto-expire, and you can list/modify at runtime without reloading rules.

### Our nftables Manager

```go
type NftablesManager struct {
    table      string  // "vpsGuard"
    setName    string  // "blacklist"
    setNameV6  string  // "blacklist6"
    logger     *zap.Logger
}
```

**BlockIP** — adds an IP to the set with a timeout:

```go
func (m *NftablesManager) BlockIP(ctx context.Context, ip string, duration time.Duration) error {
    return exec.CommandContext(ctx, "nft",
        "add", "element", "inet", m.table, set,
        fmt.Sprintf("{ %s timeout %ds }", ip, int(duration.Seconds())),
    ).Run()
}
```

**IsBlocked** — checks if an IP is in the set:

```go
func (m *NftablesManager) IsBlocked(ctx context.Context, ip string) (bool, error) {
    out, _ := exec.CommandContext(ctx, "nft",
        "list", "set", "inet", m.table, set,
    ).Output()
    return strings.Contains(string(out), ip), nil
}
```

**Why subprocess, not netlink?** nftables has a Go library (nftables/netlink), but exec'ing `nft` is simpler, more portable, and debuggable. The overhead is negligible — ~2ms per call.

---

## The Full Flow

```
processEvent(ctx, evt, scorer, decision, fw, ...)
  │
  ├─ 1. scorer.Evaluate(ctx, evt, intel)  → ScoreResult
  ├─ 2. decision.Evaluate(ctx, evt, scores, rules) → []Action
  ├─ 3. for each action:
  │      if action.Block:
  │        ├─ fw.BlockIP(ctx, ip, duration)    ← nftables
  │        ├─ blockStore.Save(ip, expires, reason)  ← persistence
  │        └─ intelClient.ReportIP(ctx, ip)    ← report to AbuseIPDB
  │      if action.Notify:
  │        └─ notifier.Send(ctx, evt, scores, action)  ← Telegram/Email
  └─ 4. auditLog.Log(AuditEntry{...})          ← JSONL audit trail
```

This happens in **under 50ms** from log line to firewall block.

---

## What We Learned

| Concept | Why It Matters |
|---------|---------------|
| **Threshold cascade** | Different severities get different responses |
| **nftables sets** | Fast, auto-expiring, runtime-modifiable |
| **exec.Command** | Simple, debuggable interface to nft |
| **Block + persist** | Survives reboot via blocks.json |

## Design Decisions

1. **Why `exec.Command` instead of a library?** netlink libraries are hard to debug — every error is "operation failed". With `nft`, you see the exact command that failed.

2. **Why args slice instead of one big string?** Security. Never interpolate IPs into a shell string — it's an injection attack waiting to happen. Go's `exec.Command` takes separate args, which bypasses the shell entirely.

3. **Why 3 tiers?** You need at least: "block and forget" (high score), "slow down" (medium), and "watch" (low). Anything less would be either too aggressive or too passive.

---

## What's Missing

We block. But no one knows about it. Next lesson: **notifications**.

---

## Check Your Understanding

1. Why are nftables sets better than individual iptables rules for dynamic blocking?
2. What's the difference between "block", "rate-limit", and "quarantine"?
3. Why use separate args in `exec.Command` instead of a single string?
4. What happens to a block after the timeout expires?
