# RFC-0001: vpsGuard Event Schema

**Status**: Active  
**Version**: 0.3.0  
**Last Updated**: 2026-05-24

---

## Scope

This RFC defines the event model used internally by the vpsGuard **Agent**.  
Events flow through the Event Bus from sources (monitor) to processors (scorer, decision).

The Central Platform API contract is defined separately in [`AGENT-API-CONTRACT.md`](AGENT-API-CONTRACT.md).

---

## Event Envelope

Every event is wrapped in an `Envelope` struct:

```go
type Envelope struct {
    TraceID   string    // UUID v4 — end-to-end correlation
    Priority  Priority  // 0=Low, 1=Normal, 2=High, 3=Critical
    Source    string    // "journal", "feed", "tailer"
    Timestamp time.Time // When the event was created
    Version   int       // Schema version (currently 1)
    Event     Event     // Interface — concrete event payload
}
```

### TraceID

- Generated at event creation via `uuid.New().String()`
- Passed through every processing stage unchanged
- Logged in all action outputs (block, notify) for debugging

### Priority Levels

| Priority | Value | Meaning |
|----------|-------|---------|
| `PriorityLow` | 0 | Informational |
| `PriorityNormal` | 1 | Standard threat |
| `PriorityHigh` | 2 | Aggressive/confirmed threat |
| `PriorityCritical` | 3 | Immediate action required |

---

## Event Interface

```go
type Event interface {
    Type() EventType
    SourceIP() string
    Severity() int
    Data() map[string]interface{}
}
```

All event types implement this interface.

---

## Event Types

### BaseEvent

Used for generic/unknown events:

```go
type BaseEvent struct {
    TypeVal      EventType
    IP           string
    SeverityVal  int
    Metadata     map[string]interface{}
}
```

### SSHFailedLogin

```go
type SSHFailedLogin struct {
    BaseEvent
    Username string
    Port     int
}
```

- **Source**: auth.log / journald
- **Trigger**: `Failed password for <user> from <ip> port <port>`
- **Severity**: 5 (base) + (root → +5)

### InvalidUser

```go
type InvalidUser struct {
    BaseEvent
    Username string
    Port     int
}
```

- **Source**: auth.log / journald
- **Trigger**: `Invalid user <user> from <ip>`
- **Severity**: 7

### PortScan

```go
type PortScan struct {
    BaseEvent
    Ports []int
    Count int
}
```

- **Source**: nftables logs / future connection tracking
- **Trigger**: >20 unique destination ports within 5 minutes (via rules engine)
- **Severity**: 8

### CentralFeedMatch

```go
type CentralFeedMatch struct {
    BaseEvent
    Confidence      int
    Category        []string
    RecommendedAction string
    Source          string // "central_feed"
}
```

- **Source**: Central Platform pull client
- **Trigger**: Feed item matches monitored IP
- **Severity**: Based on confidence (confidence × 0.8)

---

## Scoring Output

The `ScoreResult` struct is the output of the engine and input to the decision:

```go
type ScoreResult struct {
    IP           string
    FinalScore   int       // 0–100 final hybrid score
    AbuseScore   int       // AbuseIPDB sub-score
    OTXScore     int       // AlienVault sub-score
    Behavioral   int       // Behavioral sub-score
    Temporal     int       // Temporal memory sub-score
    CentralScore int       // Central feed sub-score
    CentralConf  int       // Central feed confidence (0–100)
    Sources      []string  // Which sources contributed
}
```

### Verdict Derivation

```go
func (s *ScoreResult) Verdict() string {
    switch {
    case s.FinalScore >= 80: return "critical"
    case s.FinalScore >= 50: return "high"
    case s.FinalScore >= 25: return "suspicious"
    case s.FinalScore >= 1:  return "low"
    default:                 return "clean"
    }
}
```

---

## Decision Action

```go
type Action struct {
    Type     string        // "block", "quarantine", "monitor", "ignore"
    Block    bool          // Whether to call nftables
    Notify   bool          // Whether to send notification
    Duration time.Duration // Block/quarantine duration
    Score    int           // FinalScore that triggered this action
    Reason   string        // Human-readable reason
    RuleName string        // Rule that matched (if any)
}
```

---

## Event Flow Example

```
1. auth.log line:
   "Failed password for root from 185.220.101.X port 22 ssh2"

2. Parser → SSHFailedLogin{
       BaseEvent: BaseEvent{IP: "185.220.101.X", SeverityVal: 10},
       Username: "root",
       Port: 22,
   }

3. Envelope{
       TraceID:   "b7f3a1c2-4d5e-4f6a-8b7c-9d0e1f2a3b4c",
       Priority:  PriorityNormal,
       Source:    "journal",
       Timestamp: time.Now(),
       Version:   1,
       Event:     SSHFailedLogin{...},
   }

4. Bus.Publish(envelope)

5. Scorer.RecordEvent(envelope)       → behavioral update
6. Scorer.Evaluate(ctx, envelope, intel) → ScoreResult{FinalScore: 72}
7. Decision.Evaluate(..., ScoreResult, rules) → Action{Type: "block", Block: true}
8. fw.BlockIP(ctx, "185.220.101.X", 24h)
9. notifier.Send(ctx, envelope, scores, action)
```

---

## Cache Schema (SQLite)

Used by `internal/threat/cache.go`:

```sql
CREATE TABLE IF NOT EXISTS ip_cache (
    ip              TEXT PRIMARY KEY,
    abuse_score     INTEGER DEFAULT 0,
    otx_score       INTEGER DEFAULT 0,
    central_score   INTEGER DEFAULT 0,
    central_conf    INTEGER DEFAULT 0,
    abuse_data      TEXT,       -- JSON blob
    otx_data        TEXT,       -- JSON blob
    central_data    TEXT,       -- JSON blob
    last_updated    TIMESTAMP,
    expires_at      TIMESTAMP
);

CREATE INDEX idx_ip_cache_expires ON ip_cache(expires_at);
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2026-05-01 | Initial event schema |
| 0.3.0 | 2026-05-26 | CLI commands, Prometheus /metrics, env-var secrets, watchdog tamper callback, IPv6 dual-stack, cache restore, arg-injection fix, course Sprint 1-4 |
