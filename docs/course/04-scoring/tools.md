# Tools: Lesson 04

## New Tools

### sync.Mutex

Go's mutual exclusion lock. Used by both `BehavioralAnalyzer` and `ReputationMemory` to protect shared maps from concurrent goroutines.

```go
mu    sync.Mutex
store map[string]*MemoryEntry

func (m *ReputationMemory) Record(ip string, score int) {
    m.mu.Lock()
    defer m.mu.Unlock()
    // ... safe to modify store
}
```

**Why not a channel?** For simple read-modify-write patterns, a mutex is clearer and faster than a channel-based "actor" approach.

### time.Duration

Go's duration type — nanoseconds under the hood, but readable constants:

```go
ttl := 7 * 24 * time.Hour         // 7 days
window := 5 * time.Minute         // 5 minutes
```

**Why not store durations as strings?** YAML config uses seconds/minutes, but Go's `time.Duration` gives us type safety and math operations for free.

## Reference: Scoring Weights

The weights are stored in `config.yaml`:

```yaml
scoring:
  abuseipdb_weight: 0.25
  alienvault_weight: 0.15
  behavior_weight: 0.30
  temporal_weight: 0.20
  central_weight: 0.10
```

Total must be ≤ 1.0 (validated in `config.Validate()`). If all sources report max score (100), the weighted sum is exactly 100.

## Reference: Behavioral Scoring Factors

| Factor | Score | Detection |
|--------|-------|-----------|
| `attempts >= threshold` | +25 | Above-normal activity |
| `attempts >= threshold × 3` | +15 | Extreme activity |
| `within time window` | +20 | Compressed in time |
| `> 3 unique usernames` | +20 | Credential stuffing |
| `> 5 unique ports` | +20 | Port scanning |
| **Max** | **100** | |
