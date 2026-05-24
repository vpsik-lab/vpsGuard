# VPS-Guard Agent — Scoring Engine

**Version**: 0.2.0  
**Status**: Stable

> The Agent uses a **hybrid weighted scoring model** that fuses multiple independent signals into a single 0–100 threat score per IP address.

---

## 1. Scoring Formula

```
FinalScore = (AbuseIPDB    × 0.25)
           + (AlienVault   × 0.20)
           + (Behavioral   × 0.30)
           + (Temporal     × 0.10)
           + (CentralFeed  × 0.15)

Constraint: sum(weights) ≤ 1.0 (validated at startup)
```

Each sub-score is independently calculated and normalized to 0–100 before weighting.

---

## 2. Score Components

### 2.1 AbuseIPDB Score (weight: 0.25)

Source | Type | Latency | Cached
-------|------|---------|-------
[AbuseIPDB API v2](https://www.abuseipdb.com/api.html) | REST | ~500ms | ✅ (24h TTL)

**Scoring logic**:
- `confidenceScore` from AbuseIPDB mapped directly (0–100)
- `totalReports`: contributes up to +20 for >100 reports
- Final: `min(confidenceScore + bonus, 100)`

### 2.2 AlienVault OTX Score (weight: 0.20)

Source | Type | Latency | Cached
-------|------|---------|-------
[OTX API v1](https://otx.alienvault.com/api) | REST | ~500ms | ✅ (24h TTL)

**Scoring logic**:
- Pulse count mapped to score:
  - 0 pulses → 0
  - 1–2 pulses → 30
  - 3–5 pulses → 50
  - 6–10 pulses → 70
  - >10 pulses → 90

### 2.3 Behavioral Score (weight: 0.30)

**Input**: Local SSH failed login events from `auth.log` / systemd journal.

**Scoring logic** (evaluated per IP within a 10-minute sliding window):

| Condition | Score |
|-----------|-------|
| Attempts > threshold (default: 5) | +25 |
| Attempts > threshold × 3 (default: 15) | +15 |
| Elapsed < window AND attempts > threshold | +20 |
| Unique usernames > 3 | +20 |
| Unique ports > 5 | +20 |

**Maximum**: 100

### 2.4 Temporal Score (weight: 0.10)

**Input**: Historical reputation from Agent's memory (7-day window).

**Scoring logic**:

| Condition | Score |
|-----------|-------|
| 1–2 events in 7 days | +5 |
| 3–5 events | +15 |
| 6–10 events | +30 |
| 11–20 events | +50 |
| >20 events | +70 |
| Historical avg score > 60 | +20 |
| Multiple unique days | +10 |

**Maximum**: 100

Memory is cleaned up hourly (goroutine in `main.go`).

### 2.5 Central Feed Score (weight: 0.15)

**Input**: Threat items pulled from the Central Platform API.

**Scoring logic**:
- `confidence` from feed item mapped directly (0–100)
- Confidence tiers override raw score:
  - ≥ 90: immediate block + no notify needed (handled by decision engine)
  - 60–89: quarantine + score boost
  - < 60: score boost only (added to final weighted sum)

---

## 3. Decision Thresholds

Once `FinalScore` is computed, the Decision Engine maps it to an action:

| Score Range | Verdict | Action |
|-------------|---------|--------|
| 80–100 | Critical | Block 24h + notify |
| 50–79 | High | Block 24h + notify |
| 25–49 | Medium | Quarantine 15m + notify |
| 1–24 | Low | Monitor only |
| 0 | Clean | Ignore |

Actions are **overridable** by the Rules Engine:
- A matching rule can escalate (e.g., `invalid_user` → block even at score 10)
- A matching rule can de-escalate (future: whitelist rules)

---

## 4. Central Feed Confidence Tiers

The Central Feed has its own confidence tiers that interact with scoring:

| Confidence | Override | Agent Behaviour |
|------------|----------|-----------------|
| ≥ 90 | Block (bypass scoring) | Immediate nftables block, 24h, notify |
| 60–89 | Quarantine | Temporary block 15m, monitor, notify |
| < 60 | Score boost | Added to weighted sum, normal thresholds |

These tiers exist to prevent false positives: even a high-confidence feed item gets local verification through behavioral analysis.

---

## 5. Edge Cases

| Scenario | Behaviour |
|----------|-----------|
| No internet (offline VPS) | AbuseIPDB + OTX = 0; Behavioral + Temporal + local only |
| Central Feed unavailable | Agent continues with local scoring; retries with backoff |
| No historical data | Temporal = 0; Behavioral builds from scratch |
| First-ever SSH attempt | All scores = 0; Clean verdict (no blocking) |
| API rate limited | Uses cached scores (24h TTL) |
| Config validation fail | Agent refuses to start |
