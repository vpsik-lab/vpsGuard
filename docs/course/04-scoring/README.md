# Lesson 04: Scoring

**Not all attackers are equal. Score them.**

---

## The Problem

From our parser, every failed login looks the same:

```
1.2.3.4 → event
5.6.7.8 → event
9.10.11.12 → event
```

But they're not the same:
- **1.2.3.4** — tried 50 times in 60 seconds across 6 different usernames → **clearly malicious**
- **5.6.7.8** — tried once, then never came back → **random scanner, low risk**
- **9.10.11.12** — tried root once every hour for a week → **persistent, high risk**

We need to **score** each IP so the agent can decide: block, rate-limit, quarantine, or just monitor.

---

## The Score Sources

We combine 5 signals into a single 0–100 score:

```
FinalScore = (AbuseIPDB × w1 + OTX × w2 + Behavioral × w3 + Temporal × w4 + CentralFeed × w5) / totalWeight
```

### 1. Behavioral Score (0–100)

How does this IP behave right now?

```go
func (b *BehavioralAnalyzer) GetScore(ip string) int {
    rec := b.ips[ip]
    score := 0

    if rec.Attempts >= threshold {        // lots of attempts?
        score += 25
    }
    if rec.Attempts >= threshold*3 {       // extreme attempts?
        score += 15
    }
    if elapsed < window {                   // all in a short window?
        score += 20
    }
    if len(rec.Usernames) > 3 {            // trying multiple users?
        score += 20
    }
    if len(rec.Ports) > 5 {                // scanning multiple ports?
        score += 20
    }
    return score  // max 100
}
```

Each factor adds to the score. An IP that tries 50 passwords against 6 usernames in 30 seconds scores 80+ — likely a bot.

### 2. Temporal Score (0–100)

History matters. An IP that attacked yesterday is more likely to attack today.

```go
func (m *ReputationMemory) GetScore(ip string) int {
    entry := m.store[ip]

    // Score by count
    switch {
    case entry.Count > 20:  score += 70
    case entry.Count > 10:  score += 50
    case entry.Count > 5:   score += 30
    case entry.Count >= 3:  score += 15
    case entry.Count >= 1:  score += 5
    }

    // Bonus for consistently high scores
    if avgScore > 60 {
        score += 20
    }
    return score
}
```

**7-day TTL** — an IP that doesn't return for a week is forgotten.

### 3. Threat Intelligence (0–100 each)

External APIs enrich our view:
- **AbuseIPDB** — "has this IP been reported for SSH attacks?"
- **AlienVault OTX** — "is this IP in known threat pulse feeds?"
- **Central Feed** — (future) our own global intelligence

### The Hybrid Formula

```go
weightedSum := float64(AbuseScore) * wAbuse +
    float64(OTXScore) * wOTX +
    float64(Behavioral) * wBehav +
    float64(Temporal) * wTemp +
    float64(CentralScore) * wCentral

FinalScore = int(weightedSum / totalWeight)
```

Default weights are configured in `config.yaml`:

```yaml
scoring:
  abuseipdb_weight: 0.25
  alienvault_weight: 0.15
  behavior_weight: 0.30
  temporal_weight: 0.20
  central_weight: 0.10
```

Behavior gets the highest weight (0.30) because **what the IP is doing right now** matters most.

---

## Verdicts

The final score maps to a verdict:

| Score | Verdict | What Happens |
|-------|---------|-------------|
| 0 | Clean | Nothing |
| 1–24 | Low | Monitor only |
| 25–49 | Suspicious | Rate-limit |
| 50–79 | High | Quarantine |
| 80–100 | Critical | Block immediately |

---

## The Code Flow

```
Parser → Event → Bus → Scorer.Evaluate() → ScoreResult
                                     ↑
                              IntelClient.CheckIP()
                              (cached + API)
```

```go
func (s *Scorer) Evaluate(ctx context.Context, evt Envelope, intel *IntelClient) *ScoreResult {
    ip := evt.SourceIP()

    // 1. Check threat intel (cached or API)
    intelResult := intel.CheckIP(ctx, ip)

    // 2. Behavioral + temporal
    behavioral := s.behavioral.GetScore(ip)
    temporal := s.memory.GetScore(ip)

    // 3. Weighted sum
    finalScore := weightedSum(abuse, otx, behavioral, temporal, central)

    // 4. Record for future temporal scoring
    s.memory.Record(ip, finalScore)

    return &ScoreResult{IP: ip, FinalScore: finalScore, ...}
}
```

---

## What We Learned

| Concept | Why It Matters |
|---------|---------------|
| **Weighted scoring** | Not all signals are equally important |
| **Behavioral analysis** | Actions speak louder than reputation |
| **Temporal memory** | History repeats — remember repeat offenders |
| **External intel** | Some IPs are known bad actors globally |
| **Configurable weights** | Every VPS has different threat tolerance |

## Design Decisions

1. **Why weighted average and not a decision tree?** A weighted average is simple, transparent, and easy to tune. A decision tree would be more accurate but harder to debug and configure.

2. **Why 0–100 scale?** Familiar to everyone. 0 = clean, 100 = nuclear. Intuitive thresholds.

3. **Why separate behavioral and temporal?** They measure different things: behavioral is *now*, temporal is *history*. Combining them gives a fuller picture.

---

## What's Next

We have scores. Now we need to:
- **Decide** what to do (block, rate-limit, monitor)
- **Block** the IP in nftables
- **Notify** you about it

That's the next sprint.

---

## Check Your Understanding

1. An IP tries 50 passwords against root in 10 seconds. What's its approximate behavioral score?
2. Why does the temporal score have a 7-day TTL?
3. What happens if all external APIs are unreachable?
4. Why does behavior get the highest weight (0.30)?
