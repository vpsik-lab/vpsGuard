# Challenge: Scoring

**Difficulty levels — pick your path.**

---

## ⭐ Level 1: Score an IP Manually

A VPS receives these SSH attempts from `1.2.3.4` in 2 minutes:

```
root — failed × 12
admin — failed × 5
ubuntu — failed × 3
deploy — failed × 2
```

The config threshold is 5, window is 5 minutes.

**Task:** Calculate the behavioral score step by step using the formula.

**Hint:** The score factors are in `behavioral.go` lines 65-79.

---

## ⭐⭐ Level 2: Test the Scorer

Write a Go test that:
1. Creates a `Scorer` with known config
2. Records 15 events from the same IP
3. Calculates the score
4. Asserts the score is > 50

```go
func TestScorerAccumulation(t *testing.T) {
    cfg := config.Config{Scoring: config.ScoringConfig{
        BehaviorThreshold: 3,
        BehaviorWindowMinutes: 5,
    }}
    scorer := engine.NewScorer(&cfg, zap.NewNop())
    
    for i := 0; i < 15; i++ {
        evt := makeFailedLogin("1.2.3.4", "root")
        scorer.RecordEvent(makeEnvelope(evt))
    }
    
    result := scorer.Evaluate(context.Background(), makeEnvelope(...), nil)
    // What's the score?
}
```

---

## ⭐⭐⭐ Level 3: Add GeoIP Scoring

Extend the `ScoreResult` with a `GeoScore` field that adds +20 if the IP is from a known high-risk country (Russia, China, Iran, North Korea).

1. Add a `geo_countries` field to `config.yaml`
2. Add a `GeoIPScore` field to `ScoreResult`
3. Add a `geo_weight` to the weighted formula
4. Adjust `Validate()` so total ≤ 1.0 still holds

**Hint:** You'll need a GeoIP database. Start with `ipinfo.io` API for simplicity — use the `org` field.

---

## Solution

<details>
<summary>Click for Level 1 solution</summary>

| Factor | Condition | Points |
|--------|-----------|--------|
| attempts >= 5 | 22 >= 5 → yes | +25 |
| attempts >= 15 | 22 >= 15 → yes | +15 |
| within 5 min window | yes | +20 |
| unique usernames > 3 | 4 > 3 → yes | +20 |
| **Total behavioral** | | **80** |

This IP would score 80+ — automatically blocked.
</details>
