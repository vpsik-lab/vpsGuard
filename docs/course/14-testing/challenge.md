# Challenge: Testing

---

## ⭐ Level 1: Write a Unit Test

The `OTXPulseToScore` function in `internal/threat/alienvault.go` maps pulse counts to scores:

```
0 → 0, 1-2 → 15, 3-5 → 35, 6-10 → 55, 11-25 → 75, >25 → 90
```

Write a table-driven test that covers ALL cases including edge cases (negative values, very large values).

**Hint:** Look at `internal/threat/alienvault_test.go`.

---

## ⭐⭐ Level 2: Write a Concurrency Test

The `IPCache` is accessed from multiple goroutines. Write a test that:

1. Creates an `IPCache`
2. Launches 10 goroutines that call `Set()` with different IPs
3. Launches 10 goroutines that call `Get()` in a loop
4. Runs for 5 seconds with `-race`
5. No race should be detected

```go
func TestIPCacheConcurrent(t *testing.T) {
    cache := NewIPCache(":memory:", time.Hour, zap.NewNop())
    
    for i := 0; i < 10; i++ {
        go func(n int) {
            for j := 0; j < 100; j++ {
                ip := fmt.Sprintf("%d.%d.%d.%d", n, j, 0, 1)
                cache.Set(ip, &CacheEntry{AbuseScore: n * j})
                cache.Get(ip)
            }
        }(i)
    }
    // Wait and verify no race
}
```

---

## ⭐⭐⭐ Level 3: Mutation Testing

Mutation testing checks test quality by introducing bugs and seeing if tests catch them.

For the `OTXPulseToScore` function:
1. Change `> 25` to `>= 25` — does a test catch it?
2. Change the return for case `6-10` from 55 to 50 — does a test catch it?
3. Add a test case for each boundary that your tests are missing

**Hint:** Make the change, run tests, see if they fail. If they don't, you need more test cases.

---

## Solution

<details>
<summary>Click for Level 1 test solution</summary>

```go
func TestOTXPulseToScore(t *testing.T) {
    tests := []struct {
        name   string
        pulses int
        want   int
    }{
        {"no pulses", 0, 0},
        {"single pulse", 1, 15},
        {"two pulses", 2, 15},
        {"three pulses", 3, 35},
        {"five pulses", 5, 35},
        {"six pulses", 6, 55},
        {"ten pulses", 10, 55},
        {"eleven pulses", 11, 75},
        {"twenty-five pulses", 25, 75},
        {"twenty-six pulses", 26, 90},
        {"one hundred pulses", 100, 90},
        {"negative input", -1, 0},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := OTXPulseToScore(tt.pulses)
            if got != tt.want {
                t.Errorf("OTXPulseToScore(%d) = %d, want %d", tt.pulses, got, tt.want)
            }
        })
    }
}
```

Check `internal/threat/alienvault_test.go` for the actual test.
</details>
