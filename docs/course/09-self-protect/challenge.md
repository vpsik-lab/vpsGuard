# Challenge: Self-Protect

---

## ⭐ Level 1: Test the Watchdog

Write a test that verifies the watchdog detects tampering:

```go
func TestWatchdogDetectsTamper(t *testing.T) {
    // 1. Create a temp config file
    // 2. Calculate its checksum
    // 3. Create watchdog with that checksum
    // 4. Modify the config file
    // 5. Verify watchdog.healthCheck() detects the change
}
```

**Hint:** Look at `internal/selfprotect/watchdog_test.go`.

---

## ⭐⭐ Level 2: Add a Ping Endpoint

Add a `Ping()` method to `Watchdog` and expose it via the health endpoint at `/health/watchdog`. The ping should verify:
1. Config file exists
2. Checksum still matches (lazy — don't recalculate on every ping)

**Hint:** The `/health` endpoint already supports component registration.

---

## ⭐⭐⭐ Level 3: Rate-Limit the Tamper Alerts

If the config keeps changing (e.g., legitimate updates), the watchdog fires alerts every interval. Implement exponential backoff: first alert immediately, then wait 1min, then 5min, then 30min until the checksum stabilizes.

**Hint:** Use `time.Since(lastAlertTime) < backoffDuration` in the health check.

---

## Solution

<details>
<summary>Click for Level 1 test solution</summary>

```go
func TestWatchdogDetectsTamper(t *testing.T) {
    f, _ := os.CreateTemp("", "config-*.yaml")
    defer os.Remove(f.Name())
    f.Write([]byte("key: value"))
    f.Close()

    // Calculate original checksum
    data, _ := os.ReadFile(f.Name())
    h := sha256.Sum256(data)
    originalSum := hex.EncodeToString(h[:])

    w := NewWatchdog(zap.NewNop(), f.Name(), 100*time.Millisecond, originalSum)

    // Modify the file
    os.WriteFile(f.Name(), []byte("key: tampered"), 0644)

    tampered := false
    w.OnTamper(func(msg string) { tampered = true })
    w.healthCheck()

    assert.True(t, tampered)
}
```

Check `internal/selfprotect/watchdog_test.go` for the actual test suite.
</details>
