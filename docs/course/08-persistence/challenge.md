# Challenge: Persistence

---

## ⭐ Level 1: Test the Block Store

Write a test that:
1. Creates a `BlockStore` with a temp file
2. Saves 3 entries (one expired, two active)
3. Loads and verifies only 2 entries are returned

```go
func TestBlockStoreLoadFilterExpired(t *testing.T) {
    f, _ := os.CreateTemp("", "blocks-*.json")
    defer os.Remove(f.Name())
    store := firewall.NewBlockStore(f.Name())
    // ... save entries ...
    // ... load and assert ...
}
```

**Hint:** Look at `internal/firewall/persist_test.go`.

---

## ⭐⭐ Level 2: Cache Performance Benchmark

Write a benchmark comparing cache lookup with vs. without SQLite:

```go
func BenchmarkCacheGet(b *testing.B) {
    cache := NewIPCache(":memory:", time.Hour, zap.NewNop())
    cache.Set("1.2.3.4", &CacheEntry{...})
    for i := 0; i < b.N; i++ {
        cache.Get("1.2.3.4")
    }
}
```

**Hint:** Use Go's `testing.B` — run with `go test -bench=.`.

---

## ⭐⭐⭐ Level 3: Corruption Recovery

The SQLite database file might get corrupted (power loss, disk full). Implement a recovery strategy:

1. Before each write, checksum the DB file
2. On checksum mismatch, restore from last backup
3. Create a backup every 100 writes

**Hint:** Use `filepath.Checksum` or simply copy the file. Don't over-engineer — a simple `.bak` file is enough.

---

## Solution

<details>
<summary>Click for Level 1 test solution</summary>

```go
func TestBlockStoreLoadFilterExpired(t *testing.T) {
    f, err := os.CreateTemp("", "blocks-*.json")
    require.NoError(t, err)
    defer os.Remove(f.Name())

    store := firewall.NewBlockStore(f.Name())

    // Expired entry
    store.Save("1.1.1.1", time.Now().Add(-1*time.Hour), "old")
    // Active entries
    store.Save("2.2.2.2", time.Now().Add(24*time.Hour), "active")
    store.Save("3.3.3.3", time.Now().Add(48*time.Hour), "active2")

    entries, err := store.Load()
    require.NoError(t, err)
    assert.Len(t, entries, 2)
}
```

Check `internal/firewall/persist_test.go` for the full test suite.
</details>
