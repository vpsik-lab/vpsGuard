# Lesson 08: Persistence

**Don't lose data when the agent restarts.**

---

## The Problem

When the agent restarts:
- **nftables sets** are gone (kernel doesn't persist them)
- **Block history** is gone (who did we block yesterday?)
- **IP reputation cache** is gone (all those API calls wasted)

We need persistence in three places:

```
┌──────────────────────────────────────┐
│            vpsGuard Agent              │
│                                        │
│  blocks.json (JSONL)  ← block entries │
│  ip_cache.db (SQLite) ← reputation    │
│  audit.jsonl (JSONL)  ← audit trail   │
│  log-hashes.yaml      ← log integrity │
└──────────────────────────────────────┘
```

---

## 1. Block Store (blocks.json)

A simple **JSONL** file (JSON Lines — one JSON object per line):

```json
{"ip":"1.2.3.4","expires_at":"2025-03-13T12:00:00Z","reason":"score_exceeded_block_threshold"}
{"ip":"5.6.7.8","expires_at":"2025-03-13T14:00:00Z","reason":"central_feed_confirmed"}
```

**Why JSONL and not SQLite?** Simplicity. The block store is append-only with occasional cleanup. JSONL is human-readable, grep-able, and requires zero schema.

```go
type BlockStore struct {
    path string
    mu   sync.Mutex
}

func (s *BlockStore) Save(ip string, expiresAt time.Time, reason string) error {
    entry := BlockEntry{IP: ip, ExpiresAt: expiresAt, Reason: reason}
    data, _ := json.Marshal(entry)
    f, _ := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
    defer f.Close()
    _, err := f.Write(append(data, '\n'))
    return err
}

func (s *BlockStore) Load() ([]BlockEntry, error) {
    // Read all, filter non-expired
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        var entry BlockEntry
        json.Unmarshal(scanner.Bytes(), &entry)
        if entry.ExpiresAt.After(time.Now()) {
            entries = append(entries, entry)
        }
    }
    return entries, nil
}
```

**On startup**, the agent calls `Load()` and re-adds all non-expired entries to nftables:

```go
entries, _ := blockStore.Load()
for _, entry := range entries {
    fw.BlockIP(ctx, entry.IP, time.Until(entry.ExpiresAt))
}
```

---

## 2. IP Reputation Cache (ip_cache.db)

### Why SQLite?

The reputation cache has **structure**: IP, multiple scores (abuse, otx, central), confidence, timestamps, TTL. A flat file would mean re-parsing everything for a single lookup.

SQLite gives us:
- **Indexed lookups** — O(log n) instead of O(n)
- **Schema** — columns are typed and validated
- **Survival** — data persists across restarts

### Schema

```sql
CREATE TABLE IF NOT EXISTS ip_cache (
    ip TEXT PRIMARY KEY,
    abuse_score INTEGER DEFAULT 0,
    otx_score INTEGER DEFAULT 0,
    central_score INTEGER DEFAULT 0,
    central_conf INTEGER DEFAULT 0,
    last_checked TEXT DEFAULT (datetime('now')),
    ttl_hours INTEGER DEFAULT 24
);
```

### The Cache Layer

```go
type IPCache struct {
    db      *sql.DB       // SQLite connection
    entries map[string]*CacheEntry  // in-memory for speed
    ttl     time.Duration
    mu      sync.Mutex
}
```

**Two-layer architecture:**
1. **In-memory map** — O(1) lookups, no disk I/O
2. **SQLite backup** — survives restarts via `loadFromDB()`

```go
func (c *IPCache) Get(ip string) *CacheEntry {
    c.mu.Lock()
    defer c.mu.Unlock()
    return c.entries[ip]
}

func (c *IPCache) Set(ip string, entry *CacheEntry) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.entries[ip] = entry
    // Also write to SQLite
    c.db.Exec("INSERT OR REPLACE INTO ip_cache ...")
}

func (c *IPCache) loadFromDB() {
    rows, _ := c.db.Query("SELECT * FROM ip_cache WHERE expiry > datetime('now')")
    for rows.Next() {
        // Restore to in-memory map
        c.entries[ip] = &entry
    }
}
```

---

## 3. Audit Log (audit.jsonl)

Every decision is logged:

```json
{"timestamp":"2025-03-12T10:00:01Z","ip":"1.2.3.4","score":85,"action":"block","reason":"score_exceeded"}
```

Used by:
- **Daily reports** — count blocks per day
- **Debugging** — why was this IP blocked?
- **Forensics** — trace attack patterns

---

## The Startup Flow

```
Agent starts
  │
  ├─ 1. Load config
  ├─ 2. Open SQLite cache → loadFromDB() restores memory
  ├─ 3. Open block store → Load() returns non-expired entries
  ├─ 4. For each entry: fw.BlockIP(ctx, ip, remaining)
  │     (re-populates nftables sets)
  ├─ 5. Open audit log (append mode)
  ├─ 6. Start monitoring
  └─ 7. Agent is live — no missed beats
```

---

## What We Learned

| Concept | Why It Matters |
|---------|---------------|
| **JSONL** | Simple, append-only, grep-able — perfect for block store |
| **SQLite** | Structured persistence with zero config — perfect for cache |
| **Two-layer cache** | Memory for speed, SQLite for survival |
| **Startup restore** | Agent picks up exactly where it left off |

## Design Decisions

1. **Why both SQLite AND in-memory map?** Pure SQLite is too slow for hot-path lookups (microseconds vs nanoseconds). Pure memory is lost on restart. Two layers give us both.

2. **Why JSONL for blocks and not SQLite?** The block store is sequential (append, read all, filter). JSONL handles this perfectly without a DB driver dependency.

3. **Why not BoltDB?** BoltDB is great but requires a separate import and has a different query model. SQLite is more widely known and gives us SQL querying for free.

---

## What's Next

We have a working agent. Now it needs to **protect itself**. Next lesson: Self-Protect.

---

## Check Your Understanding

1. Why does the agent re-add old blocks to nftables on startup?
2. What's the advantage of JSONL over a regular log file?
3. Why two layers (memory + SQLite) for the cache?
4. What happens if SQLite file is corrupted?
