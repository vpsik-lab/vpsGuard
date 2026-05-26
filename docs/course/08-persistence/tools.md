# Tools: Lesson 08

## New Tools

### SQLite (via go-sqlite3)

Embedded SQL database. No server, no setup, no config.

```go
import _ "github.com/mattn/go-sqlite3"

db, _ := sql.Open("sqlite3", "/var/cache/vpsGuard/ip_cache.db")
```

**Why go-sqlite3 over pure-go alternatives?**
- `mattn/go-sqlite3` wraps libsqlite3 via CGO — it's the fastest option
- Pure Go alternatives (like `modernc.org/sqlite`) are 2-3x slower
- Trade-off: requires CGO, but we already build without CGO for cross-compilation... wait, we need to handle this.

Actually, `mattn/go-sqlite3` requires CGO. For cross-compilation, we use `CC=aarch64-linux-gnu-gcc`. This is why the Makefile uses `CGO_ENABLED=1` for cross-builds.

### bufio.Scanner (stdlib)

Efficient line-by-line file reading:

```go
scanner := bufio.NewScanner(f)
for scanner.Scan() {
    line := scanner.Bytes()  // []byte — zero copy
    var entry BlockEntry
    json.Unmarshal(line, &entry)
}
```

**Why Scanner and not ReadString?** Scanner handles long lines, uses a growable buffer, and is more memory-efficient.

### json.Marshal / json.Unmarshal (stdlib)

JSON serialization for our block store:

```go
data, _ := json.Marshal(entry)
// {"ip":"1.2.3.4","expires_at":"2025-03-13T12:00:00Z","reason":"blocked"}

var entry BlockEntry
json.Unmarshal(data, &entry)
```

## Reference: Storage Comparison

| Format | Use Case | Pros | Cons |
|--------|----------|------|------|
| **JSONL** | Block store, audit | Human-readable, append-only, grep-able | No indexes, full scan on load |
| **SQLite** | IP cache | Indexed, queryable, structured | Requires CGO, heavier |
| **YAML** | Log hash chain | Human-readable, nested | Slow for large files |
| **Plain text** | — | Simpler than JSONL? | No structure — avoid |
