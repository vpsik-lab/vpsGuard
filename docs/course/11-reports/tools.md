# Tools: Lesson 11

## New Tools

### time.Ticker

Go's periodic timer:

```go
ticker := time.NewTicker(24 * time.Hour)
for {
    select {
    case <-ticker.C:
        sendReport()
    case <-ctx.Done():
        ticker.Stop()
        return
    }
}
```

### copytruncate (logrotate directive)

When logrotate rotates a file that's still open by a process:
- `copytruncate`: copies the file, then truncates the original to 0 bytes
- Alternative: `create` (rename + create new file — requires process to re-open)

We use `copytruncate` because vpsGuard keeps file handles open.

### /proc/uptime

Kernel file — two numbers:
```
uptime_seconds total_idle_seconds
```

Example:
```bash
cat /proc/uptime
# 1234567.89 9876543.21
```

Parsed in Go:
```go
data, _ := os.ReadFile("/proc/uptime")
var uptimeSec float64
fmt.Sscanf(string(data), "%f", &uptimeSec)
days := int(uptimeSec / 86400)
```

### runtime.ReadMemStats (stdlib)

Go runtime memory statistics:

```go
var m runtime.MemStats
runtime.ReadMemStats(&m)
fmt.Printf("Alloc: %d MB\n", m.Alloc/1024/1024)
```

Included in daily reports for health monitoring.

## Reference: Hash Chain Format

```yaml
# /var/log/vpsGuard/log-hashes.yaml
entries:
  - timestamp: "2025-03-11T10:00:00Z"
    sha256: "a1b2c3d4..."
    prev: "0000000000..."
  - timestamp: "2025-03-12T10:00:00Z"
    sha256: "e5f6a7b8..."
    prev: "a1b2c3d4..."
```
