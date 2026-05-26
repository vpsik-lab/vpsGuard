# Tools: Lesson 14

## New Tools

### testing (stdlib)

Go's built-in test framework:

```go
func TestXxx(t *testing.T) {
    // t.Error, t.Fatal, t.Log, t.Helper
}
```

### testing.B (benchmarks)

Measure performance:

```go
func BenchmarkParser(b *testing.B) {
    p := NewLogParser()
    line := "Failed password for root from 1.2.3.4 port 51234 ssh2"
    for i := 0; i < b.N; i++ {
        p.Parse(line)
    }
}
```

Run with `go test -bench=.`.

### go test -race

Built-in data race detector:

```bash
go test -race ./...
```

If any goroutine reads/writes a shared variable without synchronization, the test **immediately fails** with a detailed race report.

### go vet

Static analysis built into Go:

```bash
go vet ./...
```

## Reference: Test Commands

```bash
# Run all tests
go test -count=1 ./...

# Run with race detection
go test -race ./...

# Run a specific test
go test -v -run TestParseFailedPassword ./internal/monitor/

# Run benchmarks
go test -bench=. ./internal/threat/

# Lint + vet
go vet ./...

# Build check
go build ./...

# Full check
make check
```

## Reference: Test File Location

```
internal/config/config_test.go       → tests for config
internal/pipeline/bus_test.go        → tests for event bus
internal/firewall/persist_test.go    → tests for block store
internal/engine/pipeline_test.go     → integration tests
```

Each `_test.go` file lives next to the code it tests. This is the Go convention.
