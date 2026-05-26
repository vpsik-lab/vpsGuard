# Tools: Lesson 02

## New Tools

### regexp (stdlib)

Go's `regexp` package uses RE2 syntax (not PCRE). Key differences from Perl regex:
- No backreferences (prevents catastrophic backtracking)
- Guaranteed linear time execution
- `MustCompile` panics on invalid pattern — use for patterns that must never fail at runtime

**Why not a hand-written parser?** SSH log format is stable and predictable. Regex is the right balance of readability and performance.

### os.File (stdlib)

`os.Open`, `File.Seek`, `File.Read` — the simplest possible file I/O.

**Why not a library?** For reading a single log file, the standard library is all we need. Libraries like `tail` or `fsnotify` add complexity for marginal benefit at this stage.

### time.Sleep polling

Every 1 second we check for new lines.

**Why not inotify?** inotify is more efficient but platform-specific and more complex. Polling at 1s intervals is good enough for v0.1. We'll optimize later (spiral!).

## Reference: SSH Log Formats

```
Failed password for root from 1.2.3.4 port 51234 ssh2
Failed password for invalid user admin from 5.6.7.8 port 42356 ssh2
Invalid user nobody from 9.10.11.12
```

All three are handled by our two regex patterns.
