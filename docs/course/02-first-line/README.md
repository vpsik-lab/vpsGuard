# Lesson 02: First Line

**Parse `auth.log`, emit events — the first 100 lines of our agent.**

---

## What We Build

A log parser that reads SSH authentication logs and converts them into structured events.

By the end of this lesson, we have a program that:
1. Opens `/var/log/auth.log` (or journald output)
2. Watches for new lines (tail mode)
3. Parses each line with regex
4. Converts to a typed event object
5. Prints it to stdout

---

## The Code

### Step 1: The Parser

```go
type LogParser struct {
    sshFailed   *regexp.Regexp
    invalidUser *regexp.Regexp
}

func NewLogParser() *LogParser {
    return &LogParser{
        sshFailed:   regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)`),
        invalidUser: regexp.MustCompile(`Invalid user (\S+) from (\S+)`),
    }
}
```

Two regex patterns cover >95% of SSH attack log lines:
- `Failed password for root from 1.2.3.4 port 51234 ssh2`
- `Failed password for invalid user admin from 5.6.7.8 port 42356`
- `Invalid user nobody from 9.10.11.12`

### Step 2: Parsing a Line

```go
func (p *LogParser) Parse(line string) *ParsedEvent {
    if matches := p.sshFailed.FindStringSubmatch(line); len(matches) >= 4 {
        username := matches[1]
        ip := matches[2]
        port := matches[3]
        if strings.Contains(line, "invalid user") {
            return &ParsedEvent{Type: "invalid_user", IP: ip, Username: username, Port: port}
        }
        return &ParsedEvent{Type: "ssh_failed", IP: ip, Username: username, Port: port}
    }
    if matches := p.invalidUser.FindStringSubmatch(line); len(matches) >= 3 {
        return &ParsedEvent{Type: "invalid_user", IP: matches[2], Username: matches[1]}
    }
    return nil
}
```

**Why return `*ParsedEvent` instead of `(event, error)`?** Because a line that doesn't match isn't an error — it's just not an SSH attack. We return `nil` and the caller moves on.

### Step 3: Converting to Typed Events

We define event types so the rest of the system can switch on type:

```go
const (
    EventSSHFailedLogin = "ssh_failed_login"
    EventInvalidUser    = "invalid_user"
)

type BaseEvent struct {
    Type    string
    IP      string
    Time    time.Time
    Severity int
}
```

The parser's `ToEvent` method enriches the parsed data with metadata:

```go
func (p *LogParser) ToEvent(pe *ParsedEvent) Event {
    base := BaseEvent{
        Time:     time.Now(),
        IP:       pe.IP,
        Severity: 5,
    }
    switch pe.Type {
    case "ssh_failed":
        base.Type = EventSSHFailedLogin
        return SSH FailedLogin{
            BaseEvent: base,
            Username:  pe.Username,
        }
    case "invalid_user":
        base.Type = EventInvalidUser
        return InvalidUserEvent{
            BaseEvent: base,
            Username:  pe.Username,
        }
    }
}
```

### Step 4: Reading Live Logs

A simple file tailer that reads new lines since the last read:

```go
type FileTailer struct {
    file *os.File
    buf  []byte
}

func NewFileTailer(path string) (*FileTailer, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    f.Seek(0, 2)  // seek to end
    return &FileTailer{file: f, buf: make([]byte, 4096)}, nil
}

func (t *FileTailer) ReadNewLines() []string {
    n, err := t.file.Read(t.buf)
    if err != nil || n == 0 {
        return nil
    }
    return strings.Split(string(t.buf[:n]), "\n")
}
```

**Why `Seek(0, 2)`?** We start reading from the end of the file. We don't care about old log entries — only new ones.

### Step 5: Tying It Together

```go
func main() {
    parser := monitor.NewLogParser()
    tailer, _ := monitor.NewFileTailer("/var/log/auth.log")

    for {
        lines := tailer.ReadNewLines()
        for _, line := range lines {
            parsed := parser.Parse(line)
            if parsed != nil {
                event := parser.ToEvent(parsed)
                fmt.Printf("[%s] %s from %s (user: %s)\n",
                    event.EventType(), event.SourceIP(), event.Username())
            }
        }
        time.Sleep(1 * time.Second)
    }
}
```

---

## What We Learned

| Concept | Why It Matters |
|---------|---------------|
| **Regex parsing** | SSH logs are predictable — regex is the right tool for structured text |
| **Typed events** | Switch on type, not string matching — makes the system extensible |
| **File tailing** | Read-only, non-blocking, seek-to-end — minimal overhead |
| **Return nil for non-matches** | Not everything is an error — silence is information |

---

## Design Decisions

1. **Why regex and not a full parser?** The SSH log format is simple and stable. Regex is fast enough for thousands of lines per second. A full parser would be over-engineering.

2. **Why `[]byte` buffer instead of `bufio.Scanner`?** Scanner reads line-by-line which is simpler but allocates per line. A fixed buffer is faster and predictable — important when processing attack volume.

3. **Why separate `Parse` and `ToEvent`?** Separation of concerns: parsing extracts raw fields, conversion builds domain events. This lets us change the event format without touching the parser.

---

## What's Missing

This works for a demo. But in production:

- **What if the log file is rotated?** (We'll fix this later with inotify or polling)
- **What if we get 1000 events per second?** (We'll need a pipeline)
- **How do we score these events?** (Next lesson)
- **How do we block the attacker?** (After scoring)

This is the spiral: build the minimal thing, discover what's missing, go back and improve.

---

## Check Your Understanding

1. What two log message formats does the parser handle?
2. Why does `Parse` return `nil` for non-matching lines instead of an error?
3. What's the purpose of `Seek(0, 2)` in the file tailer?
4. Why separate `Parse` and `ToEvent` into two steps?

Ready for [Lesson 03](../03-event-bus/).
