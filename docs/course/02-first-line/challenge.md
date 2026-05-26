# Challenge: First Line

**Difficulty levels — pick your path.**

---

## ⭐ Level 1: Test the Parser

```bash
git checkout lesson-02-first-line
```

Write a Go test that feeds these log lines to the parser and verifies the output:

```
Failed password for root from 192.168.1.1 port 51234 ssh2
Failed password for invalid user admin from 10.0.0.1 port 42356 ssh2
Invalid user nobody from 172.16.0.1
```

Expected output:
- `192.168.1.1` → type `ssh_failed`, user `root`
- `10.0.0.1` → type `invalid_user`, user `admin`
- `172.16.0.1` → type `invalid_user`, user `nobody`

**Hint:** Use Go's `testing` package: `go test -v -run TestParser`.

---

## ⭐⭐ Level 2: Add Port Scan Detection

SSH logs also show connection attempts that fail before authentication:

```
Mar 13 01:23:45 vps sshd[5678]: Connection closed by authenticating user root 1.2.3.4 port 54321 [preauth]
```

Extend the parser to detect this as a `port_scan` event type.

**Hint:** Add a third regex pattern to `LogParser`. Match `Connection closed by authenticating user`.

---

## ⭐⭐⭐ Level 3: Build a Live Monitor

Write a program that:
1. Tails `/var/log/auth.log`
2. Parses every new line
3. Counts unique attacking IPs per minute
4. Prints a summary every 60 seconds

```bash
[60s report] 15 unique IPs, top attacker: 1.2.3.4 (23 attempts)
```

**Hint:** Use a `map[string]int` with a 60-second ticker. Don't use external packages — just stdlib.

---

## Solution

<details>
<summary>Click for Level 1 test solution</summary>

```go
func TestParserParse(t *testing.T) {
    p := NewLogParser()
    tests := []struct {
        line     string
        expected *ParsedEvent
    }{
        {
            line: "Failed password for root from 192.168.1.1 port 51234 ssh2",
            expected: &ParsedEvent{Type: "ssh_failed", IP: "192.168.1.1", Username: "root", Port: "51234"},
        },
        {
            line: "Failed password for invalid user admin from 10.0.0.1 port 42356 ssh2",
            expected: &ParsedEvent{Type: "invalid_user", IP: "10.0.0.1", Username: "admin", Port: "42356"},
        },
        {
            line: "Invalid user nobody from 172.16.0.1",
            expected: &ParsedEvent{Type: "invalid_user", IP: "172.16.0.1", Username: "nobody"},
        },
    }
    for _, tt := range tests {
        got := p.Parse(tt.line)
        if got.Type != tt.expected.Type || got.IP != tt.expected.IP {
            t.Errorf("Parse(%q) = %+v, want %+v", tt.line, got, tt.expected)
        }
    }
}
```

Check the actual test file at `internal/monitor/parser_test.go` for the real test suite.
</details>
