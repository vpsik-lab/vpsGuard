# Lesson 06: Alerts

**When an attacker gets blocked, someone should know.**

---

## The Problem

The agent blocked `1.2.3.4`. Great. But you're asleep. Or you're at work. Or you have 50 servers.

You need **real-time notifications** when:
- An IP gets blocked (high score)
- An IP gets quarantined (medium score)
- Config tampering is detected
- The agent crashes or restarts

---

## The Channels

We support two notification channels out of the box:

```
Telegram ── best for instant mobile alerts
Email    ── best for archival and integrations
```

Both are optional — configure what you need.

---

## Telegram Notifier

```go
type TelegramNotifier struct {
    token  string   // bot token from @BotFather
    chatID string   // your chat ID
    client *http.Client
}
```

Sending a message is a single HTTP POST:

```go
func (n *TelegramNotifier) Send(ctx context.Context, text string) error {
    url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.token)
    msg := TelegramMessage{
        ChatID:    n.chatID,
        Text:      text,
        ParseMode: "HTML",  // bold, italic, code formatting
    }
    body, _ := json.Marshal(msg)

    req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
    resp, err := n.client.Do(req)
    // ... check response
}
```

**Why not a library?** The Telegram Bot API is a single endpoint. A dependency for 30 lines of HTTP is not worth it.

---

## Email Notifier

```go
type EmailNotifier struct {
    host, port, user, pass string
    from, to              string
}

func (n *EmailNotifier) Send(ctx context.Context, subject, body string) error {
    addr := fmt.Sprintf("%s:%d", n.host, n.port)
    msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
        n.from, n.to, subject, body)
    auth := smtp.PlainAuth("", n.user, n.pass, n.host)
    return smtp.SendMail(addr, auth, n.from, []string{n.to}, []byte(msg))
}
```

**Why PLAIN auth?** It's the most widely supported. If you need TLS, use port 587 with STARTTLS.

---

## The Notifier — Multi-Channel Dispatch

```go
type Notifier struct {
    telegram *TelegramNotifier  // nil if not configured
    email    *EmailNotifier     // nil if not configured
    cooldown map[string]time.Time  // per-IP cooldown
    mu       sync.Mutex
}
```

**Send with cooldown** — don't spam you about the same IP:

```go
func (n *Notifier) Send(ctx context.Context, evt Envelope, scores *ScoreResult, action Action) {
    ip := evt.SourceIP()
    if n.onCooldown(ip) {
        return  // skip — we already notified you
    }
    n.markSent(ip)

    text := n.formatAlert(evt, scores, action)
    if n.telegram != nil {
        n.telegram.Send(ctx, text)  // best-effort
    }
    if n.email != nil {
        n.email.Send(ctx, "vpsGuard Alert", text)
    }
}
```

**SendRaw** — for emergencies (bypasses cooldown):

```go
func (n *Notifier) SendRaw(ctx context.Context, message string) {
    // Used by watchdog tamper alerts — no cooldown, no filtering
    if n.telegram != nil {
        n.telegram.Send(ctx, message)
    }
    if n.email != nil {
        n.email.Send(ctx, "vpsGuard Security Alert", message)
    }
}
```

---

## The Alert Format

```
🚨 vpsGuard Alert

IP: 1.2.3.4
Event: SSH Failed Login
Action: BLOCKED (24h)
Score: 85 — critical

Sources: abuseipdb(90) + behavioral(80) + temporal(70)

Reason: score_exceeded_block_threshold
```

HTML-formatted for Telegram, plain-text for email.

---

## What We Learned

| Concept | Why It Matters |
|---------|---------------|
| **Multi-channel** | Telegram for speed, email for archive |
| **Per-IP cooldown** | Don't spam — 10 minute default |
| **SendRaw** | Emergency bypass for tamper alerts |
| **Nil notifiers** | Graceful degradation — missing config = silent skip |

## Design Decisions

1. **Why Telegram and not Slack/Discord?** Telegram has the simplest API (no OAuth, no webhooks setup). Also, bot tokens are portable across Telegram clients.

2. **Why cooldown and not dedup?** Dedup requires state (did I already notify about this IP?). Cooldown is stateless and simpler — "don't mention the same IP twice in 10 minutes."

3. **Why best-effort send?** Network failures happen. The agent shouldn't crash because Telegram is down. Log the error and move on.

---

## What's Next

Notifications work. But we discovered some cracks in our design:
- **No whitelist** — what if we block our own admin?
- **IPv4 only** — what about IPv6 attackers?
- **Arg injection risk** — is nftables command safe?

Time to **refine**. Next lesson.

---

## Check Your Understanding

1. Why does `Send` have both `telegram` and `email` nil-check?
2. What's the difference between `Send` and `SendRaw`?
3. How does the cooldown prevent notification spam?
4. Why not use a Slack webhook instead of Telegram?
