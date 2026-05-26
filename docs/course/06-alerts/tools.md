# Tools: Lesson 06

## New Tools

### net/http (stdlib)

Go's standard HTTP client. We use it for Telegram API calls.

```go
client := &http.Client{Timeout: 10 * time.Second}
```

**Why a custom client?** The default `http.Client` has no timeout. A stuck Telegram API call would block the notification goroutine forever.

### net/smtp (stdlib)

Go's standard SMTP client. We use `smtp.SendMail` — it handles the entire SMTP conversation (HELO, AUTH, MAIL FROM, RCPT TO, DATA).

### json.Marshal (stdlib)

Convert structs to JSON for API calls:

```go
msg := TelegramMessage{ChatID: chatID, Text: text, ParseMode: "HTML"}
body, _ := json.Marshal(msg)
```

### Telegram Bot API

Single REST endpoint: `https://api.telegram.org/bot<TOKEN>/sendMessage`

- **Method**: POST
- **Content-Type**: application/json
- **Body**: `{"chat_id": "...", "text": "...", "parse_mode": "HTML"}`
- **Rate limit**: ~30 messages/second per chat

## Reference: Alert Emojis

| Verdict | Emoji | Meaning |
|---------|-------|---------|
| Critical | 🚨 | Immediate attention needed |
| High | ⚠️ | High confidence malicious |
| Suspicious | 👀 | Watch but not block |
| Low | ℹ️ | For your information |
| Clean | ✅ | Everything normal |
