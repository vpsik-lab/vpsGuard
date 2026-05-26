# Challenge: Alerts

---

## ⭐ Level 1: Format an Alert

Given this data, write the HTML alert message:

```
IP: 5.6.7.8
Score: 92 (critical)
Event: Invalid user "admin" from 5.6.7.8
Action: Blocked for 24h
Sources: abuseipdb(95), behavioral(85), temporal(70)
```

**Hint:** Look at `formatAlert()` in `internal/notify/notifier.go`.

---

## ⭐⭐ Level 2: Add a Slack Webhook

Add a third notification channel: Slack webhook.

1. Add `slack_webhook_url` to `NotifyConfig`
2. Create `SlackNotifier` struct
3. Add it to the `Notifier`
4. Test with `curl -X POST -H 'Content-type: application/json' --data '{"text":"Hello"}' <webhook_url>`

**Hint:** Slack webhooks accept `{"text": "message"}` at a POST URL.

---

## ⭐⭐⭐ Level 3: Rate-Limit Notifications Globally

Add a global rate limiter: maximum 10 notifications per minute across all IPs.

**Hint:** Use a token bucket pattern: a goroutine with a ticker refills tokens every 6 seconds. `Send` consumes a token.

---

## Solution

<details>
<summary>Click for Level 1 solution</summary>

```html
🚨 vpsGuard Alert

<b>IP:</b> 5.6.7.8
<b>Event:</b> Invalid user "admin" from 5.6.7.8
<b>Action:</b> BLOCKED (24h)
<b>Score:</b> 92 — critical

<b>Sources:</b>
  abuseipdb: 95
  behavioral: 85
  temporal: 70

<b>Reason:</b> score_exceeded_block_threshold
```

See `internal/notify/notifier.go:formatAlert()` for the full implementation.
</details>
