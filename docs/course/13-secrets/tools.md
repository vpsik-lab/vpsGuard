# Tools: Lesson 13

## New Tools

### os.Getenv (stdlib)

Read environment variables:

```go
token := os.Getenv("VPSGUARD_TELEGRAM_TOKEN")
if token == "" {
    // not set — fall back to config value
}
```

**Why not os.LookupEnv?** Both work. `Getenv` is simpler for the "use default if empty" pattern.

### systemd EnvironmentFile

Systemd services can load env vars from a file:

```ini
[Service]
EnvironmentFile=/etc/vpsGuard/env
```

File format:
```bash
# /etc/vpsGuard/env
KEY=VALUE
```

The file should be `chmod 600` (root-only readable).

## 12-Factor App Config

The 12-factor app methodology says: **store config in the environment**.

> "The twelve-factor app stores config in environment variables (often shortened to env vars or env). Env vars are easy to change between deploys without changing any code; unlike config files, there is little chance of them being checked into the code repository accidentally."

## Reference: Supported Env Vars

| Variable | Config Field |
|----------|-------------|
| `VPSGUARD_ABUSEIPDB_KEY` | `threat.abuseipdb_key` |
| `VPSGUARD_ALIENVAULT_KEY` | `threat.alienvault_key` |
| `VPSGUARD_TELEGRAM_TOKEN` | `notify.telegram_token` |
| `VPSGUARD_TELEGRAM_CHAT_ID` | `notify.telegram_chat_id` |
| `VPSGUARD_SMTP_PASS` | `notify.smtp_pass` |
| `VPSGUARD_CENTRAL_TOKEN` | `central_feed.api_token` |
