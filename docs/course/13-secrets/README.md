# Lesson 13: Secrets

**Don't put API keys in your config file.**

---

## The Problem

Look at our config file:

```yaml
threat:
  abuseipdb_key: "abc123..."      # ← API key in plain text
  alienvault_key: "def456..."

notify:
  telegram_token: "bot123..."     # ← Bot token in plain text
  smtp_pass: "smtp-password"      # ← Email password in plain text
```

**Why this is bad:**
1. **Git commit** — someone pushes config.yaml to GitHub → keys leaked
2. **File permissions** — anyone who reads `/etc/vpsGuard/config.yaml` gets your keys
3. **Backups** — config file in backup → keys in backup
4. **Shared servers** — other users on the same VPS can read config

---

## The Solution: Environment Variables

The agent never stores secrets in the config file. Instead, it reads them from environment variables:

```bash
export VPSGUARD_ABUSEIPDB_KEY="abc123..."
export VPSGUARD_TELEGRAM_TOKEN="bot123..."
sudo -E vpsGuard -config /etc/vpsGuard/config.yaml
```

Config file has **empty placeholders**:

```yaml
threat:
  abuseipdb_key: ""      # ← set via VPSGUARD_ABUSEIPDB_KEY
  alienvault_key: ""     # ← set via VPSGUARD_ALIENVAULT_KEY

notify:
  telegram_token: ""     # ← set via VPSGUARD_TELEGRAM_TOKEN
  smtp_pass: ""          # ← set via VPSGUARD_SMTP_PASS
```

---

## How It Works

```go
func (c *Config) LoadEnvOverrides() {
    if v := os.Getenv("VPSGUARD_ABUSEIPDB_KEY"); v != "" {
        c.Threat.AbuseIPDBKey = v
    }
    if v := os.Getenv("VPSGUARD_ALIENVAULT_KEY"); v != "" {
        c.Threat.AlienVaultKey = v
    }
    if v := os.Getenv("VPSGUARD_TELEGRAM_TOKEN"); v != "" {
        c.Notify.TelegramToken = v
    }
    if v := os.Getenv("VPSGUARD_TELEGRAM_CHAT_ID"); v != "" {
        c.Notify.TelegramChatID = v
    }
    if v := os.Getenv("VPSGUARD_SMTP_PASS"); v != "" {
        c.Notify.SMTPPass = v
    }
    if v := os.Getenv("VPSGUARD_CENTRAL_TOKEN"); v != "" {
        c.CentralFeed.APIToken = v
    }
}
```

**Load order:**

```
1. config.yaml → SetDefaults() → fill from file
2. LoadEnvOverrides() → override with env vars if set
3. Validate() → check everything is consistent
```

**Env always wins.** If both config.yaml and env var specify a value, the env var takes precedence.

---

## Setting Secrets Securely

### Option 1: systemd EnvironmentFile

```ini
# /etc/systemd/system/vpsGuard.service.d/override.conf
[Service]
EnvironmentFile=/etc/vpsGuard/env
```

```bash
# /etc/vpsGuard/env — permissions 600, owned by root
VPSGUARD_ABUSEIPDB_KEY=abc123...
VPSGUARD_TELEGRAM_TOKEN=bot123...
```

Now `systemctl restart vpsGuard` picks up the env vars automatically.

### Option 2: systemctl set-environment

```bash
sudo systemctl set-environment VPSGUARD_ABUSEIPDB_KEY=abc123...
sudo systemctl restart vpsGuard
```

### Option 3: Export in profile (less secure)

Only for testing:

```bash
export VPSGUARD_ABUSEIPDB_KEY="abc123..."
vpsGuard
```

---

## What About Central Feed Token?

Same pattern:

```yaml
central_feed:
  api_token: ""   # ← set via VPSGUARD_CENTRAL_TOKEN
```

Even the central platform token, which connects to the paid service, never touches disk as plain text.

---

## What We Learned

| Concept | Why It Matters |
|---------|---------------|
| **Env vars over file** | Secrets never touch disk → not in backups, not in git |
| **VPSGUARD_ prefix** | Namespaced — won't clash with other apps |
| **Empty in config.yaml** | File can be committed to git safely |
| **Override, not replace** | Works with existing configs — only overrides if set |

## Design Decisions

1. **Why env vars and not a secrets file?** Env vars are the standard for 12-factor apps. They're available at process start, inherited by child processes, and never written to disk.

2. **Why not a vault/secret manager?** HashiCorp Vault, AWS Secrets Manager, etc. are over-engineered for a single-node agent. env vars are simple and secure enough for this threat model.

3. **Why empty strings in config.yaml?** Explicit is better than implicit. An empty string means "I know this needs a value, but I'm providing it via env." If the validation sees an empty key, it errors — no silent failures.

---

## What's Next

The agent is complete. One final topic: **how we test** everything.

---

## Check Your Understanding

1. What's the load order for config values (file vs env var)?
2. How do you pass env vars to a systemd service?
3. Why is an empty string better than a default value for secrets?
4. Can you mix some secrets in config and some in env vars?
