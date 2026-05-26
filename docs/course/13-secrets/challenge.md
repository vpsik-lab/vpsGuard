# Challenge: Secrets

---

## ⭐ Level 1: Set Up Systemd Environment

Configure the agent to use env vars via systemd:

```bash
# 1. Create override directory
sudo mkdir -p /etc/systemd/system/vpsGuard.service.d/

# 2. Create override
sudo cat > /etc/systemd/system/vpsGuard.service.d/env.conf << 'EOF'
[Service]
EnvironmentFile=/etc/vpsGuard/env
EOF

# 3. Create env file
sudo touch /etc/vpsGuard/env
sudo chmod 600 /etc/vpsGuard/env
# Add your keys
```

**Task:** Verify `systemctl show vpsGuard` shows the environment file.

---

## ⭐⭐ Level 2: Test the Override

Write a test for `LoadEnvOverrides`:

```go
func TestLoadEnvOverrides(t *testing.T) {
    os.Setenv("VPSGUARD_ABUSEIPDB_KEY", "test-key-123")
    defer os.Unsetenv("VPSGUARD_ABUSEIPDB_KEY")

    cfg := &config.Config{}
    cfg.SetDefaults()
    cfg.LoadEnvOverrides()

    assert.Equal(t, "test-key-123", cfg.Threat.AbuseIPDBKey)
}
```

**Hint:** Look at `internal/config/config_test.go`.

---

## ⭐⭐⭐ Level 3: Encrypted Secrets

Implement a `--gen-secret` flag that encrypts a secret using AES-256-GCM, and a `--with-secret <key>` flag that decrypts it at startup.

```bash
# Generate encrypted secret
vpsGuard --gen-secret "my-api-key"
# Output: encrypted:aes256gcm:base64data...

# Start with secret
vpsGuard --with-secret /etc/vpsGuard/secret.key
```

**Hint:** Use Go's `crypto/aes` and `crypto/cipher` stdlib packages.

---

## Solution

<details>
<summary>Click for Level 2 test solution</summary>

```go
func TestLoadEnvOverrides(t *testing.T) {
    os.Setenv("VPSGUARD_ABUSEIPDB_KEY", "env-key")
    os.Setenv("VPSGUARD_TELEGRAM_TOKEN", "env-token")
    defer os.Unsetenv("VPSGUARD_ABUSEIPDB_KEY")
    defer os.Unsetenv("VPSGUARD_TELEGRAM_TOKEN")

    cfg := &config.Config{}
    cfg.SetDefaults()
    cfg.LoadEnvOverrides()

    assert.Equal(t, "env-key", cfg.Threat.AbuseIPDBKey)
    assert.Equal(t, "env-token", cfg.Notify.TelegramToken)

    // Fields NOT set via env should keep defaults
    assert.Equal(t, "", cfg.Notify.SMTPPass)
}
```

Check `internal/config/config_test.go` for the actual test.
</details>
