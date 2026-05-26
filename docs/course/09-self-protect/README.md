# Lesson 09: Self-Protect

**Who guards the guards?**

---

## The Problem

Our agent blocks attackers. But what if an attacker attacks the agent itself?

- **Config tampering** — modify `config.yaml` to disable blocking
- **Binary replacement** — replace `vpsGuard` with a harmless binary
- **Memory exhaustion** — flood the agent with events until it OOMs
- **Process killing** — `kill -9` the agent, attacks go unblocked

The agent must protect itself at multiple layers:
1. **systemd** — operating system level
2. **AppArmor** — mandatory access control
3. **Watchdog** — self-monitoring from within
4. **Minimal privileges** — least privilege principle

---

## Layer 1: systemd Sandbox

The systemd unit file is our first line of defense:

```ini
[Service]
User=vpsGuard                    # NOT root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYSLOG   # only 2 caps
NoNewPrivileges=yes              # can't escalate
ProtectSystem=strict             # read-only filesystem
ReadWritePaths=/var/log/vpsGuard /var/cache/vpsGuard  # except logs/cache
ProtectHome=yes                  # can't see /home
PrivateTmp=yes                   # isolated /tmp
MemoryMax=256M                   # can't OOM the server
CPUQuota=50%                     # can't hog CPU
TasksMax=50                      # can't fork-bomb
LimitNOFILE=1024                 # can't open too many files
```

Each directive is a deliberate security decision:

| Directive | Prevents |
|-----------|----------|
| `User=vpsGuard` | Root-level access — if the agent is compromised, attacker gets a non-root user |
| `CapabilityBoundingSet` | Only `CAP_NET_ADMIN` (nftables) and `CAP_SYSLOG` (read journal) — nothing else |
| `NoNewPrivileges` | Can't `sudo`, can't `su`, can't escalate via setuid binaries |
| `ProtectSystem=strict` | Can't modify `/usr`, `/etc`, `/opt` — even if exploited |
| `MemoryMax=256M` | Can't allocate all RAM — attack of 100k events/sec won't crash the server |

---

## Layer 2: AppArmor

Mandatory Access Control (MAC) — even if the agent runs as root, AppArmor restricts what it can do:

```
/usr/local/bin/vpsGuard {
    /etc/vpsGuard/** r,              # read config
    /var/log/vpsGuard/** rw,         # write logs
    /var/cache/vpsGuard/** rw,       # write cache
    capability net_admin,             # nftables
    capability syslog,                # journal
    /usr/bin/nft rix,                 # execute nft (read + inherit)
}
```

**What this prevents:**
- If the agent is exploited, it can't write to `/etc/passwd` (no shadow file access)
- It can only execute `nft`, not `bash` or `python`
- It can't read SSH private keys or database credentials

---

## Layer 3: Watchdog

Internal self-monitoring:

```go
type Watchdog struct {
    configPath       string
    expectedChecksum string
    tamperWarnings   int
    onTamperFn       func(message string)
}
```

The watchdog runs in a goroutine and periodically checks:
1. **Config file exists** — hasn't been deleted
2. **Config checksum matches** — hasn't been modified

```go
func (w *Watchdog) healthCheck() {
    h := sha256.New()
    data, _ := os.ReadFile(w.configPath)
    h.Write(data)
    got := hex.EncodeToString(h.Sum(nil))

    if got != w.expectedChecksum {
        w.tamperWarnings++
        msg := fmt.Sprintf("Config checksum mismatch on %s", w.configPath)
        logger.Error("config file checksum mismatch — possible tamper")

        if w.onTamperFn != nil {
            w.onTamperFn(msg)  // fires Telegram alert immediately
        }
    }
}
```

**On tamper detection**, the watchdog calls `SendRaw()` — an emergency notification that bypasses all cooldowns:

```go
watchdog.OnTamper(func(msg string) {
    notifier.SendRaw(ctx, "🚨 vpsGuard TAMPER ALERT\n"+msg)
})
```

---

## The Defense in Depth Stack

```
                    ┌──────────────────────┐
                    │   Attacker wants to   │
                    │  disable the agent    │
                    └──────────┬───────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
    Modify config.yaml    Kill the process    Replace the binary
          │                    │                    │
          ▼                    ▼                    ▼
    Watchdog detects     systemd restarts      AppArmor blocks
    checksum mismatch    it automatically      execution of
    + fires alert       (Restart=always)      unsigned binaries
          │                    │                    │
          └────────────────────┼────────────────────┘
                               ▼
                    Agent continues running
                    + admin is notified
```

---

## What We Learned

| Layer | Mechanism | What It Protects |
|-------|-----------|-----------------|
| **systemd** | Sandbox directives | OS-level confinement |
| **AppArmor** | MAC profile | Filesystem + capability restriction |
| **Watchdog** | Config checksum | Configuration integrity |
| **Minimal user** | `User=vpsGuard` | Privilege escalation |

## Design Decisions

1. **Why systemd sandbox and not a container?** systemd sandbox is lighter than Docker, built into every Linux distro, and sufficient for our threat model. Docker adds network complexity for no benefit here.

2. **Why SHA256 for config checksum?** Fast, available in Go stdlib, good enough for tamper detection. Not a cryptographic authentication — we're not signing the config, just detecting unauthorized changes.

3. **Why `SendRaw` for tamper alerts?** Tamper is an emergency. Normal alerts have cooldowns (don't spam about the same IP). `SendRaw` bypasses all cooldowns.

---

## What's Next

The agent is hardened. Now we need to **deploy it**. Next lesson: install scripts, hardening, and uninstall.

---

## Check Your Understanding

1. What's the difference between `ProtectSystem=strict` and `ProtectHome=yes`?
2. Why only 2 capabilities for the agent?
3. What happens when the watchdog detects tampering?
4. Can the agent write to `/etc/passwd`? Why or why not?
