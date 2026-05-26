# Lesson 10: Deploy

**From source code to production in one command.**

---

## The Problem

You've built an agent. Now you need to install it on a VPS. Manually:

```bash
go build -o vpsGuard ./cmd/vpsGuard
cp vpsGuard /usr/local/bin/
cp config.yaml /etc/vpsGuard/
cp deploy/vpsGuard.service /etc/systemd/system/
useradd -r -s /bin/false vpsGuard
mkdir -p /var/log/vpsGuard /var/cache/vpsGuard
systemctl daemon-reload
systemctl enable --now vpsGuard
```

That's 7 steps. And that's without hardening. **Nobody does this 7-step dance for every server.**

We need **one command**:

```bash
curl -sSL https://...install.sh | sudo bash -s -- --unattended
```

---

## The Install Script

`deploy/install.sh` — 563 lines of battle-tested shell.

### Structure

```
install.sh
├── Argument parsing (--dry-run, --unattended, --uninstall, ...)
├── Uninstall mode (full rollback)
├── OS detection (Ubuntu/Debian only)
├── System hardening (apt, SSH, UFW, sysctl)
├── Binary installation
│   ├── Option A: Download from GitHub Releases + SHA256 verify
│   └── Option B: Build from source (fallback)
├── User/service configuration
├── Startup
└── Success/failure output
```

### Binary Installation

**Option A — Download (preferred):**

```bash
# Download binary
wget -q "https://github.com/vpsik-lab/vpsGuard/releases/download/v0.3.0/vpsGuard-linux-amd64"
mv vpsGuard-linux-amd64 /usr/local/bin/vpsGuard
chmod +x /usr/local/bin/vpsGuard

# Verify checksum
wget -q "https://github.com/vpsik-lab/vpsGuard/releases/download/v0.3.0/checksums.txt"
sha256sum -c checksums.txt --ignore-missing
```

**Option B — Build from source (fallback):**

```bash
git clone https://github.com/vpsik-lab/vpsGuard.git
cd vpsGuard
go build -o /usr/local/bin/vpsGuard ./cmd/vpsGuard
```

### Uninstall Mode

Full rollback — every action is reversible:

```bash
install.sh --uninstall
```

It does:
1. Stop and disable the service
2. Remove binary, config, logs, cache
3. Remove systemd unit, logrotate config
4. Restore SSH config from `.vpsguard.bak`
5. Delete nftables table: `nft delete table inet vpsGuard`
6. Delete `vpsGuard` user
7. Disable UFW if we enabled it
8. Remove fail2ban jail

---

## The Hardening Script

`deploy/harden.sh` — 335 lines for locking down a VPS:

```
harden.sh
├── 1. SSH hardening
│     (PermitRootLogin no, PasswordAuthentication no, MaxAuthTries 3, ...)
├── 2. Firewall (UFW + nftables baseline)
├── 3. TLS/SSL (DH 4096, openssl.cnf)
├── 4. TCP BBR (congestion control)
├── 5. sysctl optimization
│     (fastopen, keepalive, conntrack, backlog, anti-DDoS)
├── 6. Docker secure defaults (conditional)
├── 7. Unattended upgrades (auto security updates)
├── 8. Auditd (sensitive file watch)
├── 9. AppArmor (enforce + vpsGuard profile)
└── 10. Process accounting (acct)
```

**Why separate scripts?** The install script sets up the agent. The hardening script locks down the VPS. They're independent — you can harden without vpsGuard, or install vpsGuard without hardening.

---

## The systemd Unit

```ini
[Unit]
Description=vpsGuard Security Agent
After=network.target nftables.service

[Service]
ExecStart=/usr/local/bin/vpsGuard -config /etc/vpsGuard/config.yaml
User=vpsGuard
Restart=always
RestartSec=5
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYSLOG
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log/vpsGuard /var/cache/vpsGuard
MemoryMax=256M

[Install]
WantedBy=multi-user.target
```

**`After=nftables.service`** — agent starts AFTER nftables is ready. This prevents a race where the agent tries to block before the firewall exists.

---

## The AppArmor Profile

```apparmor
/usr/local/bin/vpsGuard {
    /etc/vpsGuard/** r,
    /var/log/vpsGuard/** rw,
    /var/cache/vpsGuard/** rw,
    capability net_admin,
    capability syslog,
    /usr/bin/nft rix,
}
```

Installed automatically by the hardening script.

---

## The Logrotate Config

```logrotate
/var/log/vpsGuard/*.log
/var/log/vpsGuard/*.jsonl
{
    daily
    rotate 7
    compress
    copytruncate
    postrotate
        /usr/local/bin/vpsGuard -hash-chain /var/log/vpsGuard
    endscript
}
```

After rotating, it appends a hash chain entry — next lesson.

---

## What We Learned

| Concept | Why It Matters |
|---------|---------------|
| **One-command install** | The #1 factor in adoption — if it's hard to install, nobody uses it |
| **Full uninstall** | Users need to know they can reverse it — reduces fear |
| **Separate hardening** | Not everyone wants full lockdown — give choice |
| **SHA256 verification** | Trust the binary you downloaded |
| **Rollback SSH config** | Don't lock yourself out |

## Design Decisions

1. **Why binary download over source build?** Speed (2 seconds vs 2 minutes), deterministic (no build environment issues), verifiable (SHA256 checksums).

2. **Why `--unattended` as default for pipe?** When piping from curl, there's no TTY for prompts. Always assume non-interactive when piped.

3. **Why separate `install.sh` and `harden.sh`?** Different audiences: `install.sh` is for running the agent, `harden.sh` is for locking down the entire VPS. Ansible users may want hardening without the agent.

---

## Check Your Understanding

1. What happens if you run `install.sh --uninstall`?
2. Why `After=nftables.service` in the systemd unit?
3. What's the difference between Option A and Option B for binary install?
4. Why does `harden.sh` have 10 separate sections?
