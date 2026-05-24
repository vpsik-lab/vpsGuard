# VPS-Guard Agent — Deployment Guide

**Version**: 0.2.0  
**OS**: Ubuntu 20.04+ / Debian 11+

---

## 1. Quick Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/vps-guard/vps-guard/main/deploy/install.sh | bash
```

Or unattended:
```bash
curl -sSL https://raw.githubusercontent.com/vps-guard/vps-guard/main/deploy/install.sh | bash -s -- --unattended
```

### Install Script Options

| Flag | Description |
|------|-------------|
| `--unattended` | Skip all prompts, use defaults |
| `--no-hardening` | Skip SSH/firewall/kernel hardening |
| `--ssh-port <n>` | Custom SSH port for firewall rules |
| `--dry-run` | Print what would be done without executing |

This script:
1. Detects OS and architecture
2. Downloads the pre-built binary OR builds from source
3. Creates `/etc/vps-guard/config.yaml` with defaults
4. Installs systemd service
5. Configures logrotate
6. Starts the agent

---

## 2. Manual Install

### 2.1 Prerequisites

```bash
sudo apt update && sudo apt install -y golang nftables git
```

### 2.2 Build from Source

```bash
git clone https://github.com/vps-guard/vps-guard.git
cd vps-guard
go build -ldflags="-s -w" -o vps-guard ./cmd/vps-guard/
sudo mv vps-guard /usr/local/bin/
```

### 2.3 Create Config

```bash
sudo mkdir -p /etc/vps-guard
sudo cp config.yaml /etc/vps-guard/
sudo chown root:root /etc/vps-guard/config.yaml
sudo chmod 600 /etc/vps-guard/config.yaml
```

### 2.4 Install systemd Service

```bash
sudo cp deploy/vps-guard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable vps-guard
sudo systemctl start vps-guard
```

### 2.5 Install Logrotate

```bash
sudo cp deploy/vps-guard.logrotate /etc/logrotate.d/vps-guard
```

---

## 3. Configuration Reference

Full reference: see [`config.yaml`](../config.yaml) for all options.

### 3.1 Minimal Config

```yaml
agent_mode: hybrid
threat:
  abuseipdb_key: ""
  alienvault_key: ""
```

Agent runs in local-only mode if no API keys are set.

### 3.2 Full Config

```yaml
log_dir: /var/log/vps-guard
cache_dir: /var/cache/vps-guard
agent_mode: hybrid              # local | hybrid | central_only

monitor:
  interval_seconds: 5
  journal: true
  log_paths:
    - /var/log/auth.log

threat:
  abuseipdb_key: "your-key"
  alienvault_key: "your-key"
  cache_ttl_hours: 24
  rate_limit_per_min: 10

scoring:
  block_threshold: 60
  quarantine_score: 30
  quarantine_minutes: 15
  abuseipdb_weight: 0.25
  alienvault_weight: 0.20
  behavior_weight: 0.30
  temporal_weight: 0.10
  central_weight: 0.15
  central_block_threshold: 80
  central_quar_threshold: 50

firewall:
  table: vps_guard
  set_name: blacklist
  default_block_hours: 24

notify:
  telegram_token: ""
  telegram_chat_id: ""
  email_smtp_host: ""
  email_smtp_port: 587
  email_username: ""
  email_password: ""
  email_from: ""
  email_to: ""

central_feed:
  enabled: false
  api_url: ""
  api_token: ""
  poll_interval_seconds: 60
  min_confidence: 50

bootstrap:
  enabled: false
```

### 3.3 Agent Modes

| Mode | Local Intel | Central Feed | Use Case |
|------|-------------|--------------|----------|
| `local` | ✅ | ❌ | Fully offline VPS |
| `hybrid` | ✅ | ✅ | Default — best protection |
| `central_only` | ❌ | ✅ | Trusts central platform fully |

---

## 4. Systemd Service Management

```bash
# Status
systemctl status vps-guard

# Logs
journalctl -u vps-guard -f

# Restart
systemctl restart vps-guard

# Stop
systemctl stop vps-guard
```

### 4.1 Service Sandbox

The service runs with strict sandboxing:

```
NoNewPrivileges=yes       # No privilege escalation
ProtectSystem=strict      # Read-only root filesystem
ProtectHome=yes           # No home directory access
PrivateTmp=yes            # Isolated /tmp
MemoryMax=256M            # Memory limit
CPUQuota=50%              # CPU limit
CAP_NET_ADMIN             # nftables operations
CAP_SYSLOG                # Journal access only
```

---

## 5. Logging

- **Console**: stdout (JSON lines)
- **File**: `/var/log/vps-guard/agent.log`
- **Rotation**: daily, 7 day retention, compressed

Manual log view:
```bash
tail -f /var/log/vps-guard/agent.log | jq
```

---

## 6. Monitoring Health

```bash
# Check if agent is running
systemctl is-active vps-guard

# Check nftables set
sudo nft list set inet vps_guard blacklist

# Check agent log for actions
grep '"action":"block"' /var/log/vps-guard/agent.log
```

---

## 7. Upgrading

```bash
# Re-run the install script (upgrades binary, preserves config)
curl -sSL https://raw.githubusercontent.com/vps-guard/vps-guard/main/deploy/install.sh | bash
```

---

## 8. Uninstalling

```bash
sudo systemctl stop vps-guard
sudo systemctl disable vps-guard
sudo rm /etc/systemd/system/vps-guard.service
sudo rm /usr/local/bin/vps-guard
sudo rm -rf /etc/vps-guard
sudo rm -rf /var/log/vps-guard
sudo rm /etc/logrotate.d/vps-guard
```

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Service fails to start | Config validation error | Run `vps-guard -config /etc/vps-guard/config.yaml` to see error |
| No blocking | nftables table missing | `sudo nft create table inet vps_guard` |
| High memory | Event backlog | Check `journal` is not flooding; increase capacity |
| "Permission denied" | Missing capabilities | `setcap cap_net_admin,cap_syslog+eip /usr/local/bin/vps-guard` |
