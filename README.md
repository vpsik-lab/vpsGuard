# VPS-Guard Agent

**Lightweight intelligent security agent for VPS protection.**  
Detects SSH brute-force, enriches with threat intelligence (AbuseIPDB, AlienVault OTX), and blocks attackers via nftables dynamic sets.

**Binary size**: 7.4 MB · **Idle RAM**: ~8 MB · **Block latency**: <100ms

---

## What is this?

VPS-Guard **Agent** is the on-premise component that runs on your VPS.  
It monitors SSH logs, scores threat activity using a hybrid model, and blocks attackers.

The **Central Platform** (Phase B — separate project) will provide a managed threat intelligence feed that agents can pull from.  
See [`docs/AGENT-API-CONTRACT.md`](docs/AGENT-API-CONTRACT.md) for the interface between them.

---

## Features

- **Real-time monitoring** — auth.log + systemd journal
- **Hybrid scoring** — Behavioral (30%) + AbuseIPDB (25%) + OTX (20%) + Temporal (10%) + Central Feed (15%)
- **nftables blocking** — Dynamic sets with auto-expire
- **Works offline** — Fully functional without internet
- **Telegram + Email alerts** — Rich HTML notifications
- **Self-protecting** — Watchdog, systemd sandbox, config integrity
- **One-command deploy** — Under 30 seconds

---

## Quick Start

```bash
# 1. Build
git clone https://github.com/vps-guard/vps-guard.git
cd vps-guard
go build -ldflags="-s -w" -o vps-guard ./cmd/vps-guard/

# 2. Configure
cp config.yaml /etc/vps-guard/config.yaml
# Edit: set API keys, notification tokens, etc.

# 3. Run
sudo ./vps-guard -config /etc/vps-guard/config.yaml
```

Or use the install script:
```bash
curl -sSL https://raw.githubusercontent.com/vps-guard/vps-guard/main/deploy/install.sh | bash
```

For unattended installation:
```bash
curl -sSL https://raw.githubusercontent.com/vps-guard/vps-guard/main/deploy/install.sh | bash -s -- --unattended
```

See [`docs/AGENT-DEPLOYMENT.md`](docs/AGENT-DEPLOYMENT.md) for full installation options.

---

## Documentation

| Doc | Description |
|-----|-------------|
| [`AGENT-ARCHITECTURE.md`](docs/AGENT-ARCHITECTURE.md) | Internal architecture, components, event flow |
| [`AGENT-SCORING.md`](docs/AGENT-SCORING.md) | Scoring formula, thresholds, edge cases |
| [`AGENT-DEPLOYMENT.md`](docs/AGENT-DEPLOYMENT.md) | Install, configure, manage, troubleshoot |
| [`AGENT-API-CONTRACT.md`](docs/AGENT-API-CONTRACT.md) | Contract between Agent and Central Platform |
| [`THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Threat model, trust boundaries, attack scenarios |
| [`RFC-0001-event-model.md`](docs/RFC-0001-event-model.md) | Event schema specification |

---

## Requirements

- Ubuntu 20.04+ or Debian 11+
- systemd
- nftables

---

## Project Structure

```
├── cmd/vps-guard/main.go     Entry point
├── internal/
│   ├── api/                  Central feed pull client
│   ├── bootstrap/            System hardening
│   ├── config/               YAML config + validation
│   ├── engine/               Scorer, decision, memory
│   ├── firewall/             nftables manager
│   ├── monitor/              Log tailing, parsing, behavioral analysis
│   ├── notify/               Telegram + Email
│   ├── pipeline/             Event bus + event types
│   ├── rules/                YAML rules engine
│   ├── selfprotect/          Watchdog + health
│   └── threat/               AbuseIPDB, OTX, cache
├── deploy/
│   ├── install.sh            One-command installer
│   ├── vps-guard.service     systemd unit
│   └── vps-guard.logrotate   Log rotation config
└── docs/                     Documentation
```

---

## License

MIT
