# vpsGuard Agent

**Lightweight intelligent security agent for VPS protection.**  
Detects SSH brute-force, enriches with threat intelligence (AbuseIPDB, AlienVault OTX), and blocks attackers via nftables dynamic sets.

**Binary size**: 7.4 MB · **Idle RAM**: ~8 MB · **Block latency**: <100ms

---

## What is this?

vpsGuard **Agent** is the on-premise component that runs on your VPS.  
It monitors SSH logs, scores threat activity using a hybrid model, and blocks attackers.

The **Central Platform** (Phase B — in development) will provide a managed threat intelligence feed that agents can pull from.  
See [`docs/AGENT-API-CONTRACT.md`](docs/AGENT-API-CONTRACT.md) for the interface between them.

---

## Features

- **Real-time monitoring** — auth.log + systemd journal
- **Hybrid scoring** — Behavioral (30%) + AbuseIPDB (25%) + OTX (20%) + Temporal (10%) + Central Feed (15%)
- **Configurable thresholds** — Block, rate-limit, quarantine scores + behavior window/limit + temporal TTL all via `config.yaml`
- **nftables blocking** — Dynamic sets with auto-expire
- **Works offline** — Fully functional without internet
- **Telegram + Email alerts** — Rich HTML notifications
- **Self-protecting** — Watchdog, systemd sandbox, config integrity
- **One-command deploy** — Under 30 seconds

---

## Project Status

| Phase | Component | Status | Description |
|-------|-----------|--------|-------------|
| **A** | Agent (this repo) | ✅ **v0.2.0 — Stable** | On-premise SSH protection, hybrid scoring, nftables blocking |
| **B** | Central Platform | 🔜 In development | Managed threat intelligence feed, agent telemetry, geo-targeted blocking |
| **C** | Dashboard & Analytics | 📋 Planned | Web dashboard, multi-agent management, attack visualization |

The Agent is fully functional standalone. Phase B/C are **separate projects** — the Agent's behaviour is unaffected if they never ship.

---

## License & Editions

vpsGuard is **open-core**: the Agent is free and open-source under **GNU AGPLv3**.

| Feature | Free (AGPLv3) | Paid (Platform) |
|---------|---------------|-----------------|
| SSH brute-force detection | ✅ | ✅ |
| Local hybrid scoring | ✅ | ✅ |
| nftables auto-blocking | ✅ | ✅ |
| Threat intel (AbuseIPDB + OTX) | ✅ | ✅ |
| Telegram + Email alerts | ✅ | ✅ |
| Configurable thresholds | ✅ | ✅ |
| All source code available | ✅ (AGPLv3) | ❌ (proprietary) |
| **Central threat feed** | ❌ (requires Platform) | ✅ (submission-based) |
| Global IP reputation network | ❌ | ✅ |
| Multi-agent dashboard | ❌ | ✅ |
| Priority support | ❌ | ✅ |

**Zero telemetry**: the free Agent never phones home — no outbound connections unless you configure AbuseIPDB/OTX APIs.

---

## Quick Start

```bash
# 1. Build
git clone https://github.com/vpsik-lab/vpsGuard.git
cd vpsGuard
go build -ldflags="-s -w" -o vpsGuard ./cmd/vpsGuard/

# 2. Configure
cp config.yaml /etc/vpsGuard/config.yaml
# Edit: set API keys, notification tokens, etc.

# 3. Run
sudo ./vpsGuard -config /etc/vpsGuard/config.yaml
```

Or use the install script:
```bash
curl -sSL https://raw.githubusercontent.com/vpsik-lab/vpsGuard/main/deploy/install.sh | bash
```

For unattended installation:
```bash
curl -sSL https://raw.githubusercontent.com/vpsik-lab/vpsGuard/main/deploy/install.sh | bash -s -- --unattended
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
├── cmd/vpsGuard/main.go     Entry point
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
│   ├── vpsGuard.service     systemd unit
│   └── vpsGuard.logrotate   Log rotation config
└── docs/                     Documentation
```

---

## License

GNU AGPLv3
