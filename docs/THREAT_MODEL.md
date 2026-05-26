# vpsGuard Agent — Threat Model

**Version**: 0.3.0  
**Scope**: Agent only (Central Platform has its own threat model)

> This document describes the threat model for the vpsGuard **Agent**.  
> The Central Platform (Phase B) is out of scope — see [`AGENT-API-CONTRACT.md`](AGENT-API-CONTRACT.md) for trust boundaries between them.

---

## Assets Protected

1. **SSH service** — primary attack vector
2. **System integrity** — preventing unauthorised access
3. **Network services** (HTTP, SMTP, MySQL, etc.)
4. **User data and credentials**

---

## Trust Boundaries

```
┌─────────────────────┐      ┌──────────────────────────────┐
│  Untrusted Network  │      │  Agent (Partially Trusted)    │
│  (Internet)         │      │                              │
│                     │      │  Capabilities:               │
│  SSH Brute-force    │─────►│  • CAP_NET_ADMIN             │
│  Port Scanners      │      │  • CAP_SYSLOG                │
│  Botnets            │      │  • No root (systemd drop-in) │
│                     │      │                              │
│                     │      │  Data at rest:               │
│                     │      │  • Config: root:0600         │
│                     │      │  • Cache: agent-owned        │
│                     │      │  • Logs: agent-readable      │
└─────────────────────┘      └──────────┬───────────────────┘
                                        │
                                        │ HTTPS + Bearer
                                        ▼
                             ┌─────────────────────┐
                             │  Central Platform   │
                             │  (External, 15%     │
                             │   weight, never     │
                             │   blindly trusted)  │
                             └─────────────────────┘
```

### Agent-Level Trust
- Agent runs with minimal Linux capabilities (CAP_NET_ADMIN + CAP_SYSLOG)
- Config file is root-owned with `0600` permissions
- API keys stored only in config file (future: encrypted vault)
- SQLite cache is agent-owned, non-root readable
- Agent does **NOT** require full root access

### Central Feed Trust
- Feed is fetched via HTTPS with Bearer token auth
- Agent **never** blindly trusts central feed scores
- Central score is weighted **15%** against local scores **85%**
- Only IPs with confidence ≥ `min_confidence` are processed
- Confidence tiers: ≥90 block, 60–89 quarantine, <60 score boost only

---

## Threat Actors

| Actor | Capability | Target | Frequency |
|-------|-----------|--------|-----------|
| Script Kiddie | Low — automated tools | Any VPS | Very High |
| Botnet | Medium — distributed scanning | Mass SSH | High |
| Scanner Farms | Low — internet-wide scanning | All IPs | Continuous |
| Targeted Attacker | Medium-High | Specific orgs | Low |
| APT | High | Strategic targets | Very Low |

---

## Attack Scenarios

### 1. SSH Brute Force
- **Detection**: Failed password attempts in auth.log/journald
- **Response**: Behavioral scoring → nftables block with timeout
- **Mitigation**: Fail2ban (first line) + vpsGuard (intelligent blocking)

### 2. Agent Stopped by Attacker
- **Detection**: systemd auto-restart (RestartSec=5)
- **Response**: Watchdog monitors health
- **Mitigation**: systemd + watchdog + immutable service file

### 3. Config Tampered
- **Detection**: File permissions prevent non-root writes
- **Response**: Watchdog checks file integrity
- **Mitigation**: 0600 permissions, ProtectSystem=strict

### 4. False Positive from Central Feed
- **Detection**: Agent's hybrid scoring reduces central weight
- **Response**: Temporal quarantine (15m) not permanent block
- **Mitigation**: Central weight is only 15% of final score

### 5. API Key Leak
- **Detection**: Keys stored root-only readable
- **Response**: Key rotation
- **Mitigation**: Future: encrypted config vault

### 6. Log Flood (DoS)
- **Detection**: Bounded channels (1000 event capacity)
- **Response**: Events dropped at capacity, no memory explosion
- **Mitigation**: Bounded queues + non-blocking publish

### 7. Central Platform Compromise
- **Risk**: Platform sends malicious threat data
- **Mitigation**: 15% weight limit, local behavioural override, confidence tiers
- **Outcome**: Even with 100% malicious feed score, agent still requires local signal for block

---

## Scoring Confidence Tiers

| Confidence | Source | Agent Action |
|-----------|--------|-------------|
| 90–100 | Central Feed + Local verification | Block 24h |
| 60–89 | Central Feed Only | Quarantine + verify |
| 30–59 | Behavioral Only | Monitor + track |
| < 30 | Low confidence | Ignore |

---

## Defence in Depth

```
Layer 1: UFW (default deny incoming)
Layer 2: Fail2ban (SSH rate limiting)
Layer 3: nftables dynamic sets (vpsGuard intelligent blocking)
Layer 4: Kernel hardening (sysctl)
Layer 5: SSH hardening (no root, no password)
Layer 6: vpsGuard hybrid scoring (local + central, 85/15 split)
Layer 7: Systemd sandboxing (NoNewPrivileges, ProtectSystem)
```

---

## Agent vs Platform Threat Boundaries

| Aspect | Agent (this repo) | Central Platform (separate) |
|--------|------------------|----------------------------|
| Attack surface | SSH logs, journal, nftables, API client | Web API, database, dashboard |
| Trust model | Minimal capabilities, no root | Full admin control |
| Data at rest | SQLite cache, config | PostgreSQL, secrets |
| Network | Outbound HTTPS only | Inbound HTTPS |
| Compromise impact | Single VPS | Multi-tenant platform |
