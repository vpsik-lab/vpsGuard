# vpsGuard Agent — Architecture

**Version**: 0.2.0  
**Status**: Stable  
**Phase**: A — Agent (standalone, open-source)

> This document describes the Agent's internal architecture. The Central Platform is a separate system (Phase B); see [`AGENT-API-CONTRACT.md`](AGENT-API-CONTRACT.md) for the interface between them.

---

## 1. High-Level Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Agent Process                         │
│                                                              │
│  ┌──────────┐   ┌──────────┐   ┌──────────────┐            │
│  │ systemd  │   │ auth.log │   │ Central Feed  │            │
│  │ journal  │   │ tailer   │   │ (HTTP Pull)   │            │
│  └────┬─────┘   └────┬─────┘   └──────┬───────┘            │
│       │              │                │                     │
│       └──────────────┼────────────────┘                     │
│                      ▼                                      │
│           ┌──────────────────────┐                          │
│           │     Event Bus        │                          │
│           │  (bounded: 1000)     │                          │
│           │  non-blocking drop   │                          │
│           └──────┬───────────────┘                          │
│                  │                                          │
│         ┌────────┴────────┐                                  │
│         ▼                 ▼                                  │
│  ┌──────────────┐ ┌──────────────┐                          │
│  │  Behavioral  │ │  Threat      │                          │
│  │  Analyzer    │ │  Intel       │                          │
│  │  (instant)   │ │  (async)     │                          │
│  └──────┬───────┘ └──────┬───────┘                          │
│         │                │                                   │
│         └───────┬────────┘                                   │
│                 ▼                                            │
│        ┌────────────────┐                                    │
│        │ Hybrid Scorer  │  ← Temporal Memory (7d)           │
│        │  (weighted)    │  ← Central Feed scores            │
│        └───────┬────────┘                                    │
│                ▼                                            │
│        ┌────────────────┐                                    │
│        │ Decision       │  ← Rules Engine                   │
│        │ Engine         │  ← Thresholds                     │
│        └───────┬────────┘                                    │
│                ▼                                            │
│    ┌───────────┼───────────┐                                 │
│    ▼           ▼           ▼                                 │
│ ┌────────┐ ┌────────┐ ┌────────┐                            │
│ │nftables│ │Telegram│ │ Email  │                            │
│ │ block  │ │ notify │ │ notify │                            │
│ └────────┘ └────────┘ └────────┘                            │
│                                                              │
│ ┌────────────────────────────────────────┐                   │
│ │           Self-Protection               │                   │
│ │  Watchdog: health check + config hash   │                   │
│ │  Systemd sandbox: NoNewPrivs, ProtectSys│                   │
│ └────────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Component Architecture

### 2.1 Entry Point (`cmd/vpsGuard/main.go`)

Wires all components together:
1. Loads and validates config
2. Initialises logger (stdout + file, JSON)
3. Creates Event Bus and processing goroutines
4. Starts optional bootstrap hardening
5. Periodic cleanup goroutine (1h ticker)
6. Waits for SIGINT/SIGTERM

### 2.2 Event Bus (`internal/pipeline/`)

| Aspect | Detail |
|--------|--------|
| Type | Go channel, fan-out pattern |
| Capacity | 1000 (bounded) |
| Behaviour | Non-blocking publish; drops if full |
| Envelope | TraceID (UUID) + Priority + Source + Version |
| Events | `SSHFailedLogin`, `InvalidUser`, `PortScan`, `CentralFeedMatch` |

### 2.3 Monitor (`internal/monitor/`)

| Component | Input | Output |
|-----------|-------|--------|
| `FileTailer` | `/var/log/auth.log` | Lines (seek/tail — never re-reads) |
| `Parser` | Log lines | Parsed events via precompiled regex |
| `JournalMonitor` | systemd journal | Structured events (context-aware) |
| `BehavioralAnalyzer` | Events | Per-IP score (frequency, window, usernames) |

### 2.4 Threat Intel (`internal/threat/`)

| Provider | Type | Caching |
|----------|------|---------|
| AbuseIPDB | REST API v2 | SQLite, 24h TTL |
| AlienVault OTX | REST API v1 | SQLite, 24h TTL |
| Central Feed | HTTP Pull | SQLite, configurable TTL |

All providers run asynchronously (goroutines). Cache is shared via SQLite.

### 2.5 Scoring (`internal/engine/`)

| Sub-component | Responsibility |
|---------------|---------------|
| `Scorer` | Weighted score fusion + event recording |
| `TemporalMemory` | 7-day IP reputation (count + avg score per day) |
| `ScoreResult` | Normalised 0–100 score per IP with source breakdown |

Scoring formula: see [`AGENT-SCORING.md`](AGENT-SCORING.md).

### 2.6 Decision (`internal/engine/`)

| Sub-component | Responsibility |
|---------------|---------------|
| `Decision` | Maps score → action (block/quarantine/monitor/ignore) |
| Priority | Block > Quarantine > Monitor > Ignore |
| Rules override | Rules can escalate action regardless of score |

### 2.7 Rules Engine (`internal/rules/`)

- YAML-defined rules, 3 defaults built-in:
  - `aggressive_ssh`: block on >10 attempts/5min
  - `port_scan`: block on >20 unique ports/5min
  - `invalid_user`: block on non-existent usernames
- Custom rules loaded from `/etc/vpsGuard/rules.yaml` (replaces defaults)

### 2.8 Firewall (`internal/firewall/`)

| Aspect | Detail |
|--------|--------|
| Backend | nftables (via `exec.Command`) |
| Set type | Dynamic with timeout (auto-expire) |
| Table | `inet vpsGuard` |
| Set | `blacklist` (IPv4) |
| Default block | 24h (configurable) |

### 2.9 Notifier (`internal/notify/`)

| Channel | Format | Template |
|---------|--------|----------|
| Telegram | HTML message | IP, score, action, reason, timestamp |
| Email | HTML email | Same + server info |

### 2.10 Central Feed Client (`internal/api/`)

- HTTPS pull with Bearer token auth
- Configurable interval (default: 60s)
- Min confidence filter
- Merges into IntelClient's SQLite cache
- Periodic pull on configurable interval (default: 60s)

### 2.11 Self-Protect (`internal/selfprotect/`)

| Feature | Implementation |
|---------|---------------|
| Health check | Periodic watch, systemd auto-restart |
| Config integrity | Periodic stat check (SHA256 planned) |
| Systemd sandbox | NoNewPrivileges, ProtectSystem, PrivateTmp |

### 2.12 Bootstrap (`internal/bootstrap/`)

Optional one-time hardening:
- system updates
- SSH: no root login, no password auth
- UFW: default deny incoming
- Fail2ban: SSH jail
- Kernel sysctl: IP spoof protection, SYN flood protection

---

## 3. Event Flow (Trace Path)

```
1. [systemd journal]         → JournalMonitor.Run()
2. [auth.log tailer]         → FileTailer.Read()
3.                           → Parser.ParseLine()
4.                           → Envelope{Event, TraceID, Priority}
5.                           → Bus.Publish(envelope)
6. [Bus Fan-Out]             → FanOut goroutine
7. [Processing goroutine]    → scorer.RecordEvent(envelope)
8.                           → scorer.Evaluate(ctx, envelope, intelClient)
8a.                              └→ intelClient.GetScore(ip)  [async cache lookup]
8b.                              └→ behavioral.GetScore(ip)  [instant]
8c.                              └→ memory.GetScore(ip)      [instant]
8d.                              └→ weighted fusion
9.                           → decision.Evaluate(ctx, envelope, scoreResult, ruleEngine)
9a.                              └→ ruleEngine.Evaluate(envelope)  [match]
9b.                              └→ threshold check
10.                          → fw.BlockIP() | notifier.Send()
```

End-to-end latency target: < 100ms from log line to block.

---

## 4. Package Dependency Graph

```
cmd/vpsGuard/main.go
  ├── internal/config
  ├── internal/pipeline (bus + event types)
  ├── internal/monitor (parser, journal, behavioral)
  ├── internal/threat (abuseipdb, alienvault, cache)
  ├── internal/engine (scorer, decision, memory)
  ├── internal/rules
  ├── internal/firewall (nftables)
  ├── internal/notify (telegram, email)
  ├── internal/api (pull_client)
  ├── internal/selfprotect (watchdog)
  └── internal/bootstrap (hardening)
```

No circular dependencies. Each package depends on `config` + `pipeline` (event types) and optionally on `threat` (for `IntelClient`).

---

## 5. Agent Modes

| Mode | Local Scoring | Central Feed | API Calls | Use Case |
|------|:------------:|:------------:|:---------:|----------|
| `local` | ✅ Full | ❌ None | None | Air-gapped VPS |
| `hybrid` | ✅ Full | ✅ Weighted 15% | AbuseIPDB + OTX | Default |
| `central_only` | ❌ None | ✅ Full trust | None | Trusted platform |

---

## 6. Performance Targets

| Metric | Target | Achieved |
|--------|--------|----------|
| Idle RAM | < 20 MB | ~8 MB |
| Idle CPU | < 0.5% | ~0.1% |
| Block latency | < 100ms | ~50ms |
| Startup time | < 1s | ~200ms |
| Binary size | < 10 MB | 7.4 MB |
| Install time | < 3 min | ~30s |

---

## 7. Agent vs Platform Boundary

```
┌─────────────────────┐       ┌─────────────────────────┐
│   Agent (this repo) │       │  Central Platform       │
│                     │       │  (separate repo - TBD)  │
│  ┌───────────────┐  │       │                         │
│  │ Pull Client   │──┼──HTTP─┼─► GET /api/v1/threat    │
│  └───────────────┘  │       │  -feed                  │
│  ┌───────────────┐  │       │                         │
│  │ Report (opt.) │──┼──HTTP─┼─► POST /api/v1/report   │
│  └───────────────┘  │       │                         │
│                     │       │  DB: PostgreSQL/TiDB    │
│  DB: SQLite         │       │  UI: Dashboard          │
│  (local cache only) │       │  Auth: API keys         │
└─────────────────────┘       └─────────────────────────┘
```

The Agent and Platform communicate **only** via the documented API contract.  
The Agent never depends on Platform code, and vice versa.
