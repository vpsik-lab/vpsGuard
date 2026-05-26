# vpsGuard — Course Index

**From pain to production: build a VPS security agent from scratch.**

This is not a tutorial. This is the real journey of building, shipping, and operating a production security product. Every line of code you see here runs on real VPS servers blocking real attacks.

---

## The Vision (Phases A → E)

```
Phase A: Agent (v0.x)      ← FREE AGPLv3 — purely local, no outbound
Phase B: Central API        ← PAID — unified threat intelligence API
Phase C: Dashboard          ← ENTERPRISE — visualization & management
Phase D: P2P Network        ← HYBRID — agents share threat hashes peer-to-peer
Phase E: Global Intel Feed  ← PAID — OSINT + honeypots + partner APIs
```

**Phase D — P2P Network:**
Every agent becomes a node in a P2P network. When one node detects an attack, all other nodes learn about it instantly — using **hashed IPs only**, never raw addresses. Zero reliance on a central server for the P2P layer.

**Phase E — Global Intel Feed:**
A massive intelligence pipeline:
- **Sources**: OSINT (AbuseIPDB, AlienVault, Shodan, Censys), global honeypot network, partner APIs
- **Analysis**: Clustering, false-positive rejection, enrichment (GeoIP, ASN, reverse DNS)
- **Privacy**: All data is `SHA256(IP + salt)` — no raw IPs are ever exchanged
- **Feed**: Unified API that agents pull from. Subscription-based.

**Isolation by design:**
When Phase B+ arrives, the agent remains **fully independent**. It does not depend on fail2ban, iptables, or any external tool. Even if every other program on the server is compromised, the agent stays isolated (systemd sandbox, AppArmor, minimal capabilities).

**Agent is FREE forever.** AGPLv3. Always. The paid tier is the cloud intelligence.

---

## Course Map

### Sprint 1: Minimum Viable Agent

| # | Lesson | Topic | Tag |
|---|--------|-------|-----|
| 01 | [The Pain](01-the-pain/) | Why 3M SSH attacks/day needs a real solution | `lesson-01-pain` |
| 02 | [First Line](02-first-line/) | Parse `auth.log`, emit events | `lesson-02-first-line` |
| 03 | [Event Bus](03-event-bus/) | Backtrack: we need a pipeline | `lesson-03-event-bus` |
| 04 | [Scoring](04-scoring/) | Behavioral + temporal scoring | `lesson-04-scoring` |

### Sprint 2: Make It Useful

| # | Lesson | Topic | Tag |
|---|--------|-------|-----|
| 05 | Blocking | nftables: first real block | — |
| 06 | Alerts | Telegram + Email | — |
| 07 | Refine | Backtrack: whitelist, IPv6, security | — |
| 08 | Persistence | SQLite cache + block store | — |

### Sprint 3: Hardening

| # | Lesson | Topic | Tag |
|---|--------|-------|-----|
| 09 | Self-Protect | Watchdog, systemd sandbox, AppArmor | — |
| 10 | Deploy | install.sh, harden.sh, uninstall | — |
| 11 | Reports | Daily report, log hash chain | — |

### Sprint 4: Production Ready

| # | Lesson | Topic | Tag |
|---|--------|-------|-----|
| 12 | Metrics | Prometheus, CLI, health endpoint | — |
| 13 | Secrets | Env vars, config security | — |
| 14 | CI/CD | GitHub Actions, releases, checksums | — |
| 15 | Open Source | LICENSE, contributing, future vision | — |

---

## Tools Used in This Course

Every tool is chosen for a reason — never "just because".

| Tool | Why |
|------|-----|
| **Go** | Single binary, cross-compile, great concurrency, no runtime deps |
| **nftables** | Modern, fast, programmable firewall — the iptables successor |
| **systemd** | Built into every Linux distro — sandbox, resource limits, auto-restart |
| **SQLite** | Zero-config, file-based, perfect for single-node cache |
| **Prometheus** | Industry standard metrics — `/metrics` endpoint, no agent needed |
| **YAML** | Human-readable config — not JSON, not TOML |
| **GitHub Actions** | Free CI/CD for open-source projects |
| **zap** | Fastest structured logger for Go — zero allocations in hot path |

---

## How Each Lesson Works

```
lesson-NN-name/
├── README.md      → What we build, why, and the code
├── tools.md       → Tools introduced in this lesson + why
└── challenge.md   → 3 difficulty levels (⭐/⭐⭐/⭐⭐⭐)
```

To follow along:

```bash
git checkout lesson-01-pain
# Read the code at that exact point in history
```

---

## Prerequisites

- Basic Go syntax (if you know `if`, `for`, `struct`, you're good)
- A Linux machine (or VM) — Ubuntu 22.04+ recommended
- 30 minutes per lesson

---

## License

The agent itself is **AGPLv3** — free forever. The course content is **CC BY-SA 4.0**.
