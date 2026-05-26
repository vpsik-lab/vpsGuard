# Lesson 15: Open Source

**From personal project to community.**

---

## The Journey

15 lessons ago, we started with a question: *"Why does my VPS get 3 million SSH attacks per day?"*

Now we have:
- A real-time SSH attack detection agent
- Behavioral + threat intelligence scoring
- nftables blocking with IPv6 support
- Telegram + Email alerts
- Daily reports with log integrity
- Prometheus metrics + CLI management
- Self-protection (systemd sandbox, AppArmor, watchdog)
- One-command deploy and uninstall
- Full test suite (146 tests, 12 packages)
- CI/CD pipeline

This is not a tutorial project. This is **production software** running on real VPS servers.

---

## The License: AGPLv3

```license
GNU AFFERO GENERAL PUBLIC LICENSE v3

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License.
```

**Why AGPLv3 and not MIT or Apache 2.0?**

| License | Can Sell? | Must Open Source? | Network Use? |
|---------|-----------|-------------------|--------------|
| MIT | Yes | No | No disclosure |
| Apache 2.0 | Yes | No | No disclosure |
| GPLv3 | Yes | Yes (if distributed) | No disclosure |
| **AGPLv3** | Yes | **Yes (even if used as a service)** | **Must disclose** |

AGPLv3 closes the "SaaS loophole" — if someone runs a modified vpsGuard as a service, they must release their modifications. This protects the community.

**The business model: open core.**
- Agent: **AGPLv3 — free forever**
- Cloud API (Phase B): **paid subscription** — threat intelligence feed
- Dashboard (Phase C): **enterprise** — multi-server management

The agent never phones home. The free tier is **fully functional offline**.

---

## The CI/CD Pipeline

Every commit runs:

```yaml
# .github/workflows/ci.yml
jobs:
  test:
    steps:
      - run: go vet ./...        # static analysis
      - run: go test -race ./...  # tests + race detection
      - run: go build ./...       # compilation
      - run: ./vpsGuard -version  # version check

  cross-build:
    needs: [test]
    steps:
      - run: make cross-build     # amd64 + arm64 + arm
```

When a version tag is pushed (`v0.3.0`):

```yaml
# .github/workflows/release.yml
steps:
  - run: go test -race ./...
  - run: make release            # cross-compile + checksums
  - uses: softprops/action-gh-release
    with:
      files: dist/*              # binaries + checksums.txt
```

**Automatic releases.** Push a tag, get binaries.

---

## How to Contribute

```
CONTRIBUTING.md
├── Reporting bugs
│   - Include: OS version, Go version, config (sanitized)
│   - Include: logs from journalctl -u vpsGuard
├── Pull requests
│   - One feature/fix per PR
│   - go vet + go test must pass
│   - New code needs tests
├── Commit messages
│   feat: add GeoIP blocking support
│   fix: panic in parser on nil event
│   docs: update deployment guide
└── Code style
    - Follow standard Go formatting (gofmt)
    - No external dependencies without discussion
```

---

## The Future: Phases B → E

### Phase B: Central API

A unified threat intelligence API. Agents pull enriched threat data instead of calling AbuseIPDB/OTX individually.

```
Agent → Central API → global threat database
          ↓
      Subscription-based
      Privacy: SHA256 hashes, no raw IPs
```

**The agent becomes self-sufficient.** No more fail2ban, iptables, or external tools. The agent blocks entirely on its own analysis + our feed.

### Phase C: Dashboard

Multi-server management, visualization, historical data.

### Phase D: P2P Network

Agents share threat hashes peer-to-peer. No central server needed for the P2P layer.

```
Agent A detects 1.2.3.4 → hash(1.2.3.4) → peers
Agent B receives hash → preemptively blocks 1.2.3.4
```

### Phase E: Global Intel Feed

```
OSINT (AbuseIPDB, AlienVault, Shodan, Censys)
Honeypot network
Partner APIs
        ↓
   Analysis Engine
   (clustering, FP rejection, enrichment)
        ↓
   Unified API
        ↓
   vpsGuard agents pull data
```

**Privacy:** All data is `SHA256(IP + salt)`. No party ever sees another party's raw IPs.

### Isolation by Design

When moving to the cloud, the agent remains **fully independent**:
- It doesn't depend on fail2ban, iptables, or any external tool
- Even if every other program is compromised, the agent is isolated (systemd sandbox + AppArmor + minimal capabilities)
- The free agent works **forever** without the cloud

---

## Parting Advice

**1. Start minimal, then spiral.**

Every feature in vpsGuard started as "what's the simplest thing that works?" Then we discovered what was missing and spiraled back.

**2. Test everything.**

146 tests. Every commit. No exceptions. Tests are not a luxury — they're what let you refactor without fear.

**3. Security is a mindset, not a feature.**

Security isn't something you add at the end. It's in every decision: the args to `exec.Command`, the systemd sandbox, the AppArmor profile, the env var secrets.

**4. Open source is not free labor.**

It's a community. Protect it with a strong license, clear contributing guidelines, and respect for users' privacy.

**5. Build something real.**

The best way to learn is to build something that **must work**. When real attackers are hitting your VPS, you have no choice but to get it right.

---

## What's Next for You

- **Checkout each lesson's tag**: `git checkout lesson-01-pain`
- **Run the tests**: `go test -count=1 ./...`
- **Deploy on your VPS**: `bash deploy/install.sh --unattended`
- **Contribute**: open an issue, submit a PR
- **Watch the repository**: github.com/vpsik-lab/vpsGuard

The code is yours. The agent is free. The journey is just beginning.

---

## Check Your Understanding

1. Why AGPLv3 instead of MIT?
2. How does the CI pipeline prevent bad code from merging?
3. What's the difference between free and paid tiers?
4. How does the P2P network preserve privacy?

```bash
# Final command
curl -sSL https://raw.githubusercontent.com/vpsik-lab/vpsGuard/main/deploy/install.sh | sudo bash
```
