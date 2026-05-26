# Tools: Lesson 01

No new tools in this lesson — we're defining the problem.

But these are the tools we *will* use, and why:

| Tool | Why We Chose It |
|------|-----------------|
| **Go** | Single binary, no runtime deps, great concurrency for real-time processing, cross-compiles to any Linux arch |
| **nftables** | Modern Linux firewall, programmable via subprocess, supports sets with timeouts natively. Successor to iptables |
| **systemd** | Built into every modern Linux distro. We use its sandboxing (NoNewPrivileges, ProtectSystem, CapabilityBoundingSet) to isolate the agent |
| **SQLite** | Zero-config, single-file database. Perfect for a single-node cache — no daemon, no network, no setup |
| **zap** | Uber's structured logger. Why zap over logrus? zap has zero-allocation in the hot path — critical when processing hundreds of events per second |
| **Prometheus** | Industry standard for metrics. The agent exposes a `/metrics` endpoint — no agent or collector needed |
| **YAML** | Human-readable config. JSON is machine-friendly but painful to hand-edit. TOML is fine but less universal |
| **GitHub Actions** | Free CI/CD for public repos. Tests every commit, builds cross-platform binaries, creates releases |

## Why NOT [X]?

| Tool | Why Not |
|------|---------|
| **Python** | Too slow for real-time parsing, requires runtime, dependency hell |
| **Rust** | Great but slower to prototype. Go's goroutines are simpler for this use case |
| **iptables** | Being deprecated. nftables is the future |
| **BoltDB** | Embedded key-value store — but SQLite gives us querying capability for free |
| **logrus** | Slower than zap, allocations on every log call |
| **CloudWatch / Datadog** | Requires internet, costs money, violates privacy-first principle |
