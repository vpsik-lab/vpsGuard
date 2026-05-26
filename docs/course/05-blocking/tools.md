# Tools: Lesson 05

## New Tools

### nftables

Next-generation Linux firewall. Replaces iptables.

**Why nftables over iptables?**
- Sets with timeouts (built-in expiry — no cron jobs to clean up)
- Better performance (single evaluation pass vs multiple tables)
- Simpler syntax (no separate `-A`/`-D`/`-I`)
- Still actively maintained (unlike ip6tables/ebtables/arptables)

**Commands we use:**
```bash
nft add table inet vpsGuard
nft add set inet vpsGuard blacklist { type ipv4_addr; flags timeout; }
nft add element inet vpsGuard blacklist { 1.2.3.4 timeout 86400s }
nft list set inet vpsGuard blacklist
```

### exec.CommandContext

Go's standard library for running external commands.

```go
exec.CommandContext(ctx, "nft", "add", "element", "inet", table, set, arg)
```

**Why not `exec.Command` (without context)?** `CommandContext` cancels the process if the context is cancelled — essential for graceful shutdowns.

### Decision thresholds in config

```yaml
scoring:
  block_threshold: 80
  rate_limit_score: 50
  quarantine_score: 25
```

These are validated in `config.Validate()`: block > rate-limit > quarantine.
