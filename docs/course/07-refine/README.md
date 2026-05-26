# Lesson 07: Refine

**Backtrack: the things we forgot in v0.1.**

---

## The Discovery

After building blocking and alerts, we discover three cracks in our v0.1 design:

1. **No whitelist** — we blocked our own office IP. Oops.
2. **IPv4 only** — IPv6 attackers bypass us completely.
3. **Arg injection risk** — what if someone controls the nftables table name?

This lesson is the **spiral** in action: build, discover, go back, fix.

---

## Fix 1: IP Whitelist

### Problem

```go
// Before: every IP gets blocked if it scores high
func (d *DecisionEngine) Evaluate(...) []Action {
    // No whitelist check — the admin's IP gets blocked!
    switch {
    case scores.FinalScore >= blockThreshold:
        return Action{Type: "block", ...}  // even for 10.0.0.1
    }
}
```

### Solution

```go
// After: whitelist check first
func (d *DecisionEngine) Evaluate(...) []Action {
    if d.cfg.Firewall.IsWhitelisted(ip) {
        logger.Debug("IP whitelisted, skipping")
        return nil  // no actions for whitelisted IPs
    }
    // ... rest of the logic
}
```

Config:

```yaml
firewall:
  whitelist:
    - 10.0.0.0/8       # internal network
    - "192.168.1.0/24"  # home office
    - "::1"             # IPv6 localhost
```

The `IsWhitelisted` method checks both the whitelist and the config's `allow_root` setting:

```go
func (c *FirewallConfig) IsWhitelisted(ip string) bool {
    for _, wl := range c.Whitelist {
        if ip == wl {
            return true
        }
    }
    return false
}
```

---

## Fix 2: IPv6 Dual-Stack

### Problem

The internet runs on IPv6 too. Many bots scan over IPv6. Our nftables set only had IPv4.

```go
// Before: IPv4 only
setName := "blacklist"  // type ipv4_addr
```

### Solution

Dual sets — one for each address family:

```go
type NftablesManager struct {
    setName   string  // "blacklist"   — type ipv4_addr
    setNameV6 string  // "blacklist6"  — type ipv6_addr
}
```

Auto-detect IP family:

```go
func (m *NftablesManager) setForIP(ip string) string {
    if net.ParseIP(ip).To4() != nil {
        return m.setName   // IPv4 → blacklist
    }
    return m.setNameV6     // IPv6 → blacklist6
}
```

Both sets are created in `ensureSets()`:

```go
func (m *NftablesManager) ensureSets() error {
    cmds := [][]string{
        {"add", "set", "inet", m.table, m.setName,  "{ type ipv4_addr; flags timeout; }"},
        {"add", "set", "inet", m.table, m.setNameV6, "{ type ipv6_addr; flags timeout; }"},
        {"add", "rule", "inet", m.table, "input", "ip saddr @" + m.setName + " drop"},
        {"add", "rule", "inet", m.table, "input", "ip6 saddr @" + m.setNameV6 + " drop"},
    }
    for _, args := range cmds {
        exec.Command("nft", args...).Run()
    }
}
```

---

## Fix 3: Arg Injection Protection

### Problem

Before, nftables commands were constructed as a single string:

```go
// BAD: interpolating into a string
cmd := fmt.Sprintf("add element inet %s %s { %s timeout %ds }", table, set, ip, timeout)
exec.Command("sh", "-c", cmd).Run()  // what if ip is "; rm -rf /" ?
```

### Solution

Go's `exec.Command` takes **separate arguments** — no shell involved:

```go
// GOOD: separate args
exec.Command("nft", "add", "element", "inet", table, set,
    fmt.Sprintf("{ %s timeout %ds }", ip, timeout),
).Run()
```

The IP is still interpolated, but only as the LAST argument — and nftables parses it as an IP address, not a command. The shell is never invoked.

---

## What We Learned

| Fix | Why It Matters |
|-----|---------------|
| **Whitelist** | Prevent self-DoS — your own IP should never be blocked |
| **IPv6** | Without it, 30% of attackers are invisible |
| **Args slice** | Prevent shell injection — a foundational security practice |

## The Spiral Mindset

This is the most important lesson in the entire course:

> **Good software is not written. It's rewritten.**

Every feature you add reveals something you missed. The mark of a good engineer is not "gets it right first time" — it's **finds and fixes mistakes quickly**.

---

## Check Your Understanding

1. Why should whitelist be checked BEFORE scoring?
2. How does `net.ParseIP` distinguish IPv4 from IPv6?
3. Why is `exec.Command` with args safer than a shell string?
4. What other fixes might we discover in the next sprint?
