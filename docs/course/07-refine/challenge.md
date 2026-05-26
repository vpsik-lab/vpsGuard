# Challenge: Refine

---

## ⭐ Level 1: CIDR Whitelist

The current `IsWhitelisted` only matches exact IPs. Extend it to support CIDR notation (e.g., `10.0.0.0/8`).

```go
func (c *FirewallConfig) IsWhitelisted(ip string) bool {
    // Add CIDR support using net.ParseCIDR
}
```

**Hint:** `net.ParseCIDR("10.0.0.0/8")` returns a `*net.IPNet` with `.Contains(ip)` method.

---

## ⭐⭐ Level 2: Test the Arg Injection Fix

Write a test that proves the nftables manager is safe against injection:

```go
func TestBlockIPInjection(t *testing.T) {
    // Try to inject a malicious IP like "; rm -rf /"
    // The test should verify the command is rejected by nft,
    // not executed by the shell.
}
```

**Hint:** You don't need root for this — just verify the args are passed correctly.

---

## ⭐⭐⭐ Level 3: Add IPv6 to CLI Commands

The `--list-blocked` flag currently only shows IPv4 correctly. Modify `runListBlocked` to display IPv6 addresses and set name.

**Hint:** Look at `ListBlocked(ctx, ipv6 bool)` in `nftables.go`.

---

## Solution

<details>
<summary>Click for Level 1 solution</summary>

```go
import "net"

func (c *FirewallConfig) IsWhitelisted(ip string) bool {
    parsed := net.ParseIP(ip)
    if parsed == nil {
        return false
    }
    for _, entry := range c.Whitelist {
        // Try CIDR first
        if _, cidr, err := net.ParseCIDR(entry); err == nil {
            if cidr.Contains(parsed) {
                return true
            }
            continue
        }
        // Then exact match
        if ip == entry {
            return true
        }
    }
    return false
}
```

Check the actual implementation in `internal/config/config.go`.
</details>
