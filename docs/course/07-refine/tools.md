# Tools: Lesson 07

## New Tools

### net.ParseIP (stdlib)

Parses IPv4 and IPv6 addresses. Returns `nil` for invalid input.

```go
ip := net.ParseIP("1.2.3.4")
if ip.To4() != nil {
    // IPv4
} else {
    // IPv6
}
```

## Security Pattern: Args Over Strings

**Never** build shell commands with string interpolation:

```go
// ❌ DANGEROUS
cmd := fmt.Sprintf("nft add element %s { %s }", table, ip)
exec.Command("sh", "-c", cmd)

// ✅ SAFE
exec.Command("nft", "add", "element", table, fmt.Sprintf("{ %s }", ip))
```

With `sh -c`, the shell interprets special characters. With args, Go passes them directly to the kernel — no interpretation.
