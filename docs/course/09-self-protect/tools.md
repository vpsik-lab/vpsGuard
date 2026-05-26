# Tools: Lesson 09

## New Tools

### systemd sandbox directives

systemd unit files support security directives that act like container isolation:

| Directive | Effect |
|-----------|--------|
| `CapabilityBoundingSet=` | Limits kernel capabilities |
| `NoNewPrivileges=` | Prevents privilege escalation |
| `ProtectSystem=` | Mounts `/usr` and `/etc` read-only |
| `ProtectHome=` | Makes `/home` inaccessible |
| `PrivateTmp=` | Gives the service its own `/tmp` |
| `MemoryMax=` | Hard memory limit |
| `CPUQuota=` | CPU time limit |
| `TasksMax=` | Maximum number of processes/threads |

### AppArmor

Linux Mandatory Access Control (MAC). Every file access is checked against the profile.

**Commands:**
```bash
# Enforce a profile
sudo apparmor_parser -r /etc/apparmor.d/vpsGuard
sudo aa-enforce vpsGuard

# Check status
sudo aa-status | grep vpsGuard

# View denials
sudo journalctl -k | grep DENIED
```

### crypto/sha256 (stdlib)

```go
h := sha256.New()
h.Write(data)
checksum := hex.EncodeToString(h.Sum(nil))
```

Used by the watchdog to verify config integrity.

## Reference: Defense in Depth

| Layer | Bypass difficulty | What it stops |
|-------|------------------|---------------|
| AppArmor | Very hard (kernel-enforced) | File access, exec, capabilities |
| systemd | Hard (requires root) | Resource exhaustion, privilege escalation |
| Watchdog | Moderate (must modify code) | Config tampering without alerting admin |
| Minimal user | Easy to bypass (but escalates attack cost) | Casual exploitation |
