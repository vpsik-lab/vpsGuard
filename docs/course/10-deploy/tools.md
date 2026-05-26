# Tools: Lesson 10

## New Tools

### Bash (shell scripting)

Our deployment scripts are pure Bash with `set -euo pipefail`:

- `-e`: exit on error
- `-u`: error on undefined variables
- `-o pipefail`: fail if any command in a pipe fails
- `-x`: (debug) print commands before executing

**Why Bash and not Ansible/Python/Go?**
- Zero dependencies — Bash is on every Linux system
- The install script must work before anything is installed
- Ansible requires Python; Go requires a compiled binary

### sha256sum

Linux utility for SHA-256 hash verification:

```bash
sha256sum -c checksums.txt --ignore-missing
```

### systemctl

Manage systemd services:

```bash
systemctl daemon-reload
systemctl enable --now vpsGuard
systemctl status vpsGuard
```

### useradd

Create system users:

```bash
useradd -r -s /bin/false vpsGuard
```

The `-r` flag creates a system user (UID < 1000). `/bin/false` means the user can't log in.

## Deployment Checklist

```
✅ Binary installed + verified
✅ Config file created
✅ systemd unit installed + enabled
✅ Logrotate configured
✅ AppArmor profile loaded
✅ nftables table created
✅ User created (vpsGuard)
✅ Service running
✅ (optional) VPS hardened
```
