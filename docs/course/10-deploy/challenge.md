# Challenge: Deploy

---

## ⭐ Level 1: Dry-Run the Install

Simulate an installation without making changes:

```bash
bash deploy/install.sh --dry-run --unattended
```

**Task:** Read the output. List every step that would be performed.

---

## ⭐⭐ Level 2: Add a Health Check to Install Script

After installation, the script should verify the agent is running:

```bash
# Wait for service to start
sleep 2
systemctl is-active vpsGuard --quiet && echo "✅ Agent is running"
# Check health endpoint
curl -sf http://127.0.0.1:9090/health | jq .
```

Add this as a post-install verification step in `install.sh`.

**Hint:** Add a `post_install_check()` function.

---

## ⭐⭐⭐ Level 3: Build a Docker Image

Create a `Dockerfile` that builds and runs vpsGuard in a container:

```dockerfile
FROM golang:1.22 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -o vpsGuard ./cmd/vpsGuard

FROM ubuntu:22.04
# Install nftables
RUN apt-get update && apt-get install -y nftables
# Copy binary + config
COPY --from=builder /app/vpsGuard /usr/local/bin/
COPY config.yaml /etc/vpsGuard/
# Run
CMD ["vpsGuard", "-config", "/etc/vpsGuard/config.yaml"]
```

**Hint:** The container needs `--cap-add=NET_ADMIN --security-opt apparmor=unconfined` to run.

---

## Solution

<details>
<summary>Click for Level 2 solution</summary>

```bash
post_install_check() {
    info "Verifying installation..."
    sleep 2

    if systemctl is-active vpsGuard --quiet; then
        info "✅ vpsGuard service is running"
    else
        warn "⚠️  Service not active — check: journalctl -u vpsGuard"
    fi

    if command -v curl &>/dev/null; then
        health=$(curl -sf http://127.0.0.1:9090/health 2>/dev/null || true)
        if [ -n "$health" ]; then
            info "✅ Health endpoint responding"
        fi
    fi
}
```

Add `post_install_check` to `install.sh` after the service start.
</details>
