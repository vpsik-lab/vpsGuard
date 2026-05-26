#!/bin/bash
set -euo pipefail

VERSION="${VERSION:-latest}"
REPO="vpsik-lab/vpsGuard"
RAW_BASE="https://raw.githubusercontent.com/$REPO/main"
BINARY="vps-guard"
PREFIX="/usr/local"
CONFIG_DIR="/etc/vps-guard"
SYSTEMD_DIR="/etc/systemd/system"
CACHE_DIR="/var/cache/vps-guard"
LOG_DIR="/var/log/vps-guard"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DRY_RUN=false
UNATTENDED=false
HARDENING=true
SSH_PORT=22

usage() {
    cat <<EOF
VPS-Guard Agent Installer v${VERSION}

Usage: bash install.sh [options]

Options:
  --dry-run         Print what would be done without doing it
  --unattended      Run without prompts (use defaults)
  --no-hardening    Skip SSH/firewall/kernel hardening
  --ssh-port <n>    SSH port for firewall rules (default: 22)
  -h, --help        Show this help

Examples:
  bash install.sh                              Interactive install
  bash install.sh --unattended                 Auto install
  bash install.sh --no-hardening               Install agent only
  bash install.sh --ssh-port 2222 --unattended  Custom SSH port

VERSION=latest bash install.sh                 Install specific version
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --unattended) UNATTENDED=true; shift ;;
        --no-hardening) HARDENING=false; shift ;;
        --ssh-port) SSH_PORT="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

run() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} $*"
        return 0
    fi
    "$@"
}

info()  { echo -e "${GREEN}[*]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[!]${NC} $*"; }

if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    error "curl or wget required"
    exit 1
fi

fetch() {
    if command -v curl &>/dev/null; then
        curl -sSL "$1"
    else
        wget -qO- "$1"
    fi
}

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║        VPS-Guard Security Agent         ║"
echo "║     Lightweight Intelligent Protection  ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

if [ "$DRY_RUN" = false ] && [ "$EUID" -ne 0 ]; then
    error "Please run as root"
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    info "Detected OS: $OS $VERSION_ID"
else
    error "Cannot detect OS"
    exit 1
fi

if [ "$OS" != "ubuntu" ] && [ "$OS" != "debian" ]; then
    error "This installer supports Ubuntu/Debian only"
    exit 1
fi

# ── Harden system ──────────────────────────────────────────
if [ "$HARDENING" = true ]; then
    info "Updating system..."
    run apt-get update -qq
    run apt-get upgrade -y -qq
    run apt-get install -y -qq ufw fail2ban nftables curl

    info "Configuring UFW firewall..."
    run ufw --force enable 2>/dev/null || warn "UFW enable failed (may be cloud VPS)"
    run ufw default deny incoming 2>/dev/null || true
    run ufw default allow outgoing 2>/dev/null || true
    run ufw allow "$SSH_PORT"/tcp 2>/dev/null || true

    info "Hardening SSH..."
    if [ "$UNATTENDED" = false ]; then
        echo ""
        warn "SSH hardening will: disable root login, disable password auth"
        echo "  Make sure you have SSH key access before continuing!"
        echo ""
        read -rp "  Continue with SSH hardening? [Y/n] " confirm
        if [ "$confirm" = "n" ] || [ "$confirm" = "N" ]; then
            warn "Skipping SSH hardening"
        else
            run sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
            run sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
            run sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
            SSH_SVC="ssh"
            systemctl list-units --full -all 2>/dev/null | grep -q 'sshd\.service' && SSH_SVC="sshd" || true
            run systemctl restart "$SSH_SVC"
            info "SSH hardened"
        fi
    else
        run sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        SSH_SVC="ssh"
        systemctl list-units --full -all 2>/dev/null | grep -q 'sshd\.service' && SSH_SVC="sshd" || true
        run systemctl restart "$SSH_SVC"
        info "SSH hardened (unattended)"
    fi

    info "Hardening kernel parameters..."
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] Create /etc/sysctl.d/99-vps-guard.conf"
    else
        cat > /etc/sysctl.d/99-vps-guard.conf << 'EOF'
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_synack_retries=2
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
EOF
        sysctl -p /etc/sysctl.d/99-vps-guard.conf >/dev/null 2>&1 || true
    fi

    info "Configuring Fail2ban..."
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] Create /etc/fail2ban/jail.local"
    else
        cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF
        systemctl restart fail2ban || true
    fi
fi

# ── Setup directories ──────────────────────────────────────
info "Creating directories..."
run mkdir -p "$CONFIG_DIR" "$CACHE_DIR" "$LOG_DIR"
run useradd -r -s /bin/false -d /nonexistent vps-guard 2>/dev/null || true

# ── Install binary ─────────────────────────────────────────
ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l)  ARCH="arm" ;;
    *)       error "Unsupported architecture: $ARCH"; exit 1 ;;
esac

DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$BINARY-linux-$ARCH"
if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL=$(fetch "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
        | grep "browser_download_url.*linux-$ARCH" \
        | cut -d: -f2,3 \
        | tr -d ' "') || true
fi

installed_from=""
if [ -n "$DOWNLOAD_URL" ] && fetch "$DOWNLOAD_URL" -o "$PREFIX/bin/$BINARY" 2>/dev/null; then
    run chmod +x "$PREFIX/bin/$BINARY"
    installed_from="download"
    info "Binary downloaded: $PREFIX/bin/$BINARY"
else
    info "Building from source..."
    if ! command -v go &>/dev/null; then
        warn "Go not found, installing..."
        run apt-get install -y -qq golang 2>/dev/null || \
            run apt-get install -y -qq golang-go 2>/dev/null || true
    fi
    if command -v go &>/dev/null; then
        BUILD_DIR=$(mktemp -d)
        git clone --depth 1 "https://github.com/$REPO.git" "$BUILD_DIR/src" 2>/dev/null || true
        (cd "$BUILD_DIR/src" && go build -o "$PREFIX/bin/$BINARY" -ldflags="-s -w" ./cmd/vps-guard)
        rm -rf "$BUILD_DIR"
        installed_from="source"
        info "Binary built: $PREFIX/bin/$BINARY"
    else
        error "Could not install Go. Install manually: apt-get install golang"
        exit 1
    fi
fi

# ── Create default config ──────────────────────────────────
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    info "Creating default config..."
    if [ "$DRY_RUN" = false ]; then
        fetch "$RAW_BASE/config.yaml" > "$CONFIG_DIR/config.yaml" 2>/dev/null || {
            cat > "$CONFIG_DIR/config.yaml" << 'CONFEOF'
log_dir: /var/log/vps-guard
cache_dir: /var/cache/vps-guard
mode: agent
agent_mode: hybrid
bootstrap:
  enabled: false
  ssh_port: 22
  allow_root: false
monitor:
  journal: true
  log_paths:
    - /var/log/auth.log
    - /var/log/syslog
  interval_seconds: 5
threat:
  abuseipdb_key: ""
  alienvault_key: ""
  cache_ttl_hours: 24
  rate_limit_per_min: 10
scoring:
  abuseipdb_weight: 0.25
  alienvault_weight: 0.20
  behavior_weight: 0.30
  temporal_weight: 0.10
  central_weight: 0.15
  block_threshold: 60
  rate_limit_score: 40
  rate_limit_minutes: 5
  quarantine_score: 30
  quarantine_minutes: 15
  central_block_threshold: 80
  central_quarantine_threshold: 50
  behavior_window_minutes: 10
  behavior_threshold: 5
  temporal_ttl_hours: 168
firewall:
  table: vps_guard
  set_name: blacklist
  default_block_hours: 24
notify:
  telegram_token: ""
  telegram_chat_id: ""
  smtp_host: ""
  smtp_port: 587
  smtp_user: ""
  smtp_pass: ""
  email_from: ""
  email_to: ""
  cooldown_minutes: 10
self_protect:
  watchdog_interval_seconds: 30
  enable_file_check: true
  config_checksum: ""
central_feed:
  enabled: false
  api_url: "https://your-platform.com/api/v1/threat-feed"
  api_token: ""
  sync_interval_seconds: 60
  min_confidence: 50
CONFEOF
        }
        chmod 600 "$CONFIG_DIR/config.yaml"
        info "Config created: $CONFIG_DIR/config.yaml"
    fi
fi

# ── Install systemd service ────────────────────────────────
info "Installing systemd service..."
if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Install systemd service to $SYSTEMD_DIR/vps-guard.service"
else
    if fetch "$RAW_BASE/deploy/vps-guard.service" > /dev/null 2>&1; then
        fetch "$RAW_BASE/deploy/vps-guard.service" > "$SYSTEMD_DIR/vps-guard.service"
    else
        cat > "$SYSTEMD_DIR/vps-guard.service" << 'SVCEOF'
[Unit]
Description=VPS-Guard Security Agent
Documentation=https://github.com/vpsik-lab/vpsGuard
After=network.target nftables.service
[Service]
Type=simple
ExecStart=/usr/local/bin/vps-guard -config /etc/vps-guard/config.yaml
Restart=always
RestartSec=5
User=vps-guard
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYSLOG
AmbientCapabilities=CAP_NET_ADMIN CAP_SYSLOG
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryMax=256M
CPUQuota=50%
TasksMax=50
LimitNOFILE=1024
[Install]
WantedBy=multi-user.target
SVCEOF
    fi
fi

# ── Install logrotate ──────────────────────────────────────
info "Setting up logrotate..."
if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Install logrotate to /etc/logrotate.d/vps-guard"
else
    if fetch "$RAW_BASE/deploy/vps-guard.logrotate" > /dev/null 2>&1; then
        fetch "$RAW_BASE/deploy/vps-guard.logrotate" > /etc/logrotate.d/vps-guard
    else
        cat > /etc/logrotate.d/vps-guard << 'LOGEOF'
/var/log/vps-guard/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
LOGEOF
    fi
fi

# ── Start service ──────────────────────────────────────────
if [ "$DRY_RUN" = false ]; then
    run systemctl daemon-reload
    run systemctl enable vps-guard
    run systemctl start vps-guard

    sleep 2
    if systemctl is-active --quiet vps-guard; then
        info "Service is running"
    else
        warn "Service may not have started. Check: journalctl -u vps-guard"
    fi
fi

# ── Summary ─────────────────────────────────────────────────
if [ "$DRY_RUN" = false ]; then
    cat <<EOF

╔══════════════════════════════════════════╗
║   VPS-Guard installed successfully!     ║
╚══════════════════════════════════════════╝

  Binary:    $PREFIX/bin/$BINARY
  Config:    $CONFIG_DIR/config.yaml
  Logs:      $LOG_DIR/
  Service:   vps-guard ($installed_from)

  Commands:
    systemctl status vps-guard
    journalctl -u vps-guard -f
    nano $CONFIG_DIR/config.yaml

  Configure APIs:
    $CONFIG_DIR/config.yaml
      → threat.abuseipdb_key
      → threat.alienvault_key
      → notify.telegram_token

EOF
fi
