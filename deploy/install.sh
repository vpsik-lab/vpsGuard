#!/bin/bash
set -euo pipefail

VERSION="${VERSION:-latest}"
REPO="vpsik-lab/vpsGuard"
RAW_BASE="https://raw.githubusercontent.com/$REPO/main"
BINARY="vpsGuard"
PREFIX="/usr/local"
CONFIG_DIR="/etc/vpsGuard"
SYSTEMD_DIR="/etc/systemd/system"
CACHE_DIR="/var/cache/vpsGuard"
LOG_DIR="/var/log/vpsGuard"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

DRY_RUN=false
UNATTENDED=false
HARDENING=true
SSH_PORT=22
UNINSTALL=false

usage() {
    cat <<EOF
vpsGuard Agent Installer v${VERSION}

Usage: bash install.sh [options]

Options:
  --dry-run         Print what would be done without doing it
  --unattended      Run without prompts (use defaults)
  --no-hardening    Skip SSH/firewall/kernel hardening
  --ssh-port <n>    SSH port for firewall rules (default: 22)
  --uninstall       Remove vpsGuard completely (full rollback)
  -h, --help        Show this help

Examples:
  bash install.sh                              Interactive install
  bash install.sh --unattended                 Auto install
  bash install.sh --uninstall                  Full removal
  bash install.sh --ssh-port 2222 --unattended  Custom SSH port

  # Via curl pipe (requires root/sudo):
  curl -sSL https://raw.githubusercontent.com/vpsik-lab/vpsGuard/main/deploy/install.sh | sudo bash -s -- --unattended
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --unattended) UNATTENDED=true; shift ;;
        --no-hardening) HARDENING=false; shift ;;
        --ssh-port) SSH_PORT="$2"; shift 2 ;;
        --uninstall) UNINSTALL=true; shift ;;
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

if [ "$DRY_RUN" = false ] && [ "$EUID" -ne 0 ]; then
    error "Please run as root"
    exit 1
fi

# ── Uninstall mode ─────────────────────────────────────────
if [ "$UNINSTALL" = true ]; then
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║      vpsGuard Uninstall                ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
    info "Starting full uninstall..."

    run systemctl stop vpsGuard 2>/dev/null || true
    run systemctl disable vpsGuard 2>/dev/null || true

    run rm -f "$SYSTEMD_DIR/vpsGuard.service"
    run rm -f "$PREFIX/bin/$BINARY"
    run rm -rf "$CONFIG_DIR" "$LOG_DIR" "$CACHE_DIR"
    run rm -f /etc/logrotate.d/vpsGuard
    run rm -f /etc/sysctl.d/99-vpsGuard.conf

    # Restore nftables
    if command -v nft &>/dev/null; then
        run nft delete table inet vpsGuard 2>/dev/null || true
    fi

    # Remove vpsGuard user
    run userdel vpsGuard 2>/dev/null || true

    # Restore SSH config from backup
    if [ -f /etc/ssh/sshd_config.vpsguard.bak ]; then
        run cp /etc/ssh/sshd_config.vpsguard.bak /etc/ssh/sshd_config
        run rm -f /etc/ssh/sshd_config.vpsguard.bak
        SSH_SVC="ssh"
        systemctl list-units --full -all 2>/dev/null | grep -q 'sshd\.service' && SSH_SVC="sshd" || true
        run systemctl restart "$SSH_SVC" || warn "Could not restart SSH — restore manually: /etc/ssh/sshd_config.vpsguard.bak"
        info "SSH config restored from backup"
    fi

    # Disable UFW
    if command -v ufw &>/dev/null; then
        run ufw disable 2>/dev/null || true
        info "UFW disabled"
    fi

    # Remove fail2ban jail
    if [ -f /etc/fail2ban/jail.local ]; then
        if grep -q 'vpsGuard' /etc/fail2ban/jail.local 2>/dev/null; then
            run rm -f /etc/fail2ban/jail.local
            run systemctl restart fail2ban 2>/dev/null || true
            info "Fail2ban vpsGuard jail removed"
        fi
    fi

    run systemctl daemon-reload 2>/dev/null || true

    info "vpsGuard fully uninstalled"
    exit 0
fi

# ── Install mode ──────────────────────────────────────────
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
echo "║        vpsGuard Security Agent         ║"
echo "║     Lightweight Intelligent Protection  ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

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
    # Backup before modifying
    if [ "$DRY_RUN" = false ] && [ ! -f /etc/ssh/sshd_config.vpsguard.bak ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.vpsguard.bak
        info "SSH config backed up to /etc/ssh/sshd_config.vpsguard.bak"
    fi

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
            run sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
            run sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
            SSH_SVC="ssh"
            systemctl list-units --full -all 2>/dev/null | grep -q 'sshd\.service' && SSH_SVC="sshd" || true
            run systemctl restart "$SSH_SVC"
            info "SSH hardened"
        fi
    else
        run sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        run sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        run sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
        run sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
        run sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
        SSH_SVC="ssh"
        systemctl list-units --full -all 2>/dev/null | grep -q 'sshd\.service' && SSH_SVC="sshd" || true
        run systemctl restart "$SSH_SVC"
        info "SSH hardened (unattended)"
    fi

    info "Hardening kernel parameters..."
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] Create /etc/sysctl.d/99-vpsGuard.conf"
    else
        cat > /etc/sysctl.d/99-vpsGuard.conf << 'EOF'
# vpsGuard kernel hardening
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_synack_retries=2
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_intvl=60
net.ipv4.tcp_keepalive_probes=5
net.netfilter.nf_conntrack_max=262144
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_syn_retries=3
EOF
        sysctl -p /etc/sysctl.d/99-vpsGuard.conf >/dev/null 2>&1 || true
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
run useradd -r -s /bin/false -d /nonexistent vpsGuard 2>/dev/null || true
run chown vpsGuard:vpsGuard "$CACHE_DIR" "$LOG_DIR"

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

# ── SHA256 verification ──────────────────────────────────
verify_sha256() {
    local binary="$1"
    local checksums_url="$2"
    local arch_suffix="$3"
    local tmpdir
    tmpdir=$(mktemp -d)
    local cs_file="$tmpdir/checksums.txt"
    local expected actual

    if fetch "$checksums_url" > "$cs_file" 2>/dev/null; then
        expected=$(grep "$BINARY-linux-$arch_suffix" "$cs_file" | awk '{print $1}')
        if [ -n "$expected" ]; then
            actual=$(sha256sum "$binary" | awk '{print $1}')
            if [ "$expected" != "$actual" ]; then
                error "SHA256 mismatch for $BINARY-linux-$arch_suffix"
                error "  Expected: $expected"
                error "  Actual:   $actual"
                rm -rf "$tmpdir"
                return 1
            fi
            info "SHA256 verified: $actual"
        else
            warn "No checksum entry for $BINARY-linux-$arch_suffix"
        fi
    else
        warn "Could not download checksums.txt — skipping verification"
    fi
    rm -rf "$tmpdir"
    return 0
}

installed_from=""
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

if [ -n "$DOWNLOAD_URL" ]; then
    if fetch "$DOWNLOAD_URL" > "$TMP_DIR/$BINARY" 2>/dev/null; then
        TAG=$(echo "$DOWNLOAD_URL" | grep -oP 'download/\K[^/]+' || echo "$VERSION")
        CHECKSUMS_URL="https://github.com/$REPO/releases/download/$TAG/checksums.txt"

        if verify_sha256 "$TMP_DIR/$BINARY" "$CHECKSUMS_URL" "$ARCH"; then
            run mv "$TMP_DIR/$BINARY" "$PREFIX/bin/$BINARY"
            run chmod +x "$PREFIX/bin/$BINARY"
            installed_from="download"
            info "Binary installed: $PREFIX/bin/$BINARY"
        else
            error "Binary rejected — SHA256 verification failed"
            exit 1
        fi
    else
        warn "Binary download failed, building from source..."
    fi
fi

if [ -z "$installed_from" ]; then
    info "Building from source..."
    if ! command -v go &>/dev/null; then
        warn "Go not found, installing..."
        run apt-get install -y -qq golang 2>/dev/null || \
            run apt-get install -y -qq golang-go 2>/dev/null || true
    fi
    if command -v go &>/dev/null; then
        if ! command -v git &>/dev/null; then
            run apt-get install -y -qq git 2>/dev/null || true
        fi
        BUILD_DIR=$(mktemp -d)
        if command -v git &>/dev/null; then
            run git clone --depth 1 "https://github.com/$REPO.git" "$BUILD_DIR/src"
        else
            SRC_ARCHIVE="https://github.com/$REPO/archive/refs/heads/main.tar.gz"
            fetch "$SRC_ARCHIVE" > "$BUILD_DIR/repo.tar.gz" 2>/dev/null || true
            if [ -f "$BUILD_DIR/repo.tar.gz" ]; then
                tar xzf "$BUILD_DIR/repo.tar.gz" -C "$BUILD_DIR" 2>/dev/null || true
                SRC_DIR=$(ls -d "$BUILD_DIR"/*/ 2>/dev/null | head -1)
                [ -n "$SRC_DIR" ] && mv "$SRC_DIR" "$BUILD_DIR/src"
            fi
        fi
        if [ -f "$BUILD_DIR/src/go.mod" ]; then
            (cd "$BUILD_DIR/src" && go build -o "$PREFIX/bin/$BINARY" -ldflags="-s -w" ./cmd/vpsGuard)
            rm -rf "$BUILD_DIR"
            installed_from="source"
            info "Binary built: $PREFIX/bin/$BINARY"
        else
            rm -rf "$BUILD_DIR"
            error "Failed to download source. Check network or install Go manually."
            exit 1
        fi
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
log_dir: /var/log/vpsGuard
cache_dir: /var/cache/vpsGuard
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
  table: vpsGuard
  set_name: blacklist
  set_name_v6: blacklist6
  default_block_hours: 24
  whitelist:
    - 127.0.0.1
    - ::1
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
daily_report:
  enabled: false
  interval_hours: 24
  send_telegram: true
  send_email: false
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
        chown vpsGuard:vpsGuard "$CONFIG_DIR/config.yaml"
        chmod 640 "$CONFIG_DIR/config.yaml"
        info "Config created: $CONFIG_DIR/config.yaml"
    fi
fi

# ── Install systemd service ────────────────────────────────
info "Installing systemd service..."
if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Install systemd service to $SYSTEMD_DIR/vpsGuard.service"
else
    if fetch "$RAW_BASE/deploy/vpsGuard.service" > /dev/null 2>&1; then
        fetch "$RAW_BASE/deploy/vpsGuard.service" > "$SYSTEMD_DIR/vpsGuard.service"
    else
        cat > "$SYSTEMD_DIR/vpsGuard.service" << 'SVCEOF'
[Unit]
Description=vpsGuard Security Agent
Documentation=https://github.com/vpsik-lab/vpsGuard
After=network.target nftables.service
[Service]
Type=simple
ExecStart=/usr/local/bin/vpsGuard -config /etc/vpsGuard/config.yaml
Restart=always
RestartSec=5
User=vpsGuard
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYSLOG
AmbientCapabilities=CAP_NET_ADMIN CAP_SYSLOG
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log/vpsGuard /var/cache/vpsGuard
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
    echo "[DRY-RUN] Install logrotate to /etc/logrotate.d/vpsGuard"
else
    if fetch "$RAW_BASE/deploy/vpsGuard.logrotate" > /dev/null 2>&1; then
        fetch "$RAW_BASE/deploy/vpsGuard.logrotate" > /etc/logrotate.d/vpsGuard
    else
        cat > /etc/logrotate.d/vpsGuard << 'LOGEOF'
/var/log/vpsGuard/*.log
/var/log/vpsGuard/*.jsonl
{
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    postrotate
        /usr/local/bin/vpsGuard -hash-chain /var/log/vpsGuard
    endscript
}
LOGEOF
    fi
fi

# ── Start service ──────────────────────────────────────────
if [ "$DRY_RUN" = false ]; then
    run systemctl daemon-reload
    run systemctl enable vpsGuard
    run systemctl start vpsGuard

    sleep 2
    if systemctl is-active --quiet vpsGuard; then
        info "Service is running"
    else
        warn "Service may not have started. Check: journalctl -u vpsGuard"
    fi
fi

# ── Summary ─────────────────────────────────────────────────
if [ "$DRY_RUN" = false ]; then
    cat <<EOF

╔══════════════════════════════════════════╗
║   vpsGuard installed successfully!     ║
╚══════════════════════════════════════════╝

  Binary:    $PREFIX/bin/$BINARY
  Config:    $CONFIG_DIR/config.yaml
  Logs:      $LOG_DIR/
  Service:   vpsGuard ($installed_from)

  Commands:
    systemctl status vpsGuard
    journalctl -u vpsGuard -f
    nano $CONFIG_DIR/config.yaml
    bash deploy/harden.sh   (VPS hardening)

  Configure APIs:
    $CONFIG_DIR/config.yaml
      \u2192 threat.abuseipdb_key
      \u2192 threat.alienvault_key
      \u2192 notify.telegram_token

EOF
fi
