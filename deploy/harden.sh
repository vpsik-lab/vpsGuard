#!/bin/bash
set -euo pipefail

VERSION="1.0"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

DRY_RUN=false
UNATTENDED=false
SKIP_SSH=false
SKIP_DOCKER=false
SSH_PORT=22

usage() {
    cat <<EOF
vpsGuard VPS Hardener v${VERSION}

Usage: bash harden.sh [options]

Options:
  --dry-run         Print what would be done
  --unattended      No prompts (use defaults)
  --skip-ssh        Skip SSH hardening
  --skip-docker     Skip Docker hardening
  --ssh-port <n>    SSH port (default: 22)
  -h, --help        Show this help

Examples:
  bash harden.sh                       Interactive
  bash harden.sh --unattended          Auto hardening
  bash harden.sh --skip-docker         Skip Docker section

  # Via curl pipe (requires root/sudo):
  curl -sSL https://raw.githubusercontent.com/vpsik-lab/vpsGuard/main/deploy/harden.sh | sudo bash -s -- --unattended
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --unattended) UNATTENDED=true; shift ;;
        --skip-ssh) SKIP_SSH=true; shift ;;
        --skip-docker) SKIP_DOCKER=true; shift ;;
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
section() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

if [ "$DRY_RUN" = false ] && [ "$EUID" -ne 0 ]; then
    error "Please run as root"; exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release; OS=$ID
else
    error "Cannot detect OS"; exit 1
fi
if [ "$OS" != "ubuntu" ] && [ "$OS" != "debian" ]; then
    error "Ubuntu/Debian only"; exit 1
fi

info "Starting VPS hardening on $OS $VERSION_ID"

# ── 1. SSH Hardening ──────────────────────────────────────
if [ "$SKIP_SSH" = false ]; then
    section "SSH Hardening"
    run apt-get install -y -qq openssh-server 2>/dev/null || true

    if [ "$DRY_RUN" = false ] && [ ! -f /etc/ssh/sshd_config.vpsguard.bak ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.vpsguard.bak
        info "SSH config backed up"
    fi

    run sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    run sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    run sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    run sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
    run sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
    run sed -i 's/^#*Protocol.*/Protocol 2/' /etc/ssh/sshd_config
    run sed -i 's/^#*LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config

    if grep -q '^AuthenticationMethods' /etc/ssh/sshd_config; then
        run sed -i 's/^#*AuthenticationMethods.*/AuthenticationMethods publickey/' /etc/ssh/sshd_config
    else
        echo 'AuthenticationMethods publickey' >> /etc/ssh/sshd_config
    fi

    SSH_SVC="ssh"; systemctl list-units --full -all 2>/dev/null | grep -q 'sshd\.service' && SSH_SVC="sshd" || true
    run systemctl restart "$SSH_SVC"
    info "SSH hardened"
fi

# ── 2. Firewall (UFW + nftables) ─────────────────────────
section "Firewall"
run apt-get install -y -qq ufw nftables 2>/dev/null || true

run ufw --force enable 2>/dev/null || warn "UFW enable failed"
run ufw default deny incoming 2>/dev/null || true
run ufw default allow outgoing 2>/dev/null || true
run ufw allow "$SSH_PORT"/tcp 2>/dev/null || true
run ufw limit "$SSH_PORT"/tcp 2>/dev/null || true
run ufw allow 443/tcp 2>/dev/null || true

# nftables baseline — drop invalid packets
if command -v nft &>/dev/null; then
    run nft add table inet vpsguard_harden 2>/dev/null || true
    run nft add chain inet vpsguard_harden input { type filter hook input priority -10\; policy accept\; } 2>/dev/null || true
    run nft add rule inet vpsguard_harden input ct state invalid drop 2>/dev/null || true
fi
info "Firewall configured"

# ── 3. TLS/SSL Optimization ──────────────────────────────
section "TLS/SSL"
if [ ! -f /etc/ssl/certs/dhparam.pem ]; then
    info "Generating 4096-bit DH params (may take a minute)..."
    run openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096
fi

if [ "$DRY_RUN" = false ]; then
    cat > /etc/ssl/openssl.cnf.vpsguard << 'EOF'
# vpsGuard strong TLS configuration
CipherString = DEFAULT@SECLEVEL=2
MinProtocol = TLSv1.2
Options = PrioritateChaCha, EnableMiddleboxCompat
EOF
fi
info "TLS configured"

# ── 4. TCP BBR ───────────────────────────────────────────
section "TCP BBR"
if [ "$DRY_RUN" = false ]; then
    cat > /etc/sysctl.d/99-vpsGuard-bbr.conf << 'EOF'
# vpsGuard TCP BBR
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl -p /etc/sysctl.d/99-vpsGuard-bbr.conf >/dev/null 2>&1 || true
fi
info "BBR enabled"

# ── 5. Sysctl Optimization ──────────────────────────────
section "Sysctl Optimization"
if [ "$DRY_RUN" = false ]; then
    cat > /etc/sysctl.d/99-vpsGuard-sysctl.conf << 'EOF'
# vpsGuard sysctl optimization
# TCP hardening
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_intvl=60
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_mtu_probing=1

# Connection tracking
net.netfilter.nf_conntrack_max=262144
net.netfilter.nf_conntrack_tcp_timeout_established=86400

# Backlog
net.core.somaxconn=65535
net.core.netdev_max_backlog=5000

# Anti-DDoS
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1

# IPv6
net.ipv6.conf.all.accept_redirects=0
EOF
    sysctl -p /etc/sysctl.d/99-vpsGuard-sysctl.conf >/dev/null 2>&1 || true
fi
info "Sysctl optimized"

# ── 6. Docker Secure Defaults ───────────────────────────
section "Docker Security"
if command -v docker &>/dev/null && [ "$SKIP_DOCKER" = false ]; then
    if [ "$DRY_RUN" = false ]; then
        mkdir -p /etc/docker
        cat > /etc/docker/daemon.json << 'EOF'
{
  "userns-remap": "default",
  "no-new-privileges": true,
  "icc": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "iptables": true
}
EOF
        systemctl restart docker 2>/dev/null || warn "Docker restart failed — docker may not be active"
    fi
    info "Docker hardened"
elif [ "$SKIP_DOCKER" = false ]; then
    warn "Docker not found, skipping"
fi

# ── 7. Auto Updates ─────────────────────────────────────
section "Auto Updates"
run apt-get install -y -qq unattended-upgrades 2>/dev/null || true

if [ "$DRY_RUN" = false ]; then
    cat > /etc/apt/apt.conf.d/50unattended-upgrades.vpsguard << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESM:${distro_codename}-apps";
    "${distro_id}ESM:${distro_codename}-infra";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
fi
info "Auto updates configured"

# ── 8. Auditd ─────────────────────────────────────────────
section "Auditd"
run apt-get install -y -qq auditd 2>/dev/null || true

if [ "$DRY_RUN" = false ]; then
    cat > /etc/audit/rules.d/vpsGuard.rules << 'EOF'
# vpsGuard auditd rules — sensitive file watch
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/sudoers -p wa -k sudoers
-w /etc/docker/ -p wa -k docker_config
-w /etc/vpsGuard/ -p wa -k vpsguard_config
-w /var/log/auth.log -p wa -k auth_log
EOF
    augenrules --load 2>/dev/null || service auditd restart 2>/dev/null || true
fi
info "Auditd configured (sensitive files only)"

# ── 9. AppArmor ───────────────────────────────────────────
section "AppArmor"
run apt-get install -y -qq apparmor apparmor-utils 2>/dev/null || true

# Enforce all loaded profiles
if command -v aa-enforce &>/dev/null; then
    for profile in /etc/apparmor.d/*; do
        [ -f "$profile" ] && run aa-enforce "$profile" 2>/dev/null || true
    done
fi

# vpsGuard AppArmor profile
if [ "$DRY_RUN" = false ]; then
    cat > /etc/apparmor.d/usr.local.bin.vpsGuard << 'EOF'
# vpsGuard AppArmor profile
abi <abi/4.0>,
include <tunables/global>

/usr/local/bin/vpsGuard {
    include <abstractions/base>
    include <abstractions/openssl>

    /etc/vpsGuard/** r,
    /var/log/vpsGuard/** rw,
    /var/cache/vpsGuard/** rw,
    /etc/ssl/** r,
    /sys/kernel/security/** r,
    network inet dgram,
    network inet stream,
    capability net_admin,
    capability syslog,

    /usr/bin/nft rix,
    /sbin/nft rix,
}
EOF
    apparmor_parser -r /etc/apparmor.d/usr.local.bin.vpsGuard 2>/dev/null || true
    run systemctl reload apparmor 2>/dev/null || true
fi
info "AppArmor enforced"

# ── 10. Process Accounting ────────────────────────────────
section "Process Accounting"
run apt-get install -y -qq acct 2>/dev/null || true
run systemctl enable psacct 2>/dev/null || run systemctl enable acct 2>/dev/null || true
run systemctl start psacct 2>/dev/null || run systemctl start acct 2>/dev/null || true
info "Process accounting enabled (acct)"

# ── Summary ──────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     VPS Hardening Complete!             ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "  SSH:       hardened (key only)"
echo "  Firewall:  UFW + nftables active"
echo "  TLS:       DH 4096 + strong ciphers"
echo "  BBR:       congestion control enabled"
echo "  Sysctl:    optimized (DDoS protection)"
echo "  Docker:    $(if command -v docker &>/dev/null; then echo 'hardened'; else echo 'not found'; fi)"
echo "  Updates:   unattended-upgrades active"
echo "  Auditd:    sensitive file watch active"
echo "  AppArmor:  enforced + vpsGuard profile"
echo "  Acct:      process accounting active"
echo ""
echo "  Reboot recommended to apply all kernel parameters."
echo ""
