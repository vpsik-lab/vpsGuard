package firewall

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vpsik-lab/vpsGuard/internal/config"
)

type NftablesManager struct {
	cfg       *config.Config
	logger    *zap.Logger
	table     string
	setName   string
	setNameV6 string
}

func NewNftables(cfg *config.Config, logger *zap.Logger) (*NftablesManager, error) {
	m := &NftablesManager{
		cfg:       cfg,
		logger:    logger,
		table:     cfg.Firewall.Table,
		setName:   cfg.Firewall.SetName,
		setNameV6: cfg.Firewall.SetNameV6,
	}

	if err := m.ensureSets(); err != nil {
		return nil, fmt.Errorf("failed to create nftables sets: %w", err)
	}

	return m, nil
}

func (m *NftablesManager) ensureSets() error {
	cmds := []string{
		fmt.Sprintf("add table inet %s", m.table),
		fmt.Sprintf("add set inet %s %s { type ipv4_addr; flags timeout; }", m.table, m.setName),
		fmt.Sprintf("add set inet %s %s { type ipv6_addr; flags timeout; }", m.table, m.setNameV6),
		fmt.Sprintf("add chain inet %s input { type filter hook input priority 0; policy accept; }", m.table),
		fmt.Sprintf("add rule inet %s input ip saddr @%s drop", m.table, m.setName),
		fmt.Sprintf("add rule inet %s input ip6 saddr @%s drop", m.table, m.setNameV6),
	}

	for _, cmd := range cmds {
		exec.Command("nft", cmd).Run()
	}

	return nil
}

func ipFamily(ip string) (string, string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", "", fmt.Errorf("invalid IP address: %s", ip)
	}
	if parsed.To4() != nil {
		return "ip", "ipv4_addr", nil
	}
	return "ip6", "ipv6_addr", nil
}

func (m *NftablesManager) setForIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return m.setName
	}
	if parsed.To4() != nil {
		return m.setName
	}
	return m.setNameV6
}

func (m *NftablesManager) BlockIP(ctx context.Context, ip string, duration time.Duration) error {
	set := m.setForIP(ip)
	timeout := int(duration.Seconds())
	cmd := fmt.Sprintf("add element inet %s %s { %s timeout %ds }", m.table, set, ip, timeout)
	m.logger.Info("blocking IP",
		zap.String("ip", ip),
		zap.String("set", set),
		zap.Duration("duration", duration),
	)
	return exec.CommandContext(ctx, "nft", cmd).Run()
}

func (m *NftablesManager) UnblockIP(ctx context.Context, ip string) error {
	set := m.setForIP(ip)
	cmd := fmt.Sprintf("delete element inet %s %s { %s }", m.table, set, ip)
	return exec.CommandContext(ctx, "nft", cmd).Run()
}

func (m *NftablesManager) IsBlocked(ctx context.Context, ip string) (bool, error) {
	set := m.setForIP(ip)
	cmd := fmt.Sprintf("list set inet %s %s", m.table, set)
	out, err := exec.CommandContext(ctx, "nft", cmd).Output()
	if err != nil {
		return false, err
	}
	return containsIP(string(out), ip), nil
}

func containsIP(output, ip string) bool {
	return strings.Contains(output, ip)
}
