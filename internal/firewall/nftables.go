package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"go.uber.org/zap"

	"github.com/vps-guard/vps-guard/internal/config"
)

type NftablesManager struct {
	cfg     *config.Config
	logger  *zap.Logger
	table   string
	setName string
}

func NewNftables(cfg *config.Config, logger *zap.Logger) (*NftablesManager, error) {
	m := &NftablesManager{
		cfg:     cfg,
		logger:  logger,
		table:   cfg.Firewall.Table,
		setName: cfg.Firewall.SetName,
	}

	if err := m.ensureSet(); err != nil {
		return nil, fmt.Errorf("failed to create nftables set: %w", err)
	}

	return m, nil
}

func (m *NftablesManager) ensureSet() error {
	cmds := []string{
		fmt.Sprintf("add table inet %s", m.table),
		fmt.Sprintf("add set inet %s %s { type ipv4_addr; flags timeout; }", m.table, m.setName),
		fmt.Sprintf("add chain inet %s input { type filter hook input priority 0; policy accept; }", m.table),
		fmt.Sprintf("add rule inet %s input ip saddr @%s drop", m.table, m.setName),
	}

	for _, cmd := range cmds {
		exec.Command("nft", cmd).Run()
	}

	return nil
}

func (m *NftablesManager) BlockIP(ctx context.Context, ip string, duration time.Duration) error {
	timeout := int(duration.Seconds())
	cmd := fmt.Sprintf("add element inet %s %s { %s timeout %ds }", m.table, m.setName, ip, timeout)
	m.logger.Info("blocking IP", zap.String("ip", ip), zap.Duration("duration", duration))
	return exec.CommandContext(ctx, "nft", cmd).Run()
}

func (m *NftablesManager) UnblockIP(ctx context.Context, ip string) error {
	cmd := fmt.Sprintf("delete element inet %s %s { %s }", m.table, m.setName, ip)
	return exec.CommandContext(ctx, "nft", cmd).Run()
}

func (m *NftablesManager) IsBlocked(ctx context.Context, ip string) (bool, error) {
	cmd := fmt.Sprintf("list set inet %s %s", m.table, m.setName)
	out, err := exec.CommandContext(ctx, "nft", cmd).Output()
	if err != nil {
		return false, err
	}
	return containsIP(string(out), ip), nil
}

func containsIP(output, ip string) bool {
	for i := 0; i+len(ip) <= len(output); i++ {
		if output[i:i+len(ip)] == ip {
			return true
		}
	}
	return false
}
