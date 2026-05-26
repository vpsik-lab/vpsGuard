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

// ensureSets creates the nftables table, sets, chain and drop rules if they don't exist.
// Each command is passed as separate arguments (never a single concatenated string)
// to eliminate any argument-injection risk from config-controlled table/set names.
func (m *NftablesManager) ensureSets() error {
	cmds := [][]string{
		{"add", "table", "inet", m.table},
		{"add", "set", "inet", m.table, m.setName, "{ type ipv4_addr; flags timeout; }"},
		{"add", "set", "inet", m.table, m.setNameV6, "{ type ipv6_addr; flags timeout; }"},
		{"add", "chain", "inet", m.table, "input", "{ type filter hook input priority 0; policy accept; }"},
		{"add", "rule", "inet", m.table, "input", fmt.Sprintf("ip saddr @%s drop", m.setName)},
		{"add", "rule", "inet", m.table, "input", fmt.Sprintf("ip6 saddr @%s drop", m.setNameV6)},
	}

	for _, args := range cmds {
		// Ignore errors: commands are idempotent — sets/chains already existing is OK.
		exec.Command("nft", args...).Run() //nolint:errcheck
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
	m.logger.Info("blocking IP",
		zap.String("ip", ip),
		zap.String("set", set),
		zap.Duration("duration", duration),
	)
	// Separate args — never interpolate IP or table names into a single string.
	return exec.CommandContext(ctx, "nft", "add", "element", "inet", m.table, set,
		fmt.Sprintf("{ %s timeout %ds }", ip, timeout)).Run()
}

func (m *NftablesManager) UnblockIP(ctx context.Context, ip string) error {
	set := m.setForIP(ip)
	return exec.CommandContext(ctx, "nft", "delete", "element", "inet", m.table, set,
		fmt.Sprintf("{ %s }", ip)).Run()
}

func (m *NftablesManager) IsBlocked(ctx context.Context, ip string) (bool, error) {
	set := m.setForIP(ip)
	out, err := exec.CommandContext(ctx, "nft", "list", "set", "inet", m.table, set).Output()
	if err != nil {
		return false, err
	}
	return containsIP(string(out), ip), nil
}

// ListBlocked returns all IPs currently in the nftables set.
// Pass ipv6=true to query the IPv6 set, false for IPv4.
func (m *NftablesManager) ListBlocked(ctx context.Context, ipv6 bool) ([]string, error) {
	set := m.setName
	if ipv6 {
		set = m.setNameV6
	}
	out, err := exec.CommandContext(ctx, "nft", "list", "set", "inet", m.table, set).Output()
	if err != nil {
		return nil, err
	}
	return parseNftSetElements(string(out)), nil
}

// parseNftSetElements extracts individual IP addresses from nft list set output.
// Example output line:  "elements = { 1.2.3.4 timeout 86400s expires ..., 5.6.7.8 ... }"
func parseNftSetElements(output string) []string {
	var ips []string
	// Find the elements block
	start := strings.Index(output, "elements = {")
	if start == -1 {
		return ips
	}
	block := output[start:]
	end := strings.Index(block, "}")
	if end == -1 {
		return ips
	}
	block = block[len("elements = {"):end]
	// Each element is "IP timeout Xs expires Ys," — split on comma
	for _, part := range strings.Split(block, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// The IP is always the first token
		fields := strings.Fields(part)
		if len(fields) > 0 && net.ParseIP(fields[0]) != nil {
			ips = append(ips, fields[0])
		}
	}
	return ips
}

func containsIP(output, ip string) bool {
	return strings.Contains(output, ip)
}
