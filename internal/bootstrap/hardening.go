package bootstrap

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"go.uber.org/zap"

	"github.com/vps-guard/vps-guard/internal/config"
)

func RunHardening(cfg *config.Config, logger *zap.Logger) {
	logger.Info("starting system hardening")

	steps := []struct {
		name string
		fn   func() error
	}{
		{"system_updates", runSystemUpdates},
		{"configure_ssh", func() error { return configureSSH(cfg) }},
		{"setup_firewall", setupFirewall},
		{"install_fail2ban", installFail2ban},
		{"kernel_hardening", kernelHardening},
	}

	for _, step := range steps {
		if err := step.fn(); err != nil {
			logger.Warn("hardening step failed", zap.String("step", step.name), zap.Error(err))
		} else {
			logger.Info("hardening step completed", zap.String("step", step.name))
		}
	}

	logger.Info("system hardening completed")
}

func runSystemUpdates() error {
	cmds := [][]string{
		{"apt-get", "update"},
		{"apt-get", "upgrade", "-y"},
		{"apt-get", "install", "-y", "unattended-upgrades", "ufw", "fail2ban", "nftables"},
	}
	for _, cmd := range cmds {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			return fmt.Errorf("%s failed: %w", strings.Join(cmd, " "), err)
		}
	}
	return nil
}

func configureSSH(cfg *config.Config) error {
	path := "/etc/ssh/sshd_config"
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	content := string(data)
	content = setConfigValue(content, "PermitRootLogin", "no")
	content = setConfigValue(content, "PasswordAuthentication", "no")
	content = setConfigValue(content, "MaxAuthTries", "3")
	content = setConfigValue(content, "MaxSessions", "3")
	content = setConfigValue(content, "Port", fmt.Sprintf("%d", cfg.Bootstrap.SSHPort))
	content = setConfigValue(content, "PubkeyAuthentication", "yes")

	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return err
	}

	return exec.Command("systemctl", "restart", "sshd").Run()
}

func setConfigValue(content, key, value string) string {
	lines := strings.Split(content, "\n")
	hasKey := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key) {
			lines[i] = fmt.Sprintf("%s %s", key, value)
			hasKey = true
		}
	}
	if !hasKey {
		lines = append(lines, fmt.Sprintf("%s %s", key, value))
	}
	return strings.Join(lines, "\n")
}

func setupFirewall() error {
	cmds := [][]string{
		{"ufw", "--force", "enable"},
		{"ufw", "default", "deny", "incoming"},
		{"ufw", "default", "allow", "outgoing"},
		{"ufw", "allow", "ssh"},
	}
	for _, cmd := range cmds {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			return fmt.Errorf("%s failed: %w", strings.Join(cmd, " "), err)
		}
	}
	return nil
}

func installFail2ban() error {
	config := `[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
`
	path := "/etc/fail2ban/jail.local"
	if err := os.WriteFile(path, []byte(config), 0644); err != nil {
		return err
	}
	return exec.Command("systemctl", "restart", "fail2ban").Run()
}

func kernelHardening() error {
	params := map[string]string{
		"net.ipv4.tcp_syncookies":              "1",
		"net.ipv4.tcp_synack_retries":          "2",
		"net.ipv4.conf.all.rp_filter":          "1",
		"net.ipv4.conf.default.rp_filter":      "1",
		"net.ipv4.conf.all.accept_source_route": "0",
		"net.ipv6.conf.all.accept_source_route": "0",
		"net.ipv4.icmp_echo_ignore_broadcasts":  "1",
		"net.ipv4.icmp_ignore_bogus_error_responses": "1",
	}

	path := "/etc/sysctl.d/99-vps-guard.conf"
	var lines []string
	for k, v := range params {
		lines = append(lines, fmt.Sprintf("%s=%s", k, v))
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}
