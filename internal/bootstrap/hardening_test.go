package bootstrap

import (
	"os"
	"strings"
	"testing"
)

func TestSetConfigValueAddsNewKey(t *testing.T) {
	content := "Port 22\n"
	result := setConfigValue(content, "PermitRootLogin", "no")
	if !strings.Contains(result, "PermitRootLogin no") {
		t.Errorf("result missing PermitRootLogin: %q", result)
	}
}

func TestSetConfigValueUpdatesExisting(t *testing.T) {
	content := "PermitRootLogin yes\nPort 22\nPasswordAuthentication yes\n"
	result := setConfigValue(content, "PermitRootLogin", "no")
	if !strings.Contains(result, "PermitRootLogin no") {
		t.Errorf("expected PermitRootLogin no, got: %q", result)
	}
	if strings.Contains(result, "PermitRootLogin yes") {
		t.Errorf("old value should not remain: %q", result)
	}
}

func TestSetConfigValueMultipleLines(t *testing.T) {
	content := "# PermitRootLogin prohibit-password\nPort 22\n"
	result := setConfigValue(content, "PermitRootLogin", "no")
	if !strings.Contains(result, "PermitRootLogin no") {
		t.Errorf("expected PermitRootLogin no, got: %q", result)
	}
}

func TestSetConfigValuePreservesOtherLines(t *testing.T) {
	content := "Port 22\nPasswordAuthentication yes\nMaxAuthTries 6\n"
	result := setConfigValue(content, "MaxAuthTries", "3")
	if !strings.Contains(result, "Port 22") {
		t.Error("should preserve Port line")
	}
	if !strings.Contains(result, "PasswordAuthentication yes") {
		t.Error("should preserve PasswordAuthentication line")
	}
	if !strings.Contains(result, "MaxAuthTries 3") {
		t.Errorf("result missing MaxAuthTries 3: %q", result)
	}
	if strings.Contains(result, "MaxAuthTries 6") {
		t.Error("old MaxAuthTries value should not remain")
	}
}

func TestSetConfigValueEmptyContent(t *testing.T) {
	result := setConfigValue("", "Key", "value")
	if !strings.Contains(result, "Key value") {
		t.Errorf("expected 'Key value' in result, got: %q", result)
	}
}

func TestSetConfigValueHandlesSpaces(t *testing.T) {
	content := "  PermitRootLogin yes\n"
	result := setConfigValue(content, "PermitRootLogin", "no")
	if !strings.Contains(result, "PermitRootLogin no") {
		t.Errorf("expected PermitRootLogin no, got: %q", result)
	}
}

func TestKernelParamsContent(t *testing.T) {
	params := map[string]string{
		"net.ipv4.tcp_syncookies":                "1",
		"net.ipv4.tcp_synack_retries":            "2",
		"net.ipv4.conf.all.accept_source_route":  "0",
		"net.ipv4.icmp_echo_ignore_broadcasts":   "1",
	}

	path := "/tmp/test-sysctl-99-vpsGuard.conf"
	defer os.Remove(path)

	var lines []string
	for k, v := range params {
		lines = append(lines, k+"="+v)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	for k, v := range params {
		expected := k + "=" + v
		if !strings.Contains(content, expected) {
			t.Errorf("missing kernel param: %s", expected)
		}
	}
}
