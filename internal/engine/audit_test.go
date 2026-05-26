package engine

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAuditLoggerLog(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "audit-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	logger := NewAuditLogger(tmpFile.Name())

	entry := AuditEntry{
		Timestamp: time.Now(),
		IP:        "1.2.3.4",
		TraceID:   "trace-123",
		EventType: "ssh_failed_login",
		Score:     85,
		Verdict:   "critical",
		Action:    "block",
		Reason:    "score_exceeded_block_threshold",
		Duration:  "24h0m0s",
		Sources:   []string{"abuseipdb", "behavioral"},
	}

	err = logger.Log(entry)
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !strings.Contains(string(data), "1.2.3.4") {
		t.Error("audit log missing IP")
	}
	if !strings.Contains(string(data), "block") {
		t.Error("audit log missing action")
	}

	// Verify valid JSON
	var decoded AuditEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON in audit log: %v", err)
	}
	if decoded.IP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", decoded.IP)
	}
}

func TestAuditLoggerMultipleEntries(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "audit-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	logger := NewAuditLogger(tmpFile.Name())

	for i := 0; i < 50; i++ {
		entry := AuditEntry{
			Timestamp: time.Now(),
			IP:        "10.0.0.1",
			EventType: "ssh_failed_login",
			Score:     i,
			Action:    "monitor",
		}
		if err := logger.Log(entry); err != nil {
			t.Fatalf("Log %d failed: %v", i, err)
		}
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 50 {
		t.Errorf("expected 50 lines, got %d", len(lines))
	}
}
