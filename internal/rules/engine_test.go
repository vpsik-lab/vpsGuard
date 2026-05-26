package rules

import (
	"testing"
	"time"

	"github.com/vpsik-lab/vpsGuard/internal/config"
	"github.com/vpsik-lab/vpsGuard/internal/pipeline"
)

func TestEngineDefaults(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()

	eng := NewEngine(cfg, nil)
	eng.LoadDefaults()

	eng.mu.RLock()
	n := len(eng.rules)
	eng.mu.RUnlock()

	if n == 0 {
		t.Fatal("expected default rules, got 0")
	}
	if n != 3 {
		t.Errorf("expected 3 default rules, got %d", n)
	}
}

func TestEvaluateMatch(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()

	eng := NewEngine(cfg, nil)
	eng.LoadDefaults()

	evt := pipeline.Envelope{
		Source: "journal",
		Event: pipeline.SSHFailedLogin{
			BaseEvent:  pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
			Username:   "root",
			Attempts:   15,
			WindowSec:  5,
			AuthMethod: "password",
		},
	}

	matched := eng.Evaluate(evt)
	if len(matched) == 0 {
		t.Fatal("expected at least 1 matched rule for SSH failed login with high attempts")
	}
}

func TestEvaluateNoMatch(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()

	eng := NewEngine(cfg, nil)
	eng.LoadDefaults()

	evt := pipeline.Envelope{
		Source: "unknown",
		Event:  pipeline.BaseEvent{Type: "unknown_type", IP: "1.2.3.4"},
	}

	matched := eng.Evaluate(evt)
	if len(matched) != 0 {
		t.Errorf("expected 0 matched rules for unknown event, got %d", len(matched))
	}
}

func TestEvaluateNumericConditions(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()

	eng := NewEngine(cfg, nil)

	// Load custom rules with numeric conditions
	yamlData := []byte(`
rules:
  - name: high_attempts
    description: Block high attempt rates
    conditions:
      type: ssh_failed_login
      attempts: ">5"
    action: block
    score_weight: 50
    duration: 24h
`)
	if err := eng.LoadFromYAML(yamlData); err != nil {
		t.Fatalf("LoadFromYAML() error = %v", err)
	}

	// Should match: Attempts = 10 > 5
	evt := pipeline.Envelope{
		Source: "journal",
		Event: pipeline.SSHFailedLogin{
			BaseEvent: pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
			Attempts: 10,
		},
	}
	matched := eng.Evaluate(evt)
	if len(matched) != 1 {
		t.Fatalf("expected 1 match for attempts >5 with Attempts=10, got %d", len(matched))
	}
	if matched[0].Name != "high_attempts" {
		t.Errorf("expected rule 'high_attempts', got %q", matched[0].Name)
	}

	// Should NOT match: Attempts = 2 not > 5
	evt2 := pipeline.Envelope{
		Source: "journal",
		Event: pipeline.SSHFailedLogin{
			BaseEvent: pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "5.6.7.8"},
			Attempts:  2,
		},
	}
	matched2 := eng.Evaluate(evt2)
	if len(matched2) != 0 {
		t.Errorf("expected 0 matches for attempts >5 with Attempts=2, got %d", len(matched2))
	}
}

func TestEvaluateWindowCondition(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()

	eng := NewEngine(cfg, nil)

	yamlData := []byte(`
rules:
  - name: fast_attacks
    description: Block fast sequential attacks
    conditions:
      type: ssh_failed_login
      window_seconds: "<30"
    action: block
    score_weight: 25
    duration: 1h
`)
	if err := eng.LoadFromYAML(yamlData); err != nil {
		t.Fatalf("LoadFromYAML() error = %v", err)
	}

	evt := pipeline.Envelope{
		Source: "journal",
		Event: pipeline.SSHFailedLogin{
			BaseEvent: pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
			WindowSec: 5,
		},
	}
	matched := eng.Evaluate(evt)
	if len(matched) != 1 {
		t.Fatalf("expected 1 match for window <30 with WindowSec=5, got %d", len(matched))
	}

	evt2 := pipeline.Envelope{
		Source: "journal",
		Event: pipeline.SSHFailedLogin{
			BaseEvent: pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
			WindowSec: 60,
		},
	}
	matched2 := eng.Evaluate(evt2)
	if len(matched2) != 0 {
		t.Errorf("expected 0 matches for window <30 with WindowSec=60, got %d", len(matched2))
	}
}

func TestCompareNumeric(t *testing.T) {
	tests := []struct {
		fieldVal  int
		condition string
		want      bool
	}{
		{10, ">5", true},
		{3, ">5", false},
		{5, ">5", false},
		{5, ">=5", true},
		{3, "<5", true},
		{5, "<5", false},
		{5, "=5", true},
		{5, "==5", true},
		{6, "==5", false},
		{10, "<=5", false},
		{3, "<=5", true},
		{100, ">90", true},
		{85, ">90", false},
	}

	for _, tt := range tests {
		got := compareNumeric(tt.fieldVal, tt.condition)
		if got != tt.want {
			t.Errorf("compareNumeric(%d, %q) = %v, want %v", tt.fieldVal, tt.condition, got, tt.want)
		}
	}
}

func TestCompareNumericInvalid(t *testing.T) {
	if compareNumeric(10, "") != false {
		t.Error("expected false for empty condition")
	}
	if compareNumeric(10, "abc") != false {
		t.Error("expected false for non-numeric condition")
	}
	if compareNumeric(10, ">") != false {
		t.Error("expected false for incomplete condition")
	}
}

func TestGetFieldValue(t *testing.T) {
	evt := pipeline.Envelope{
		Event: pipeline.SSHFailedLogin{
			BaseEvent:  pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
			Attempts:   10,
			WindowSec:  30,
			AuthMethod: "password",
		},
	}

	val, ok := getFieldValue(evt, "attempts")
	if !ok || val != 10 {
		t.Errorf("getFieldValue(attempts) = %d, %v; want 10, true", val, ok)
	}

	val, ok = getFieldValue(evt, "window_seconds")
	if !ok || val != 30 {
		t.Errorf("getFieldValue(window_seconds) = %d, %v; want 30, true", val, ok)
	}

	val, ok = getFieldValue(evt, "nonexistent")
	if ok {
		t.Errorf("getFieldValue(nonexistent) should return false")
	}
}

func TestLoadFromYAML(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()

	eng := NewEngine(cfg, nil)

	yamlData := []byte(`
rules:
  - name: test_rule
    description: Test rule
    conditions:
      type: ssh_failed_login
    action: block
    score_weight: 50
    duration: 48h
`)

	if err := eng.LoadFromYAML(yamlData); err != nil {
		t.Fatalf("LoadFromYAML() error = %v", err)
	}

	eng.mu.RLock()
	n := len(eng.rules)
	eng.mu.RUnlock()

	if n != 1 {
		t.Errorf("expected 1 rule, got %d", n)
	}
}

func TestInvalidYAML(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()

	eng := NewEngine(cfg, nil)

	badYAML := []byte(`rules: [invalid`)

	if err := eng.LoadFromYAML(badYAML); err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestDefaultRulesTimestamp(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()

	eng := NewEngine(cfg, nil)
	eng.LoadDefaults()

	// Verify aggressive_ssh rule with SSH failed login event at high frequency
	evt := pipeline.Envelope{
		Timestamp: time.Now(),
		Source:    "journal",
		Event: pipeline.SSHFailedLogin{
			BaseEvent:  pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
			Username:   "root",
			Attempts:   15,
			WindowSec:  5,
			AuthMethod: "password",
		},
	}

	matched := eng.Evaluate(evt)
	matchedNames := make(map[string]bool)
	for _, r := range matched {
		matchedNames[r.Name] = true
	}

	if !matchedNames["aggressive_ssh"] {
		t.Errorf("expected aggressive_ssh to match for 15 attempts in 5 seconds")
	}
}
