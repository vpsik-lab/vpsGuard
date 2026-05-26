package engine

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vpsik-lab/vpsGuard/internal/config"
	"github.com/vpsik-lab/vpsGuard/internal/pipeline"
	"github.com/vpsik-lab/vpsGuard/internal/rules"
	"github.com/vpsik-lab/vpsGuard/internal/threat"
)

func TestPipelineRecordThenEvaluateAndDecide(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	scorer := NewScorer(cfg, logger)
	intel := threat.NewIntelClient(cfg, logger)
	dec := NewDecision(cfg, nil, logger)
	ruleEng := rules.NewEngine(cfg, logger)
	ruleEng.LoadDefaults()

	evt := pipeline.Envelope{
		Timestamp: time.Now(),
		Source:    "journal",
		Event: pipeline.SSHFailedLogin{
			BaseEvent:  pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
			Username:   "root",
			Attempts:   1,
			AuthMethod: "password",
		},
	}

	scorer.RecordEvent(evt)
	scores := scorer.Evaluate(context.Background(), evt, intel)
	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)

	if scores == nil {
		t.Fatal("Evaluate returned nil")
	}
	if scores.IP != "1.2.3.4" {
		t.Errorf("IP = %q, want %q", scores.IP, "1.2.3.4")
	}

	_ = actions
}

func TestPipelineScoreCrossesBlockThreshold(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.Scoring.BlockThreshold = 50
	logger := zap.NewNop()

	dec := NewDecision(cfg, nil, logger)
	ruleEng := rules.NewEngine(cfg, logger)
	ruleEng.LoadDefaults()

	scores := &ScoreResult{
		IP: "1.2.3.4", FinalScore: 75,
		AbuseScore: 80, OTXScore: 60, Behavioral: 90,
		Sources: []string{"abuseipdb", "alienvault", "behavioral"},
	}

	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
	}

	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)

	if len(actions) == 0 {
		t.Fatal("expected at least 1 action for score >= threshold")
	}

	blockFound := false
	notifyFound := false
	for _, a := range actions {
		if a.Block {
			blockFound = true
		}
		if a.Notify {
			notifyFound = true
		}
	}
	if !blockFound {
		t.Error("expected block action for score >= threshold")
	}
	if !notifyFound {
		t.Error("expected notify for block action")
	}
}

func TestPipelineQuarantineThreshold(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	dec := NewDecision(cfg, nil, logger)
	ruleEng := rules.NewEngine(cfg, logger)
	ruleEng.LoadDefaults()

	scores := &ScoreResult{
		IP: "1.2.3.4", FinalScore: 35,
		Behavioral: 40, Sources: []string{"behavioral"},
	}

	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
	}

	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)

	if len(actions) == 0 {
		t.Fatal("expected action for quarantine-level score")
	}
	if actions[0].Type != "quarantine" {
		t.Errorf("expected quarantine action, got %s", actions[0].Type)
	}
}

func TestPipelineMonitorOnly(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	dec := NewDecision(cfg, nil, logger)
	ruleEng := rules.NewEngine(cfg, logger)
	ruleEng.LoadDefaults()

	scores := &ScoreResult{
		IP: "1.2.3.4", FinalScore: 15,
		Behavioral: 10, Sources: []string{"behavioral"},
	}

	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
	}

	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)

	if len(actions) == 0 {
		t.Fatal("expected monitor action for low behavioral score")
	}
	if actions[0].Type != "monitor" {
		t.Errorf("expected monitor action, got %s", actions[0].Type)
	}
	if actions[0].Block {
		t.Error("monitor action should not block")
	}
}

func TestPipelineCleanSlateNoAction(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	dec := NewDecision(cfg, nil, logger)
	ruleEng := rules.NewEngine(cfg, logger)
	ruleEng.LoadDefaults()

	scores := &ScoreResult{
		IP: "1.2.3.4", FinalScore: 0,
	}

	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
	}

	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)

	if len(actions) != 0 {
		t.Errorf("expected 0 actions for clean IP, got %d", len(actions))
	}
}

func TestPipelineCentralFeedBlock(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	dec := NewDecision(cfg, nil, logger)
	ruleEng := rules.NewEngine(cfg, logger)
	ruleEng.LoadDefaults()

	scores := &ScoreResult{
		IP: "1.2.3.4", FinalScore: 20,
		CentralScore: 85, CentralConf: 95,
		Sources: []string{"central_feed"},
	}

	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
	}

	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)

	foundCentralBlock := false
	for _, a := range actions {
		if a.Reason == "central_feed_confirmed" && a.Block {
			foundCentralBlock = true
		}
	}
	if !foundCentralBlock {
		t.Errorf("expected central_feed_confirmed block action with FinalScore=%d CentralScore=%d, got %v",
			scores.FinalScore, scores.CentralScore, actions)
	}
}

func TestPipelineCentralFeedQuarantine(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	dec := NewDecision(cfg, nil, logger)
	ruleEng := rules.NewEngine(cfg, logger)
	ruleEng.LoadDefaults()

	scores := &ScoreResult{
		IP: "1.2.3.4", FinalScore: 20,
		CentralScore: 60, CentralConf: 70,
		Sources: []string{"central_feed"},
	}

	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
	}

	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)

	foundCentralQuarantine := false
	for _, a := range actions {
		if a.Reason == "central_feed_quarantine" {
			foundCentralQuarantine = true
		}
	}
	if !foundCentralQuarantine {
		t.Error("expected central_feed_quarantine action")
	}
}

func TestPipelineRuleEngineMatch(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	dec := NewDecision(cfg, nil, logger)

	ruleEng := rules.NewEngine(cfg, logger)
	yamlData := []byte(`
rules:
  - name: test_high_attempts
    description: Test rule
    conditions:
      type: ssh_failed_login
      attempts: ">5"
    action: block
    score_weight: 50
    duration: 24h
`)
	if err := ruleEng.LoadFromYAML(yamlData); err != nil {
		t.Fatalf("LoadFromYAML error: %v", err)
	}

	scores := &ScoreResult{
		IP: "1.2.3.4", FinalScore: 10,
		Behavioral: 5, Sources: []string{"behavioral"},
	}

	evt := pipeline.Envelope{
		Source: "journal",
		Event: pipeline.SSHFailedLogin{
			BaseEvent: pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
			Attempts: 10,
		},
	}

	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)

	ruleFound := false
	for _, a := range actions {
		if a.Reason == "rule:test_high_attempts" {
			ruleFound = true
		}
	}
	if !ruleFound {
		t.Errorf("expected rule match action, got actions: %v", actions)
	}
}

func TestPipelineScorerBehavioralAccumulation(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	scorer := NewScorer(cfg, logger)
	intel := threat.NewIntelClient(cfg, logger)

	evt := pipeline.Envelope{
		Source: "journal",
		Event: pipeline.SSHFailedLogin{
			BaseEvent:  pipeline.BaseEvent{Type: pipeline.EventSSHFailedLogin, IP: "1.2.3.4"},
			Username:   "root",
			Attempts:   1,
			AuthMethod: "password",
		},
	}

	var prevScore int
	for i := 0; i < 20; i++ {
		scorer.RecordEvent(evt)
		scores := scorer.Evaluate(context.Background(), evt, intel)
		if scores == nil {
			t.Fatal("Evaluate returned nil")
		}
		if i >= 10 && scores.Behavioral < prevScore {
			t.Errorf("behavioral score decreased at iteration %d: %d -> %d", i, prevScore, scores.Behavioral)
		}
		prevScore = scores.Behavioral
	}
}

func TestPipelineCleanup(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	scorer := NewScorer(cfg, logger)

	evt := pipeline.Envelope{
		Event: pipeline.SSHFailedLogin{
			BaseEvent: pipeline.BaseEvent{IP: "1.2.3.4"},
			Username:  "root",
		},
	}

	for i := 0; i < 10; i++ {
		scorer.RecordEvent(evt)
	}

	scorer.behavioral.Cleanup()
	scorer.memory.Cleanup()
}
