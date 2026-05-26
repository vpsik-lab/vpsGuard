package engine

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/vpsik-lab/vpsGuard/internal/config"
	"github.com/vpsik-lab/vpsGuard/internal/pipeline"
	"github.com/vpsik-lab/vpsGuard/internal/rules"
)

func TestDecisionEvaluateBlock(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	dec := NewDecision(cfg, nil, logger)
	ruleEng := rules.NewEngine(cfg, logger)
	ruleEng.LoadDefaults()

	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{IP: "1.2.3.4", SeverityVal: 5},
	}

	scores := &ScoreResult{
		IP: "1.2.3.4", FinalScore: 85,
		AbuseScore: 90, OTXScore: 80,
		Behavioral: 30, Temporal: 10,
		Sources: []string{"abuseipdb", "alienvault", "behavioral"},
	}

	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)
	if len(actions) == 0 {
		t.Fatal("expected at least 1 action for high score")
	}

	hasBlock := false
	for _, a := range actions {
		if a.Block {
			hasBlock = true
			break
		}
	}
	if !hasBlock {
		t.Error("expected block action for score 85, got:", actions)
	}
}

func TestDecisionEvaluateMonitor(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	dec := NewDecision(cfg, nil, logger)
	ruleEng := rules.NewEngine(cfg, logger)
	ruleEng.LoadDefaults()

	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{IP: "1.2.3.4", SeverityVal: 5},
	}

	scores := &ScoreResult{
		IP: "1.2.3.4", FinalScore: 10,
		Behavioral: 5, Sources: []string{"behavioral"},
	}

	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)
	if len(actions) == 0 {
		t.Fatal("expected monitor action for behavioral anomaly")
	}

	if actions[0].Type != "monitor" {
		t.Errorf("expected monitor action, got %s", actions[0].Type)
	}
}

func TestDecisionEvaluateRateLimit(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	dec := NewDecision(cfg, nil, logger)
	ruleEng := rules.NewEngine(cfg, logger)
	ruleEng.LoadDefaults()

	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{IP: "1.2.3.4"},
	}

	// rate_limit_score = 40, block_threshold = 60 → score 50 hits rate limit
	scores := &ScoreResult{
		IP: "1.2.3.4", FinalScore: 50,
		Behavioral: 50, Sources: []string{"behavioral"},
	}

	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)
	if len(actions) == 0 {
		t.Fatal("expected action for rate limit score")
	}

	if actions[0].Type != "rate_limit" {
		t.Errorf("expected rate_limit action, got %s", actions[0].Type)
	}

	if actions[0].Notify {
		t.Error("rate_limit should not notify")
	}

	if !actions[0].Block {
		t.Error("rate_limit should block (short duration)")
	}

	if actions[0].Duration.Minutes() != float64(cfg.Scoring.RateLimitMin) {
		t.Errorf("expected %d min rate limit, got %v", cfg.Scoring.RateLimitMin, actions[0].Duration)
	}
}

func TestDecisionEvaluateRateLimitBelowThreshold(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	dec := NewDecision(cfg, nil, logger)
	ruleEng := rules.NewEngine(cfg, logger)
	ruleEng.LoadDefaults()

	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{IP: "1.2.3.4"},
	}

	// 35 is below rate_limit_score (40) but above quarantine_score (30)
	scores := &ScoreResult{
		IP: "1.2.3.4", FinalScore: 35,
		Behavioral: 35, Sources: []string{"behavioral"},
	}

	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)
	if len(actions) == 0 {
		t.Fatal("expected action for quarantine score")
	}

	if actions[0].Type != "quarantine" {
		t.Errorf("expected quarantine for score 35, got %s", actions[0].Type)
	}
}

func TestDecisionEvaluateCentralFeed(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	dec := NewDecision(cfg, nil, logger)
	ruleEng := rules.NewEngine(cfg, logger)
	ruleEng.LoadDefaults()

	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{IP: "1.2.3.4", SeverityVal: 5},
	}

	scores := &ScoreResult{
		IP: "1.2.3.4", FinalScore: 30,
		CentralScore: 85, CentralConf: 92,
		Sources: []string{"central_feed"},
	}

	actions := dec.Evaluate(context.Background(), evt, scores, ruleEng)
	if len(actions) == 0 {
		t.Fatal("expected action for central feed high score")
	}
}
