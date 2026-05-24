package engine

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/vps-guard/vps-guard/internal/config"
	"github.com/vps-guard/vps-guard/internal/firewall"
	"github.com/vps-guard/vps-guard/internal/pipeline"
	"github.com/vps-guard/vps-guard/internal/rules"
)

func TestDecisionEvaluateBlock(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	fw, err := firewall.NewNftables(cfg, logger)
	if err != nil {
		t.Skip("nftables not available:", err)
	}

	dec := NewDecision(cfg, fw, logger)
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

	fw, err := firewall.NewNftables(cfg, logger)
	if err != nil {
		t.Skip("nftables not available:", err)
	}

	dec := NewDecision(cfg, fw, logger)
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

func TestDecisionEvaluateCentralFeed(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	fw, err := firewall.NewNftables(cfg, logger)
	if err != nil {
		t.Skip("nftables not available:", err)
	}

	dec := NewDecision(cfg, fw, logger)
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
