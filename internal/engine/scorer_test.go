package engine

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/vpsik-lab/vpsGuard/internal/config"
	"github.com/vpsik-lab/vpsGuard/internal/pipeline"
	"github.com/vpsik-lab/vpsGuard/internal/threat"
)

func TestScoreResultVerdict(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{0, "clean"},
		{10, "low"},
		{25, "suspicious"},
		{50, "high"},
		{80, "critical"},
		{100, "critical"},
	}

	for _, tt := range tests {
		sr := &ScoreResult{FinalScore: tt.score}
		got := sr.Verdict()
		if got != tt.want {
			t.Errorf("ScoreResult{FinalScore=%d}.Verdict() = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestNewScorer(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	scorer := NewScorer(cfg, logger)
	if scorer == nil {
		t.Fatal("NewScorer returned nil")
	}
}

func TestScorerEvaluateNoIntel(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()

	scorer := NewScorer(cfg, logger)
	intel := threat.NewIntelClient(cfg, logger)

	evt := pipeline.Envelope{
		Event: pipeline.BaseEvent{
			IP: "1.2.3.4", SeverityVal: 5,
		},
	}

	result := scorer.Evaluate(context.Background(), evt, intel)
	if result == nil {
		t.Fatal("Evaluate returned nil")
	}
	if result.IP != "1.2.3.4" {
		t.Errorf("IP = %q, want %q", result.IP, "1.2.3.4")
	}
}

func TestScorerRecordEvent(t *testing.T) {
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

	for i := 0; i < 6; i++ {
		scorer.RecordEvent(evt)
	}

	score := scorer.behavioral.GetScore("1.2.3.4")
	if score <= 0 {
		t.Errorf("expected positive behavioral score after 6 records, got %d", score)
	}
}
