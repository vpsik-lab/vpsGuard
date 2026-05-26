package engine

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/vpsik-lab/vpsGuard/internal/config"
	"github.com/vpsik-lab/vpsGuard/internal/firewall"
	"github.com/vpsik-lab/vpsGuard/internal/pipeline"
	"github.com/vpsik-lab/vpsGuard/internal/rules"
)

type Action struct {
	Type     string        `json:"type"`
	Score    int           `json:"score"`
	Block    bool          `json:"block"`
	Duration time.Duration `json:"duration"`
	Notify   bool          `json:"notify"`
	Reason   string        `json:"reason"`
}

type DecisionEngine struct {
	cfg    *config.Config
	logger *zap.Logger
	fw     *firewall.NftablesManager
}

func NewDecision(cfg *config.Config, fw *firewall.NftablesManager, logger *zap.Logger) *DecisionEngine {
	return &DecisionEngine{
		cfg:    cfg,
		logger: logger,
		fw:     fw,
	}
}

func (d *DecisionEngine) Evaluate(ctx context.Context, evt pipeline.Envelope, scores *ScoreResult, rulesEngine *rules.Engine) []Action {
	var actions []Action
	ip := evt.SourceIP()

	blockThreshold := d.cfg.Scoring.BlockThreshold
	rateLimitScore := d.cfg.Scoring.RateLimitScore
	rateLimitMin := time.Duration(d.cfg.Scoring.RateLimitMin) * time.Minute
	quarantineScore := d.cfg.Scoring.QuarantineScore
	quarantineMin := time.Duration(d.cfg.Scoring.QuarantineMin) * time.Minute
	defaultBlock := time.Duration(d.cfg.Firewall.DefaultBlockDuration) * time.Hour

	switch {
	case scores.FinalScore >= blockThreshold:
		actions = append(actions, Action{
			Type:     "block",
			Score:    scores.FinalScore,
			Block:    true,
			Duration: defaultBlock,
			Notify:   true,
			Reason:   "score_exceeded_block_threshold",
		})
		d.logger.Info("blocking IP",
			zap.String("ip", ip),
			zap.Int("score", scores.FinalScore),
			zap.Duration("duration", defaultBlock),
		)

	case scores.FinalScore >= rateLimitScore:
		actions = append(actions, Action{
			Type:     "rate_limit",
			Score:    scores.FinalScore,
			Block:    true,
			Duration: rateLimitMin,
			Notify:   false,
			Reason:   "rate_limit_applied",
		})
		d.logger.Info("rate limiting IP",
			zap.String("ip", ip),
			zap.Int("score", scores.FinalScore),
			zap.Duration("duration", rateLimitMin),
		)

	case scores.FinalScore >= quarantineScore:
		actions = append(actions, Action{
			Type:     "quarantine",
			Score:    scores.FinalScore,
			Block:    true,
			Duration: quarantineMin,
			Notify:   true,
			Reason:   "temporary_quarantine",
		})
		d.logger.Info("quarantining IP",
			zap.String("ip", ip),
			zap.Int("score", scores.FinalScore),
			zap.Duration("duration", quarantineMin),
		)
	}

	if scores.CentralScore >= d.cfg.Scoring.CentralBlockThreshold && len(actions) == 0 {
		actions = append(actions, Action{
			Type:     "block",
			Score:    scores.FinalScore,
			Block:    true,
			Duration: defaultBlock,
			Notify:   true,
			Reason:   "central_feed_confirmed",
		})
		d.logger.Info("blocking from central feed",
			zap.String("ip", ip),
			zap.Int("central_score", scores.CentralScore),
			zap.Int("confidence", scores.CentralConf),
		)
	} else if scores.CentralScore >= d.cfg.Scoring.CentralQuarThreshold && len(actions) == 0 {
		actions = append(actions, Action{
			Type:     "quarantine",
			Score:    scores.FinalScore,
			Block:    true,
			Duration: quarantineMin,
			Notify:   true,
			Reason:   "central_feed_quarantine",
		})
	}

	matchedRules := rulesEngine.Evaluate(evt)
	for _, rule := range matchedRules {
		if rule.ScoreAdd > 0 && len(actions) == 0 {
			actions = append(actions, Action{
				Type:     "rule_match",
				Score:    scores.FinalScore + rule.ScoreAdd,
				Block:    rule.Action == "block",
				Duration: defaultBlock,
				Notify:   true,
				Reason:   "rule:" + rule.Name,
			})
		}
	}

	if len(actions) == 0 && scores.Behavioral > 0 {
		actions = append(actions, Action{
			Type:     "monitor",
			Score:    scores.FinalScore,
			Block:    false,
			Notify:   false,
			Reason:   "behavioral_anomaly_tracking",
		})
	}

	return actions
}
