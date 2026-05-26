package engine

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/vpsik-lab/vpsGuard/internal/config"
	"github.com/vpsik-lab/vpsGuard/internal/monitor"
	"github.com/vpsik-lab/vpsGuard/internal/pipeline"
	"github.com/vpsik-lab/vpsGuard/internal/threat"
)

type ScoreResult struct {
	IP           string
	AbuseScore   int
	OTXScore     int
	CentralScore int
	CentralConf  int
	Behavioral   int
	Temporal     int
	FinalScore   int
	Sources      []string
}

func (s *ScoreResult) Verdict() string {
	switch {
	case s.FinalScore >= 80:
		return "critical"
	case s.FinalScore >= 50:
		return "high"
	case s.FinalScore >= 25:
		return "suspicious"
	case s.FinalScore > 0:
		return "low"
	default:
		return "clean"
	}
}

func (s *ScoreResult) String() string {
	return fmt.Sprintf("IP=%s Score=%d Verdict=%s Sources=%v",
		s.IP, s.FinalScore, s.Verdict(), s.Sources)
}

type Scorer struct {
	cfg        *config.Config
	logger     *zap.Logger
	behavioral *monitor.BehavioralAnalyzer
	memory     *ReputationMemory
}

func NewScorer(cfg *config.Config, logger *zap.Logger) *Scorer {
	return &Scorer{
		cfg:        cfg,
		logger:     logger,
		behavioral: monitor.NewBehavioralAnalyzer(
			time.Duration(cfg.Scoring.BehaviorWindowMinutes)*time.Minute,
			cfg.Scoring.BehaviorThreshold,
		),
		memory: NewReputationMemory(time.Duration(cfg.Scoring.TemporalTTLHours) * time.Hour),
	}
}

func (s *Scorer) Evaluate(ctx context.Context, evt pipeline.Envelope, intel *threat.IntelClient) *ScoreResult {
	ip := evt.SourceIP()
	result := &ScoreResult{IP: ip}

	intelResult := intel.CheckIP(ctx, ip)
	result.AbuseScore = intelResult.AbuseScore
	result.OTXScore = intelResult.OTXScore
	result.CentralScore = intelResult.CentralScore
	result.CentralConf = intelResult.CentralConf

	result.Behavioral = s.behavioral.GetScore(ip)
	result.Temporal = s.memory.GetScore(ip)

	wAbuse := s.cfg.Scoring.AbuseIPDBWeight
	wOTX := s.cfg.Scoring.AlienVaultWeight
	wBehav := s.cfg.Scoring.BehaviorWeight
	wTemp := s.cfg.Scoring.TemporalWeight
	wCentral := s.cfg.Scoring.CentralWeight
	totalW := wAbuse + wOTX + wBehav + wTemp + wCentral

	if totalW <= 0 {
		totalW = 1
	}

	weightedSum := float64(result.AbuseScore)*wAbuse +
		float64(result.OTXScore)*wOTX +
		float64(result.Behavioral)*wBehav +
		float64(result.Temporal)*wTemp +
		float64(result.CentralScore)*wCentral

	result.FinalScore = int(weightedSum / totalW)

	s.memory.Record(ip, result.FinalScore)

	if result.AbuseScore > 0 {
		result.Sources = append(result.Sources, "abuseipdb")
	}
	if result.OTXScore > 0 {
		result.Sources = append(result.Sources, "alienvault")
	}
	if result.CentralScore > 0 {
		result.Sources = append(result.Sources, "central_feed")
	}
	if result.Behavioral > 0 {
		result.Sources = append(result.Sources, "behavioral")
	}
	if result.Temporal > 0 {
		result.Sources = append(result.Sources, "temporal")
	}

	return result
}

func (s *Scorer) Cleanup() {
	s.behavioral.Cleanup()
	s.memory.Cleanup()
}

func (s *Scorer) RecordEvent(evt pipeline.Envelope) {
	ip := evt.SourceIP()
	username := ""
	port := ""

	switch e := evt.Event.(type) {
	case pipeline.SSHFailedLogin:
		username = e.Username
		port = fmt.Sprintf("%d", e.Port)
	case pipeline.InvalidUserEvent:
		username = e.Username
	case pipeline.PortScanDetected:
		port = fmt.Sprintf("%d", e.Port)
	}

	s.behavioral.Record(ip, username, port)
}
