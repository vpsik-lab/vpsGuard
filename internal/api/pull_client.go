package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/vps-guard/vps-guard/internal/config"
	"github.com/vps-guard/vps-guard/internal/threat"
)

type ThreatFeedItem struct {
	IP            string   `json:"ip"`
	Confidence    int      `json:"confidence"`
	Score         int      `json:"score"`
	Category      string   `json:"category"`
	FirstSeen     string   `json:"first_seen"`
	LastSeen      string   `json:"last_seen"`
	TTL           int      `json:"ttl_seconds"`
	Sources       []string `json:"sources"`
	RecommendedAction string `json:"recommended_action"`
}

type ThreatFeedResponse struct {
	FeedID      string           `json:"feed_id"`
	GeneratedAt string           `json:"generated_at"`
	Threats     []ThreatFeedItem `json:"threats"`
	Total       int              `json:"total"`
}

type PullClient struct {
	cfg    *config.Config
	logger *zap.Logger
	client *http.Client
	intel  *threat.IntelClient
}

func NewPullClient(cfg *config.Config, logger *zap.Logger, intel *threat.IntelClient) *PullClient {
	return &PullClient{
		cfg:    cfg,
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
		intel:  intel,
	}
}

func (p *PullClient) Start(ctx context.Context) {
	if !p.cfg.CentralFeed.Enabled {
		p.logger.Info("central feed disabled")
		return
	}

	p.logger.Info("central feed pull client started",
		zap.String("url", p.cfg.CentralFeed.APIURL),
		zap.Int("interval", p.cfg.CentralFeed.SyncInterval),
	)

	ticker := time.NewTicker(time.Duration(p.cfg.CentralFeed.SyncInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.pull(ctx)
		case <-ctx.Done():
			p.logger.Info("central feed pull client stopped")
			return
		}
	}
}

func (p *PullClient) pull(ctx context.Context) {
	feed, err := p.fetchFeed(ctx)
	if err != nil {
		p.logger.Warn("failed to fetch central feed", zap.Error(err))
		return
	}

	if feed == nil || len(feed.Threats) == 0 {
		return
	}

	p.logger.Info("received central feed",
		zap.String("feed_id", feed.FeedID),
		zap.Int("threats", feed.Total),
	)

	minConf := p.cfg.CentralFeed.MinConfidence
	for _, item := range feed.Threats {
		if item.Confidence >= minConf {
			p.intel.SetCentralScore(ctx, item.IP, item.Score, item.Confidence)
		}
	}
}

func (p *PullClient) fetchFeed(ctx context.Context) (*ThreatFeedResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.cfg.CentralFeed.APIURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.CentralFeed.APIToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feed request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed returned status %d", resp.StatusCode)
	}

	var feed ThreatFeedResponse
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, fmt.Errorf("feed decode failed: %w", err)
	}
	return &feed, nil
}
