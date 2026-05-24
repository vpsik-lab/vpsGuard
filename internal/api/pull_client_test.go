package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vps-guard/vps-guard/internal/config"
	"github.com/vps-guard/vps-guard/internal/threat"
)

func TestNewPullClient(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	logger := zap.NewNop()
	intel := threat.NewIntelClient(cfg, logger)

	pc := NewPullClient(cfg, logger, intel)
	if pc == nil {
		t.Fatal("NewPullClient returned nil")
	}
}

func TestFetchFeed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Accept") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp := ThreatFeedResponse{
			FeedID:      "feed-001",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Total:       2,
			Threats: []ThreatFeedItem{
				{
					IP:                "1.2.3.4",
					Confidence:        95,
					Score:             85,
					Category:          "ssh_brute",
					LastSeen:          time.Now().UTC().Format(time.RFC3339),
					TTL:               86400,
					Sources:           []string{"honeypot"},
					RecommendedAction: "block",
				},
				{
					IP:                "5.6.7.8",
					Confidence:        45,
					Score:             30,
					Category:          "scanner",
					LastSeen:          time.Now().UTC().Format(time.RFC3339),
					TTL:               43200,
					RecommendedAction: "monitor",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.CentralFeed.APIURL = server.URL
	cfg.CentralFeed.APIToken = "test-token"
	logger := zap.NewNop()
	intel := threat.NewIntelClient(cfg, logger)

	pc := NewPullClient(cfg, logger, intel)
	feed, err := pc.fetchFeed(context.Background())
	if err != nil {
		t.Fatalf("fetchFeed() error = %v", err)
	}
	if feed == nil {
		t.Fatal("fetchFeed() returned nil")
	}
	if feed.FeedID != "feed-001" {
		t.Errorf("FeedID = %q", feed.FeedID)
	}
	if feed.Total != 2 {
		t.Errorf("Total = %d", feed.Total)
	}
	if len(feed.Threats) != 2 {
		t.Errorf("len(Threats) = %d", len(feed.Threats))
	}
	if feed.Threats[0].IP != "1.2.3.4" {
		t.Errorf("Threats[0].IP = %q", feed.Threats[0].IP)
	}
}

func TestFetchFeedUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.CentralFeed.APIURL = server.URL
	cfg.CentralFeed.APIToken = "bad-token"
	logger := zap.NewNop()
	intel := threat.NewIntelClient(cfg, logger)

	pc := NewPullClient(cfg, logger, intel)
	_, err := pc.fetchFeed(context.Background())
	if err == nil {
		t.Fatal("expected error for unauthorized, got nil")
	}
}

func TestPullWithMinConfidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ThreatFeedResponse{
			FeedID: "feed-002",
			Total:  2,
			Threats: []ThreatFeedItem{
				{IP: "1.2.3.4", Confidence: 95, Score: 85,
					LastSeen: time.Now().UTC().Format(time.RFC3339)},
				{IP: "5.6.7.8", Confidence: 30, Score: 20,
					LastSeen: time.Now().UTC().Format(time.RFC3339)},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.CentralFeed.APIURL = server.URL
	cfg.CentralFeed.APIToken = "token"
	cfg.CentralFeed.MinConfidence = 50
	logger := zap.NewNop()
	intel := threat.NewIntelClient(cfg, logger)

	pc := NewPullClient(cfg, logger, intel)
	pc.pull(context.Background())

	entry := intel.CacheGet("1.2.3.4")
	if entry == nil {
		t.Error("expected 1.2.3.4 to be cached (confidence 95 >= 50)")
	}

	entry2 := intel.CacheGet("5.6.7.8")
	if entry2 != nil {
		t.Error("expected 5.6.7.8 to NOT be cached (confidence 30 < 50)")
	}
}

func TestStartDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.CentralFeed.Enabled = false
	logger := zap.NewNop()
	intel := threat.NewIntelClient(cfg, logger)

	pc := NewPullClient(cfg, logger, intel)
	pc.Start(context.Background())
}

func TestFeedMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.SetDefaults()
	cfg.CentralFeed.APIURL = server.URL
	cfg.CentralFeed.APIToken = "token"
	logger := zap.NewNop()
	intel := threat.NewIntelClient(cfg, logger)

	pc := NewPullClient(cfg, logger, intel)
	_, err := pc.fetchFeed(context.Background())
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
