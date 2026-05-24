package threat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type AlienVaultClient struct {
	apiKey string
	client *http.Client
}

type OTXResponse struct {
	PulseInfo struct {
		Count      int      `json:"count"`
		References []string `json:"references"`
	} `json:"pulse_info"`
	Reputation int `json:"reputation"`
}

func NewAlienVaultClient(apiKey string) *AlienVaultClient {
	return &AlienVaultClient{
		apiKey: apiKey,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *AlienVaultClient) Check(ctx context.Context, ip string) (*OTXResponse, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OTX-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result OTXResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func OTXPulseToScore(pulseCount int) int {
	switch {
	case pulseCount == 0:
		return 0
	case pulseCount <= 2:
		return 15
	case pulseCount <= 5:
		return 35
	case pulseCount <= 10:
		return 55
	case pulseCount <= 25:
		return 75
	default:
		return 90
	}
}
