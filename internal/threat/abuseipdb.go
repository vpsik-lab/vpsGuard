package threat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type AbuseIPDBClient struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

type AbuseIPDBResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		TotalReports         int    `json:"totalReports"`
		LastReportedAt       string `json:"lastReportedAt"`
		CountryCode          string `json:"countryCode"`
		ISP                  string `json:"isp"`
		Domain               string `json:"domain"`
		UsageType            string `json:"usageType"`
	} `json:"data"`
}

func NewAbuseIPDBClient(apiKey string) *AbuseIPDBClient {
	return &AbuseIPDBClient{
		apiKey:  apiKey,
		baseURL: "https://api.abuseipdb.com/api/v2",
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *AbuseIPDBClient) Check(ctx context.Context, ip string) (*AbuseIPDBResponse, error) {
	url := fmt.Sprintf("%s/check?ipAddress=%s&maxAgeInDays=90&verbose=true", c.baseURL, ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result AbuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *AbuseIPDBClient) Report(ctx context.Context, ip string, categories []int, comment string) error {
	url := fmt.Sprintf("%s/report", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	q := req.URL.Query()
	q.Add("ip", ip)
	for _, cat := range categories {
		q.Add("categories", fmt.Sprintf("%d", cat))
	}
	q.Add("comment", comment)
	req.URL.RawQuery = q.Encode()

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
