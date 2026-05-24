package threat

import "testing"

func TestOTXPulseToScore(t *testing.T) {
	tests := []struct {
		pulses int
		want   int
	}{
		{0, 0},
		{1, 15},
		{2, 15},
		{3, 35},
		{5, 35},
		{6, 55},
		{10, 55},
		{11, 75},
		{25, 75},
		{26, 90},
		{100, 90},
	}

	for _, tt := range tests {
		got := OTXPulseToScore(tt.pulses)
		if got != tt.want {
			t.Errorf("OTXPulseToScore(%d) = %d, want %d", tt.pulses, got, tt.want)
		}
	}
}

func TestNewAlienVaultClient(t *testing.T) {
	client := NewAlienVaultClient("test-key")
	if client == nil {
		t.Fatal("NewAlienVaultClient returned nil")
	}
	if client.apiKey != "test-key" {
		t.Errorf("apiKey = %q", client.apiKey)
	}
}

func TestNewAbuseIPDBClient(t *testing.T) {
	client := NewAbuseIPDBClient("test-key")
	if client == nil {
		t.Fatal("NewAbuseIPDBClient returned nil")
	}
	if client.apiKey != "test-key" {
		t.Errorf("apiKey = %q", client.apiKey)
	}
	if client.baseURL != "https://api.abuseipdb.com/api/v2" {
		t.Errorf("baseURL = %q", client.baseURL)
	}
}
