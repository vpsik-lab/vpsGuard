package monitor

import (
	"testing"
)

func TestParserParse(t *testing.T) {
	p := NewLogParser()

	tests := []struct {
		name     string
		line     string
		wantType string
		wantIP   string
		wantUser string
		wantPort string
		wantNil  bool
	}{
		{
			name:     "ssh failed password",
			line:     "May 24 10:00:00 server sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2",
			wantType: "ssh_failed",
			wantIP:   "1.2.3.4",
			wantUser: "root",
			wantPort: "22",
		},
		{
			name:     "ssh failed invalid user",
			line:     "May 24 10:00:00 server sshd[1234]: Failed password for invalid user admin from 5.6.7.8 port 44322 ssh2",
			wantType: "invalid_user",
			wantIP:   "5.6.7.8",
			wantUser: "admin",
			wantPort: "44322",
		},
		{
			name:     "invalid user message",
			line:     "May 24 10:00:00 server sshd[1234]: Invalid user nobody from 9.9.9.9",
			wantType: "invalid_user",
			wantIP:   "9.9.9.9",
			wantUser: "nobody",
			wantPort: "",
		},
		{
			name:     "non-matching log line",
			line:     "May 24 10:00:00 server sshd[1234]: Accepted publickey for user from 1.2.3.4 port 22",
			wantNil:  true,
		},
		{
			name:     "empty line",
			line:     "",
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.Parse(tt.line)
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected event, got nil")
			}
			if got.Type != tt.wantType {
				t.Errorf("type = %q, want %q", got.Type, tt.wantType)
			}
			if got.IP != tt.wantIP {
				t.Errorf("ip = %q, want %q", got.IP, tt.wantIP)
			}
			if got.Username != tt.wantUser {
				t.Errorf("username = %q, want %q", got.Username, tt.wantUser)
			}
			if got.Port != tt.wantPort {
				t.Errorf("port = %q, want %q", got.Port, tt.wantPort)
			}
		})
	}
}

func TestToEvent(t *testing.T) {
	p := NewLogParser()

	pe := &ParsedEvent{Type: "ssh_failed", IP: "1.2.3.4", Username: "root", Port: "22"}
	evt := p.ToEvent(pe)
	if evt == nil {
		t.Fatal("expected event, got nil")
	}
	if evt.SourceIP() != "1.2.3.4" {
		t.Errorf("SourceIP = %q, want %q", evt.SourceIP(), "1.2.3.4")
	}

	pe2 := &ParsedEvent{Type: "invalid_user", IP: "5.6.7.8", Username: "admin"}
	evt2 := p.ToEvent(pe2)
	if evt2 == nil {
		t.Fatal("expected event, got nil")
	}
	if evt2.SourceIP() != "5.6.7.8" {
		t.Errorf("SourceIP = %q, want %q", evt2.SourceIP(), "5.6.7.8")
	}
}

func TestBehaviouralAnalyzer(t *testing.T) {
	ba := NewBehavioralAnalyzer(10, 3)

	score := ba.GetScore("1.2.3.4")
	if score != 0 {
		t.Errorf("expected 0 for unknown IP, got %d", score)
	}

	for i := 0; i < 6; i++ {
		ba.Record("1.2.3.4", "root", "22")
	}

	score = ba.GetScore("1.2.3.4")
	if score <= 0 {
		t.Errorf("expected positive score after 6 attempts, got %d", score)
	}

	for i := 0; i < 5; i++ {
		ba.Record("5.6.7.8", "admin", "22")
		ba.Record("5.6.7.8", "root", "22")
		ba.Record("5.6.7.8", "test", "22")
		ba.Record("5.6.7.8", "nobody", "22")
	}
	score = ba.GetScore("5.6.7.8")
	if score <= 0 {
		t.Errorf("expected positive score for multiple usernames, got %d", score)
	}
}
