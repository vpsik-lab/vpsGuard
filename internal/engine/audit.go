package engine

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	TraceID   string    `json:"trace_id,omitempty"`
	EventType string    `json:"event_type"`
	Score     int       `json:"score"`
	Verdict   string    `json:"verdict"`
	Action    string    `json:"action"`
	Reason    string    `json:"reason"`
	Duration  string    `json:"duration,omitempty"`
	Sources   []string  `json:"sources,omitempty"`
}

type AuditLogger struct {
	path string
	mu   sync.Mutex
}

func NewAuditLogger(path string) *AuditLogger {
	return &AuditLogger{path: path}
}

func (a *AuditLogger) Log(entry AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(append(data, '\n'))
	return err
}
