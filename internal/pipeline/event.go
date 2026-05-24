package pipeline

import (
	"time"
)

type EventType string

const (
	EventSSHFailedLogin EventType = "ssh_failed_login"
	EventPortScan       EventType = "port_scan"
	EventInvalidUser    EventType = "invalid_user"
	EventHTTPBruteforce EventType = "http_bruteforce"
)

type Priority int

const (
	PriorityLow    Priority = 0
	PriorityMedium Priority = 1
	PriorityHigh   Priority = 2
	PriorityCritical Priority = 3
)

type Event interface {
	EventType() EventType
	SourceIP() string
	Severity() int
	Priority() Priority
	Timestamp() time.Time
}

type Envelope struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Version   string    `json:"version"`
	TraceID   string    `json:"trace_id"`
	Event     Event     `json:"event"`
}

func (e Envelope) SourceIP() string {
	return e.Event.SourceIP()
}

type BaseEvent struct {
	Type        EventType              `json:"type"`
	IP          string                 `json:"ip"`
	Port        int                    `json:"port,omitempty"`
	SeverityVal int                    `json:"severity"`
	PriorityVal Priority               `json:"priority"`
	Time        time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func (e BaseEvent) EventType() EventType { return e.Type }
func (e BaseEvent) SourceIP() string     { return e.IP }
func (e BaseEvent) Severity() int        { return e.SeverityVal }
func (e BaseEvent) Priority() Priority   { return e.PriorityVal }
func (e BaseEvent) Timestamp() time.Time { return e.Time }

type SSHFailedLogin struct {
	BaseEvent
	Username   string `json:"username"`
	Attempts   int    `json:"attempts"`
	WindowSec  int    `json:"window_seconds"`
	AuthMethod string `json:"auth_method"`
}

type PortScanDetected struct {
	BaseEvent
	TargetPorts []int  `json:"target_ports"`
	ScanType    string `json:"scan_type"`
}

type InvalidUserEvent struct {
	BaseEvent
	Username string `json:"username"`
}
