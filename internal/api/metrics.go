package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// AgentMetrics holds counters updated by the event-processing loop.
// All fields are updated atomically so no locking is needed.
type AgentMetrics struct {
	startTime    time.Time
	EventsTotal  atomic.Int64
	BlocksTotal  atomic.Int64
	QuarantTotal atomic.Int64
	RateLimTotal atomic.Int64
	MonitorTotal atomic.Int64
	TamperAlerts atomic.Int64
}

// NewAgentMetrics creates a metrics tracker initialised to the current time.
func NewAgentMetrics() *AgentMetrics {
	return &AgentMetrics{startTime: time.Now()}
}

// UptimeSeconds returns how long the agent has been running.
func (m *AgentMetrics) UptimeSeconds() float64 {
	return time.Since(m.startTime).Seconds()
}

// metricsJSON is the JSON shape returned by /metrics?format=json
type metricsJSON struct {
	UptimeSeconds float64 `json:"uptime_seconds"`
	EventsTotal   int64   `json:"events_total"`
	BlocksTotal   int64   `json:"blocks_total"`
	QuarantTotal  int64   `json:"quarantine_total"`
	RateLimTotal  int64   `json:"rate_limit_total"`
	MonitorTotal  int64   `json:"monitor_total"`
	TamperAlerts  int64   `json:"tamper_alerts_total"`
}

// RegisterMetrics attaches the /metrics endpoint to the HealthServer mux.
// The endpoint supports two formats:
//
//	GET /metrics               → Prometheus text exposition format
//	GET /metrics?format=json   → JSON (handy for curl / scripts)
func (h *HealthServer) RegisterMetrics(m *AgentMetrics) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.metrics = m
}

// handleMetrics serves the /metrics endpoint.
func (h *HealthServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.mu.RLock()
	m := h.metrics
	h.mu.RUnlock()

	if m == nil {
		http.Error(w, "metrics not available", http.StatusServiceUnavailable)
		return
	}

	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metricsJSON{
			UptimeSeconds: m.UptimeSeconds(),
			EventsTotal:   m.EventsTotal.Load(),
			BlocksTotal:   m.BlocksTotal.Load(),
			QuarantTotal:  m.QuarantTotal.Load(),
			RateLimTotal:  m.RateLimTotal.Load(),
			MonitorTotal:  m.MonitorTotal.Load(),
			TamperAlerts:  m.TamperAlerts.Load(),
		})
		return
	}

	// Default: Prometheus text exposition format
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP vpsguard_uptime_seconds Time the agent has been running\n")
	fmt.Fprintf(w, "# TYPE vpsguard_uptime_seconds gauge\n")
	fmt.Fprintf(w, "vpsguard_uptime_seconds %.2f\n", m.UptimeSeconds())

	fmt.Fprintf(w, "# HELP vpsguard_events_total Total SSH events processed\n")
	fmt.Fprintf(w, "# TYPE vpsguard_events_total counter\n")
	fmt.Fprintf(w, "vpsguard_events_total %d\n", m.EventsTotal.Load())

	fmt.Fprintf(w, "# HELP vpsguard_blocks_total Total IPs blocked\n")
	fmt.Fprintf(w, "# TYPE vpsguard_blocks_total counter\n")
	fmt.Fprintf(w, "vpsguard_blocks_total %d\n", m.BlocksTotal.Load())

	fmt.Fprintf(w, "# HELP vpsguard_quarantine_total Total IPs quarantined\n")
	fmt.Fprintf(w, "# TYPE vpsguard_quarantine_total counter\n")
	fmt.Fprintf(w, "vpsguard_quarantine_total %d\n", m.QuarantTotal.Load())

	fmt.Fprintf(w, "# HELP vpsguard_rate_limit_total Total IPs rate-limited\n")
	fmt.Fprintf(w, "# TYPE vpsguard_rate_limit_total counter\n")
	fmt.Fprintf(w, "vpsguard_rate_limit_total %d\n", m.RateLimTotal.Load())

	fmt.Fprintf(w, "# HELP vpsguard_monitor_total Total IPs put under monitor-only\n")
	fmt.Fprintf(w, "# TYPE vpsguard_monitor_total counter\n")
	fmt.Fprintf(w, "vpsguard_monitor_total %d\n", m.MonitorTotal.Load())

	fmt.Fprintf(w, "# HELP vpsguard_tamper_alerts_total Config tamper warnings fired\n")
	fmt.Fprintf(w, "# TYPE vpsguard_tamper_alerts_total counter\n")
	fmt.Fprintf(w, "vpsguard_tamper_alerts_total %d\n", m.TamperAlerts.Load())
}
