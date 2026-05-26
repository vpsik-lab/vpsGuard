package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

type ComponentStatus struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type HealthResponse struct {
	Status     string                     `json:"status"`
	Version    string                     `json:"version"`
	Uptime     string                     `json:"uptime"`
	Components map[string]ComponentStatus `json:"components"`
}

type ComponentChecker func(ctx context.Context) ComponentStatus

type HealthServer struct {
	logger    *zap.Logger
	version   string
	startTime time.Time
	server    *http.Server
	Addr      string
	mu        sync.RWMutex
	checkers  map[string]ComponentChecker
}

func NewHealthServer(logger *zap.Logger, version string) *HealthServer {
	return &HealthServer{
		logger:    logger,
		version:   version,
		startTime: time.Now(),
		checkers:  make(map[string]ComponentChecker),
	}
}

func (h *HealthServer) RegisterComponent(name string, checker ComponentChecker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkers[name] = checker
}

func (h *HealthServer) ListenAndServe(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.handleHealth)

	h.server = &http.Server{
		Handler:  mux,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	h.Addr = ln.Addr().String()
	h.logger.Info("health endpoint listening", zap.String("addr", h.Addr))

	go func() {
		<-ctx.Done()
		h.server.Close()
	}()

	return h.server.Serve(ln)
}

func (h *HealthServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	overall := "ok"
	components := make(map[string]ComponentStatus)

	for name, check := range h.checkers {
		status := check(r.Context())
		components[name] = status
		if status.Status != "ok" {
			overall = "degraded"
		}
	}

	resp := HealthResponse{
		Status:     overall,
		Version:    h.version,
		Uptime:     time.Since(h.startTime).Round(time.Second).String(),
		Components: components,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
