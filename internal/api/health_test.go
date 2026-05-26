package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestHealthServerStartStop(t *testing.T) {
	logger := zap.NewNop()
	srv := NewHealthServer(logger, "test-v1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx, "127.0.0.1:0")
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop within timeout")
	}
}

func TestHealthServerResponse(t *testing.T) {
	logger := zap.NewNop()
	srv := NewHealthServer(logger, "1.0.0")

	srv.RegisterComponent("test_comp", func(ctx context.Context) ComponentStatus {
		return ComponentStatus{Status: "ok"}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx, "127.0.0.1:0")
	}()

	time.Sleep(50 * time.Millisecond)

	if srv.Addr == "" {
		t.Fatal("server address not set")
	}
	resp, err := http.Get("http://" + srv.Addr + "/health")
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
	<-errCh
}

func TestHealthServerMethodNotAllowed(t *testing.T) {
	logger := zap.NewNop()
	srv := NewHealthServer(logger, "1.0.0")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx, "127.0.0.1:0")
	}()

	time.Sleep(50 * time.Millisecond)

	if srv.Addr == "" {
		t.Fatal("server address not set")
	}
	resp, err := http.Post("http://" + srv.Addr + "/health", "application/json", nil)
	if err != nil {
		t.Fatalf("health POST request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}

	cancel()
	<-errCh
}

func TestHealthServerDegraded(t *testing.T) {
	logger := zap.NewNop()
	srv := NewHealthServer(logger, "1.0.0")

	srv.RegisterComponent("failing_comp", func(ctx context.Context) ComponentStatus {
		return ComponentStatus{Status: "degraded", Message: "something wrong"}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx, "127.0.0.1:0")
	}()

	time.Sleep(50 * time.Millisecond)

	if srv.Addr == "" {
		t.Fatal("server address not set")
	}
	resp, err := http.Get("http://" + srv.Addr + "/health")
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected application/json, got %s", contentType)
	}

	cancel()
	<-errCh
}
