package pipeline

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNewBus(t *testing.T) {
	logger := zap.NewNop()
	bus := NewBus(logger)
	if bus == nil {
		t.Fatal("NewBus returned nil")
	}
}

func TestSubscribe(t *testing.T) {
	logger := zap.NewNop()
	bus := NewBus(logger)

	ch := bus.Subscribe()
	if ch == nil {
		t.Fatal("Subscribe returned nil channel")
	}

	select {
	case <-ch:
		t.Fatal("channel should be empty")
	default:
	}
}

func TestPublish(t *testing.T) {
	logger := zap.NewNop()
	bus := NewBus(logger)

	ch := bus.Subscribe()
	ctx := context.Background()

	evt := Envelope{
		TraceID: "test-trace",
		Source:  "test",
		Version: "1",
		Event:   BaseEvent{Type: EventSSHFailedLogin, IP: "1.2.3.4"},
	}

	bus.Publish(ctx, evt)

	select {
	case received := <-ch:
		if received.TraceID != "test-trace" {
			t.Errorf("TraceID = %q, want %q", received.TraceID, "test-trace")
		}
		if received.Source != "test" {
			t.Errorf("Source = %q, want %q", received.Source, "test")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestPublishMultipleListeners(t *testing.T) {
	logger := zap.NewNop()
	bus := NewBus(logger)

	ch1 := bus.Subscribe()
	ch2 := bus.Subscribe()
	ctx := context.Background()

	evt := Envelope{
		TraceID: "multi-test",
		Source:  "test",
		Event:   BaseEvent{IP: "1.2.3.4"},
	}

	bus.Publish(ctx, evt)

	select {
	case <-ch1:
	case <-time.After(time.Second):
		t.Fatal("listener 1 did not receive event")
	}

	select {
	case <-ch2:
	case <-time.After(time.Second):
		t.Fatal("listener 2 did not receive event")
	}
}

func TestPublishContextCancel(t *testing.T) {
	logger := zap.NewNop()
	bus := NewBus(logger)

	ch := make(chan Envelope)
	bus.Subscribe()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	evt := Envelope{
		TraceID: "ctx-cancel",
		Event:   BaseEvent{IP: "1.2.3.4"},
	}

	bus.Publish(ctx, evt)

	select {
	case <-ch:
		t.Fatal("should not receive after context cancel")
	default:
	}
}

func TestFanOut(t *testing.T) {
	logger := zap.NewNop()
	bus := NewBus(logger)

	output := make(chan Envelope, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := bus.Subscribe()
	go func() {
		for evt := range ch {
			output <- evt
		}
	}()

	publishEvt := Envelope{
		TraceID: "fanout-test",
		Event:   BaseEvent{IP: "1.2.3.4"},
	}

	bus.Publish(ctx, publishEvt)

	select {
	case received := <-output:
		if received.TraceID != "fanout-test" {
			t.Errorf("TraceID = %q, want %q", received.TraceID, "fanout-test")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for fanout event")
	}
}

func TestEnvelopeSourceIP(t *testing.T) {
	base := BaseEvent{IP: "10.0.0.1"}
	env := Envelope{Event: base}

	if ip := env.SourceIP(); ip != "10.0.0.1" {
		t.Errorf("SourceIP() = %q, want %q", ip, "10.0.0.1")
	}
}

func TestEventTypes(t *testing.T) {
	now := time.Now()

	t.Run("BaseEvent", func(t *testing.T) {
		e := BaseEvent{
			Type:        EventSSHFailedLogin,
			IP:          "1.2.3.4",
			SeverityVal: 5,
			PriorityVal: PriorityHigh,
			Time:        now,
		}
		if e.EventType() != EventSSHFailedLogin {
			t.Errorf("EventType = %q", e.EventType())
		}
		if e.SourceIP() != "1.2.3.4" {
			t.Errorf("SourceIP = %q", e.SourceIP())
		}
		if e.Severity() != 5 {
			t.Errorf("Severity = %d", e.Severity())
		}
		if e.Priority() != PriorityHigh {
			t.Errorf("Priority = %d", e.Priority())
		}
		if !e.Timestamp().Equal(now) {
			t.Errorf("Timestamp mismatch")
		}
	})

	t.Run("SSHFailedLogin", func(t *testing.T) {
		e := SSHFailedLogin{
			BaseEvent:  BaseEvent{IP: "5.6.7.8", Type: EventSSHFailedLogin},
			Username:   "root",
			Attempts:   10,
			WindowSec:  30,
			AuthMethod: "password",
		}
		if e.SourceIP() != "5.6.7.8" {
			t.Errorf("SourceIP = %q", e.SourceIP())
		}
		if e.Username != "root" {
			t.Errorf("Username = %q", e.Username)
		}
		if e.Attempts != 10 {
			t.Errorf("Attempts = %d", e.Attempts)
		}
	})

	t.Run("InvalidUserEvent", func(t *testing.T) {
		e := InvalidUserEvent{
			BaseEvent: BaseEvent{IP: "9.9.9.9", Type: EventInvalidUser},
			Username:  "nobody",
		}
		if e.SourceIP() != "9.9.9.9" {
			t.Errorf("SourceIP = %q", e.SourceIP())
		}
		if e.Username != "nobody" {
			t.Errorf("Username = %q", e.Username)
		}
	})

	t.Run("PortScanDetected", func(t *testing.T) {
		e := PortScanDetected{
			BaseEvent:   BaseEvent{IP: "1.1.1.1", Type: EventPortScan},
			TargetPorts: []int{22, 80, 443},
			ScanType:    "syn",
		}
		if e.SourceIP() != "1.1.1.1" {
			t.Errorf("SourceIP = %q", e.SourceIP())
		}
		if len(e.TargetPorts) != 3 {
			t.Errorf("len(TargetPorts) = %d", len(e.TargetPorts))
		}
	})
}

func TestPriorityConstants(t *testing.T) {
	if PriorityLow != 0 {
		t.Errorf("PriorityLow = %d, want 0", PriorityLow)
	}
	if PriorityMedium != 1 {
		t.Errorf("PriorityMedium = %d, want 1", PriorityMedium)
	}
	if PriorityHigh != 2 {
		t.Errorf("PriorityHigh = %d, want 2", PriorityHigh)
	}
	if PriorityCritical != 3 {
		t.Errorf("PriorityCritical = %d, want 3", PriorityCritical)
	}
}

func TestEventTypeConstants(t *testing.T) {
	if EventSSHFailedLogin != "ssh_failed_login" {
		t.Errorf("EventSSHFailedLogin = %q", EventSSHFailedLogin)
	}
	if EventPortScan != "port_scan" {
		t.Errorf("EventPortScan = %q", EventPortScan)
	}
	if EventInvalidUser != "invalid_user" {
		t.Errorf("EventInvalidUser = %q", EventInvalidUser)
	}
}
