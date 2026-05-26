package engine

import (
	"sync"
	"testing"
	"time"
)

func TestNewReputationMemory(t *testing.T) {
	m := 	NewReputationMemory(7 * 24 * time.Hour)
	if m == nil {
		t.Fatal("NewReputationMemory returned nil")
	}
	if m.store == nil {
		t.Fatal("store not initialized")
	}
	if m.ttl != 7*24*time.Hour {
		t.Errorf("expected 7 day TTL, got %v", m.ttl)
	}
}

func TestReputationMemoryRecord(t *testing.T) {
	m := 	NewReputationMemory(7 * 24 * time.Hour)
	m.Record("1.2.3.4", 50)

	if len(m.store) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(m.store))
	}

	entry := m.store["1.2.3.4"]
	if entry == nil {
		t.Fatal("entry not found")
	}
	if entry.Count != 1 {
		t.Errorf("expected Count=1, got %d", entry.Count)
	}
	if entry.FirstSeen.IsZero() {
		t.Error("FirstSeen should be set")
	}
	if entry.LastSeen.IsZero() {
		t.Error("LastSeen should be set")
	}
	if len(entry.Scores) != 1 || entry.Scores[0] != 50 {
		t.Errorf("expected Scores=[50], got %v", entry.Scores)
	}
}

func TestReputationMemoryRecordMultiple(t *testing.T) {
	m := 	NewReputationMemory(7 * 24 * time.Hour)
	for i := 0; i < 10; i++ {
		m.Record("1.2.3.4", 30+i)
	}

	entry := m.store["1.2.3.4"]
	if entry.Count != 10 {
		t.Errorf("expected Count=10, got %d", entry.Count)
	}
	if len(entry.Scores) != 10 {
		t.Errorf("expected 10 scores, got %d", len(entry.Scores))
	}
}

func TestReputationMemoryMaxHistory(t *testing.T) {
	m := 	NewReputationMemory(7 * 24 * time.Hour)
	for i := 0; i < 150; i++ {
		m.Record("1.2.3.4", 10)
	}

	entry := m.store["1.2.3.4"]
	if len(entry.Scores) > 100 {
		t.Errorf("expected max 100 scores, got %d", len(entry.Scores))
	}
}

func TestReputationMemoryRecordDifferentIPs(t *testing.T) {
	m := 	NewReputationMemory(7 * 24 * time.Hour)
	m.Record("1.2.3.4", 50)
	m.Record("5.6.7.8", 30)

	if len(m.store) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m.store))
	}
	if m.store["1.2.3.4"].Count != 1 {
		t.Errorf("expected Count=1 for 1.2.3.4, got %d", m.store["1.2.3.4"].Count)
	}
	if m.store["5.6.7.8"].Count != 1 {
		t.Errorf("expected Count=1 for 5.6.7.8, got %d", m.store["5.6.7.8"].Count)
	}
}

func TestReputationMemoryGetScoreEmpty(t *testing.T) {
	m := 	NewReputationMemory(7 * 24 * time.Hour)
	score := m.GetScore("nonexistent")
	if score != 0 {
		t.Errorf("expected 0 for unknown IP, got %d", score)
	}
}

func TestReputationMemoryGetScoreByCount(t *testing.T) {
	tests := []struct {
		name     string
		entries  int
		want     int
	}{
		{"single entry", 1, 5},
		{"three entries (count>=3)", 3, 15},
		{"six entries (count>5)", 6, 30},
		{"eleven entries (count>10)", 11, 50},
		{"twenty one entries (count>20)", 21, 70},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := 	NewReputationMemory(7 * 24 * time.Hour)
			for i := 0; i < tt.entries; i++ {
				m.Record("1.2.3.4", 10)
			}
			score := m.GetScore("1.2.3.4")
			if score != tt.want {
				t.Errorf("expected %d for %d entries, got %d", tt.want, tt.entries, score)
			}
		})
	}
}

func TestReputationMemoryGetScoreWithHighAverage(t *testing.T) {
	m := 	NewReputationMemory(7 * 24 * time.Hour)
	for i := 0; i < 3; i++ {
		m.Record("1.2.3.4", 80)
	}

	score := m.GetScore("1.2.3.4")
	// count >= 3: +15, avg (80) > 60: +20 = 35
	if score != 35 {
		t.Errorf("expected 35 (count>=3=15 + avg>60=20), got %d", score)
	}
}

func TestReputationMemoryGetScoreCombined(t *testing.T) {
	m := 	NewReputationMemory(7 * 24 * time.Hour)
	for i := 0; i < 10; i++ {
		m.Record("1.2.3.4", 80)
	}

	score := m.GetScore("1.2.3.4")
	// count > 5: +30, count > 10: no, avg(80) > 60: +20 = 50
	if score != 50 {
		t.Errorf("expected 50 for 10 entries with avg 80, got %d", score)
	}
}

func TestReputationMemoryCleanup(t *testing.T) {
	m := 	NewReputationMemory(7 * 24 * time.Hour)
	m.Record("1.2.3.4", 10)

	m.store["1.2.3.4"].LastSeen = time.Now().Add(-8 * 24 * time.Hour)

	m.Cleanup()

	if _, exists := m.store["1.2.3.4"]; exists {
		t.Error("expected entry to be cleaned up after 7+ days")
	}
}

func TestReputationMemoryCleanupKeepsRecent(t *testing.T) {
	m := 	NewReputationMemory(7 * 24 * time.Hour)
	m.Record("1.2.3.4", 10)
	m.Record("5.6.7.8", 20)

	m.store["1.2.3.4"].LastSeen = time.Now().Add(-8 * 24 * time.Hour)

	m.Cleanup()

	if _, exists := m.store["1.2.3.4"]; exists {
		t.Error("expected old entry to be cleaned up")
	}
	if _, exists := m.store["5.6.7.8"]; !exists {
		t.Error("expected recent entry to remain")
	}
}

func TestReputationMemoryAutoCleanupGetScore(t *testing.T) {
	m := 	NewReputationMemory(7 * 24 * time.Hour)
	m.Record("1.2.3.4", 10)

	m.store["1.2.3.4"].LastSeen = time.Now().Add(-8 * 24 * time.Hour)

	score := m.GetScore("1.2.3.4")
	if score != 0 {
		t.Errorf("expected 0 for expired entry, got %d", score)
	}
	if _, exists := m.store["1.2.3.4"]; exists {
		t.Error("expected expired entry to be auto-deleted on GetScore")
	}
}

func TestReputationMemoryConcurrentSafe(t *testing.T) {
	m := 	NewReputationMemory(7 * 24 * time.Hour)
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Record("1.2.3.4", 30)
			m.GetScore("1.2.3.4")
		}()
	}

	wg.Wait()

	entry := m.store["1.2.3.4"]
	if entry == nil {
		t.Fatal("entry should exist after concurrent writes")
	}
	if entry.Count != 50 {
		t.Errorf("expected Count=50 after 50 concurrent writes, got %d", entry.Count)
	}
}
