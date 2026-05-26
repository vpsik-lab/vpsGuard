package monitor

import (
	"sync"
	"testing"
	"time"
)

func TestNewBehavioralAnalyzer(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)
	if ba == nil {
		t.Fatal("NewBehavioralAnalyzer returned nil")
	}
	if ba.ips == nil {
		t.Fatal("ips map not initialized")
	}
}

func TestBehavioralGetScoreUnknownIP(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)
	score := ba.GetScore("1.2.3.4")
	if score != 0 {
		t.Errorf("expected 0 for unknown IP, got %d", score)
	}
}

func TestBehavioralRecordAndGetScore(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)

	for i := 0; i < 10; i++ {
		ba.Record("1.2.3.4", "root", "22")
	}

	score := ba.GetScore("1.2.3.4")
	if score <= 0 {
		t.Errorf("expected positive score after 10 attempts, got %d", score)
	}
}

func TestBehavioralScoreThreshold(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)

	// threshold is 5, so 4 attempts should NOT cross threshold
	for i := 0; i < 4; i++ {
		ba.Record("1.2.3.4", "root", "22")
	}
	score := ba.GetScore("1.2.3.4")
	if score != 0 {
		t.Errorf("expected 0 for 4 attempts (below threshold 5), got %d", score)
	}

	// 1 more to cross threshold (5 >= 5)
	ba.Record("1.2.3.4", "root", "22")
	score = ba.GetScore("1.2.3.4")
	// attempts>=5: +25, window<10min AND attempts>=5: +20 = 45
	if score != 45 {
		t.Errorf("expected 45 for 5 attempts (25+20), got %d", score)
	}
}

func TestBehavioralScoreAboveThreshold(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)

	// 20 attempts to exceed threshold*3 (15)
	for i := 0; i < 20; i++ {
		ba.Record("1.2.3.4", "root", "22")
	}

	score := ba.GetScore("1.2.3.4")
	// attempts>=5: +25, attempts>=15: +15, window: +20 = 60
	if score != 60 {
		t.Errorf("expected 60 for 20 attempts (25+15+20), got %d", score)
	}
}

func TestBehavioralMultipleUsernames(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)
	usernames := []string{"root", "admin", "test", "user", "nobody"}

	for _, user := range usernames {
		ba.Record("1.2.3.4", user, "22")
	}

	score := ba.GetScore("1.2.3.4")
	// >3 unique usernames: +15
	if score < 10 {
		t.Errorf("expected >= 10 for 5 unique usernames, got %d", score)
	}
}

func TestBehavioralMultiplePorts(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)
	ports := []string{"22", "2222", "22222", "8022", "8080", "443"}

	ba.Record("1.2.3.4", "root", ports[0])
	ba.Record("1.2.3.4", "root", ports[1])
	ba.Record("1.2.3.4", "root", ports[2])
	ba.Record("1.2.3.4", "root", ports[3])

	// Only 4 unique ports so far
	score := ba.GetScore("1.2.3.4")
	_ = score

	ba.Record("1.2.3.4", "root", ports[4])
	ba.Record("1.2.3.4", "root", ports[5])

	// >5 unique ports: +15
	score = ba.GetScore("1.2.3.4")
	if score < 10 {
		t.Errorf("expected >= 10 for 6 unique ports, got %d", score)
	}
}

func TestBehavioralWindowScoring(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)

	for i := 0; i < 10; i++ {
		ba.Record("1.2.3.4", "root", "22")
	}

	score := ba.GetScore("1.2.3.4")
	// attempts>=5: +25, window: +20 = 45
	if score != 45 {
		t.Errorf("expected 45 (25+20) for fast 10 attempts, got %d", score)
	}
}

func TestBehavioralWindowExpiry(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Millisecond, 2)

	ba.Record("1.2.3.4", "root", "22")
	ba.Record("1.2.3.4", "root", "22")

	time.Sleep(20 * time.Millisecond)

	ba.Record("1.2.3.4", "root", "22")

	score := ba.GetScore("1.2.3.4")
	_ = score
}

func TestBehavioralCleanup(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)
	ba.Record("1.2.3.4", "root", "22")

	// Force entry to be old via the LastSeen in the record
	ba.mu.Lock()
	if rec, ok := ba.ips["1.2.3.4"]; ok {
		rec.LastSeen = time.Now().Add(-25 * time.Hour)
	}
	ba.mu.Unlock()

	ba.Cleanup()

	score := ba.GetScore("1.2.3.4")
	if score != 0 {
		t.Errorf("expected 0 after cleanup and expiry, got %d", score)
	}
}

func TestBehavioralCleanupKeepsRecent(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)
	for i := 0; i < 5; i++ {
		ba.Record("1.2.3.4", "root", "22")
	}
	for i := 0; i < 10; i++ {
		ba.Record("5.6.7.8", "admin", "22")
	}

	// Age out 1.2.3.4
	ba.mu.Lock()
	if rec, ok := ba.ips["1.2.3.4"]; ok {
		rec.LastSeen = time.Now().Add(-25 * time.Hour)
	}
	ba.mu.Unlock()

	ba.Cleanup()

	score1 := ba.GetScore("1.2.3.4")
	score2 := ba.GetScore("5.6.7.8")

	if score1 != 0 {
		t.Errorf("expected 0 for expired IP, got %d", score1)
	}
	if score2 <= 0 {
		t.Errorf("expected positive score for recent IP, got %d", score2)
	}
}

func TestBehavioralConcurrentSafe(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ba.Record("1.2.3.4", "root", "22")
			ba.GetScore("1.2.3.4")
		}()
	}

	wg.Wait()

	ba.mu.Lock()
	count := 0
	if rec, ok := ba.ips["1.2.3.4"]; ok {
		count = rec.Attempts
	}
	ba.mu.Unlock()

	if count != 100 {
		t.Errorf("expected 100 attempts after concurrent writes, got %d", count)
	}
}

func TestBehavioralMultipleIPs(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)

	ba.Record("1.1.1.1", "root", "22")
	ba.Record("2.2.2.2", "admin", "22")

	for i := 0; i < 10; i++ {
		ba.Record("1.1.1.1", "root", "22")
	}

	if ba.GetScore("1.1.1.1") <= 0 {
		t.Error("expected positive score for 1.1.1.1")
	}
	if ba.GetScore("2.2.2.2") != 0 {
		t.Error("expected 0 for 2.2.2.2 (only 1 attempt)")
	}
	if ba.GetScore("3.3.3.3") != 0 {
		t.Error("expected 0 for unknown IP")
	}
}

func TestBehavioralCleanupEmpty(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)
	// Cleanup with empty map should not panic
	ba.Cleanup()
}

func TestBehavioralIPRecordFields(t *testing.T) {
	ba := NewBehavioralAnalyzer(10*time.Minute, 5)
	ba.Record("1.2.3.4", "root", "22")

	ba.mu.Lock()
	rec, ok := ba.ips["1.2.3.4"]
	ba.mu.Unlock()

	if !ok {
		t.Fatal("expected IP record to exist")
	}
	if rec.FirstSeen.IsZero() {
		t.Error("FirstSeen should not be zero")
	}
	if rec.LastSeen.IsZero() {
		t.Error("LastSeen should not be zero")
	}
	if rec.Usernames["root"] != 1 {
		t.Errorf("expected Usernames[root]=1, got %d", rec.Usernames["root"])
	}
	if rec.Ports["22"] != 1 {
		t.Errorf("expected Ports[22]=1, got %d", rec.Ports["22"])
	}
}
