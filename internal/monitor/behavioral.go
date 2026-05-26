package monitor

import (
	"sync"
	"time"
)

type IPRecord struct {
	Attempts  int
	FirstSeen time.Time
	LastSeen  time.Time
	Usernames map[string]int
	Ports     map[string]int
}

type BehavioralAnalyzer struct {
	mu        sync.Mutex
	ips       map[string]*IPRecord
	window    time.Duration
	threshold int
}

func NewBehavioralAnalyzer(window time.Duration, threshold int) *BehavioralAnalyzer {
	return &BehavioralAnalyzer{
		ips:       make(map[string]*IPRecord),
		window:    window,
		threshold: threshold,
	}
}

func (b *BehavioralAnalyzer) Record(ip, username, port string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	rec, ok := b.ips[ip]
	if !ok {
		rec = &IPRecord{
			Usernames: make(map[string]int),
			Ports:     make(map[string]int),
			FirstSeen: now,
		}
		b.ips[ip] = rec
	}
	rec.Attempts++
	rec.LastSeen = now
	rec.Usernames[username]++
	if port != "" {
		rec.Ports[port]++
	}
}

func (b *BehavioralAnalyzer) GetScore(ip string) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	rec, ok := b.ips[ip]
	if !ok {
		return 0
	}

	score := 0
	elapsed := time.Since(rec.FirstSeen)

	if rec.Attempts >= b.threshold {
		score += 25
	}
	if rec.Attempts >= b.threshold*3 {
		score += 15
	}
	if elapsed < b.window && rec.Attempts >= b.threshold {
		score += 20
	}
	if len(rec.Usernames) > 3 {
		score += 20
	}
	if len(rec.Ports) > 5 {
		score += 20
	}

	return score
}

func (b *BehavioralAnalyzer) Cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour)
	for ip, rec := range b.ips {
		if rec.LastSeen.Before(cutoff) {
			delete(b.ips, ip)
		}
	}
}
