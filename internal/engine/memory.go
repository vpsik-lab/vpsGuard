package engine

import (
	"sync"
	"time"
)

type MemoryEntry struct {
	IP        string
	Scores    []int
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int
}

type ReputationMemory struct {
	mu    sync.Mutex
	store map[string]*MemoryEntry
	ttl   time.Duration
}

func NewReputationMemory(ttl time.Duration) *ReputationMemory {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	return &ReputationMemory{
		store: make(map[string]*MemoryEntry),
		ttl:   ttl,
	}
}

func (m *ReputationMemory) Record(ip string, score int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	entry, ok := m.store[ip]
	if !ok {
		entry = &MemoryEntry{
			IP:        ip,
			FirstSeen: now,
		}
		m.store[ip] = entry
	}

	entry.Scores = append(entry.Scores, score)
	entry.LastSeen = now
	entry.Count++

	if len(entry.Scores) > 100 {
		entry.Scores = entry.Scores[len(entry.Scores)-100:]
	}
}

func (m *ReputationMemory) GetScore(ip string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.store[ip]
	if !ok {
		return 0
	}

	if time.Since(entry.LastSeen) > m.ttl {
		delete(m.store, ip)
		return 0
	}

	score := 0

	switch {
	case entry.Count > 20:
		score += 70
	case entry.Count > 10:
		score += 50
	case entry.Count > 5:
		score += 30
	case entry.Count >= 3:
		score += 15
	case entry.Count >= 1:
		score += 5
	}

	avg := 0
	for _, s := range entry.Scores {
		avg += s
	}
	if len(entry.Scores) > 0 {
		avg /= len(entry.Scores)
	}

	if avg > 60 {
		score += 20
	}

	return score
}

func (m *ReputationMemory) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-m.ttl)
	for ip, entry := range m.store {
		if entry.LastSeen.Before(cutoff) {
			delete(m.store, ip)
		}
	}
}
