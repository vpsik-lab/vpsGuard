package firewall

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

type BlockEntry struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason"`
}

type BlockStore struct {
	path string
	mu   sync.Mutex
}

func NewBlockStore(path string) *BlockStore {
	return &BlockStore{path: path}
}

func (s *BlockStore) Save(ip string, expiresAt time.Time, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := BlockEntry{
		IP:        ip,
		ExpiresAt: expiresAt,
		Reason:    reason,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(append(data, '\n'))
	return err
}

func (s *BlockStore) Load() ([]BlockEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []BlockEntry
	now := time.Now()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry BlockEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if entry.ExpiresAt.After(now) {
			entries = append(entries, entry)
		}
	}
	return entries, scanner.Err()
}

func (s *BlockStore) Remove(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	var kept []BlockEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry BlockEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if entry.IP != ip {
			kept = append(kept, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	return s.rewrite(kept)
}

func (s *BlockStore) Cleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	var kept []BlockEntry
	now := time.Now()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry BlockEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if entry.ExpiresAt.After(now) {
			kept = append(kept, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if len(kept) == 0 {
		os.Remove(s.path)
		return nil
	}
	return s.rewrite(kept)
}

func (s *BlockStore) rewrite(entries []BlockEntry) error {
	f, err := os.Create(s.path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			return err
		}
	}
	return nil
}
