package firewall

import (
	"os"
	"testing"
	"time"
)

func TestBlockStoreSaveAndLoad(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "blocks-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	store := NewBlockStore(tmpFile.Name())

	err = store.Save("1.2.3.4", time.Now().Add(1*time.Hour), "test_block")
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	entries, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].IP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", entries[0].IP)
	}
	if entries[0].Reason != "test_block" {
		t.Errorf("expected reason test_block, got %s", entries[0].Reason)
	}
}

func TestBlockStoreLoadExpired(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "blocks-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	store := NewBlockStore(tmpFile.Name())

	err = store.Save("1.2.3.4", time.Now().Add(-1*time.Hour), "expired")
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	entries, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("expected 0 expired entries, got %d", len(entries))
	}
}

func TestBlockStoreLoadNonExistent(t *testing.T) {
	store := NewBlockStore("/tmp/nonexistent-blocks-12345.json")
	entries, err := store.Load()
	if err != nil {
		t.Fatalf("Load should not error for missing file: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for missing file, got %d", len(entries))
	}
}

func TestBlockStoreRemove(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "blocks-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	store := NewBlockStore(tmpFile.Name())

	store.Save("1.1.1.1", time.Now().Add(1*time.Hour), "first")
	store.Save("2.2.2.2", time.Now().Add(1*time.Hour), "second")

	err = store.Remove("1.1.1.1")
	if err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	entries, _ := store.Load()
	if len(entries) != 1 || entries[0].IP != "2.2.2.2" {
		t.Errorf("expected only 2.2.2.2 after remove, got %v", entries)
	}
}

func TestBlockStoreCleanup(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "blocks-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	store := NewBlockStore(tmpFile.Name())

	store.Save("1.1.1.1", time.Now().Add(-1*time.Hour), "expired")
	store.Save("2.2.2.2", time.Now().Add(1*time.Hour), "active")

	err = store.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	entries, _ := store.Load()
	if len(entries) != 1 || entries[0].IP != "2.2.2.2" {
		t.Errorf("expected only active entry, got %v", entries)
	}
}

func TestBlockStoreMultipleSaves(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "blocks-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	store := NewBlockStore(tmpFile.Name())

	for i := 0; i < 100; i++ {
		ip := "10.0.0.%d"
		err := store.Save(ip, time.Now().Add(1*time.Hour), "bulk")
		if err != nil {
			t.Fatalf("Save %d failed: %v", i, err)
		}
	}

	entries, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(entries) != 100 {
		t.Errorf("expected 100 entries, got %d", len(entries))
	}
}
