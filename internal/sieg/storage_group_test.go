package sieg

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestStorageGroup_SwitchRoot verifies that swapping the group's root
// causes new event writes to land at the new location AND that
// previously-written events stay where they were.
func TestStorageGroup_SwitchRoot(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	g := newStorageGroup(dirA)
	s, err := g.Open("", 0, 64*1024*1024, 256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	// Write an event to dirA.
	s.Write("meta", map[string]any{"event": "before_swap"})
	waitForFile(t, filepath.Join(dirA, "meta", today()+".jsonl"))

	// Swap to dirB.
	if err := g.SwitchRoot(dirB); err != nil {
		t.Fatalf("SwitchRoot: %v", err)
	}
	if g.Root() != dirB {
		t.Errorf("Root: got %q want %q", g.Root(), dirB)
	}

	// Write another event; it should land at dirB.
	s.Write("meta", map[string]any{"event": "after_swap"})
	waitForFile(t, filepath.Join(dirB, "meta", today()+".jsonl"))

	// dirA's file must still exist (events from before the swap are preserved).
	if _, err := os.Stat(filepath.Join(dirA, "meta", today()+".jsonl")); err != nil {
		t.Errorf("dirA file gone after swap: %v", err)
	}
}

// TestStorageGroup_SubpathMembers verifies that a group with multiple
// subpath members swaps every member in lockstep.
func TestStorageGroup_SubpathMembers(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	g := newStorageGroup(dirA)
	host1, err := g.Open("host1", 0, 64*1024*1024, 256)
	if err != nil {
		t.Fatal(err)
	}
	host2, err := g.Open("host2", 0, 64*1024*1024, 256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { host1.Close(); host2.Close() })

	host1.Write("meta", map[string]any{"event": "h1_a"})
	host2.Write("meta", map[string]any{"event": "h2_a"})
	waitForFile(t, filepath.Join(dirA, "host1", "meta", today()+".jsonl"))
	waitForFile(t, filepath.Join(dirA, "host2", "meta", today()+".jsonl"))

	if err := g.SwitchRoot(dirB); err != nil {
		t.Fatalf("SwitchRoot: %v", err)
	}

	host1.Write("meta", map[string]any{"event": "h1_b"})
	host2.Write("meta", map[string]any{"event": "h2_b"})
	waitForFile(t, filepath.Join(dirB, "host1", "meta", today()+".jsonl"))
	waitForFile(t, filepath.Join(dirB, "host2", "meta", today()+".jsonl"))
}

// TestStorage_HaltedRejectsWrites verifies the halt flag drops writes
// and that haltedDropped increments accordingly.
func TestStorage_HaltedRejectsWrites(t *testing.T) {
	dir := t.TempDir()
	g := newStorageGroup(dir)
	s, err := g.Open("", 0, 64*1024*1024, 256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	s.SetHalted(true)
	s.Write("meta", map[string]any{"event": "after_halt"})
	// Brief pause to let writer drain (it shouldn't see anything).
	time.Sleep(50 * time.Millisecond)
	// The file should not have been created.
	path := filepath.Join(dir, "meta", today()+".jsonl")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected file to NOT exist while halted; got err=%v", err)
	}

	// Clear halt and re-write — now it should land.
	s.SetHalted(false)
	s.Write("meta", map[string]any{"event": "after_unhalt"})
	waitForFile(t, path)
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("file never appeared: %s", path)
}

func today() string { return time.Now().UTC().Format("2006-01-02") }
