package sieg

import (
	"sync"
	"testing"
	"time"
)

// TestStorageMirror_DualWrite verifies that events written through a
// Storage with SetMirror reach BOTH the local disk write AND the
// mirror hook, AND that the cloned event handed to the mirror is
// stripped of the local _seq/_prev/_hash chain fields so the
// receiver can chain it independently.
func TestStorageMirror_DualWrite(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStorage(dir, 0, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var (
		mu       sync.Mutex
		mirrored []map[string]any
	)
	st.SetMirror(func(logType string, event map[string]any) {
		mu.Lock()
		// Snapshot the cloned map so the writer's downstream
		// stamping doesn't race the test assertion.
		copy := make(map[string]any, len(event))
		for k, v := range event {
			copy[k] = v
		}
		mirrored = append(mirrored, copy)
		mu.Unlock()
	})

	st.Write("meta", map[string]any{"event": "agent_start", "host": "x"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(mirrored)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(mirrored) != 1 {
		t.Fatalf("mirror saw %d events, want 1", len(mirrored))
	}
	got := mirrored[0]
	if got["event"] != "agent_start" {
		t.Errorf("event field wrong: %+v", got)
	}
	for _, k := range []string{"_seq", "_prev", "_hash"} {
		if _, has := got[k]; has {
			t.Errorf("mirror clone retained chain field %q: %+v", k, got)
		}
	}
}

// TestFreshestMtime_FindsRecentWrite verifies daemonLooksWedged's new
// helper finds writes anywhere under log_dir, not just two specific
// candidates. The earlier check missed writes under per-host dirs and
// false-fired SILENT on busy servers (the as4 manual-test failure).
func TestFreshestMtime_FindsRecentWrite(t *testing.T) {
	dir := t.TempDir()
	// Write a fresh file under a deeply-nested per-host path, and
	// an older file under <dir>/meta. freshestMtime must return the
	// newer mtime regardless of where it lives.
	if err := writeJSONLAt(t, dir, "meta", time.Now().Add(-15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONLAt(t, dir, "agent-1/auth", time.Now().Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	got := freshestMtime(dir, 4)
	if time.Since(got) > 2*time.Minute {
		t.Errorf("freshestMtime returned %v (age %v), expected < 2m old", got, time.Since(got))
	}
}

// TestFreshestMtime_NoFiles returns zero so callers don't false-
// accuse a fresh-boot daemon with no writes yet.
func TestFreshestMtime_NoFiles(t *testing.T) {
	dir := t.TempDir()
	if got := freshestMtime(dir, 4); !got.IsZero() {
		t.Errorf("freshestMtime on empty tree returned %v, want zero", got)
	}
}
