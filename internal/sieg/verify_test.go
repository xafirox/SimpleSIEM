package sieg

import (
	"path/filepath"
	"testing"
)

// TestVerifyFile_TolerantOfSubChainReset locks in the rule that
// `_prev = ""` mid-file marks a benign sub-chain start (daemon
// restart, size rotation, etc.) — not tampering. Prior to the fix,
// `verifyFile` only tolerated `_prev=""` on the very first line and
// flagged every restart-induced reset as 8 problems per file.
func TestVerifyFile_TolerantOfSubChainReset(t *testing.T) {
	dir := t.TempDir()

	// First "daemon" run: 3 events.
	st1, err := NewStorage(dir, 0, 0, 64)
	if err != nil {
		t.Fatalf("NewStorage 1: %v", err)
	}
	st1.Write("meta", map[string]any{"event": "start", "run": 1})
	st1.Write("meta", map[string]any{"event": "alive", "run": 1})
	st1.Write("meta", map[string]any{"event": "stop", "run": 1})
	st1.Close()

	// Second "daemon" run against the same dir: appends to the same
	// daily file with a fresh chain (prev_hash empty, seq starts at 1).
	st2, err := NewStorage(dir, 0, 0, 64)
	if err != nil {
		t.Fatalf("NewStorage 2: %v", err)
	}
	st2.Write("meta", map[string]any{"event": "start", "run": 2})
	st2.Write("meta", map[string]any{"event": "alive", "run": 2})
	st2.Close()

	// Find the daily meta file and verify it.
	matches, err := filepath.Glob(filepath.Join(dir, "meta", "*.jsonl"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no daily file: %v / %d matches", err, len(matches))
	}
	res := verifyFile(matches[0])
	if len(res.problems) != 0 {
		t.Errorf("expected 0 problems on a clean restart-spanning file, got %d:", len(res.problems))
		for _, p := range res.problems {
			t.Logf("  %s", p)
		}
	}
	if res.events < 5 {
		t.Errorf("expected to see at least 5 events, got %d", res.events)
	}
}
