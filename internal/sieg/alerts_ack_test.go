package sieg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestAlertAck_LoadAckIndex confirms that the loadAckIndex helper
// parses sidecar JSONL ack records correctly and dedupes by hash.
func TestAlertAck_LoadAckIndex(t *testing.T) {
	dir := t.TempDir()
	acksDir := filepath.Join(dir, "_acks")
	if err := os.MkdirAll(acksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	records := []map[string]any{
		{"alert_hash": "abc123", "ack_ts": "2026-05-02T12:00:00Z", "by": "ops"},
		{"alert_hash": "def456", "ack_ts": "2026-05-02T12:01:00Z", "by": "ops", "note": "investigated"},
		{"alert_hash": "abc123", "ack_ts": "2026-05-02T13:00:00Z", "by": "ops2"}, // duplicate
	}
	path := filepath.Join(acksDir, "2026-05-02.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		b, _ := json.Marshal(r)
		f.Write(append(b, '\n'))
	}
	// Add a malformed line to confirm it's skipped, not fatal.
	f.WriteString("not json at all\n")
	f.Close()

	idx := loadAckIndex(dir)
	if !idx["abc123"] || !idx["def456"] {
		t.Errorf("loadAckIndex missing expected hashes: %v", idx)
	}
	if len(idx) != 2 {
		t.Errorf("loadAckIndex size: got %d, want 2 (dedupe across records)", len(idx))
	}
}

// TestAlertAck_LoadAckIndex_NoDir confirms the helper returns an empty
// map (not an error or panic) when _acks/ doesn't exist yet — the
// common case before the operator has ack'd anything.
func TestAlertAck_LoadAckIndex_NoDir(t *testing.T) {
	dir := t.TempDir()
	idx := loadAckIndex(dir)
	if len(idx) != 0 {
		t.Errorf("loadAckIndex on missing dir: got %d entries, want 0", len(idx))
	}
}
