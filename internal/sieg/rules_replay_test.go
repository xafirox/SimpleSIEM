package sieg

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRulesReplay_FindsHistoricalFires writes a small history of
// events to a synthetic log_dir, runs replay against a rules file
// that matches them, and verifies the fires are counted. The test
// drives the matchRule path directly (the same path replay uses
// when --with-threshold is OFF) so it doesn't need to build a full
// daemon + collector + clock harness.
func TestRulesReplay_FindsHistoricalFires(t *testing.T) {
	dir := t.TempDir()
	g := newStorageGroup(dir)
	s, err := g.Open("", 0, 64*1024*1024, 256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	// Write 5 "auth_failed" events.
	for i := 0; i < 5; i++ {
		s.Write("auth", map[string]any{
			"event": "auth_failed",
			"user":  "alice",
			"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
	// And 3 unrelated events.
	for i := 0; i < 3; i++ {
		s.Write("network", map[string]any{
			"event": "active_connection",
			"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		})
	}

	// Settle the writer goroutine.
	time.Sleep(200 * time.Millisecond)

	// Build a rule via the JSON loader (the only public path to
	// construct an alertRule).
	rulesJSON := `[{"name":"auth-failed-replay","severity":"high","match":{"event":"auth_failed"}}]`
	rulesPath := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rulesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("loadRules: got %d rules, want 1", len(rules))
	}
	rule := rules[0]

	// Run a tiny replay loop directly against the on-disk events.
	cfg := Config{Mode: "standalone", LogDir: dir}
	roots := searchRoots(cfg, "")
	events := loadEventsInRangeMulti(roots, time.Now().Add(-1*time.Hour), time.Now().Add(time.Hour), "")
	fires := 0
	for _, e := range events {
		if matchRule(rule, e.Type, e.Data) {
			fires++
		}
	}
	if fires != 5 {
		t.Errorf("rules replay fires: got %d, want 5", fires)
	}
}

// TestRulesReplay_TypeFilter verifies the --type flag narrows the
// scan to one log type only.
func TestRulesReplay_TypeFilter(t *testing.T) {
	dir := t.TempDir()
	g := newStorageGroup(dir)
	s, err := g.Open("", 0, 64*1024*1024, 256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	for i := 0; i < 4; i++ {
		s.Write("auth", map[string]any{"event": "auth_failed"})
		s.Write("network", map[string]any{"event": "auth_failed"})
	}
	time.Sleep(200 * time.Millisecond)
	// Verify both files exist on disk.
	authPath := filepath.Join(dir, "auth")
	if _, err := os.Stat(authPath); err != nil {
		t.Fatalf("auth dir missing: %v", err)
	}

	cfg := Config{Mode: "standalone", LogDir: dir}
	roots := searchRoots(cfg, "")
	auth := loadEventsInRangeMulti(roots, time.Now().Add(-1*time.Hour), time.Now().Add(time.Hour), "auth")
	all := loadEventsInRangeMulti(roots, time.Now().Add(-1*time.Hour), time.Now().Add(time.Hour), "")
	if len(auth) != 4 {
		t.Errorf("auth-only events: got %d, want 4", len(auth))
	}
	if len(all) != 8 {
		t.Errorf("all events: got %d, want 8", len(all))
	}
}
