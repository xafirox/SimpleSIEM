package sieg

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestMasterRules_EvaluateRulesFiresThroughHook confirms that
// Storage.EvaluateRules (which the master pull loop calls on every
// replicated event) fires through the registered alert hooks. This
// is the cross-host correlation entry point — without this path
// firing, master-side rules would silently swallow matches.
func TestMasterRules_EvaluateRulesFiresThroughHook(t *testing.T) {
	dir := t.TempDir()
	g := newStorageGroup(dir)
	s, err := g.Open("_master", 0, 64*1024*1024, 256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	rulesPath := filepath.Join(t.TempDir(), "rules.json")
	rulesJSON := `[{"name":"master-failed-login","severity":"high","match":{"event":"auth_failed"}}]`
	if err := os.WriteFile(rulesPath, []byte(rulesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	s.SetRules(rules)

	// Capture alert dispatches via a counter hook (mirrors how the
	// webhook / syslog / metrics dispatchers attach in production).
	var fires uint64
	var mu sync.Mutex
	var lastRule string
	s.AddAlertHook(func(a map[string]any) {
		atomic.AddUint64(&fires, 1)
		mu.Lock()
		lastRule, _ = a["rule"].(string)
		mu.Unlock()
	})

	// Simulate a pulled event from a server. masterPullOnce calls
	// EvaluateRules with the type and the event verbatim.
	event := map[string]any{
		"event": "auth_failed",
		"user":  "alice",
		"host":  "agent-7",
		"type":  "auth",
	}
	s.EvaluateRules("auth", event)

	// Storage writeNow is async (goroutine drains the queue), so wait
	// briefly for the alert write to land.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadUint64(&fires) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if atomic.LoadUint64(&fires) != 1 {
		t.Errorf("master rule fires: got %d, want 1", atomic.LoadUint64(&fires))
	}
	mu.Lock()
	defer mu.Unlock()
	if lastRule != "master-failed-login" {
		t.Errorf("fired rule: got %q, want master-failed-login", lastRule)
	}
}

// TestMasterRules_NonMatchingEventStays_silent confirms that an event
// not matching any master-side rule produces no fires.
func TestMasterRules_NonMatchingEventStays_silent(t *testing.T) {
	dir := t.TempDir()
	g := newStorageGroup(dir)
	s, err := g.Open("_master", 0, 64*1024*1024, 256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	rulesPath := filepath.Join(t.TempDir(), "rules.json")
	rulesJSON := `[{"name":"only-on-failed","severity":"high","match":{"event":"auth_failed"}}]`
	if err := os.WriteFile(rulesPath, []byte(rulesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	s.SetRules(rules)

	var fires uint64
	s.AddAlertHook(func(a map[string]any) { atomic.AddUint64(&fires, 1) })

	s.EvaluateRules("auth", map[string]any{"event": "auth_success"})
	time.Sleep(200 * time.Millisecond)
	if got := atomic.LoadUint64(&fires); got != 0 {
		t.Errorf("expected 0 fires for non-matching event, got %d", got)
	}
}
