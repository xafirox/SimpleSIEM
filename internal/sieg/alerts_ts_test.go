package sieg

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRuleEngine_AlertsHaveTimestamp locks in the fix for the bug where
// rule_match events were written with chain integrity but no ts/type
// fields, so `simplesiem alerts --since N` and any other time-windowed
// reader silently dropped every alert. Prior to the fix this test
// failed because the parsed alert event had ts == "".
func TestRuleEngine_AlertsHaveTimestamp(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStorage(dir, 0, 0, 64)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer st.Close()

	rule := &alertRule{
		Name:     "ts_regression",
		Severity: "high",
		Match:    map[string]matcher{"event": {kind: matchExact, s: "test_event"}},
	}
	st.SetRules([]*alertRule{rule})

	st.Write("files", map[string]any{"event": "test_event", "path": "/tmp/x"})

	// Give the writer goroutine time to drain the queue, evaluate rules,
	// and write the alert.
	deadline := time.Now().Add(2 * time.Second)
	alertPath := filepath.Join(dir, "alerts", time.Now().UTC().Format("2006-01-02")+".jsonl")
	for time.Now().Before(deadline) {
		if _, err := os.Stat(alertPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	f, err := os.Open(alertPath)
	if err != nil {
		t.Fatalf("alert file not written: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatal("alert file is empty")
	}
	var event map[string]any
	if err := json.Unmarshal(sc.Bytes(), &event); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if ts, _ := event["ts"].(string); ts == "" {
		t.Fatal("alert event has no ts — runAlertsCmd / triage will silently drop it")
	}
	if typ, _ := event["type"].(string); typ != "alerts" {
		t.Errorf("type = %q, want %q", typ, "alerts")
	}
}
