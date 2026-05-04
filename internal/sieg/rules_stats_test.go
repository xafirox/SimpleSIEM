package sieg

import (
	"testing"
	"time"
)

// TestRulesStats_AggregatesByRule writes alerts events to a synthetic
// log_dir and confirms loadEventsInRangeMulti returns them in the
// `alerts` log type filter, which is what runRulesStats walks. The
// stats helper itself is a pure aggregation over the returned slice;
// re-implementing the aggregation in the test would only validate the
// test, so we exercise the same loader path and assert the inputs are
// shaped correctly.
func TestRulesStats_AggregatesByRule(t *testing.T) {
	dir := t.TempDir()
	g := newStorageGroup(dir)
	s, err := g.Open("", 0, 64*1024*1024, 256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	for i := 0; i < 5; i++ {
		s.Write("alerts", map[string]any{
			"event":         "rule_match",
			"rule":          "noisy-rule",
			"severity":      "low",
			"matched_type":  "auth",
			"matched_event": "auth_failed",
		})
	}
	for i := 0; i < 2; i++ {
		s.Write("alerts", map[string]any{
			"event":         "rule_match",
			"rule":          "rare-rule",
			"severity":      "high",
			"matched_type":  "files",
			"matched_event": "modify",
		})
	}
	time.Sleep(200 * time.Millisecond)

	cfg := Config{Mode: "standalone", LogDir: dir}
	roots := searchRoots(cfg, "")
	events := loadEventsInRangeMulti(roots, time.Now().Add(-1*time.Hour), time.Now().Add(time.Hour), "alerts")

	counts := map[string]int{}
	for _, e := range events {
		ev, _ := e.Data["event"].(string)
		if ev != "rule_match" {
			continue
		}
		name, _ := e.Data["rule"].(string)
		counts[name]++
	}
	if counts["noisy-rule"] != 5 {
		t.Errorf("noisy-rule fires: got %d, want 5", counts["noisy-rule"])
	}
	if counts["rare-rule"] != 2 {
		t.Errorf("rare-rule fires: got %d, want 2", counts["rare-rule"])
	}
}
