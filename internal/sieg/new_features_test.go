package sieg

import (
	"testing"
	"time"
)

// TestVolumeAnomaly_Tune verifies as21 — the tune() helper applies
// non-zero overrides and leaves zero-valued fields at their default.
func TestVolumeAnomaly_Tune(t *testing.T) {
	d := newVolumeAnomalyDetector(nil)
	// Defaults captured here so the test doesn't drift if newDetector's
	// defaults are ever bumped.
	wantBaseline := d.minBaseline
	wantDropRatio := d.dropRatio
	wantConsec := d.consecutive
	wantCooldown := d.cooldown

	// Empty config — every field should keep its default.
	d.tune(VolumeAnomalyConfig{})
	if d.minBaseline != wantBaseline || d.dropRatio != wantDropRatio || d.consecutive != wantConsec || d.cooldown != wantCooldown {
		t.Errorf("zero-config tune drifted defaults: %+v", d)
	}

	// Override every field.
	d.tune(VolumeAnomalyConfig{
		MinBaseline:  12,
		DropRatio:    0.10,
		Consecutive:  4,
		CooldownMins: 60,
	})
	if d.minBaseline != 12 {
		t.Errorf("MinBaseline: got %v want 12", d.minBaseline)
	}
	if d.dropRatio != 0.10 {
		t.Errorf("DropRatio: got %v want 0.10", d.dropRatio)
	}
	if d.consecutive != 4 {
		t.Errorf("Consecutive: got %v want 4", d.consecutive)
	}
	if d.cooldown != 60*time.Minute {
		t.Errorf("Cooldown: got %v want 60m", d.cooldown)
	}

	// Partial override — only DropRatio. Others must keep their last
	// applied values (12 / 4 / 60m), not snap back to defaults.
	d.tune(VolumeAnomalyConfig{DropRatio: 0.20})
	if d.dropRatio != 0.20 {
		t.Errorf("partial DropRatio: got %v want 0.20", d.dropRatio)
	}
	if d.minBaseline != 12 {
		t.Errorf("partial MinBaseline drifted: got %v want 12 (no override)", d.minBaseline)
	}
}

// TestCollectorPullState_TransitionEvents verifies c7 — the
// up/down transitions emit collector_query_failsafe_on /
// collector_query_failsafe_off via the collector's storage logger.
func TestCollectorPullState_TransitionEvents(t *testing.T) {
	dir := t.TempDir()
	g := newStorageGroup(dir)
	// Open at the root so the standalone-shape loader finds the
	// emitted meta events without needing a per-host subdir walk.
	st, err := g.Open("", 0, 64*1024*1024, 256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	// Reset the package-level state so we don't see stale flags from
	// a parallel test.
	collectorPullStateMu.Lock()
	collectorPullDown = false
	collectorPullStateMu.Unlock()

	// First call: down=true → emits failsafe_on.
	collectorMarkSourceState(st, "https://master.example.com:9445", true)
	// Second call: still down → no transition.
	collectorMarkSourceState(st, "https://master.example.com:9445", true)
	// Third call: up → emits failsafe_off.
	collectorMarkSourceState(st, "https://master.example.com:9445", false)

	// Wait for the writer goroutine to flush.
	time.Sleep(200 * time.Millisecond)

	// Walk the meta dir and count transitions.
	cfg := Config{Mode: "standalone", LogDir: dir}
	roots := searchRoots(cfg, "")
	events := loadEventsInRangeMulti(roots, time.Now().Add(-1*time.Hour), time.Now().Add(time.Hour), "meta")
	on := 0
	off := 0
	for _, e := range events {
		switch e.Data["event"] {
		case "collector_query_failsafe_on":
			on++
		case "collector_query_failsafe_off":
			off++
		}
	}
	if on != 1 || off != 1 {
		t.Errorf("transition events: got on=%d off=%d, want 1+1", on, off)
	}
}
