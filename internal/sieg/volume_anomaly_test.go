package sieg

import (
	"testing"
	"time"
)

// TestVolumeAnomaly_FiresWhenAgentGoesQuiet verifies the canonical
// detection: an agent that's been steady at ~50 events/min suddenly
// drops to 0, and the detector fires after `consecutive` minutes
// of silence.
func TestVolumeAnomaly_FiresWhenAgentGoesQuiet(t *testing.T) {
	d := newVolumeAnomalyDetector(nil)
	var fires []string
	var recovers []string
	d.onAlert = func(agent string, base, cur float64) { fires = append(fires, agent) }
	d.onRecovered = func(agent string, base, cur float64) { recovers = append(recovers, agent) }
	d.consecutive = 2
	d.minBaseline = 5
	d.dropRatio = 0.05

	now := time.Now()
	// Warm-up: feed 50 events/min for 6 minutes so the EWMA stabilises
	// past the 3-minute warming threshold.
	for i := 0; i < 6; i++ {
		d.recordIngress("agent-1", 50)
		now = now.Add(time.Minute)
		d.rotate(now)
	}
	if len(fires) != 0 {
		t.Errorf("warmup fired %d times; expected 0", len(fires))
	}
	// Override firstSeen so the warming gate doesn't suppress checks.
	d.mu.Lock()
	d.stats["agent-1"].firstSeen = now.Add(-10 * time.Minute)
	d.mu.Unlock()

	// Quiet minute 1 — under the 5% threshold (0.05*~50 = 2.5 events).
	now = now.Add(time.Minute)
	d.rotate(now)
	if len(fires) != 0 {
		t.Errorf("after 1 quiet minute: fired %d times; expected 0 (need %d consecutive)", len(fires), d.consecutive)
	}
	// Quiet minute 2 — should fire now.
	now = now.Add(time.Minute)
	d.rotate(now)
	if len(fires) != 1 {
		t.Errorf("after 2 quiet minutes: fired %d times; expected 1", len(fires))
	}
	// Quiet minute 3 — alert is sticky (cooldown), don't refire.
	now = now.Add(time.Minute)
	d.rotate(now)
	if len(fires) != 1 {
		t.Errorf("after 3 quiet minutes: fired %d times; expected 1 (cooldown)", len(fires))
	}
	// Recovery: a busy minute should clear the alerted flag and fire
	// the recovered event.
	d.recordIngress("agent-1", 30)
	now = now.Add(time.Minute)
	d.rotate(now)
	if len(recovers) != 1 {
		t.Errorf("after recovery minute: recovered %d times; expected 1", len(recovers))
	}
}

// TestVolumeAnomaly_QuietAgentNotFlagged verifies the minBaseline
// guard: an agent that was already producing < minBaseline events
// per minute is not "anomalous" when it goes silent — there's no
// statistical signal to fire on.
func TestVolumeAnomaly_QuietAgentNotFlagged(t *testing.T) {
	d := newVolumeAnomalyDetector(nil)
	var fires int
	d.onAlert = func(string, float64, float64) { fires++ }
	d.minBaseline = 5
	d.dropRatio = 0.05
	d.consecutive = 2

	now := time.Now()
	// 1 event/min for 10 minutes — well below minBaseline.
	for i := 0; i < 10; i++ {
		d.recordIngress("quiet-agent", 1)
		now = now.Add(time.Minute)
		d.rotate(now)
	}
	d.mu.Lock()
	d.stats["quiet-agent"].firstSeen = now.Add(-15 * time.Minute)
	d.mu.Unlock()

	// Now go silent for 5 minutes.
	for i := 0; i < 5; i++ {
		now = now.Add(time.Minute)
		d.rotate(now)
	}
	if fires != 0 {
		t.Errorf("quiet agent silenced for 5 minutes: fired %d times; expected 0 (below minBaseline)", fires)
	}
}

// TestVolumeAnomaly_WarmupSuppression verifies that the first 3
// minutes after an agent's first appearance can't trigger an
// anomaly, even if it bounces above and below baseline. Without
// this guard, a brand-new agent that appears + disappears within
// the first few minutes would falsely fire.
func TestVolumeAnomaly_WarmupSuppression(t *testing.T) {
	d := newVolumeAnomalyDetector(nil)
	var fires int
	d.onAlert = func(string, float64, float64) { fires++ }
	d.consecutive = 2
	d.minBaseline = 5

	now := time.Now()
	d.recordIngress("new-agent", 100)
	d.rotate(now.Add(time.Minute))
	// Suddenly silent — but inside the warmup window.
	d.rotate(now.Add(2 * time.Minute))
	d.rotate(now.Add(3 * time.Minute - time.Second))
	if fires != 0 {
		t.Errorf("warmup window: fired %d times; expected 0", fires)
	}
}
