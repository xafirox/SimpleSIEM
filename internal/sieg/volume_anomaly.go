package sieg

import (
	"context"
	"sync"
	"time"
)

// volumeAnomalyDetector watches the per-agent ingress rate at the
// server and fires `meta:agent_silent_anomaly` when an agent that
// was previously contributing events suddenly goes quiet. Catches
// the canonical "attacker rooted the agent + killed the daemon"
// scenario faster than waiting for a manual operator review.
//
// Algorithm:
//
//   - Maintain an exponentially weighted moving average (EWMA) of
//     events-per-minute per agent. Alpha = 0.2 (the new sample
//     contributes 20%, the prior EWMA 80%) so a single quiet minute
//     during a heartbeat blip doesn't tank the baseline.
//   - Every minute, rotate: ewma = alpha*current + (1-alpha)*ewma,
//     reset `current` to 0.
//   - After rotation, check: if ewma >= minBaseline AND current <
//     ewma * dropRatio for `consecutive` minutes in a row, fire
//     once and enter "alerted" state.
//   - Recovery: when current ≥ ewma * 0.5 AND we were alerted,
//     fire `meta:agent_silent_recovered`.
//
// Suppression: a single agent_silent_anomaly per agent per
// cooldownDuration. Without suppression, a sustained outage would
// produce one alert per minute for hours; the operator's inbox
// fills up while the actual signal ("agent X went quiet") is
// already visible.
//
// Why minBaseline matters: an agent that's never been chatty can
// LOOK silent without anything being wrong. We require ewma >=
// minBaseline (default 5 events/min) before treating a drop as
// suspicious — quiet agents stay quietly OK.
type volumeAnomalyDetector struct {
	mu          sync.Mutex
	stats       map[string]*agentVolumeStats
	server      *serverState
	minBaseline float64
	dropRatio   float64
	consecutive int
	cooldown    time.Duration

	// onAlert / onRecovered are abstracted so the unit test can
	// substitute a recorder. Production wires both to writeAnomaly /
	// writeRecovered which emit meta events into the agent's per-host
	// log stream.
	onAlert     func(agent string, baseline, current float64)
	onRecovered func(agent string, baseline, current float64)
}

type agentVolumeStats struct {
	ewma       float64
	current    int
	consecLow  int
	alerted    bool
	lastAlert  time.Time
	firstSeen  time.Time
}

func newVolumeAnomalyDetector(s *serverState) *volumeAnomalyDetector {
	return &volumeAnomalyDetector{
		stats:       map[string]*agentVolumeStats{},
		server:      s,
		minBaseline: 5,
		dropRatio:   0.05,
		consecutive: 2,
		cooldown:    30 * time.Minute,
	}
}

// tune applies an operator-configured override. Zero values keep the
// built-in default — operators who only want to tweak one knob don't
// have to redeclare every field. Called once at server startup AND
// from configWatcher when cfg.server.volume_anomaly changes, so
// adjustments take effect within ~1 s of editing config.json without
// a daemon restart.
func (d *volumeAnomalyDetector) tune(cfg VolumeAnomalyConfig) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if cfg.MinBaseline > 0 {
		d.minBaseline = cfg.MinBaseline
	}
	if cfg.DropRatio > 0 {
		d.dropRatio = cfg.DropRatio
	}
	if cfg.Consecutive > 0 {
		d.consecutive = cfg.Consecutive
	}
	if cfg.CooldownMins > 0 {
		d.cooldown = time.Duration(cfg.CooldownMins) * time.Minute
	}
}

// recordIngress is called by handleEvents on every successfully-
// authenticated batch arrival. count is the number of events in the
// batch. agent is the cert CN. Cheap: a single increment under the
// detector's mutex.
func (d *volumeAnomalyDetector) recordIngress(agent string, count int) {
	if count <= 0 || agent == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.stats[agent]
	if !ok {
		st = &agentVolumeStats{firstSeen: time.Now()}
		d.stats[agent] = st
	}
	st.current += count
}

// rotate is the per-minute tick. Called by start()'s goroutine. For
// each tracked agent: update ewma from this minute's count, reset
// the count, run the anomaly check.
func (d *volumeAnomalyDetector) rotate(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for agent, st := range d.stats {
		// Skip the warm-up window: an agent that's been seen for less
		// than 3 minutes hasn't built up a stable baseline yet.
		warming := now.Sub(st.firstSeen) < 3*time.Minute
		current := float64(st.current)
		st.current = 0
		const alpha = 0.2
		if st.ewma == 0 {
			st.ewma = current
		} else {
			st.ewma = alpha*current + (1-alpha)*st.ewma
		}
		if warming {
			continue
		}
		// Anomaly check: was the rate high enough to be meaningful,
		// and did this minute drop way below it?
		threshold := st.ewma * d.dropRatio
		if st.ewma >= d.minBaseline && current < threshold {
			st.consecLow++
		} else {
			// Recovery — current is back near baseline.
			if st.alerted && current >= st.ewma*0.5 {
				st.alerted = false
				if d.onRecovered != nil {
					d.onRecovered(agent, st.ewma, current)
				}
			}
			st.consecLow = 0
		}
		// Fire (once per cooldown window).
		if st.consecLow >= d.consecutive && !st.alerted {
			if now.Sub(st.lastAlert) >= d.cooldown {
				st.alerted = true
				st.lastAlert = now
				if d.onAlert != nil {
					d.onAlert(agent, st.ewma, current)
				}
			}
		}
	}
}

// start launches the per-minute rotate loop. Stops cleanly when ctx
// is cancelled. The wg ensures the daemon's Stop path waits for the
// final rotation to complete before exiting.
func (d *volumeAnomalyDetector) start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				d.rotate(now)
			}
		}
	}()
}

// writeAnomaly emits the meta event into the agent's per-host log
// stream so triage --host <agent> --type meta surfaces it. Also
// writes a copy under _server/meta so a server-wide triage finds
// it without --host filtering. Best-effort: a storage error doesn't
// re-fire the alert.
func (s *serverState) writeAnomaly(agent string, baseline, current float64) {
	fields := map[string]any{
		"event":              "agent_silent_anomaly",
		"agent":              agent,
		"baseline_per_min":   baseline,
		"observed_per_min":   current,
		"drop_ratio":         current / baseline,
		"hint":               "agent's event rate dropped below 5% of its rolling baseline for 2+ consecutive minutes — possible compromise + daemon kill, network outage, or aggressive shutdown",
	}
	if st, err := s.storageFor(agent); err == nil {
		st.Write("meta", fields)
	}
	if st, err := s.storageFor("_server"); err == nil {
		st.Write("meta", fields)
	}
}

func (s *serverState) writeRecovered(agent string, baseline, current float64) {
	fields := map[string]any{
		"event":            "agent_silent_recovered",
		"agent":            agent,
		"baseline_per_min": baseline,
		"observed_per_min": current,
	}
	if st, err := s.storageFor(agent); err == nil {
		st.Write("meta", fields)
	}
	if st, err := s.storageFor("_server"); err == nil {
		st.Write("meta", fields)
	}
}
