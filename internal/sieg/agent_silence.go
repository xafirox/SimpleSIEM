package sieg

import (
	"context"
	"sync"
	"time"
)

// agentSilenceDetector fires meta:agent_silent_anomaly when an
// allowlisted agent stops talking. Complementary to the
// volumeAnomalyDetector — that one needs an established baseline
// (≥5 events/min) before it can call a drop suspicious, so it never
// fires for an agent that enrolled and then was killed before it
// built up a chatty cadence (the as7 manual-test scenario).
//
// Algorithm is purely time-based:
//   - Every minute, walk the cfg.Server.AgentAllowlist.
//   - For each entry: lookup hostLastSeen[agent] under the server's
//     liveness map. handleHeartbeat / handleEvents / handleEnroll
//     all bump that map, so the timestamp tracks anything we'd
//     reasonably call "this agent is alive."
//   - If lastSeen is older than threshold (default 5 min) AND we
//     haven't already alerted on this silence, write the meta event
//     and mark alerted.
//   - When lastSeen comes back inside the window, fire
//     agent_silent_recovered and clear the alerted flag.
//
// Threshold is intentionally generous (5x the 60-second default
// reauth_seconds) so a single flaky network minute doesn't trip an
// alert. Operators can tune via cfg.server.volume_anomaly.silence_mins
// if their environment runs longer reauth intervals.
//
// Suppression: per-agent, until recovery. A sustained outage produces
// one alert and one recovery event per outage — not one per minute.
type agentSilenceDetector struct {
	server    *serverState
	threshold time.Duration

	mu       sync.Mutex
	alerted  map[string]bool
}

func newAgentSilenceDetector(s *serverState, threshold time.Duration) *agentSilenceDetector {
	if threshold <= 0 {
		threshold = 5 * time.Minute
	}
	return &agentSilenceDetector{
		server:    s,
		threshold: threshold,
		alerted:   map[string]bool{},
	}
}

func (d *agentSilenceDetector) start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Bootstrap hostLastSeen from disk so a server restart doesn't
		// flag every allowlisted agent as silent for the first 5
		// minutes. Newest .jsonl mtime under <log_dir>/<agent>/ is a
		// faithful "we heard from this agent at time X" stand-in for
		// the in-memory map that we lost across restart.
		d.bootstrapFromDisk()
		// First check after a full threshold window so an agent that
		// just heartbeated has time to land.
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				d.tick()
			}
		}
	}()
}

func (d *agentSilenceDetector) bootstrapFromDisk() {
	s := d.server
	allow := s.snapshotAllowlist()
	if len(allow) == 0 {
		return
	}
	s.hostLivenessMu.Lock()
	defer s.hostLivenessMu.Unlock()
	if s.hostLastSeen == nil {
		s.hostLastSeen = map[string]time.Time{}
	}
	for _, h := range allow {
		if _, ok := s.hostLastSeen[h]; ok {
			continue
		}
		mt := newestMTimeForHost(s.base, h)
		if !mt.IsZero() {
			s.hostLastSeen[h] = mt
		}
	}
}

func (d *agentSilenceDetector) tick() {
	s := d.server
	allow := s.snapshotAllowlist()
	now := time.Now().UTC()

	s.hostLivenessMu.RLock()
	seen := make(map[string]time.Time, len(s.hostLastSeen))
	for k, v := range s.hostLastSeen {
		seen[k] = v
	}
	s.hostLivenessMu.RUnlock()

	d.mu.Lock()
	defer d.mu.Unlock()
	for _, agent := range allow {
		ls, ok := seen[agent]
		if !ok || ls.IsZero() {
			// Never heard from. Don't alert — we can't tell silence
			// from "agent has not started yet". The 5-minute clock
			// only ticks once we've ever observed activity (enroll,
			// heartbeat, or events).
			continue
		}
		stalled := now.Sub(ls)
		alerted := d.alerted[agent]
		switch {
		case stalled > d.threshold && !alerted:
			d.alerted[agent] = true
			s.writeSilenceAlert(agent, stalled)
		case stalled <= d.threshold && alerted:
			d.alerted[agent] = false
			s.writeSilenceRecovered(agent)
		}
	}
}

// snapshotAllowlist returns a copy of the configured agent IDs under
// the allowlist mutex. Empty result means "open mode" — silence
// detector intentionally does nothing in that case (we can't enumerate
// who's expected to be alive).
func (s *serverState) snapshotAllowlist() []string {
	s.allowlistMu.RLock()
	defer s.allowlistMu.RUnlock()
	out := make([]string, 0, len(s.allowlist))
	for id := range s.allowlist {
		out = append(out, id)
	}
	return out
}

func (s *serverState) writeSilenceAlert(agent string, stalled time.Duration) {
	// Each Write call sends the event into a separate writer
	// goroutine that stamps _seq/_prev/_hash on the map — sharing
	// one map between two queues races, so build a fresh copy per
	// recipient.
	build := func() map[string]any {
		return map[string]any{
			"event":      "agent_silent_anomaly",
			"agent":      agent,
			"silent_for": stalled.Round(time.Second).String(),
			"hint":       "agent has not heartbeated or shipped events for over 5 minutes — possible compromise + daemon kill, network outage, or aggressive shutdown",
			"detector":   "absolute_silence",
		}
	}
	if st, err := s.storageFor(agent); err == nil {
		st.Write("meta", build())
	}
	if st, err := s.storageFor("_server"); err == nil {
		st.Write("meta", build())
	}
}

func (s *serverState) writeSilenceRecovered(agent string) {
	build := func() map[string]any {
		return map[string]any{
			"event":    "agent_silent_recovered",
			"agent":    agent,
			"hint":     "agent has resumed heartbeating or shipping events",
			"detector": "absolute_silence",
		}
	}
	if st, err := s.storageFor(agent); err == nil {
		st.Write("meta", build())
	}
	if st, err := s.storageFor("_server"); err == nil {
		st.Write("meta", build())
	}
}

