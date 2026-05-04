package sieg

import (
	"context"
	"sync"
	"time"
)

// HealthMonitor tracks per-collector liveness. Each collector calls Beat
// when it makes progress; HealthMonitor periodically checks for collectors
// that have gone silent and emits a meta event so a rule (or a human
// reading the meta log) can notice. The daemon-running-but-broken case
// otherwise looks identical to a quiet system.
//
// Beat is intentionally cheap (one map write under a mutex) because it's
// called from the hot path of every collector loop.
type HealthMonitor struct {
	storage  *Storage
	interval time.Duration
	timeout  time.Duration

	mu     sync.Mutex
	beats  map[string]time.Time
	silent map[string]bool
}

func newHealthMonitor(storage *Storage, interval, timeout time.Duration) *HealthMonitor {
	return &HealthMonitor{
		storage:  storage,
		interval: interval,
		timeout:  timeout,
		beats:    map[string]time.Time{},
		silent:   map[string]bool{},
	}
}

// Register seeds a collector name as expected, with `now` as the initial
// beat. Without this, a collector that never beats would never trigger a
// silent alert because it wouldn't be in the map. Called by daemon.go for
// each collector at startup.
func (h *HealthMonitor) Register(names ...string) {
	if h == nil {
		return
	}
	now := time.Now()
	h.mu.Lock()
	for _, n := range names {
		h.beats[n] = now
	}
	h.mu.Unlock()
}

func (h *HealthMonitor) Beat(name string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.beats[name] = time.Now()
	if h.silent[name] {
		// Recovered — emit a meta event so the timeline shows the gap.
		// Drop the silent flag so a future stall re-fires.
		delete(h.silent, name)
		go h.storage.Write("meta", map[string]any{
			"event":     "collector_recovered",
			"collector": name,
		})
	}
	h.mu.Unlock()
}

func (h *HealthMonitor) Start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(h.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			h.check()
		}
	}()
}

func (h *HealthMonitor) check() {
	cutoff := time.Now().Add(-h.timeout)
	h.mu.Lock()
	defer h.mu.Unlock()
	for name, last := range h.beats {
		if last.Before(cutoff) && !h.silent[name] {
			h.silent[name] = true
			h.storage.Write("meta", map[string]any{
				"event":        "collector_silent",
				"collector":    name,
				"last_beat":    last.UTC().Format(time.RFC3339),
				"silent_for_s": int(time.Since(last).Seconds()),
				"timeout_s":    int(h.timeout.Seconds()),
			})
		}
	}
}
