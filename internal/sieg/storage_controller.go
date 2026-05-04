package sieg

import (
	"context"
	"sync"
	"time"
)

// storageController watches the volume backing the daemon's primary
// Storage instance, raising warnings as free space erodes and
// switching to a configured failover location (or halting writes)
// when usage crosses the halt threshold.
//
// Lifecycle:
//   - Spawned by the daemon at startup.
//   - Polls every probeInterval (default 30s).
//   - Emits storage_warning / storage_halt / storage_recovered events
//     into the storage's own meta log so realm peers and any master
//     above replicate them naturally — no separate RPC.
//   - Honours an internal hourly rate limit on warning re-emission so
//     a sustained 80% volume doesn't spam meta.
//
// The controller never panics on probe errors. A volume that can't be
// statfs-ed is treated as "skip this round" rather than a halt — a
// disconnected USB drive shouldn't take the daemon down on its own.
type storageController struct {
	group         *storageGroup
	cfg           Config
	probeInterval time.Duration
	warnCooldown  time.Duration

	mu            sync.Mutex
	lastState     storageState
	lastWarnEmit  time.Time
	currentLocIdx int
	failoverChain []string
}

func newStorageController(g *storageGroup, cfg Config) *storageController {
	chain := allStorageLocations(cfg)
	idx := 0
	for i, loc := range chain {
		if loc == g.Root() {
			idx = i
			break
		}
	}
	return &storageController{
		group:         g,
		cfg:           cfg,
		probeInterval: 30 * time.Second,
		warnCooldown:  time.Hour,
		lastState:     storageOK,
		currentLocIdx: idx,
		failoverChain: chain,
	}
}

func (c *storageController) start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go c.run(ctx, wg)
}

func (c *storageController) run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	// Run an initial probe immediately so an operator who starts the
	// daemon on an already-full volume sees the halt event in
	// `simplesiem tail` within seconds rather than waiting a full
	// probe interval.
	c.probeOnce()
	t := time.NewTicker(c.probeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.probeOnce()
		}
	}
}

func (c *storageController) probeOnce() {
	c.mu.Lock()
	defer c.mu.Unlock()

	q := resolveQuotas(c.cfg)
	active := c.group.Root()
	v, err := probeVolume(active)
	if err != nil {
		// Volume unavailable. Don't change state on a single probe
		// failure — a flaky NFS mount shouldn't cause a halt event.
		// If the failure persists the next round will retry.
		return
	}
	state := classifyVolume(v, q.Warn, q.Halt)

	switch state {
	case storageOK:
		if c.lastState != storageOK {
			c.emitRecovered(active, v, q)
		}
		c.lastState = storageOK
		// If we're operating on a failover location and the primary
		// has come back below halt, fail back to it. Failing back
		// avoids permanently abandoning the operator's preferred
		// storage just because of a transient fill.
		if c.currentLocIdx > 0 {
			c.tryFailback(q)
		}
		c.group.SetHalted(false)
	case storageWarn:
		if c.lastState != storageWarn || time.Since(c.lastWarnEmit) >= c.warnCooldown {
			c.emitWarning(active, v, q)
			c.lastWarnEmit = time.Now()
		}
		c.lastState = storageWarn
		c.group.SetHalted(false)
	case storageHalt:
		// Try to fail over before halting writes. If a non-halted
		// downstream location is configured, that's better than
		// dropping events entirely.
		if c.tryFailover(q) {
			// A failover happened; every member of the group is
			// now writing to the new volume. Clear halted; the
			// next tick will re-probe the new location. lastState
			// resets to OK so a subsequent fill of the new
			// location re-emits warnings cleanly.
			c.group.SetHalted(false)
			c.lastState = storageOK
			return
		}
		if c.lastState != storageHalt {
			c.emitHalt(active, v, q)
		}
		c.lastState = storageHalt
		c.group.SetHalted(true)
	}
}

// tryFailover steps forward through the configured failover chain
// looking for the first volume below the halt threshold. Returns true
// if a switch was performed. The new active location's halt-state is
// not re-checked here — the next probe tick will classify it.
func (c *storageController) tryFailover(q resolvedQuotas) bool {
	for i := c.currentLocIdx + 1; i < len(c.failoverChain); i++ {
		loc := c.failoverChain[i]
		v, err := probeVolume(loc)
		if err != nil {
			continue
		}
		if classifyVolume(v, q.Warn, q.Halt) == storageHalt {
			continue
		}
		if err := c.group.SwitchRoot(loc); err != nil {
			continue
		}
		c.emitFailover(c.failoverChain[c.currentLocIdx], loc, v, q)
		c.currentLocIdx = i
		return true
	}
	return false
}

// tryFailback attempts to move back to the primary log_dir (or any
// earlier entry in the chain) once those have recovered below the warn
// threshold. Stricter recovery threshold than failover — we want a
// comfortable margin before flapping back to a volume that just hit
// 90%, otherwise a write burst could re-halt it immediately.
func (c *storageController) tryFailback(q resolvedQuotas) {
	for i := 0; i < c.currentLocIdx; i++ {
		loc := c.failoverChain[i]
		v, err := probeVolume(loc)
		if err != nil {
			continue
		}
		if classifyVolume(v, q.Warn, q.Halt) != storageOK {
			continue
		}
		if err := c.group.SwitchRoot(loc); err != nil {
			continue
		}
		c.emitFailback(c.failoverChain[c.currentLocIdx], loc, v, q)
		c.currentLocIdx = i
		return
	}
}

func (c *storageController) emitWarning(path string, v volumeUsage, q resolvedQuotas) {
	c.group.PrimaryStorage().WriteForced("meta", map[string]any{
		"event":        "storage_warning",
		"path":         path,
		"used_pct":     formatPercent(v.UsedPercent),
		"used_bytes":   v.Used,
		"free_bytes":   v.Free,
		"total_bytes":  v.Total,
		"warn":         q.Warn.Original,
		"halt":         q.Halt.Original,
		"hint":         "free space below warn threshold; halt threshold approaching",
	})
}

func (c *storageController) emitHalt(path string, v volumeUsage, q resolvedQuotas) {
	c.group.PrimaryStorage().WriteForced("meta", map[string]any{
		"event":        "storage_halt",
		"path":         path,
		"used_pct":     formatPercent(v.UsedPercent),
		"used_bytes":   v.Used,
		"free_bytes":   v.Free,
		"total_bytes":  v.Total,
		"warn":         q.Warn.Original,
		"halt":         q.Halt.Original,
		"hint":         "writes rejected; free disk space or configure storage.failover_locations",
	})
}

func (c *storageController) emitRecovered(path string, v volumeUsage, q resolvedQuotas) {
	c.group.PrimaryStorage().WriteForced("meta", map[string]any{
		"event":        "storage_recovered",
		"path":         path,
		"used_pct":     formatPercent(v.UsedPercent),
		"used_bytes":   v.Used,
		"free_bytes":   v.Free,
		"total_bytes":  v.Total,
		"warn":         q.Warn.Original,
		"halt":         q.Halt.Original,
	})
}

func (c *storageController) emitFailover(from, to string, v volumeUsage, q resolvedQuotas) {
	c.group.PrimaryStorage().WriteForced("meta", map[string]any{
		"event":        "storage_failover",
		"from":         from,
		"to":           to,
		"to_used_pct":  formatPercent(v.UsedPercent),
		"to_free":      v.Free,
		"to_total":     v.Total,
		"hint":         "primary volume halted; events now writing to failover location",
	})
}

func (c *storageController) emitFailback(from, to string, v volumeUsage, q resolvedQuotas) {
	c.group.PrimaryStorage().WriteForced("meta", map[string]any{
		"event":        "storage_failback",
		"from":         from,
		"to":           to,
		"to_used_pct":  formatPercent(v.UsedPercent),
		"to_free":      v.Free,
		"to_total":     v.Total,
		"hint":         "primary volume recovered below warn; events now writing back to it",
	})
}

func formatPercent(p float64) string {
	// One decimal is enough for status display ("82.4%") and keeps the
	// emitted JSON stable (no float-precision noise) when peers
	// replicate the warning event.
	return formatFloat1(p) + "%"
}

func formatFloat1(p float64) string {
	// Avoid pulling fmt for one number; keep the meta event compact.
	// Round half away from zero by adding 0.05 before truncation.
	if p < 0 {
		return "-" + formatFloat1(-p)
	}
	whole := int64(p)
	frac := int64((p-float64(whole))*10 + 0.5)
	if frac >= 10 {
		whole++
		frac = 0
	}
	return itoaInt64(whole) + "." + string(rune('0'+frac))
}

func itoaInt64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
