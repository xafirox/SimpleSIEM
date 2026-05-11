package sieg

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// firstSeenDetector tracks per-host sets of "entities we've seen" for
// a fixed list of fields (user, source_ip, sha256, remote_host,
// process_name) and emits a `meta:first_seen_<field>` event the first
// time a given (host, field, value) tuple appears. Persistent across
// restarts via state_dir; entries decay after retentionDays so a
// long-running daemon doesn't keep forever-old values "first-seen".
//
// Threat-detection value: this catches the "first time alice logged
// in from a Russian IP", "first time nginx connected to <C2 IP>",
// "first time this binary appeared on the box" patterns that pure
// rule-based detection can't see without per-environment tuning.
//
// Cross-platform: pure Go, no syscall-level dependencies. Works on
// Linux, macOS, Windows uniformly.
type firstSeenDetector struct {
	stateDir        string
	retentionDays   int
	maxValuesPerKey int
	mu              sync.Mutex
	// state[hostID][field] = map[value]time.Time (last-seen ts)
	state map[string]map[string]map[string]time.Time
	// logger is the global _server / _master / standalone meta store
	// (always set). The per-host store lookup goes through onWrite,
	// which is wired by the server when it owns the per-host storages.
	logger   *Storage
	onWrite  func(host string, fields map[string]any)
	dirty    bool
	saveTick *time.Ticker
}

// firstSeenFields names the event fields we track. Operators can't
// tune this in v0; the list is the practical sweet spot for
// detection (covers user/network/process/file activity uniformly).
var firstSeenFields = []string{
	"user", "source_ip", "remote_host", "remote", "process", "name", "sha256",
}

func newFirstSeenDetector(stateDir string, retentionDays int, logger *Storage) *firstSeenDetector {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	d := &firstSeenDetector{
		stateDir:        stateDir,
		retentionDays:   retentionDays,
		maxValuesPerKey: 10000,
		state:           map[string]map[string]map[string]time.Time{},
		logger:          logger,
	}
	d.load()
	return d
}

// observe is the hot-path entry point. Called once per ingested
// event. For each tracked field, looks up the (host, field, value)
// tuple and emits `meta:first_seen_<field>` if it's new. Returns
// the number of first-seen events emitted (callers can use this for
// metrics).
func (d *firstSeenDetector) observe(host string, event map[string]any) int {
	if d == nil || event == nil {
		return 0
	}
	emitted := 0
	d.mu.Lock()
	hostState, ok := d.state[host]
	if !ok {
		hostState = map[string]map[string]time.Time{}
		d.state[host] = hostState
	}
	now := time.Now().UTC()
	for _, field := range firstSeenFields {
		raw, has := event[field]
		if !has {
			continue
		}
		v := strings.TrimSpace(strFieldFromAny(raw))
		if v == "" {
			continue
		}
		// Cap on values per (host, field) to bound memory; once full
		// we stop emitting first-seen for this slot until decay.
		bucket, ok := hostState[field]
		if !ok {
			bucket = map[string]time.Time{}
			hostState[field] = bucket
		}
		if _, seen := bucket[v]; seen {
			bucket[v] = now
			continue
		}
		if len(bucket) >= d.maxValuesPerKey {
			bucket[v] = now
			continue
		}
		bucket[v] = now
		emitted++
		// Build a fresh map per Write target. d.logger and d.onWrite
		// each route to a different Storage with its own writer
		// goroutine; sharing a single map between two writers races on
		// the _seq/_prev/_hash stamping inside writeNow and corrupts
		// the chain (the verifier reports "hash mismatch" on those
		// lines). Same pattern as recordAgentHeartbeat above.
		build := func() map[string]any {
			return map[string]any{
				"event": "first_seen_" + field,
				"host":  host,
				"field": field,
				"value": v,
				"hint":  "first time this (host, " + field + ") tuple has been observed in the retention window",
			}
		}
		if d.logger != nil {
			d.logger.Write("meta", build())
		}
		if d.onWrite != nil {
			d.onWrite(host, build())
		}
	}
	if emitted > 0 {
		d.dirty = true
	}
	d.mu.Unlock()
	return emitted
}

// Start kicks off the periodic prune-and-save loop. Pruning runs
// once per hour; save runs every 5 min when dirty.
func (d *firstSeenDetector) Start(ctx context.Context, wg *sync.WaitGroup) {
	if d == nil {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		prune := time.NewTicker(time.Hour)
		save := time.NewTicker(5 * time.Minute)
		defer prune.Stop()
		defer save.Stop()
		for {
			select {
			case <-ctx.Done():
				d.persistIfDirty()
				return
			case <-prune.C:
				d.prune()
			case <-save.C:
				d.persistIfDirty()
			}
		}
	}()
}

func (d *firstSeenDetector) prune() {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().UTC().Add(-time.Duration(d.retentionDays) * 24 * time.Hour)
	pruned := 0
	for host, fields := range d.state {
		for field, bucket := range fields {
			for v, ts := range bucket {
				if ts.Before(cutoff) {
					delete(bucket, v)
					pruned++
				}
			}
			if len(bucket) == 0 {
				delete(fields, field)
			}
		}
		if len(fields) == 0 {
			delete(d.state, host)
		}
	}
	if pruned > 0 {
		d.dirty = true
	}
}

func (d *firstSeenDetector) persistIfDirty() {
	d.mu.Lock()
	dirty := d.dirty
	if !dirty {
		d.mu.Unlock()
		return
	}
	// Marshal a deep copy under the lock so save can release it
	// while doing IO.
	snap := map[string]map[string]map[string]time.Time{}
	for h, fields := range d.state {
		fcp := map[string]map[string]time.Time{}
		for f, bucket := range fields {
			bcp := map[string]time.Time{}
			for v, t := range bucket {
				bcp[v] = t
			}
			fcp[f] = bcp
		}
		snap[h] = fcp
	}
	d.mu.Unlock()
	// Don't clear `dirty` until we've durably persisted. If WriteFile
	// or Rename fails, the next tick will retry. Clearing the flag
	// before the IO completes loses the in-memory state on the next
	// restart when the IO never landed.
	if d.stateDir == "" {
		return
	}
	if err := os.MkdirAll(d.stateDir, 0o750); err != nil {
		return
	}
	path := filepath.Join(d.stateDir, "firstseen.json")
	tmp := path + ".tmp"
	data, err := json.Marshal(snap)
	if err != nil {
		return
	}
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return
	}
	d.mu.Lock()
	d.dirty = false
	d.mu.Unlock()
}

func (d *firstSeenDetector) load() {
	if d.stateDir == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(d.stateDir, "firstseen.json"))
	if err != nil {
		return
	}
	var snap map[string]map[string]map[string]time.Time
	if err := json.Unmarshal(data, &snap); err != nil {
		return
	}
	d.state = snap
}

// strFieldFromAny coerces an event field value into a string. Used
// instead of fieldString to avoid importing the whole alerts.go
// helpers here; first-seen wants a stable canonical form not the
// matcher-friendly form.
func strFieldFromAny(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	if data, err := json.Marshal(v); err == nil {
		s := string(data)
		// Trim quotes from JSON-marshalled strings so the value
		// stored in the seen-set is the natural form.
		if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
			s = s[1 : len(s)-1]
		}
		return s
	}
	return ""
}
