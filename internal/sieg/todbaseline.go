package sieg

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// todBaselineDetector keeps a per-(host, entity-field, entity-value)
// 24-bin hour-of-day histogram of activity. Once the histogram has
// settled (≥minSamples observations), a new event arriving in a
// previously-unused hour fires `meta:unusual_time_anomaly`.
//
// The detection signal answers questions like:
//   - "alice always logs in 8 AM – 6 PM, why is she suddenly active at 3 AM?"
//   - "this batch host writes to /etc on weekday mornings, why is /etc
//     being touched at 11 PM Sunday?"
//
// Cross-platform: pure Go, no syscall-level dependencies.
type todBaselineDetector struct {
	stateDir       string
	minSamples     int
	cooldown       time.Duration
	maxEntities    int
	mu             sync.Mutex
	state          map[string]map[string]map[string]*todBaseline
	logger         *Storage
	dirty          bool
}

// todBaseline is a single (host, field, value) histogram.
type todBaseline struct {
	Hours    [24]int   `json:"hours"`     // counts per hour-of-day in the daemon's local TZ
	Total    int       `json:"total"`
	LastFire time.Time `json:"last_fire"`
}

// todBaselineFields are the entity types we baseline against. Same
// list as firstSeen so the detection surface is consistent.
var todBaselineFields = []string{"user", "source_ip", "process", "name"}

func newTodBaselineDetector(stateDir string, logger *Storage) *todBaselineDetector {
	d := &todBaselineDetector{
		stateDir:    stateDir,
		minSamples:  50,
		cooldown:    6 * time.Hour,
		maxEntities: 5000,
		state:       map[string]map[string]map[string]*todBaseline{},
		logger:      logger,
	}
	d.load()
	return d
}

// observe is called from the ingest hot path. For each tracked
// entity field present on the event, increments the histogram bin
// for the current hour and — if the histogram is settled and the
// current bin's count is anomalously low relative to the entity's
// usual cadence — emits a meta:unusual_time_anomaly event.
func (d *todBaselineDetector) observe(host string, event map[string]any) int {
	if d == nil || event == nil {
		return 0
	}
	now := time.Now()
	hour := now.Hour()
	d.mu.Lock()
	defer d.mu.Unlock()
	hostState, ok := d.state[host]
	if !ok {
		hostState = map[string]map[string]*todBaseline{}
		d.state[host] = hostState
	}
	emitted := 0
	for _, field := range todBaselineFields {
		raw, has := event[field]
		if !has {
			continue
		}
		v := strFieldFromAny(raw)
		if v == "" {
			continue
		}
		bucket, ok := hostState[field]
		if !ok {
			bucket = map[string]*todBaseline{}
			hostState[field] = bucket
		}
		b, ok := bucket[v]
		if !ok {
			if len(bucket) >= d.maxEntities {
				continue
			}
			b = &todBaseline{}
			bucket[v] = b
		}
		// Anomaly check BEFORE we increment (so the current event
		// doesn't count toward "this hour is normal").
		anomalous := b.Total >= d.minSamples && b.Hours[hour] == 0
		b.Hours[hour]++
		b.Total++
		d.dirty = true
		if anomalous && now.Sub(b.LastFire) > d.cooldown {
			b.LastFire = now
			emitted++
			if d.logger != nil {
				d.logger.Write("meta", map[string]any{
					"event":          "unusual_time_anomaly",
					"host":           host,
					"field":          field,
					"value":          v,
					"hour_local":     hour,
					"baseline_total": b.Total,
					"hint":           fmt.Sprintf("first activity from this entity in hour %d (local time) after %d samples in other hours", hour, b.Total),
				})
			}
		}
	}
	return emitted
}

// Start kicks off the periodic save loop. Save runs every 5 min
// when dirty.
func (d *todBaselineDetector) Start(ctx context.Context, wg *sync.WaitGroup) {
	if d == nil {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				d.persistIfDirty()
				return
			case <-t.C:
				d.persistIfDirty()
			}
		}
	}()
}

func (d *todBaselineDetector) persistIfDirty() {
	d.mu.Lock()
	if !d.dirty || d.stateDir == "" {
		d.mu.Unlock()
		return
	}
	snap := map[string]map[string]map[string]*todBaseline{}
	for h, fields := range d.state {
		fcp := map[string]map[string]*todBaseline{}
		for f, bucket := range fields {
			bcp := map[string]*todBaseline{}
			for v, b := range bucket {
				bb := *b
				bcp[v] = &bb
			}
			fcp[f] = bcp
		}
		snap[h] = fcp
	}
	d.mu.Unlock()
	// Don't clear dirty until the on-disk write is durable; same
	// rationale as firstseenDetector.persistIfDirty.
	if err := os.MkdirAll(d.stateDir, 0o750); err != nil {
		return
	}
	path := filepath.Join(d.stateDir, "tod_baselines.json")
	data, err := json.Marshal(snap)
	if err != nil {
		return
	}
	if err := atomicWriteFile(path, data, 0o640); err != nil {
		return
	}
	d.mu.Lock()
	d.dirty = false
	d.mu.Unlock()
}

func (d *todBaselineDetector) load() {
	if d.stateDir == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(d.stateDir, "tod_baselines.json"))
	if err != nil {
		return
	}
	var snap map[string]map[string]map[string]*todBaseline
	if err := json.Unmarshal(data, &snap); err != nil {
		return
	}
	d.state = snap
}
