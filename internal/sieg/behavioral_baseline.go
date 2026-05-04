package sieg

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// #4 — Behavioral baselining (per-host events/hour).
//
// Buckets event counts per (host, hour-of-day, day-of-week) over a
// rolling N-day window. When the current rate exceeds N standard
// deviations from the baseline, emit `meta:baseline_anomaly` so the
// rule engine can fire on it.
//
// Bounded: `cfg.baseline.max_hosts` (default 200) caps the per-host
// table. Top-N by recent activity wins; the rest are dropped silently.
//
// State persisted to <state>/baseline.json on a 5-minute timer + at
// graceful shutdown so a daemon restart doesn't lose the learning
// window.

type BaselineConfig struct {
	Enabled       bool    `json:"enabled"`
	WindowDays    int     `json:"window_days"`
	StdDevTrigger float64 `json:"stddev_trigger"`
	MaxHosts      int     `json:"max_hosts"`
}

func defaultBaselineConfig() BaselineConfig {
	return BaselineConfig{
		Enabled:       true,
		WindowDays:    14,
		StdDevTrigger: 3.0,
		MaxHosts:      200,
	}
}

// hostBucket is one (host, hour, dow) bucket carrying summary stats.
type hostBucket struct {
	Host  string  `json:"host"`
	Hour  int     `json:"hour"`
	DOW   int     `json:"dow"`
	N     int     `json:"n"`     // sample count
	Sum   float64 `json:"sum"`   // sum of observations
	Sum2  float64 `json:"sum2"`  // sum of squared observations (for stddev)
	Last  time.Time `json:"last"`
}

func (b *hostBucket) mean() float64 {
	if b.N == 0 {
		return 0
	}
	return b.Sum / float64(b.N)
}

func (b *hostBucket) stddev() float64 {
	if b.N < 2 {
		return 0
	}
	mean := b.mean()
	v := b.Sum2/float64(b.N) - mean*mean
	if v < 0 {
		return 0
	}
	return math.Sqrt(v)
}

type baselineDetector struct {
	mu       sync.Mutex
	cfg      BaselineConfig
	stateDir string
	logger   *Storage
	buckets  map[string]*hostBucket // key: host|hour|dow
	current  map[string]int         // host → events in the current 5-min slice
	lastFlip time.Time
}

func newBaselineDetector(cfg BaselineConfig, stateDir string, logger *Storage) *baselineDetector {
	if cfg.WindowDays <= 0 {
		cfg.WindowDays = 14
	}
	if cfg.StdDevTrigger <= 0 {
		cfg.StdDevTrigger = 3.0
	}
	if cfg.MaxHosts <= 0 {
		cfg.MaxHosts = 200
	}
	if stateDir == "" {
		stateDir = filepath.Join(defaultStateDir(), "baseline")
	}
	d := &baselineDetector{
		cfg:      cfg,
		stateDir: stateDir,
		logger:   logger,
		buckets:  map[string]*hostBucket{},
		current:  map[string]int{},
		lastFlip: time.Now().UTC(),
	}
	d.load()
	return d
}

func (d *baselineDetector) bucketKey(host string, hour, dow int) string {
	return fmt.Sprintf("%s|%d|%d", host, hour, dow)
}

// Observe records a single event for a host. Cheap; called from the
// alert pipeline (alongside the existing sinks) for every fired
// alert. Skips when the host count is past MaxHosts unless the host
// is already tracked.
func (d *baselineDetector) Observe(host string) {
	if d == nil || !d.cfg.Enabled || host == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.current[host]; !ok && len(d.current) >= d.cfg.MaxHosts {
		return
	}
	d.current[host]++
}

// flipIfElapsed promotes the current 5-minute slice into the bucket
// table when at least 5 minutes have passed. Triggers anomaly checks
// against the historical bucket before the slice is rolled in.
func (d *baselineDetector) flipIfElapsed() {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now().UTC()
	if now.Sub(d.lastFlip) < 5*time.Minute {
		return
	}
	hour := now.Hour()
	dow := int(now.Weekday())
	for host, count := range d.current {
		key := d.bucketKey(host, hour, dow)
		b, ok := d.buckets[key]
		if !ok {
			b = &hostBucket{Host: host, Hour: hour, DOW: dow}
			d.buckets[key] = b
		}
		// Anomaly check BEFORE we fold the new sample in.
		if b.N >= 3 {
			mean := b.mean()
			sd := b.stddev()
			if sd > 0 && (float64(count)-mean) > d.cfg.StdDevTrigger*sd {
				if d.logger != nil {
					d.logger.Write("meta", map[string]any{
						"event":         "baseline_anomaly",
						"host":          host,
						"observed":      count,
						"baseline_mean": mean,
						"baseline_sd":   sd,
						"trigger_sd":    d.cfg.StdDevTrigger,
						"hour":          hour,
						"dow":           dow,
					})
				}
			}
		}
		b.N++
		b.Sum += float64(count)
		b.Sum2 += float64(count) * float64(count)
		b.Last = now
	}
	d.current = map[string]int{}
	d.lastFlip = now
	d.evictOldUnsafe(now)
}

func (d *baselineDetector) evictOldUnsafe(now time.Time) {
	cutoff := now.Add(-time.Duration(d.cfg.WindowDays) * 24 * time.Hour)
	for k, b := range d.buckets {
		if b.Last.Before(cutoff) {
			delete(d.buckets, k)
		}
	}
}

// Start runs the periodic flip loop + persistence.
func (d *baselineDetector) Start(ctx context.Context, wg *sync.WaitGroup) {
	if !d.cfg.Enabled {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		flip := time.NewTicker(time.Minute)
		save := time.NewTicker(5 * time.Minute)
		defer flip.Stop()
		defer save.Stop()
		for {
			select {
			case <-ctx.Done():
				d.persist()
				return
			case <-flip.C:
				d.flipIfElapsed()
			case <-save.C:
				d.persist()
			}
		}
	}()
}

func (d *baselineDetector) persist() {
	d.mu.Lock()
	snap := make([]*hostBucket, 0, len(d.buckets))
	for _, b := range d.buckets {
		snap = append(snap, b)
	}
	d.mu.Unlock()
	_ = os.MkdirAll(d.stateDir, 0o750)
	path := filepath.Join(d.stateDir, "baseline.json")
	data, _ := json.Marshal(snap)
	tmp := path + ".tmp"
	_ = os.WriteFile(tmp, data, 0o640)
	_ = os.Rename(tmp, path)
}

func (d *baselineDetector) load() {
	path := filepath.Join(d.stateDir, "baseline.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var snap []*hostBucket
	if err := json.Unmarshal(data, &snap); err != nil {
		return
	}
	for _, b := range snap {
		d.buckets[d.bucketKey(b.Host, b.Hour, b.DOW)] = b
	}
}

// runBaselineStatus dispatches `simplesiem baseline status [--top N]`.
func runBaselineStatus(args []string) {
	args = permuteArgs(args, map[string]bool{"top": true})
	fs := flag.NewFlagSet("baseline status", flag.ExitOnError)
	top := fs.Int("top", 10, "show the top N hosts by sample count")
	_ = fs.Parse(args)

	cfg := loadConfig(defaultConfigPath())
	if !cfg.Baseline.Enabled {
		fmt.Println("baseline: disabled (cfg.baseline.enabled=false)")
		return
	}
	stateDir := filepath.Join(defaultStateDir(), "baseline")
	data, err := os.ReadFile(filepath.Join(stateDir, "baseline.json"))
	if err != nil {
		fmt.Println("baseline: no observations recorded yet")
		return
	}
	var snap []hostBucket
	if err := json.Unmarshal(data, &snap); err != nil {
		fmt.Println("baseline: state file unreadable:", err)
		return
	}
	type rollup struct {
		host  string
		n     int
		mean  float64
		stdev float64
	}
	byHost := map[string]*rollup{}
	for _, b := range snap {
		r, ok := byHost[b.Host]
		if !ok {
			r = &rollup{host: b.Host}
			byHost[b.Host] = r
		}
		r.n += b.N
		r.mean += b.Sum
		r.stdev += b.Sum2
	}
	out := make([]rollup, 0, len(byHost))
	for _, r := range byHost {
		if r.n > 0 {
			r.mean = r.mean / float64(r.n)
		}
		if r.n >= 2 {
			v := r.stdev/float64(r.n) - r.mean*r.mean
			if v < 0 {
				v = 0
			}
			r.stdev = math.Sqrt(v)
		} else {
			r.stdev = 0
		}
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].n > out[j].n })
	fmt.Printf("Baseline (window_days=%d, stddev_trigger=%.1f, max_hosts=%d):\n",
		cfg.Baseline.WindowDays, cfg.Baseline.StdDevTrigger, cfg.Baseline.MaxHosts)
	limit := *top
	if limit > len(out) {
		limit = len(out)
	}
	for i := 0; i < limit; i++ {
		fmt.Printf("  %s  n=%d  mean=%.1f  stddev=%.1f\n", out[i].host, out[i].n, out[i].mean, out[i].stdev)
	}
}
