package sieg

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// #4 — Threat-intel feed loop. Default-on with abuse.ch ThreatFox.
//
// ThreatFox is free, no API key, CC0 license. Each indicator carries
// confidence_level (0-100), first_seen, last_seen, threat_type, and
// reference URL — covers every metadata field operators need.
//
// Privacy: default-on means the SIEM phones threatfox-api.abuse.ch
// every 6h. Set cfg.threatintel.enabled=false for zero outbound.

// ThreatIntelConfig is the operator-tunable feed surface.
type ThreatIntelConfig struct {
	Enabled bool                  `json:"enabled"`
	Feeds   []ThreatIntelFeedSpec `json:"feeds"`
	// CacheDir defaults to <state>/threatintel.
	CacheDir     string `json:"cache_dir"`
	MaxSetSize   int    `json:"max_set_size"`
	StaleAfterDays int  `json:"stale_after_days"`
}

type ThreatIntelFeedSpec struct {
	Name           string   `json:"name"`
	Kind           string   `json:"kind"` // "abuse.ch.threatfox"
	URL            string   `json:"url"`
	IntervalHours  int      `json:"interval_hours"`
	MinConfidence  int      `json:"min_confidence"`
	MaxAgeDays     int      `json:"max_age_days"`
	IndicatorKinds []string `json:"indicator_kinds"`
}

func defaultThreatIntelConfig() ThreatIntelConfig {
	return ThreatIntelConfig{
		Enabled:        true,
		MaxSetSize:     100000,
		StaleAfterDays: 7,
		Feeds: []ThreatIntelFeedSpec{{
			Name:           "threatfox",
			Kind:           "abuse.ch.threatfox",
			URL:            "https://threatfox-api.abuse.ch/api/v1/",
			IntervalHours:  6,
			MinConfidence:  75,
			MaxAgeDays:     30,
			IndicatorKinds: []string{"ip:port", "domain", "sha256"},
		}},
	}
}

// indicatorEntry captures the per-IOC metadata from the feed.
type indicatorEntry struct {
	Value      string    `json:"value"`
	Kind       string    `json:"kind"`
	Confidence int       `json:"confidence"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	ThreatType string    `json:"threat_type"`
	Reference  string    `json:"reference"`
}

// indicatorSet is a queryable collection by feed.kind. Stored on disk
// + held in memory for fast rule predicate evaluation.
type indicatorSet struct {
	Name        string                       `json:"name"`
	FetchedAt   time.Time                    `json:"fetched_at"`
	Entries     map[string]map[string]indicatorEntry // kind -> value -> entry
}

// threatIntelManager owns the in-process indicator sets, the
// background fetch loop, and the stale-cache fallback semantics.
type threatIntelManager struct {
	mu          sync.RWMutex
	cfg         ThreatIntelConfig
	sets        map[string]*indicatorSet // feed name -> set
	logger      *Storage
	failedOnce  atomic.Bool
	cacheDir    string
}

func newThreatIntelManager(cfg ThreatIntelConfig, logger *Storage) *threatIntelManager {
	if cfg.MaxSetSize <= 0 {
		cfg.MaxSetSize = 100000
	}
	if cfg.StaleAfterDays <= 0 {
		cfg.StaleAfterDays = 7
	}
	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(defaultStateDir(), "threatintel")
	}
	return &threatIntelManager{
		cfg:      cfg,
		sets:     map[string]*indicatorSet{},
		logger:   logger,
		cacheDir: cacheDir,
	}
}

// Start runs the fetch loop. Loads cached sets immediately so rules
// can match before the first fetch completes.
func (m *threatIntelManager) Start(ctx context.Context, wg *sync.WaitGroup) {
	if !m.cfg.Enabled || len(m.cfg.Feeds) == 0 {
		return
	}
	for _, f := range m.cfg.Feeds {
		if set, err := m.loadCachedSet(f.Name); err == nil {
			m.mu.Lock()
			m.sets[f.Name] = set
			m.mu.Unlock()
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.fetchAll(ctx)
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.fetchAll(ctx)
			}
		}
	}()
}

func (m *threatIntelManager) fetchAll(ctx context.Context) {
	for _, f := range m.cfg.Feeds {
		if m.shouldFetch(f) {
			if err := m.fetchOne(ctx, f); err != nil {
				if !m.failedOnce.Load() && m.logger != nil {
					m.logger.Write("meta", map[string]any{
						"event": "threatintel_fetch_failed",
						"feed":  f.Name,
						"error": err.Error(),
						"hint":  "reusing cached indicator set; rules continue to match against last successful fetch",
					})
					m.failedOnce.Store(true)
				}
				continue
			}
			m.failedOnce.Store(false)
		}
	}
}

func (m *threatIntelManager) shouldFetch(f ThreatIntelFeedSpec) bool {
	m.mu.RLock()
	set := m.sets[f.Name]
	m.mu.RUnlock()
	if set == nil {
		return true
	}
	interval := time.Duration(f.IntervalHours) * time.Hour
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return time.Since(set.FetchedAt) >= interval
}

func (m *threatIntelManager) fetchOne(ctx context.Context, f ThreatIntelFeedSpec) error {
	switch f.Kind {
	case "abuse.ch.threatfox":
		return m.fetchThreatFox(ctx, f)
	default:
		return fmt.Errorf("unknown feed kind %q", f.Kind)
	}
}

func (m *threatIntelManager) fetchThreatFox(ctx context.Context, f ThreatIntelFeedSpec) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.URL,
		strings.NewReader(`{"query":"get_iocs","days":1}`))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var doc struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			IOC          string `json:"ioc"`
			IOCType      string `json:"ioc_type"`
			ThreatType   string `json:"threat_type"`
			Confidence   int    `json:"confidence_level"`
			FirstSeenStr string `json:"first_seen"`
			LastSeenStr  string `json:"last_seen,omitempty"`
			Reference    string `json:"reference"`
		} `json:"data"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	set := &indicatorSet{
		Name:      f.Name,
		FetchedAt: time.Now().UTC(),
		Entries:   map[string]map[string]indicatorEntry{},
	}
	for _, d := range doc.Data {
		if d.Confidence < f.MinConfidence {
			continue
		}
		kind := normalizeIOCKind(d.IOCType)
		if !contains(f.IndicatorKinds, kind) {
			continue
		}
		first, _ := time.Parse("2006-01-02 15:04:05", d.FirstSeenStr)
		last, _ := time.Parse("2006-01-02 15:04:05", d.LastSeenStr)
		ent := indicatorEntry{
			Value: d.IOC, Kind: kind, Confidence: d.Confidence,
			FirstSeen: first, LastSeen: last,
			ThreatType: d.ThreatType, Reference: d.Reference,
		}
		bucket, ok := set.Entries[kind]
		if !ok {
			bucket = map[string]indicatorEntry{}
			set.Entries[kind] = bucket
		}
		if len(bucket) >= m.cfg.MaxSetSize {
			break
		}
		bucket[d.IOC] = ent
	}
	if err := m.saveCachedSet(set); err != nil {
		return err
	}
	m.mu.Lock()
	m.sets[f.Name] = set
	m.mu.Unlock()
	if m.logger != nil {
		m.logger.Write("meta", map[string]any{
			"event":           "threatintel_updated",
			"feed":            f.Name,
			"indicator_count": countEntries(set),
		})
	}
	return nil
}

func normalizeIOCKind(kind string) string {
	switch strings.ToLower(kind) {
	case "ip:port":
		return "ip:port"
	case "domain":
		return "domain"
	case "sha256_hash", "sha256":
		return "sha256"
	}
	return kind
}

func countEntries(set *indicatorSet) int {
	n := 0
	for _, bucket := range set.Entries {
		n += len(bucket)
	}
	return n
}

func (m *threatIntelManager) saveCachedSet(set *indicatorSet) error {
	if err := os.MkdirAll(m.cacheDir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(m.cacheDir, set.Name+".json")
	tmp := path + ".tmp"
	data, err := json.Marshal(set)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (m *threatIntelManager) loadCachedSet(name string) (*indicatorSet, error) {
	path := filepath.Join(m.cacheDir, name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var set indicatorSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, err
	}
	return &set, nil
}

// Match reports whether value is in the named feed+kind. Used by
// rule predicate `in_threat_set`.
func (m *threatIntelManager) Match(feed, kind, value string) (indicatorEntry, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	set, ok := m.sets[feed]
	if !ok {
		return indicatorEntry{}, false
	}
	bucket, ok := set.Entries[kind]
	if !ok {
		return indicatorEntry{}, false
	}
	ent, ok := bucket[value]
	return ent, ok
}

// runThreatIntelStatus dispatches `simplesiem threatintel status`.
func runThreatIntelStatus(args []string) {
	fs := flag.NewFlagSet("threatintel status", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	cfg := loadConfig(*cfgPath)
	if !cfg.ThreatIntel.Enabled {
		fmt.Println("threatintel: disabled (cfg.threatintel.enabled=false)")
		return
	}
	cacheDir := cfg.ThreatIntel.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(defaultStateDir(), "threatintel")
	}
	for _, f := range cfg.ThreatIntel.Feeds {
		path := filepath.Join(cacheDir, f.Name+".json")
		fi, err := os.Stat(path)
		if err != nil {
			fmt.Printf("feed %s (%s): NOT YET FETCHED\n", f.Name, f.Kind)
			continue
		}
		data, _ := os.ReadFile(path)
		var set indicatorSet
		_ = json.Unmarshal(data, &set)
		age := time.Since(fi.ModTime()).Round(time.Minute)
		fmt.Printf("feed %s (%s):\n", f.Name, f.Kind)
		fmt.Printf("  fetched: %s (%s ago)\n", set.FetchedAt.Format(time.RFC3339), age)
		fmt.Printf("  indicators: %d\n", countEntries(&set))
		stale := time.Hour * 24 * time.Duration(cfg.ThreatIntel.StaleAfterDays)
		if stale > 0 && time.Since(set.FetchedAt) > stale {
			fmt.Printf("  STALE (>%dd) — feed unreachable; rules continue matching against this snapshot\n", cfg.ThreatIntel.StaleAfterDays)
		}
	}
}
