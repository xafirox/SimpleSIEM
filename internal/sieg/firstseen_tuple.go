package sieg

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// #7 — First-seen detection extended to arbitrary tuples. The
// existing firstSeenDetector tracks single fields per host. This
// adds tuple-based detection ((user, country), (process, file_dir),
// (parent_proc, child_proc)) with persistent state under
// <state>/firstseen/.

type FirstSeenConfig struct {
	Enabled              bool       `json:"enabled"`
	MaxEntriesPerTuple   int        `json:"max_entries_per_tuple"`
	TTLDays              int        `json:"ttl_days"`
	Tuples               []TupleSpec `json:"tuples"`
}

type TupleSpec struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
}

func defaultFirstSeenConfig() FirstSeenConfig {
	return FirstSeenConfig{
		Enabled:            true,
		MaxEntriesPerTuple: 1_000_000,
		TTLDays:            90,
		Tuples: []TupleSpec{
			{Name: "user_country", Fields: []string{"user", "geoip.country"}},
			{Name: "process_file_dir", Fields: []string{"process", "path_dir"}},
			{Name: "parent_child_proc", Fields: []string{"parent_proc", "process"}},
		},
	}
}

// tupleSeenSet tracks one tuple kind: tupleKey -> first_seen_at.
type tupleSeenSet struct {
	mu      sync.Mutex
	name    string
	fields  []string
	seen    map[string]time.Time
	dirty   bool
}

// tupleManager owns all configured tuple sets, with periodic
// persistence + TTL pruning.
type tupleManager struct {
	cfg      FirstSeenConfig
	stateDir string
	logger   *Storage
	sets     map[string]*tupleSeenSet
}

func newTupleManager(cfg FirstSeenConfig, stateDir string, logger *Storage) *tupleManager {
	if cfg.MaxEntriesPerTuple <= 0 {
		cfg.MaxEntriesPerTuple = 1_000_000
	}
	if cfg.TTLDays <= 0 {
		cfg.TTLDays = 90
	}
	if stateDir == "" {
		stateDir = filepath.Join(defaultStateDir(), "firstseen")
	}
	m := &tupleManager{
		cfg:      cfg,
		stateDir: stateDir,
		logger:   logger,
		sets:     map[string]*tupleSeenSet{},
	}
	for _, sp := range cfg.Tuples {
		set := &tupleSeenSet{name: sp.Name, fields: sp.Fields, seen: map[string]time.Time{}}
		m.sets[sp.Name] = set
		m.loadSet(set)
	}
	return m
}

// Observe processes an event against every tuple. Returns the names
// of tuples that fired first-seen on this event.
func (m *tupleManager) Observe(event map[string]any) []string {
	if m == nil || !m.cfg.Enabled {
		return nil
	}
	var fired []string
	for name, set := range m.sets {
		if m.observeOne(set, event) {
			fired = append(fired, name)
		}
	}
	return fired
}

func (m *tupleManager) observeOne(set *tupleSeenSet, event map[string]any) bool {
	parts := make([]string, len(set.fields))
	for i, f := range set.fields {
		v := strings.TrimSpace(strFieldFromAny(extractField(event, f)))
		if v == "" {
			return false
		}
		parts[i] = v
	}
	key := strings.Join(parts, "|")
	set.mu.Lock()
	defer set.mu.Unlock()
	if _, ok := set.seen[key]; ok {
		set.seen[key] = time.Now().UTC()
		return false
	}
	if len(set.seen) >= m.cfg.MaxEntriesPerTuple {
		if m.logger != nil {
			m.logger.Write("meta", map[string]any{
				"event": "firstseen_capacity_exhausted",
				"tuple": set.name,
				"hint":  "evicting 10% oldest; tune cfg.firstseen.max_entries_per_tuple",
			})
		}
		m.evictOldestUnsafe(set)
	}
	set.seen[key] = time.Now().UTC()
	set.dirty = true
	if m.logger != nil {
		m.logger.Write("meta", map[string]any{
			"event":      "first_seen_tuple",
			"tuple":      set.name,
			"key":        key,
			"fields":     set.fields,
			"first_seen": set.seen[key].Format(time.RFC3339),
		})
	}
	return true
}

func (m *tupleManager) evictOldestUnsafe(set *tupleSeenSet) {
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(set.seen))
	for k, t := range set.seen {
		all = append(all, kv{k, t})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	target := len(all) / 10
	if target < 1 {
		target = 1
	}
	for i := 0; i < target; i++ {
		delete(set.seen, all[i].k)
	}
	set.dirty = true
}

// extractField supports nested keys like "geoip.country" by walking
// json-style maps with dot-separated path.
func extractField(event map[string]any, path string) any {
	if !strings.Contains(path, ".") {
		return event[path]
	}
	parts := strings.Split(path, ".")
	var cur any = event
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

// Persist writes dirty sets to disk; called from a watcher.
func (m *tupleManager) Persist() {
	if err := os.MkdirAll(m.stateDir, 0o750); err != nil {
		return
	}
	for _, set := range m.sets {
		set.mu.Lock()
		if !set.dirty {
			set.mu.Unlock()
			continue
		}
		snap := map[string]string{}
		for k, t := range set.seen {
			snap[k] = t.Format(time.RFC3339Nano)
		}
		set.mu.Unlock()
		// Don't clear `dirty` until the state is durably on disk. If
		// the marshal/write/rename fails, the next tick retries; we
		// must NOT acknowledge a write that didn't land.
		data, err := json.Marshal(map[string]any{
			"name":   set.name,
			"fields": set.fields,
			"seen":   snap,
		})
		if err != nil {
			continue
		}
		path := filepath.Join(m.stateDir, set.name+".json")
		if err := atomicWriteFile(path, data, 0o640); err != nil {
			continue
		}
		set.mu.Lock()
		set.dirty = false
		set.mu.Unlock()
	}
}

func (m *tupleManager) loadSet(set *tupleSeenSet) {
	path := filepath.Join(m.stateDir, set.name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var doc struct {
		Seen map[string]string `json:"seen"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	for k, ts := range doc.Seen {
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		set.seen[k] = t
	}
}

// Prune removes entries past TTL. Called from a watcher.
func (m *tupleManager) Prune() int {
	cutoff := time.Now().UTC().Add(-time.Duration(m.cfg.TTLDays) * 24 * time.Hour)
	pruned := 0
	for _, set := range m.sets {
		set.mu.Lock()
		for k, t := range set.seen {
			if t.Before(cutoff) {
				delete(set.seen, k)
				pruned++
			}
		}
		if pruned > 0 {
			set.dirty = true
		}
		set.mu.Unlock()
	}
	return pruned
}

// runFirstSeenStatus dispatches `simplesiem firstseen status`.
func runFirstSeenStatus(args []string) {
	fs := flag.NewFlagSet("firstseen status", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	cfg := loadConfig(*cfgPath)
	if !cfg.FirstSeen.Enabled {
		fmt.Println("firstseen: disabled")
		return
	}
	stateDir := filepath.Join(defaultStateDir(), "firstseen")
	for _, sp := range cfg.FirstSeen.Tuples {
		path := filepath.Join(stateDir, sp.Name+".json")
		fi, err := os.Stat(path)
		if err != nil {
			fmt.Printf("tuple %s (%v): NO STATE\n", sp.Name, sp.Fields)
			continue
		}
		data, _ := os.ReadFile(path)
		var doc struct {
			Seen map[string]string `json:"seen"`
		}
		_ = json.Unmarshal(data, &doc)
		fmt.Printf("tuple %s (%v): %d entries, file %d bytes, mtime %s\n",
			sp.Name, sp.Fields, len(doc.Seen), fi.Size(), fi.ModTime().Format(time.RFC3339))
	}
}
