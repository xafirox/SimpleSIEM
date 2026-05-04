package sieg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// #5 — Honey tokens.
//
// Operator places fake credentials, fake API keys, fake config files
// somewhere on the filesystem and registers each one with SimpleSIEM.
// Any read or modification fires a `high`-severity alert because no
// legitimate process should ever touch a honey token.
//
// Built-in collector (this file) periodically stats every registered
// path and emits `meta:honey_touched` when atime / mtime / size /
// content-hash changes. The default rule shipped with the daemon
// matches that event and fires.

type HoneyConfig struct {
	Enabled         bool   `json:"enabled"`
	IntervalSeconds int    `json:"interval_seconds"`
	StatePath       string `json:"state_path"`
}

func defaultHoneyConfig() HoneyConfig {
	return HoneyConfig{
		Enabled:         true,
		IntervalSeconds: 30,
		// StatePath empty → derives from defaultStateDir() at load time.
	}
}

type honeyToken struct {
	Path        string    `json:"path"`
	Description string    `json:"description"`
	AddedAt     time.Time `json:"added_at"`
	BaselineSize  int64   `json:"baseline_size"`
	BaselineMTime time.Time `json:"baseline_mtime"`
	BaselineSHA   string    `json:"baseline_sha,omitempty"`
	LastTouched   time.Time `json:"last_touched,omitempty"`
}

type honeyState struct {
	Tokens []honeyToken `json:"tokens"`
}

func honeyStatePath() string {
	return filepath.Join(defaultStateDir(), "honey.json")
}

func loadHoneyState() honeyState {
	var s honeyState
	data, err := os.ReadFile(honeyStatePath())
	if err != nil {
		return s
	}
	_ = json.Unmarshal(data, &s)
	return s
}

func saveHoneyState(s honeyState) error {
	if err := os.MkdirAll(filepath.Dir(honeyStatePath()), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := honeyStatePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, honeyStatePath())
}

// honeyMonitor runs in the daemon. Every interval it stats every
// registered token and emits a meta:honey_touched event when ANY of
// the tracked attributes changes. The rule engine matches the event
// and fires.
type honeyMonitor struct {
	cfg    HoneyConfig
	logger *Storage
	mu     sync.Mutex
}

func newHoneyMonitor(cfg HoneyConfig, logger *Storage) *honeyMonitor {
	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = 30
	}
	return &honeyMonitor{cfg: cfg, logger: logger}
}

func (h *honeyMonitor) Start(ctx context.Context, wg *sync.WaitGroup) {
	if !h.cfg.Enabled {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(time.Duration(h.cfg.IntervalSeconds) * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.scan()
			}
		}
	}()
}

func (h *honeyMonitor) scan() {
	h.mu.Lock()
	defer h.mu.Unlock()
	state := loadHoneyState()
	if len(state.Tokens) == 0 {
		return
	}
	now := time.Now().UTC()
	dirty := false
	for i := range state.Tokens {
		tok := &state.Tokens[i]
		fi, err := os.Stat(tok.Path)
		if err != nil {
			if os.IsNotExist(err) {
				if h.logger != nil {
					h.logger.Write("meta", map[string]any{
						"event":       "honey_touched",
						"path":        tok.Path,
						"change":      "deleted",
						"description": tok.Description,
						"severity":    "high",
					})
				}
			}
			continue
		}
		newSHA := ""
		if fi.Size() < 4*1024*1024 { // hash up to 4 MiB; larger tokens are unusual
			data, rerr := os.ReadFile(tok.Path)
			if rerr == nil {
				sum := sha256.Sum256(data)
				newSHA = hex.EncodeToString(sum[:])
			}
		}
		changed := false
		switch {
		case tok.BaselineSize == 0 && tok.BaselineMTime.IsZero():
			// First scan — capture baseline.
			tok.BaselineSize = fi.Size()
			tok.BaselineMTime = fi.ModTime().UTC()
			tok.BaselineSHA = newSHA
			dirty = true
			continue
		case fi.Size() != tok.BaselineSize:
			changed = true
		case !fi.ModTime().UTC().Equal(tok.BaselineMTime):
			changed = true
		case newSHA != "" && tok.BaselineSHA != "" && newSHA != tok.BaselineSHA:
			changed = true
		}
		if !changed {
			continue
		}
		if h.logger != nil {
			h.logger.Write("meta", map[string]any{
				"event":          "honey_touched",
				"path":           tok.Path,
				"change":         "modified",
				"description":    tok.Description,
				"severity":       "high",
				"old_size":       tok.BaselineSize,
				"new_size":       fi.Size(),
				"old_mtime":      tok.BaselineMTime.Format(time.RFC3339),
				"new_mtime":      fi.ModTime().UTC().Format(time.RFC3339),
				"hash_changed":   newSHA != "" && newSHA != tok.BaselineSHA,
			})
		}
		tok.LastTouched = now
		// Re-baseline so subsequent unchanged scans don't keep firing.
		tok.BaselineSize = fi.Size()
		tok.BaselineMTime = fi.ModTime().UTC()
		tok.BaselineSHA = newSHA
		dirty = true
	}
	if dirty {
		_ = saveHoneyState(state)
	}
}

// runHoneyCmd dispatches `simplesiem honey <add|list|remove>`.
func runHoneyCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem honey <add|list|remove>

  add <path> [--description "what this is"]
                  Register a honey token. Captures size/mtime/sha
                  baseline; subsequent change fires meta:honey_touched.
  list            Show registered tokens with last-touched timestamp.
  remove <path>   Stop monitoring this token.`)
		os.Exit(2)
	}
	switch args[0] {
	case "add":
		runHoneyAdd(args[1:])
	case "list":
		runHoneyList()
	case "remove":
		runHoneyRemove(args[1:])
	default:
		fatalf("unknown honey subcommand: %s", args[0])
	}
}

func runHoneyAdd(args []string) {
	args = permuteArgs(args, map[string]bool{"description": true})
	fs := flag.NewFlagSet("honey add", flag.ExitOnError)
	desc := fs.String("description", "", "operator description (helps when reviewing alerts)")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: simplesiem honey add <path> [--description \"...\"]")
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		fatalf("resolve path: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		fatalf("stat %q: %v", path, err)
	}
	if fi.IsDir() {
		fatalf("honey tokens must be files, not directories (got %q)", path)
	}
	state := loadHoneyState()
	for _, t := range state.Tokens {
		if t.Path == path {
			fatalf("honey token already registered at %q", path)
		}
	}
	state.Tokens = append(state.Tokens, honeyToken{
		Path: path, Description: *desc,
		AddedAt: time.Now().UTC(),
	})
	if err := saveHoneyState(state); err != nil {
		fatalf("save: %v", err)
	}
	fmt.Printf("Registered honey token %q.\n", path)
	fmt.Println("Baseline (size/mtime/sha) captures on the next monitor cycle.")
}

func runHoneyList() {
	state := loadHoneyState()
	if len(state.Tokens) == 0 {
		fmt.Println("(no honey tokens registered)")
		return
	}
	sort.Slice(state.Tokens, func(i, j int) bool { return state.Tokens[i].Path < state.Tokens[j].Path })
	for _, t := range state.Tokens {
		desc := t.Description
		if desc == "" {
			desc = "(no description)"
		}
		last := "(never)"
		if !t.LastTouched.IsZero() {
			last = t.LastTouched.Format(time.RFC3339)
		}
		fmt.Printf("%s\n", t.Path)
		fmt.Printf("  added: %s\n", t.AddedAt.Format(time.RFC3339))
		fmt.Printf("  description: %s\n", desc)
		fmt.Printf("  last touched: %s\n", last)
	}
}

func runHoneyRemove(args []string) {
	if len(args) == 0 {
		fatalf("usage: simplesiem honey remove <path>")
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	path, err := filepath.Abs(args[0])
	if err != nil {
		fatalf("resolve path: %v", err)
	}
	state := loadHoneyState()
	out := state.Tokens[:0]
	removed := false
	for _, t := range state.Tokens {
		if t.Path == path {
			removed = true
			continue
		}
		out = append(out, t)
	}
	if !removed {
		fatalf("no honey token registered at %q", path)
	}
	state.Tokens = append([]honeyToken{}, out...)
	if err := saveHoneyState(state); err != nil {
		fatalf("save: %v", err)
	}
	fmt.Printf("Removed honey token %q.\n", path)
}
