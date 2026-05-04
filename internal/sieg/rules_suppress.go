package sieg

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// #2 — One-shot suppressions with auto-expiry. Stored in
// rules.json under a parallel "suppressions" array. Operators add
// via `alerts ack <id> --suppress-future ...`; daemon prunes
// expired entries on a 5-minute cycle and on startup.

type suppression struct {
	ID         string            `json:"id"`
	Matches    map[string]string `json:"matches"`
	Reason     string            `json:"reason"`
	AddedBy    string            `json:"added_by"`
	AddedAt    time.Time         `json:"added_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
}

const suppressionMaxDuration = 90 * 24 * time.Hour

// loadSuppressions reads the suppressions array from rules.json.
// rules.json today is canonically a top-level ARRAY of rules; the
// suppressions sidecar lives under a sibling file
// rules-suppressions.json so writes never disturb the rule loader.
// (Best effort — missing file → empty slice.)
func loadSuppressions(rulesPath string) []suppression {
	path := suppressionsPath(rulesPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var list []suppression
	if err := json.Unmarshal(data, &list); err != nil {
		return nil
	}
	return list
}

// saveSuppressions atomically rewrites the suppressions sidecar.
// Caller takes the allowlistEditMu lock.
func saveSuppressions(rulesPath string, list []suppression) error {
	path := suppressionsPath(rulesPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	out, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// suppressionsPath returns the sidecar path. Lives next to rules.json
// so backup/restore picks it up via the same config-dir walk.
func suppressionsPath(rulesPath string) string {
	if rulesPath == "" {
		rulesPath = filepath.Join(defaultConfigDir(), "rules.json")
	}
	return filepath.Join(filepath.Dir(rulesPath), "rules-suppressions.json")
}

// suppressionMatches reports whether a fired alert is suppressed by
// any non-expired entry. Used in the alert path BEFORE the alertHooks
// fanout so a suppressed alert is dropped silently (still logged at
// the storage level for audit).
func suppressionMatches(list []suppression, alert map[string]any) (string, bool) {
	now := time.Now().UTC()
	for _, s := range list {
		if !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt) {
			continue
		}
		ok := true
		for k, want := range s.Matches {
			got := strFieldFromAny(alert[k])
			if got != want {
				ok = false
				break
			}
		}
		if ok {
			return s.ID, true
		}
	}
	return "", false
}

// pruneSuppressions removes expired entries and returns the count
// removed. Called by the watcher loop and at daemon startup.
func pruneSuppressions(rulesPath string, logger *Storage) int {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	list := loadSuppressions(rulesPath)
	if len(list) == 0 {
		return 0
	}
	now := time.Now().UTC()
	kept := list[:0]
	pruned := 0
	for _, s := range list {
		if !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt) {
			pruned++
			if logger != nil {
				logger.Write("meta", map[string]any{
					"event":      "suppression_expired",
					"suppression_id": s.ID,
					"reason":     s.Reason,
				})
			}
			continue
		}
		kept = append(kept, s)
	}
	if pruned > 0 {
		_ = saveSuppressions(rulesPath, append([]suppression{}, kept...))
	}
	return pruned
}

// startSuppressionWatcher prunes suppressions every 5 minutes plus
// once on entry. Logger is the daemon's own _server / _master /
// standalone storage so meta:suppression_expired lands in the audit
// trail.
func startSuppressionWatcher(ctx context.Context, wg *sync.WaitGroup, rulesPath string, logger *Storage) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = pruneSuppressions(rulesPath, logger)
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = pruneSuppressions(rulesPath, logger)
			}
		}
	}()
}

// runRulesSuppressCmd dispatches `simplesiem rules suppress <subcmd>`.
//
//	simplesiem rules suppress add --match host=foo --match rule_id=bar --for 7d --reason "..."
//	simplesiem rules suppress list
//	simplesiem rules suppress remove <id>
//	simplesiem rules suppress extend <id> --by 7d
func runRulesSuppressCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem rules suppress <add|list|remove|extend>

  add --match k=v ... --for <dur> --reason "..."  Suppress matching alerts for <dur>.
                                                  Max 90d. for=permanent refused.
  list                                            Show active suppressions with TTL countdown.
  remove <id>                                     Remove early.
  extend <id> --by <dur>                          Bump expiry by <dur>.`)
		os.Exit(2)
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	rulesPath := loadConfig(defaultConfigPath()).RulesPath
	if rulesPath == "" {
		rulesPath = filepath.Join(defaultConfigDir(), "rules.json")
	}
	switch args[0] {
	case "add":
		runSuppressAdd(args[1:], rulesPath, "rules suppress add")
	case "list":
		runSuppressList(rulesPath)
	case "remove":
		if len(args) < 2 {
			fatalf("usage: simplesiem rules suppress remove <id>")
		}
		runSuppressRemove(args[1], rulesPath)
	case "extend":
		runSuppressExtend(args[1:], rulesPath)
	default:
		fatalf("unknown rules suppress subcommand: %s", args[0])
	}
}

func runSuppressAdd(args []string, rulesPath, addedBy string) {
	args = permuteArgs(args, map[string]bool{"for": true, "reason": true, "match": true})
	fs := flag.NewFlagSet("rules suppress add", flag.ExitOnError)
	forStr := fs.String("for", "", "duration (required, e.g. 7d, 24h). Refuses 'permanent'. Max 90d.")
	reason := fs.String("reason", "", "free-text reason recorded in the suppression entry")
	var matches matchSlice
	fs.Var(&matches, "match", "k=v match clause; pass multiple to combine (AND)")
	_ = fs.Parse(args)
	if *forStr == "" {
		fatalf("--for is required (e.g. --for 7d). 'permanent' is refused; pass an explicit duration.")
	}
	if strings.EqualFold(*forStr, "permanent") {
		fatalf("--for permanent is refused — auto-expiry prevents suppression rot. Use a finite duration up to 90d.")
	}
	dur, err := parseDurationDays(*forStr)
	if err != nil {
		fatalf("--for %q: %v", *forStr, err)
	}
	if dur > suppressionMaxDuration {
		fatalf("--for %s exceeds the max of 90d. Re-add later if still needed.", dur)
	}
	if len(matches) == 0 {
		fatalf("at least one --match k=v is required")
	}
	matchMap := map[string]string{}
	for _, m := range matches {
		k, v, ok := strings.Cut(m, "=")
		if !ok || k == "" {
			fatalf("invalid --match %q (expected k=v)", m)
		}
		matchMap[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	now := time.Now().UTC()
	id := fmt.Sprintf("supp-%s-%s", now.Format("20060102T150405Z"), suppressShortHash(matches.String()))
	s := suppression{
		ID:        id,
		Matches:   matchMap,
		Reason:    *reason,
		AddedBy:   addedBy,
		AddedAt:   now,
		ExpiresAt: now.Add(dur),
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	list := append(loadSuppressions(rulesPath), s)
	if err := saveSuppressions(rulesPath, list); err != nil {
		fatalf("save suppressions: %v", err)
	}
	fmt.Printf("Added suppression %s (expires %s)\n", id, s.ExpiresAt.Format(time.RFC3339))
}

func runSuppressList(rulesPath string) {
	list := loadSuppressions(rulesPath)
	if len(list) == 0 {
		fmt.Println("No active suppressions.")
		return
	}
	now := time.Now().UTC()
	for _, s := range list {
		ttl := time.Until(s.ExpiresAt).Round(time.Minute)
		fmt.Printf("%s\n", s.ID)
		fmt.Printf("  matches: %v\n", s.Matches)
		if !s.ExpiresAt.IsZero() {
			if now.After(s.ExpiresAt) {
				fmt.Printf("  expires: %s (EXPIRED, will prune on next cycle)\n", s.ExpiresAt.Format(time.RFC3339))
			} else {
				fmt.Printf("  expires: %s (in %s)\n", s.ExpiresAt.Format(time.RFC3339), ttl)
			}
		}
		if s.Reason != "" {
			fmt.Printf("  reason:  %s\n", s.Reason)
		}
	}
}

func runSuppressRemove(id, rulesPath string) {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	list := loadSuppressions(rulesPath)
	out := list[:0]
	removed := false
	for _, s := range list {
		if s.ID == id {
			removed = true
			continue
		}
		out = append(out, s)
	}
	if !removed {
		fatalf("suppression %q not found", id)
	}
	if err := saveSuppressions(rulesPath, append([]suppression{}, out...)); err != nil {
		fatalf("save: %v", err)
	}
	fmt.Printf("Removed suppression %s\n", id)
}

func runSuppressExtend(args []string, rulesPath string) {
	args = permuteArgs(args, map[string]bool{"by": true})
	fs := flag.NewFlagSet("rules suppress extend", flag.ExitOnError)
	by := fs.String("by", "", "extension duration, e.g. 7d")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: rules suppress extend <id> --by <dur>")
	}
	id := fs.Arg(0)
	dur, err := parseDurationDays(*by)
	if err != nil {
		fatalf("--by %q: %v", *by, err)
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	list := loadSuppressions(rulesPath)
	updated := false
	for i := range list {
		if list[i].ID == id {
			list[i].ExpiresAt = list[i].ExpiresAt.Add(dur)
			if list[i].ExpiresAt.Sub(list[i].AddedAt) > suppressionMaxDuration {
				fatalf("extending would exceed the 90d cap from added_at")
			}
			updated = true
			break
		}
	}
	if !updated {
		fatalf("suppression %q not found", id)
	}
	if err := saveSuppressions(rulesPath, list); err != nil {
		fatalf("save: %v", err)
	}
	fmt.Printf("Extended %s by %s\n", id, dur)
}

// parseDurationDays accepts "7d", "24h", "30m" — same surface as
// parseSince's relative window.
func parseDurationDays(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	if strings.HasSuffix(s, "d") {
		num := strings.TrimSuffix(s, "d")
		n := 0
		for _, c := range num {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("not a number: %q", num)
			}
			n = n*10 + int(c-'0')
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// suppressShortHash returns the first 6 hex chars of a fnv-32 hash of input,
// used to make suppression IDs unique within the same second.
func suppressShortHash(in string) string {
	h := uint32(2166136261)
	for i := 0; i < len(in); i++ {
		h ^= uint32(in[i])
		h *= 16777619
	}
	return fmt.Sprintf("%06x", h&0xffffff)
}

// matchSlice implements flag.Value for repeating --match k=v.
type matchSlice []string

func (m *matchSlice) String() string     { return strings.Join(*m, ",") }
func (m *matchSlice) Set(v string) error { *m = append(*m, v); return nil }
