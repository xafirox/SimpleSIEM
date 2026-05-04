package sieg

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// #2 — Allowlist learning. Walk recent ack records, identify
// (rule_id, host) pairs that get acked repeatedly, and suggest a
// scoped suppression. Operator runs `simplesiem rules
// suggest-suppression` to see the candidates and `--apply` to
// land them with a default 7-day TTL.

type ackEntry struct {
	AlertHash string    `json:"alert_hash"`
	AckTS     time.Time `json:"ack_ts"`
	By        string    `json:"by"`
	Note      string    `json:"note,omitempty"`
}

type suggestionCandidate struct {
	RuleID    string
	Host      string
	Count     int
	LatestTS  time.Time
	SampleNote string
}

// scanAckRecords walks <log_dir>/_acks/*.jsonl over the configured
// window and groups entries by (rule_id, host). The rule_id + host
// come from the alert payload referenced by alert_hash; we resolve
// by walking the alerts log over the same window.
func scanAckRecords(cfg Config, since time.Time) []suggestionCandidate {
	dir := filepath.Join(cfg.LogDir, "_acks")
	entries, _ := os.ReadDir(dir)
	if len(entries) == 0 {
		return nil
	}
	// Build a hash → (rule_id, host) lookup over the same window.
	roots := searchRoots(cfg, "")
	alerts := loadEventsInRangeMulti(roots, since, time.Now().UTC(), "alerts")
	hashRule := map[string]string{}
	hashHost := map[string]string{}
	for _, ev := range alerts {
		if ev.Data == nil {
			continue
		}
		h := strFieldFromAny(ev.Data["_hash"])
		if h == "" {
			continue
		}
		hashRule[h] = strFieldFromAny(ev.Data["rule"])
		host := strFieldFromAny(ev.Data["host"])
		if host == "" {
			host = strFieldFromAny(ev.Data["matched_host"])
		}
		hashHost[h] = host
	}

	groups := map[string]*suggestionCandidate{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			var a ackEntry
			if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
				continue
			}
			if a.AckTS.Before(since) {
				continue
			}
			rule := hashRule[a.AlertHash]
			host := hashHost[a.AlertHash]
			if rule == "" {
				continue
			}
			key := rule + "|" + host
			c, ok := groups[key]
			if !ok {
				c = &suggestionCandidate{RuleID: rule, Host: host}
				groups[key] = c
			}
			c.Count++
			if a.AckTS.After(c.LatestTS) {
				c.LatestTS = a.AckTS
			}
			if c.SampleNote == "" && a.Note != "" {
				c.SampleNote = a.Note
			}
		}
		f.Close()
	}
	out := make([]suggestionCandidate, 0, len(groups))
	for _, c := range groups {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// runRulesSuggestSuppression dispatches `simplesiem rules suggest-suppression`.
//
//	simplesiem rules suggest-suppression [--since 30d] [--min-acks 5]
//	  Show suppression candidates ranked by ack count.
//
//	simplesiem rules suggest-suppression --apply [--for 7d] [--min-acks 5]
//	  Add suggested suppressions for every candidate above the threshold.
func runRulesSuggestSuppression(args []string) {
	args = permuteArgs(args, map[string]bool{"since": true, "min-acks": true, "for": true})
	fs := flag.NewFlagSet("rules suggest-suppression", flag.ExitOnError)
	since := fs.String("since", "30d", "ack-record window to scan")
	minAcks := fs.Int("min-acks", 5, "minimum ack count to surface a candidate")
	apply := fs.Bool("apply", false, "add suppressions for every candidate above threshold")
	forDur := fs.String("for", "7d", "TTL applied when --apply lands a suppression")
	jsonOut := fs.Bool("json", false, "machine-readable output")
	_ = fs.Parse(args)

	sinceT, err := parseSince(*since)
	if err != nil {
		fatalf("--since %q: %v", *since, err)
	}
	cfg := loadConfig(defaultConfigPath())
	candidates := scanAckRecords(cfg, sinceT)
	filtered := candidates[:0]
	for _, c := range candidates {
		if c.Count >= *minAcks {
			filtered = append(filtered, c)
		}
	}
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(filtered)
		return
	}
	if len(filtered) == 0 {
		fmt.Printf("No suppression candidates (window=%s, min-acks=%d).\n", *since, *minAcks)
		fmt.Println("Acks accumulate over time; if you've just deployed, try a longer --since window or wait a few weeks.")
		return
	}
	fmt.Printf("Suppression candidates (window=%s, min-acks=%d):\n", *since, *minAcks)
	for _, c := range filtered {
		host := c.Host
		if host == "" {
			host = "(any)"
		}
		fmt.Printf("  rule=%s  host=%s  acks=%d  latest=%s\n", c.RuleID, host, c.Count, c.LatestTS.Format(time.RFC3339))
		if c.SampleNote != "" {
			fmt.Printf("    sample note: %q\n", c.SampleNote)
		}
	}
	if !*apply {
		fmt.Println()
		fmt.Println("Run with --apply to add these as suppressions (default TTL 7d).")
		return
	}
	if !isAdmin() {
		fatalf("--apply requires admin")
	}
	if normaliseMode(cfg.Mode) == "server" && len(cfg.Server.MasterCNs) > 0 {
		fatalf("--apply is refused on a server with a master enrolled. Run on the master.")
	}
	dur, err := parseDurationDays(*forDur)
	if err != nil {
		fatalf("--for %q: %v", *forDur, err)
	}
	if dur > suppressionMaxDuration {
		fatalf("--for exceeds 90d cap")
	}
	added := 0
	now := time.Now().UTC()
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	list := loadSuppressions(cfg.RulesPath)
	for _, c := range filtered {
		matches := map[string]string{"rule_id": c.RuleID}
		if c.Host != "" {
			matches["host"] = c.Host
		}
		id := fmt.Sprintf("supp-suggest-%s-%s", now.Format("20060102T150405Z"), suppressShortHash(c.RuleID+"|"+c.Host))
		list = append(list, suppression{
			ID:        id,
			Matches:   matches,
			Reason:    fmt.Sprintf("auto-suggested from %d acks (sample: %q)", c.Count, c.SampleNote),
			AddedBy:   "rules suggest-suppression --apply",
			AddedAt:   now,
			ExpiresAt: now.Add(dur),
		})
		added++
	}
	if err := saveSuppressions(cfg.RulesPath, list); err != nil {
		fatalf("save suppressions: %v", err)
	}
	fmt.Printf("Added %d suppression(s); each expires in %s.\n", added, dur)
}
