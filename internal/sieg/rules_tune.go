package sieg

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// #1 — rules tune: classify rules into dead / runaway / severity-mismatch
// based on the rolling stats stream stored at <state>/rules_stats.ndjson.
// Read-only by default; --apply rewrites rules.json with suggested edits.

type ruleStat struct {
	TS        time.Time `json:"ts"`
	RuleID    string    `json:"rule_id"`
	Fired     int       `json:"fired"`
	Severity  string    `json:"severity"`
	Host      string    `json:"host"`
	AlertID   string    `json:"alert_id"`
	AckedAt   string    `json:"acked_at,omitempty"`
	AckReason string    `json:"ack_reason,omitempty"`
}

func ruleStatsPath() string { return filepath.Join(defaultStateDir(), "rules_stats.ndjson") }

// recordRuleFire is called from the alert hook fanout to append a stat
// line. Best-effort; write failures don't block alerts.
func recordRuleFire(ruleID, severity, host, alertID string) {
	rec := ruleStat{
		TS: time.Now().UTC(), RuleID: ruleID, Fired: 1,
		Severity: severity, Host: host, AlertID: alertID,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(ruleStatsPath()), 0o750)
	f, err := os.OpenFile(ruleStatsPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}

// recordRuleAck records the operator's ack of an alert so tune can
// compute severity-vs-ack-rate.
func recordRuleAck(alertID, reason string) {
	rec := ruleStat{
		TS: time.Now().UTC(), AlertID: alertID, AckedAt: time.Now().UTC().Format(time.RFC3339), AckReason: reason,
	}
	data, _ := json.Marshal(rec)
	_ = os.MkdirAll(filepath.Dir(ruleStatsPath()), 0o750)
	f, err := os.OpenFile(ruleStatsPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}

type tuneSuggestion struct {
	RuleID   string
	Kind     string // "dead", "runaway", "severity_high", "severity_low"
	Detail   string
	Suggest  string
}

// classifyStats scans the stats file and reports suggestions. Returns
// suggestions sorted by RuleID for deterministic output.
func classifyStats(statsPath string, since time.Time) []tuneSuggestion {
	f, err := os.Open(statsPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	type acc struct {
		fires       int
		acks        int
		severity    string
		lastFireAt  time.Time
	}
	byRule := map[string]*acc{}
	alertSeverity := map[string]string{}
	alertRule := map[string]string{}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var rec ruleStat
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		if !since.IsZero() && rec.TS.Before(since) {
			continue
		}
		if rec.Fired > 0 && rec.RuleID != "" {
			a, ok := byRule[rec.RuleID]
			if !ok {
				a = &acc{severity: rec.Severity}
				byRule[rec.RuleID] = a
			}
			a.fires++
			a.lastFireAt = rec.TS
			if a.severity == "" {
				a.severity = rec.Severity
			}
			if rec.AlertID != "" {
				alertSeverity[rec.AlertID] = rec.Severity
				alertRule[rec.AlertID] = rec.RuleID
			}
			continue
		}
		if rec.AckedAt != "" && rec.AlertID != "" {
			rid := alertRule[rec.AlertID]
			if a, ok := byRule[rid]; ok {
				a.acks++
			}
		}
	}

	var out []tuneSuggestion
	now := time.Now().UTC()
	deadCutoff := now.Add(-30 * 24 * time.Hour)
	for rid, a := range byRule {
		if a.fires == 0 || a.lastFireAt.Before(deadCutoff) {
			out = append(out, tuneSuggestion{rid, "dead", "no fires in 30d", "review or delete"})
			continue
		}
		windowH := 24.0
		ratePerDay := float64(a.fires) // approximation if all stats within 24h
		if !since.IsZero() {
			elapsed := now.Sub(since).Hours()
			if elapsed > 0 {
				ratePerDay = float64(a.fires) / (elapsed / windowH)
			}
		}
		if ratePerDay > 1000 {
			out = append(out, tuneSuggestion{rid, "runaway", fmt.Sprintf("fires/day≈%.0f", ratePerDay), "tighten threshold or add dedup"})
		}
		if a.fires >= 10 {
			ackRate := float64(a.acks) / float64(a.fires)
			switch a.severity {
			case "high", "critical":
				if ackRate >= 0.9 {
					out = append(out, tuneSuggestion{rid, "severity_high", fmt.Sprintf("severity=%s ack_rate=%.0f%%", a.severity, ackRate*100), "lower to medium"})
				}
			case "low":
				if ackRate <= 0.05 && a.acks <= 1 {
					// Mostly unacked = nobody cares = severity is right OR rule needs attention.
					// Don't flip; classify as severity_low only when SEVERELY skewed.
					out = append(out, tuneSuggestion{rid, "severity_low", fmt.Sprintf("severity=%s ack_rate=%.0f%%", a.severity, ackRate*100), "raise to medium"})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// runRulesTune dispatches `simplesiem rules tune [--apply] [--since 30d]`.
func runRulesTune(args []string) {
	args = permuteArgs(args, map[string]bool{"since": true})
	fs := flag.NewFlagSet("rules tune", flag.ExitOnError)
	apply := fs.Bool("apply", false, "rewrite rules.json with suggested severity edits")
	sinceStr := fs.String("since", "30d", "window over which stats are evaluated")
	jsonOut := fs.Bool("json", false, "machine-readable output")
	_ = fs.Parse(args)

	since := time.Now().UTC()
	if d, err := parseSince(*sinceStr); err == nil {
		since = d
	}

	suggestions := classifyStats(ruleStatsPath(), since)

	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(suggestions)
		return
	}

	if len(suggestions) == 0 {
		fmt.Println("No tune suggestions. Either rules are firing as expected or there's not enough data yet (run for 7+ days).")
		return
	}
	fmt.Println("Rule tune suggestions:")
	for _, s := range suggestions {
		fmt.Printf("  [%s] %s — %s — suggest: %s\n", s.Kind, s.RuleID, s.Detail, s.Suggest)
	}

	if *apply {
		if !isAdmin() {
			fatalf("must run as admin to apply changes")
		}
		// #1 authority: refused on a server when master is enrolled.
		cfg := loadConfig(defaultConfigPath())
		if normaliseMode(cfg.Mode) == "server" && len(cfg.Server.MasterCNs) > 0 {
			fatalf("rules tune --apply is refused on a server with a master enrolled. Run on the master.")
		}
		applyTuneSuggestions(cfg.RulesPath, suggestions)
	}
}

func applyTuneSuggestions(rulesPath string, suggestions []tuneSuggestion) {
	if rulesPath == "" {
		rulesPath = filepath.Join(defaultConfigDir(), "rules.json")
	}
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		fatalf("read rules.json: %v", err)
	}
	// Backup first.
	if err := os.WriteFile(rulesPath+".bak", data, 0o640); err != nil {
		fatalf("backup rules.json: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		fatalf("parse rules.json: %v", err)
	}
	rulesAny, _ := doc["rules"].([]any)
	changed := 0
	for _, s := range suggestions {
		if s.Kind != "severity_high" && s.Kind != "severity_low" {
			continue
		}
		newSev := "medium"
		for _, ra := range rulesAny {
			rm, _ := ra.(map[string]any)
			if rm == nil {
				continue
			}
			if id, _ := rm["name"].(string); id == s.RuleID {
				rm["severity"] = newSev
				changed++
				break
			}
		}
	}
	if changed == 0 {
		fmt.Println("Nothing to apply (no severity adjustments matched a rule by name).")
		return
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(rulesPath, out, 0o640); err != nil {
		fatalf("write rules.json: %v", err)
	}
	fmt.Printf("Applied %d severity adjustment(s); backup at %s.bak\n", changed, rulesPath)
}

