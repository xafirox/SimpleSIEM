package sieg

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// #9 — Detection-as-code with auto-fixtures. Auto-captures events
// surrounding fired alerts; rules test replays them and asserts
// regression. Operator never hand-writes a fixture.

type RulesExtrasConfig struct {
	Fixtures FixturesConfig `json:"fixtures"`
}

type FixturesConfig struct {
	Enabled       bool `json:"enabled"`
	KeepPerRule   int  `json:"keep_per_rule"`
	MaxTotalMB    int  `json:"max_total_mb"`
	WindowSeconds int  `json:"window_seconds"`
}

func defaultFixturesConfig() FixturesConfig {
	return FixturesConfig{
		Enabled:       true,
		KeepPerRule:   5,
		MaxTotalMB:    100,
		WindowSeconds: 60,
	}
}

type ruleFixture struct {
	FixtureID     string             `json:"fixture_id"`
	RuleID        string             `json:"rule_id"`
	RuleHash      string             `json:"rule_hash"`
	Expected      string             `json:"expected"`
	Events        []map[string]any   `json:"events"`
	SourceAlertID string             `json:"source_alert_id"`
	CapturedAt    time.Time          `json:"captured_at"`
	Curated       bool               `json:"curated,omitempty"`
}

func fixturesDir() string {
	return filepath.Join(defaultStateDir(), "fixtures", "auto")
}

// captureFixture is called from the alert hook. Best-effort.
func captureFixture(ruleID, ruleHash, alertID string, events []map[string]any, expected string, keepPerRule int) {
	if ruleID == "" || alertID == "" {
		return
	}
	dir := filepath.Join(fixturesDir(), ruleID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return
	}
	fix := ruleFixture{
		FixtureID:     fmt.Sprintf("auto-%s-%s-%s", time.Now().UTC().Format("20060102T150405Z"), ruleID, fixtureShortHash(alertID)),
		RuleID:        ruleID,
		RuleHash:      ruleHash,
		Expected:      expected,
		Events:        events,
		SourceAlertID: alertID,
		CapturedAt:    time.Now().UTC(),
	}
	data, _ := json.MarshalIndent(fix, "", "  ")
	path := filepath.Join(dir, fix.FixtureID+".json")
	_ = os.WriteFile(path, data, 0o640)
	if keepPerRule > 0 {
		pruneOldFixtures(dir, keepPerRule)
	}
}

func pruneOldFixtures(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	files := []os.DirEntry{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			files = append(files, e)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name() > files[j].Name() })
	curated := 0
	pruned := 0
	for _, f := range files {
		path := filepath.Join(dir, f.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var fx ruleFixture
		_ = json.Unmarshal(data, &fx)
		if fx.Curated {
			curated++
			continue
		}
		if (curated + (len(files) - pruned - curated)) <= keep {
			continue
		}
		_ = os.Remove(path)
		pruned++
	}
}

func fixtureShortHash(in string) string {
	h := sha1.Sum([]byte(in))
	return hex.EncodeToString(h[:3])
}

func ruleBodyHash(r *alertRule) string {
	type marshalable struct {
		Name, Severity string
		Match          map[string]string
		Threshold      *thresholdConfig
		Tactic         string
		Technique      string
	}
	m := marshalable{
		Name: r.Name, Severity: r.Severity, Threshold: r.Threshold,
		Tactic: r.Tactic, Technique: r.Technique,
		Match: map[string]string{},
	}
	for k := range r.Match {
		m.Match[k] = "<matcher>"
	}
	data, _ := json.Marshal(m)
	h := sha1.Sum(data)
	return hex.EncodeToString(h[:8])
}

// runRulesTestCmd dispatches `simplesiem rules test`.
func runRulesTestCmd(args []string) {
	args = permuteArgs(args, map[string]bool{"rule": true})
	fs := flag.NewFlagSet("rules test", flag.ExitOnError)
	ruleFilter := fs.String("rule", "", "test only this rule (default: all)")
	jsonOut := fs.Bool("json", false, "machine-readable output")
	refresh := fs.Bool("refresh", false, "accept current rule body for all needs-review fixtures")
	_ = fs.Parse(args)

	cfg := loadConfig(defaultConfigPath())
	rules, err := loadRules(cfg.RulesPath)
	if err != nil {
		fatalf("load rules: %v", err)
	}
	ruleByName := map[string]*alertRule{}
	hashByName := map[string]string{}
	for _, r := range rules {
		ruleByName[r.Name] = r
		hashByName[r.Name] = ruleBodyHash(r)
	}

	type result struct {
		RuleID   string
		Pass     int
		Fail     int
		Details  []string
	}
	var results []result
	dir := fixturesDir()
	ruleDirs, _ := os.ReadDir(dir)
	for _, rd := range ruleDirs {
		if !rd.IsDir() {
			continue
		}
		if *ruleFilter != "" && rd.Name() != *ruleFilter {
			continue
		}
		res := result{RuleID: rd.Name()}
		fixFiles, _ := os.ReadDir(filepath.Join(dir, rd.Name()))
		for _, ff := range fixFiles {
			if !strings.HasSuffix(ff.Name(), ".json") {
				continue
			}
			path := filepath.Join(dir, rd.Name(), ff.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var fx ruleFixture
			if err := json.Unmarshal(data, &fx); err != nil {
				continue
			}
			rule := ruleByName[fx.RuleID]
			if rule == nil {
				res.Fail++
				res.Details = append(res.Details, fmt.Sprintf("ORPHAN rule=%s fixture=%s (rule no longer in rules.json)", fx.RuleID, fx.FixtureID))
				continue
			}
			expected := hashByName[fx.RuleID]
			if fx.RuleHash != "" && fx.RuleHash != expected {
				if *refresh {
					fx.RuleHash = expected
					data, _ := json.MarshalIndent(fx, "", "  ")
					_ = os.WriteFile(path, data, 0o640)
					res.Details = append(res.Details, fmt.Sprintf("REFRESHED rule=%s fixture=%s", fx.RuleID, fx.FixtureID))
				} else {
					res.Details = append(res.Details, fmt.Sprintf("NEEDS-REVIEW rule=%s fixture=%s (rule body changed; rerun with --refresh after verifying)", fx.RuleID, fx.FixtureID))
				}
				continue
			}
			fired := false
			for _, ev := range fx.Events {
				ok, _ := rule.shouldFire("", ev)
				if ok {
					fired = true
					break
				}
			}
			wantFire := fx.Expected == "fires"
			if fired == wantFire {
				res.Pass++
			} else {
				res.Fail++
				res.Details = append(res.Details, fmt.Sprintf("FAIL rule=%s fixture=%s expected=%s fired=%v", fx.RuleID, fx.FixtureID, fx.Expected, fired))
			}
		}
		results = append(results, res)
	}

	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(results)
		return
	}
	totalFail := 0
	for _, r := range results {
		status := "PASS"
		if r.Fail > 0 {
			status = "FAIL"
			totalFail += r.Fail
		}
		fmt.Printf("%s  rule=%s  pass=%d  fail=%d\n", status, r.RuleID, r.Pass, r.Fail)
		for _, d := range r.Details {
			fmt.Printf("      %s\n", d)
		}
	}
	if totalFail > 0 {
		os.Exit(1)
	}
}
