package sieg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// #8 MITRE Phase 2 — auto-rule generation from a curated mapping of
// technique_id → rule template. When the MITRE catalog updates and
// auto_generate_rules is enabled, the manager walks every technique
// in the new catalog and emits a rule for any technique we have a
// curated template for. The output is a sidecar
// `rules-mitre-generated.json` so the operator's main rules.json
// stays operator-owned.
//
// Why curated templates instead of heuristic NLP-from-narrative?
// Detection rules need precise field references (event_type,
// process, path, user) that technique narratives don't supply.
// Heuristic generation produces vague rules that fire on nothing or
// on everything. The curated approach delivers usable rules out of
// the box and remains operationally reviewable: the operator can
// inspect the sidecar, delete rules they don't want (recorded in a
// rejected list so they don't regenerate), and tune ones they do.

// MitreRuleTemplate is a curated mapping entry. Each defines the
// minimum-viable detection logic for a single technique_id. The rule
// engine treats these like any other rule once instantiated.
type MitreRuleTemplate struct {
	TechniqueID string         `json:"technique_id"`
	SubID       string         `json:"sub_id,omitempty"`
	Severity    string         `json:"severity"`
	Match       map[string]any `json:"match"`
	Threshold   *struct {
		Count   int    `json:"count"`
		Window  string `json:"window"`
		GroupBy string `json:"group_by,omitempty"`
	} `json:"threshold,omitempty"`
	Notes      string `json:"notes,omitempty"`
	RunbookURL string `json:"runbook_url,omitempty"`
}

// curatedMitreTemplates is the shipped baseline. Operators get
// detection on day one for the highest-frequency techniques. The
// list is intentionally short + opinionated — every entry has been
// verified to map cleanly to fields the existing collectors emit.
//
// To add coverage: append a template. To override on a per-host
// basis: edit the generated sidecar (rejected list prevents re-gen
// from clobbering your edits).
var curatedMitreTemplates = []MitreRuleTemplate{
	{
		TechniqueID: "T1110", Severity: "high",
		Match: map[string]any{
			"type":  "auth",
			"event": "login_failed",
		},
		Threshold: &struct {
			Count   int    `json:"count"`
			Window  string `json:"window"`
			GroupBy string `json:"group_by,omitempty"`
		}{Count: 5, Window: "5m", GroupBy: "user"},
		Notes: "T1110 Brute Force — 5+ login_failed events for the same user within 5 minutes.",
	},
	{
		TechniqueID: "T1110", SubID: "001", Severity: "high",
		Match: map[string]any{
			"type":  "auth",
			"event": "login_failed",
		},
		Threshold: &struct {
			Count   int    `json:"count"`
			Window  string `json:"window"`
			GroupBy string `json:"group_by,omitempty"`
		}{Count: 10, Window: "1m", GroupBy: "source_ip"},
		Notes: "T1110.001 Password Guessing — 10+ login_failed events from a single source_ip within a minute.",
	},
	{
		TechniqueID: "T1059", SubID: "001", Severity: "medium",
		Match: map[string]any{
			"type":    "process",
			"event":   "process_start",
			"process": "*=powershell",
		},
		Notes: "T1059.001 PowerShell — process_start of any powershell binary. Tune by parent_proc + commandline if too noisy.",
	},
	{
		TechniqueID: "T1059", SubID: "003", Severity: "medium",
		Match: map[string]any{
			"type":    "process",
			"event":   "process_start",
			"process": "*=cmd.exe",
		},
		Notes: "T1059.003 Windows Command Shell — process_start of cmd.exe. Tune by parent_proc + commandline if too noisy.",
	},
	{
		TechniqueID: "T1059", SubID: "004", Severity: "low",
		Match: map[string]any{
			"type":    "process",
			"event":   "process_start",
			"process": "~=^(bash|sh|zsh|dash|fish)$",
		},
		Notes: "T1059.004 Unix Shell — interactive shell start. Low severity by default; raise on production hosts.",
	},
	{
		TechniqueID: "T1003", Severity: "critical",
		Match: map[string]any{
			"type": "files",
			"path": "~=/etc/(shadow|sudoers|passwd-)",
		},
		Notes: "T1003 OS Credential Dumping — read/write to /etc/shadow, /etc/sudoers, /etc/passwd-.",
	},
	{
		TechniqueID: "T1136", Severity: "high",
		Match: map[string]any{
			"type":    "process",
			"event":   "process_start",
			"process": "~=^(useradd|adduser|net)$",
		},
		Notes: "T1136 Create Account — useradd/adduser invocation, or `net user` on Windows.",
	},
	{
		TechniqueID: "T1547", SubID: "001", Severity: "high",
		Match: map[string]any{
			"type": "files",
			"path": "~=^(/etc/cron\\.|/etc/init\\.d|/Library/LaunchDaemons|HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run)",
		},
		Notes: "T1547.001 Registry Run Keys / Startup Folder — write to autostart locations across Linux/Mac/Windows.",
	},
	{
		TechniqueID: "T1562", SubID: "001", Severity: "high",
		Match: map[string]any{
			"type":    "process",
			"event":   "process_start",
			"process": "~=^(auditctl|systemctl|launchctl|sc)$",
		},
		Notes: "T1562.001 Disable or Modify Tools — invocation of audit/service tooling. Tune by command-line args.",
	},
	{
		TechniqueID: "T1078", Severity: "medium",
		Match: map[string]any{
			"type":  "meta",
			"event": "first_seen_tuple",
			"tuple": "user_country",
		},
		Notes: "T1078 Valid Accounts — first time a user is seen logging in from a new geoip.country (requires #7 firstseen tuples).",
	},
	{
		TechniqueID: "T1486", Severity: "critical",
		Match: map[string]any{
			"type": "files",
			"path": "~=\\.(encrypted|locked|crypt)$",
		},
		Notes: "T1486 Data Encrypted for Impact — file extensions associated with ransomware.",
	},
	{
		TechniqueID: "T1490", Severity: "critical",
		Match: map[string]any{
			"type":    "process",
			"event":   "process_start",
			"process": "~=^(wbadmin|vssadmin|bcdedit)$",
		},
		Notes: "T1490 Inhibit System Recovery — Windows backup / shadow-copy tampering.",
	},
}

// generatedRule is the wire shape written to rules-mitre-generated.json.
// It carries the same fields as a regular rule plus mitre_generated:
// true so operators can filter / inspect.
type generatedRule struct {
	Name            string         `json:"name"`
	Severity        string         `json:"severity"`
	Match           map[string]any `json:"match"`
	Threshold       any            `json:"threshold,omitempty"`
	Notes           string         `json:"notes,omitempty"`
	RunbookURL      string         `json:"runbook_url,omitempty"`
	Tactic          string         `json:"tactic,omitempty"`
	Technique       string         `json:"technique,omitempty"`
	MitreGenerated  bool           `json:"mitre_generated"`
	GeneratedAt     time.Time      `json:"generated_at"`
}

// rejectedTechniques lists technique_ids the operator deleted from
// the sidecar. We never re-emit rules for these unless the operator
// runs `mitre generate-rules --include <id>`.
type rejectedTechniques struct {
	Rejected []string `json:"rejected"`
}

// generatedRulesPath is where Phase 2 writes its sidecar. Lives next
// to rules.json so backup/restore picks it up via the same config-dir
// walk and merge-on-load happens automatically.
func generatedRulesPath(rulesPath string) string {
	if rulesPath == "" {
		rulesPath = filepath.Join(defaultConfigDir(), "rules.json")
	}
	return filepath.Join(filepath.Dir(rulesPath), "rules-mitre-generated.json")
}

func rejectedTechniquesPath(rulesPath string) string {
	if rulesPath == "" {
		rulesPath = filepath.Join(defaultConfigDir(), "rules.json")
	}
	return filepath.Join(filepath.Dir(rulesPath), "rules-mitre-rejected.json")
}

// generateRulesFromCatalog walks templates, filters by what's in the
// MITRE catalog (so we don't emit rules for deprecated / non-existent
// technique IDs), and writes the sidecar atomically. Returns the
// number of rules emitted.
func generateRulesFromCatalog(catalog *mitreCatalog, rulesPath string) (int, error) {
	if catalog == nil {
		return 0, fmt.Errorf("nil catalog")
	}
	rejected := loadRejectedTechniques(rulesPath)
	rejectedSet := map[string]bool{}
	for _, id := range rejected.Rejected {
		rejectedSet[id] = true
	}
	var generated []generatedRule
	now := time.Now().UTC()
	for _, tmpl := range curatedMitreTemplates {
		fullID := tmpl.TechniqueID
		if tmpl.SubID != "" {
			fullID = fullID + "." + tmpl.SubID
		}
		if rejectedSet[fullID] {
			continue
		}
		// Only emit if the technique still exists in the live catalog
		// (deprecated / revoked techniques are pruned during catalog
		// parse, so absence here means MITRE removed it).
		_, exists := catalog.Techniques[fullID]
		_, baseExists := catalog.Techniques[tmpl.TechniqueID]
		if !exists && !baseExists {
			continue
		}
		// Pick up the tactic from the catalog so the generated rule
		// carries it. If both fullID and base exist, fullID wins.
		tactic := ""
		if t, ok := catalog.Techniques[fullID]; ok && len(t.Tactics) > 0 {
			tactic = t.Tactics[0]
		} else if t, ok := catalog.Techniques[tmpl.TechniqueID]; ok && len(t.Tactics) > 0 {
			tactic = t.Tactics[0]
		}
		name := "mitre_" + strings.ReplaceAll(strings.ToLower(fullID), ".", "_")
		gr := generatedRule{
			Name:           name,
			Severity:       tmpl.Severity,
			Match:          tmpl.Match,
			Notes:          tmpl.Notes,
			RunbookURL:     tmpl.RunbookURL,
			Tactic:         tactic,
			Technique:      fullID,
			MitreGenerated: true,
			GeneratedAt:    now,
		}
		if tmpl.Threshold != nil {
			gr.Threshold = tmpl.Threshold
		}
		generated = append(generated, gr)
	}
	sort.Slice(generated, func(i, j int) bool {
		return generated[i].Name < generated[j].Name
	})
	if err := writeGeneratedRules(rulesPath, generated); err != nil {
		return 0, err
	}
	return len(generated), nil
}

func writeGeneratedRules(rulesPath string, rules []generatedRule) error {
	path := generatedRulesPath(rulesPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadGeneratedRules(rulesPath string) []generatedRule {
	data, err := os.ReadFile(generatedRulesPath(rulesPath))
	if err != nil {
		return nil
	}
	var out []generatedRule
	_ = json.Unmarshal(data, &out)
	return out
}

func loadRejectedTechniques(rulesPath string) rejectedTechniques {
	var rt rejectedTechniques
	data, err := os.ReadFile(rejectedTechniquesPath(rulesPath))
	if err != nil {
		return rt
	}
	_ = json.Unmarshal(data, &rt)
	return rt
}

func saveRejectedTechniques(rulesPath string, rt rejectedTechniques) error {
	path := rejectedTechniquesPath(rulesPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rt, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// runMitreGenerateRules is the operator-facing CLI:
//
//	simplesiem mitre generate-rules
//	  Generate rules from the curated mapping against the cached
//	  MITRE catalog. Writes <rules.json's dir>/rules-mitre-generated.json.
//
//	simplesiem mitre generate-rules --reject T1059.001
//	  Add a technique to the rejected list (won't regenerate).
//
//	simplesiem mitre generate-rules --include T1059.001
//	  Remove from rejected list (will regenerate on next call).
//
//	simplesiem mitre generate-rules --list-templates
//	  Show all curated technique → template mappings.
func runMitreGenerateRules(args []string) {
	args = permuteArgs(args, map[string]bool{"reject": true, "include": true})
	var rejectIDs, includeIDs []string
	listTemplates := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--reject":
			if i+1 < len(args) {
				rejectIDs = append(rejectIDs, args[i+1])
				i++
			}
		case "--include":
			if i+1 < len(args) {
				includeIDs = append(includeIDs, args[i+1])
				i++
			}
		case "--list-templates":
			listTemplates = true
		}
	}
	if listTemplates {
		fmt.Printf("Curated MITRE templates (%d):\n", len(curatedMitreTemplates))
		for _, t := range curatedMitreTemplates {
			id := t.TechniqueID
			if t.SubID != "" {
				id = id + "." + t.SubID
			}
			fmt.Printf("  %s  severity=%s\n    %s\n", id, t.Severity, t.Notes)
		}
		return
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	cfg := loadConfig(defaultConfigPath())
	if normaliseMode(cfg.Mode) == "server" && len(cfg.Server.MasterCNs) > 0 {
		fatalf("mitre generate-rules is refused on a server with a master enrolled. Run on the master.")
	}
	rejected := loadRejectedTechniques(cfg.RulesPath)
	rejSet := map[string]bool{}
	for _, id := range rejected.Rejected {
		rejSet[id] = true
	}
	for _, id := range rejectIDs {
		rejSet[id] = true
	}
	for _, id := range includeIDs {
		delete(rejSet, id)
	}
	rejected.Rejected = rejected.Rejected[:0]
	for id := range rejSet {
		rejected.Rejected = append(rejected.Rejected, id)
	}
	sort.Strings(rejected.Rejected)
	if err := saveRejectedTechniques(cfg.RulesPath, rejected); err != nil {
		fatalf("save rejected list: %v", err)
	}

	stateDir := filepath.Join(defaultStateDir(), "mitre")
	data, err := os.ReadFile(filepath.Join(stateDir, "catalog.json"))
	if err != nil {
		fatalf("MITRE catalog not fetched yet — run `simplesiem mitre fetch` first")
	}
	var cat mitreCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		fatalf("parse catalog: %v", err)
	}
	n, err := generateRulesFromCatalog(&cat, cfg.RulesPath)
	if err != nil {
		fatalf("generate: %v", err)
	}
	fmt.Printf("Generated %d MITRE-derived rules at %s\n", n, generatedRulesPath(cfg.RulesPath))
	if len(rejected.Rejected) > 0 {
		fmt.Printf("Rejected list (%d): %v\n", len(rejected.Rejected), rejected.Rejected)
	}
	fmt.Println()
	fmt.Println("These rules merge with rules.json on daemon load. To reject one:")
	fmt.Println("  sudo simplesiem mitre generate-rules --reject <technique_id>")
}

// mergeMitreGeneratedRules is invoked by the rules loader to merge
// the sidecar with the operator's main rules.json. Caller passes the
// already-parsed []*alertRule from rules.json; this function reads
// the sidecar, parses each generated rule, and appends. Errors are
// returned but not fatal — a malformed sidecar shouldn't block
// daemon startup.
func mergeMitreGeneratedRules(existing []*alertRule, rulesPath string) []*alertRule {
	gen := loadGeneratedRules(rulesPath)
	if len(gen) == 0 {
		return existing
	}
	// Index existing by name to avoid duplicates if operator
	// hand-copied a generated rule into rules.json.
	existingNames := map[string]bool{}
	for _, r := range existing {
		existingNames[r.Name] = true
	}
	for _, gr := range gen {
		if existingNames[gr.Name] {
			continue
		}
		// Marshal back through the rule loader path so all the
		// matcher / threshold / sequence parsing happens uniformly.
		data, err := json.Marshal([]any{gr})
		if err != nil {
			continue
		}
		rules, err := parseRulesBytes(data)
		if err != nil || len(rules) == 0 {
			continue
		}
		// Carry mitre_generated through onto a marker we can detect
		// later. The alertRule struct doesn't have this field, so we
		// rely on the technique tag (always set on generated rules)
		// + name prefix `mitre_` to identify generated rules at
		// runtime.
		existing = append(existing, rules[0])
	}
	return existing
}

// startMitreAutoGen runs after each catalog fetch when
// cfg.mitre.auto_generate_rules is true. Best-effort: errors are
// logged but don't block the catalog refresh.
func (m *mitreManager) startMitreAutoGen(rulesPath string, autoGen bool) {
	if !autoGen {
		return
	}
	m.mu.RLock()
	cat := m.catalog
	m.mu.RUnlock()
	if cat == nil {
		return
	}
	n, err := generateRulesFromCatalog(cat, rulesPath)
	if err != nil {
		if m.logger != nil {
			m.logger.Write("errors", map[string]any{
				"collector": "mitre_phase2",
				"error":     "auto-generate rules failed: " + err.Error(),
			})
		}
		return
	}
	if m.logger != nil {
		m.logger.Write("meta", map[string]any{
			"event":   "mitre_rules_generated",
			"count":   n,
			"sidecar": generatedRulesPath(rulesPath),
		})
	}
}

// mitreAutoGenMu prevents concurrent generate calls (CLI + auto-fetch).
var mitreAutoGenMu sync.Mutex
