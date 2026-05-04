package sieg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// #8 — MITRE ATT&CK Phase 1: bundled tagged rules + auto-pull of the
// catalog from MITRE's enterprise-attack STIX bundle. Coverage report
// uses fresh data; new techniques surface as gaps.
//
// Auto-rule-generation from technique definitions is research-grade
// and deferred to Phase 2 (docs/future.md).

type MitreConfig struct {
	Enabled            bool   `json:"enabled"`
	UpdateIntervalDays int    `json:"update_interval_days"`
	BundleURL          string `json:"bundle_url"`
	// AutoGenerateRules (Phase 2) — when true, auto-emit a sidecar
	// rules-mitre-generated.json from the curated technique→template
	// mapping after each catalog fetch. Default true; operators
	// who want to hand-curate set false.
	AutoGenerateRules bool `json:"auto_generate_rules"`
}

func defaultMitreConfig() MitreConfig {
	return MitreConfig{
		Enabled:            true,
		UpdateIntervalDays: 7,
		BundleURL:          "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
		AutoGenerateRules:  true,
	}
}

type mitreTechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tactics     []string `json:"tactics"`
}

type mitreCatalog struct {
	FetchedAt  time.Time                  `json:"fetched_at"`
	Techniques map[string]mitreTechnique `json:"techniques"`
	Source     string                    `json:"source"`
}

type mitreManager struct {
	mu      sync.RWMutex
	cfg     MitreConfig
	catalog *mitreCatalog
	logger  *Storage
	stateDir string
}

func newMitreManager(cfg MitreConfig, logger *Storage) *mitreManager {
	if cfg.UpdateIntervalDays <= 0 {
		cfg.UpdateIntervalDays = 7
	}
	if cfg.BundleURL == "" {
		cfg.BundleURL = defaultMitreConfig().BundleURL
	}
	m := &mitreManager{
		cfg:      cfg,
		logger:   logger,
		stateDir: filepath.Join(defaultStateDir(), "mitre"),
	}
	_ = os.MkdirAll(m.stateDir, 0o750)
	if cat, err := m.loadCached(); err == nil {
		m.catalog = cat
	}
	return m
}

// Start runs the periodic fetch loop. Refetches if the cache is past
// UpdateIntervalDays.
func (m *mitreManager) Start(ctx context.Context, wg *sync.WaitGroup) {
	if !m.cfg.Enabled {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.maybeFetch(ctx)
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.maybeFetch(ctx)
			}
		}
	}()
}

func (m *mitreManager) maybeFetch(ctx context.Context) {
	m.mu.RLock()
	stale := m.catalog == nil || time.Since(m.catalog.FetchedAt) > time.Duration(m.cfg.UpdateIntervalDays)*24*time.Hour
	m.mu.RUnlock()
	if !stale {
		return
	}
	cat, err := m.fetch(ctx)
	if err != nil {
		if m.logger != nil {
			m.logger.Write("meta", map[string]any{
				"event": "mitre_fetch_failed",
				"error": err.Error(),
				"hint":  "reusing cached catalog if available; coverage report will note staleness",
			})
		}
		return
	}
	prevCount := 0
	m.mu.Lock()
	if m.catalog != nil {
		prevCount = len(m.catalog.Techniques)
	}
	m.catalog = cat
	m.mu.Unlock()
	_ = m.saveCached(cat)
	delta := len(cat.Techniques) - prevCount
	if m.logger != nil {
		m.logger.Write("meta", map[string]any{
			"event":            "mitre_catalog_updated",
			"techniques_total": len(cat.Techniques),
			"new_since_last":   delta,
		})
	}
	// Phase 2 auto-generation. Best-effort.
	if m.cfg.AutoGenerateRules {
		mitreAutoGenMu.Lock()
		defer mitreAutoGenMu.Unlock()
		cfgPath := defaultConfigPath()
		fullCfg := loadConfig(cfgPath)
		m.startMitreAutoGen(fullCfg.RulesPath, true)
	}
}

func (m *mitreManager) fetch(ctx context.Context) (*mitreCatalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.BundleURL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	return parseSTIXBundle(body, m.cfg.BundleURL)
}

func parseSTIXBundle(data []byte, source string) (*mitreCatalog, error) {
	var bundle struct {
		Type    string `json:"type"`
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("parse STIX bundle: %w", err)
	}
	cat := &mitreCatalog{
		FetchedAt: time.Now().UTC(),
		Techniques: map[string]mitreTechnique{},
		Source:    source,
	}
	for _, raw := range bundle.Objects {
		var obj struct {
			Type             string `json:"type"`
			Name             string `json:"name"`
			XMitreDeprecated bool   `json:"x_mitre_deprecated"`
			Revoked          bool   `json:"revoked"`
			ExternalRefs     []struct {
				SourceName string `json:"source_name"`
				ExternalID string `json:"external_id"`
			} `json:"external_references"`
			KillChainPhases []struct {
				PhaseName string `json:"phase_name"`
			} `json:"kill_chain_phases"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue
		}
		if obj.Type != "attack-pattern" || obj.XMitreDeprecated || obj.Revoked {
			continue
		}
		var techID string
		for _, ref := range obj.ExternalRefs {
			if ref.SourceName == "mitre-attack" {
				techID = ref.ExternalID
				break
			}
		}
		if techID == "" {
			continue
		}
		var tactics []string
		for _, kcp := range obj.KillChainPhases {
			tactics = append(tactics, kcp.PhaseName)
		}
		cat.Techniques[techID] = mitreTechnique{
			ID: techID, Name: obj.Name,
			Description: obj.Description, Tactics: tactics,
		}
	}
	if len(cat.Techniques) == 0 {
		return nil, fmt.Errorf("STIX bundle had 0 attack-pattern objects")
	}
	return cat, nil
}

func (m *mitreManager) loadCached() (*mitreCatalog, error) {
	data, err := os.ReadFile(filepath.Join(m.stateDir, "catalog.json"))
	if err != nil {
		return nil, err
	}
	var cat mitreCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil, err
	}
	return &cat, nil
}

func (m *mitreManager) saveCached(cat *mitreCatalog) error {
	data, err := json.Marshal(cat)
	if err != nil {
		return err
	}
	tmp := filepath.Join(m.stateDir, "catalog.json.tmp")
	final := filepath.Join(m.stateDir, "catalog.json")
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// runMitreCmd dispatches `simplesiem mitre <catalog|coverage|fetch|disable>`.
func runMitreCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem mitre <catalog|coverage|fetch|disable|generate-rules>

  catalog            Show last-fetched timestamp + technique count.
  coverage           Compare rules.json technique tags against catalog.
  fetch              Force-refresh the catalog now.
  disable            Set cfg.mitre.enabled=false.
  generate-rules     (Phase 2) Emit rules-mitre-generated.json from the
                     curated technique→template mapping. Flags:
                       --reject <id>    skip a technique on regen
                       --include <id>   un-reject a previously-rejected technique
                       --list-templates show all curated mappings`)
		os.Exit(2)
	}
	switch args[0] {
	case "catalog":
		runMitreCatalog()
	case "coverage":
		runMitreCoverage()
	case "fetch":
		runMitreFetch()
	case "disable":
		runMitreDisable()
	case "generate-rules":
		runMitreGenerateRules(args[1:])
	default:
		fatalf("unknown mitre subcommand: %s", args[0])
	}
}

func runMitreCatalog() {
	stateDir := filepath.Join(defaultStateDir(), "mitre")
	data, err := os.ReadFile(filepath.Join(stateDir, "catalog.json"))
	if err != nil {
		fmt.Println("catalog: not yet fetched (run `simplesiem mitre fetch`)")
		return
	}
	var cat mitreCatalog
	_ = json.Unmarshal(data, &cat)
	fmt.Printf("catalog fetched_at: %s\n", cat.FetchedAt.Format(time.RFC3339))
	fmt.Printf("techniques:        %d\n", len(cat.Techniques))
	fmt.Printf("source:            %s\n", cat.Source)
}

func runMitreCoverage() {
	cfg := loadConfig(defaultConfigPath())
	stateDir := filepath.Join(defaultStateDir(), "mitre")
	data, err := os.ReadFile(filepath.Join(stateDir, "catalog.json"))
	if err != nil {
		fmt.Println("catalog not fetched yet (run `simplesiem mitre fetch`).")
		return
	}
	var cat mitreCatalog
	_ = json.Unmarshal(data, &cat)
	rules, err := loadRules(cfg.RulesPath)
	if err != nil {
		fatalf("load rules: %v", err)
	}
	covered := map[string]bool{}
	for _, r := range rules {
		if r.Technique != "" {
			covered[r.Technique] = true
		}
	}
	uncovered := []string{}
	for id := range cat.Techniques {
		if !covered[id] {
			uncovered = append(uncovered, id)
		}
	}
	sort.Strings(uncovered)
	fmt.Printf("Total techniques: %d\n", len(cat.Techniques))
	fmt.Printf("Covered:          %d (%.0f%%)\n", len(covered), 100.0*float64(len(covered))/float64(maxInt(1, len(cat.Techniques))))
	fmt.Printf("Uncovered:        %d\n", len(uncovered))
	if len(uncovered) > 0 {
		fmt.Println("Uncovered (first 10):")
		for i, id := range uncovered {
			if i >= 10 {
				break
			}
			fmt.Printf("  %s  %s\n", id, cat.Techniques[id].Name)
		}
	}
	stale := time.Since(cat.FetchedAt) > 14*24*time.Hour
	if stale {
		fmt.Printf("(catalog is stale: %s old)\n", time.Since(cat.FetchedAt).Round(time.Hour))
	}
}

func runMitreFetch() {
	cfg := loadConfig(defaultConfigPath())
	if !cfg.Mitre.Enabled {
		fatalf("mitre is disabled in config (cfg.mitre.enabled=false)")
	}
	mgr := newMitreManager(cfg.Mitre, nil)
	cat, err := mgr.fetch(context.Background())
	if err != nil {
		fatalf("fetch: %v", err)
	}
	if err := mgr.saveCached(cat); err != nil {
		fatalf("save cache: %v", err)
	}
	fmt.Printf("Fetched %d techniques from %s\n", len(cat.Techniques), cfg.Mitre.BundleURL)
}

func runMitreDisable() {
	if !isAdmin() {
		fatalf("must run as admin")
	}
	cfg := loadConfig(defaultConfigPath())
	cfg.Mitre.Enabled = false
	if err := saveConfig(defaultConfigPath(), cfg); err != nil {
		fatalf("save: %v", err)
	}
	fmt.Println("mitre.enabled = false (run `simplesiem restart` to apply)")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Note about contains() — string slice helper: already defined
// elsewhere (see realm.go). Don't redefine.
var _ = strings.HasPrefix
