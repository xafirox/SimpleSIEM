package sieg

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// #3 — Cross-tier sequence rules.
//
// Sequence rules already exist (alerts.go::sequenceConfig). cross_host
// extends them: when set, the state machine correlates by user/key
// across hosts on the master tier (it has full-realm visibility).
//
// Hard caps in cfg.master.rules:
//   - sequence_max_window_seconds: 300
//   - sequence_max_per_rule_kb: 64
//   - sequence_max_total_kb: 1024
//
// Rule loader rejects rules exceeding caps; runtime overflow evicts
// oldest partials and emits meta:sequence_budget_overflow once per
// rule per outage.

// CrossTierSequenceCaps holds the operator-tunable hard caps.
type CrossTierSequenceCaps struct {
	MaxWindowSeconds int `json:"sequence_max_window_seconds"`
	MaxPerRuleKB     int `json:"sequence_max_per_rule_kb"`
	MaxTotalKB       int `json:"sequence_max_total_kb"`
}

func defaultCrossTierCaps() CrossTierSequenceCaps {
	return CrossTierSequenceCaps{
		MaxWindowSeconds: 300,
		MaxPerRuleKB:     64,
		MaxTotalKB:       1024,
	}
}

// crossTierState tracks per-key partial matches with LRU eviction.
type crossTierState struct {
	mu          sync.Mutex
	caps        CrossTierSequenceCaps
	overflowed  map[string]bool // rule_id -> already-emitted-overflow-this-outage
	partials    map[string]map[string]*crossTierPartial // ruleID -> correlateKey -> partial
	approxBytes int
}

type crossTierPartial struct {
	stageIdx  int
	startTS   time.Time
	hosts     []string // hosts traversed so far
	users     []string // users seen
	updatedAt time.Time
}

func newCrossTierState(caps CrossTierSequenceCaps) *crossTierState {
	return &crossTierState{
		caps:       caps,
		overflowed: map[string]bool{},
		partials:   map[string]map[string]*crossTierPartial{},
	}
}

// validateCrossTierRule checks a rule against the configured caps.
// Returns nil if acceptable, an error naming the cap if not.
func validateCrossTierRule(ruleID string, windowSeconds int, perRuleKB int, caps CrossTierSequenceCaps) error {
	if windowSeconds > caps.MaxWindowSeconds {
		return fmt.Errorf("rule %q window_max_seconds=%d exceeds sequence_max_window_seconds=%d", ruleID, windowSeconds, caps.MaxWindowSeconds)
	}
	if perRuleKB > caps.MaxPerRuleKB {
		return fmt.Errorf("rule %q memory_budget_kb=%d exceeds sequence_max_per_rule_kb=%d", ruleID, perRuleKB, caps.MaxPerRuleKB)
	}
	return nil
}

// validateCrossTierRuleSet checks the AGGREGATE budget across all
// cross-tier sequence rules (sum of per-rule budgets <= total cap).
func validateCrossTierRuleSet(perRuleKB []int, caps CrossTierSequenceCaps) error {
	total := 0
	for _, b := range perRuleKB {
		total += b
	}
	if total > caps.MaxTotalKB {
		return fmt.Errorf("sum of cross-tier sequence memory budgets (%d KB) exceeds sequence_max_total_kb=%d", total, caps.MaxTotalKB)
	}
	return nil
}

// evict drops the oldest partials for ruleID until approxBytes is
// under the per-rule cap. Emits meta:sequence_budget_overflow once.
func (c *crossTierState) evict(ruleID string, perRuleKB int, logger *Storage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pmap, ok := c.partials[ruleID]
	if !ok {
		return
	}
	type kv struct {
		key string
		p   *crossTierPartial
	}
	var items []kv
	for k, p := range pmap {
		items = append(items, kv{k, p})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].p.updatedAt.Before(items[j].p.updatedAt)
	})
	// Approximate: ~256 bytes per partial; evict 10% of items.
	target := len(items) / 10
	if target < 1 {
		target = 1
	}
	for i := 0; i < target && i < len(items); i++ {
		delete(pmap, items[i].key)
		c.approxBytes -= 256
	}
	if !c.overflowed[ruleID] && logger != nil {
		logger.Write("meta", map[string]any{
			"event":         "sequence_budget_overflow",
			"rule":          ruleID,
			"hint":          "per-rule memory cap reached; evicted oldest partials",
			"per_rule_kb":   perRuleKB,
			"evicted_count": target,
		})
		c.overflowed[ruleID] = true
	}
}

// reset clears the overflow flag (called when a rule fires cleanly,
// signaling the outage condition has cleared).
func (c *crossTierState) reset(ruleID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.overflowed, ruleID)
}

// loadCrossTierCaps reads the caps from cfg.master.rules; falls back
// to defaults when the master block is absent (server tier reads
// defaults so it can refuse cross_host rules at load).
func loadCrossTierCaps(cfgPath string) CrossTierSequenceCaps {
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return defaultCrossTierCaps()
	}
	var probe struct {
		Master struct {
			Rules CrossTierSequenceCaps `json:"rules"`
		} `json:"master"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return defaultCrossTierCaps()
	}
	caps := probe.Master.Rules
	if caps.MaxWindowSeconds <= 0 {
		caps.MaxWindowSeconds = 300
	}
	if caps.MaxPerRuleKB <= 0 {
		caps.MaxPerRuleKB = 64
	}
	if caps.MaxTotalKB <= 0 {
		caps.MaxTotalKB = 1024
	}
	return caps
}

