package sieg

import (
	"context"
	"sync"
)

// alertPipeline wires the SIEM-enhancement alert sinks into the
// existing alertHooks fanout. Sinks run in this order:
//
//   1. #2 suppression check (drops the alert + stops pipeline)
//   2. #1 enrichment from threat intel (decorates alert in-place)
//   3. #1 rule fire stats
//   4. #4 baseline observation (per-host event counter)
//   5. #9 fixture capture
//   6. #6 incident grouping
//
// One pipeline per daemon instance; each per-host Storage gets the
// same hook so every fire flows through the same machinery
// regardless of source host.
type alertPipeline struct {
	suppressionsPath string
	incidents        *incidentGrouper
	fixtureKeep      int
	threatIntel      *threatIntelManager
	baseline         *baselineDetector
}

func newAlertPipeline(cfg Config, logDir string, logger *Storage) *alertPipeline {
	rulesPath := cfg.RulesPath
	if rulesPath == "" {
		rulesPath = defaultConfigPath()
	}
	keep := cfg.RulesExtras.Fixtures.KeepPerRule
	if keep <= 0 {
		keep = 5
	}
	var grouper *incidentGrouper
	if cfg.Incidents.Enabled {
		grouper = newIncidentGrouper(cfg.Incidents, logDir, logger)
	}
	return &alertPipeline{
		suppressionsPath: rulesPath,
		incidents:        grouper,
		fixtureKeep:      keep,
	}
}

// hook is what gets attached via AddAlertHook. See package doc on
// alertPipeline for the sink ordering.
func (p *alertPipeline) hook(alert map[string]any) {
	if p == nil {
		return
	}
	// #2 suppression: if this alert matches an active suppression,
	// stop the pipeline — it stays in the on-disk alerts log for
	// audit but doesn't fan out to webhooks/syslog/incidents.
	list := loadSuppressions(p.suppressionsPath)
	if _, matched := suppressionMatches(list, alert); matched {
		return
	}
	// #1 enrichment: decorate the alert with TI metadata before any
	// downstream sink reads it. Mutation is in-place so subsequent
	// alertHooks (webhook, syslog, metrics) see the enriched payload.
	if p.threatIntel != nil {
		_ = enrichAlertFromThreatIntel(alert, p.threatIntel)
	}
	ruleID := strFieldFromAny(alert["rule"])
	severity := strFieldFromAny(alert["severity"])
	// Pull host from the alert payload, falling back to the original
	// matched event when the rule_match wrapper didn't carry it.
	host := strFieldFromAny(alert["host"])
	if host == "" {
		host = strFieldFromAny(alert["matched_host"])
	}
	if host == "" {
		if orig, ok := alert["original"].(map[string]any); ok {
			host = strFieldFromAny(orig["host"])
		}
	}
	alertID := strFieldFromAny(alert["alert_id"])
	if alertID == "" {
		alertID = strFieldFromAny(alert["@id"])
	}
	if alertID == "" {
		alertID = strFieldFromAny(alert["_hash"])
	}
	recordRuleFire(ruleID, severity, host, alertID)
	if p.baseline != nil && host != "" {
		p.baseline.Observe(host)
	}
	if orig, ok := alert["original"].(map[string]any); ok && ruleID != "" && alertID != "" {
		captureFixture(ruleID, "", alertID, []map[string]any{orig}, "fires", p.fixtureKeep)
	}
	if p.incidents != nil {
		_ = p.incidents.IngestAlert(alert)
	}
}

// startSiemEnhancements is called from each daemon's run loop to spin
// up the SIEM-enhancement background workers. Best-effort: failures
// are logged but don't block daemon startup. The pipeline pointer
// receives the threat-intel + baseline managers so the alert hook
// can use them; nil means the feature is disabled.
func startSiemEnhancements(ctx context.Context, wg *sync.WaitGroup, cfg Config, logger *Storage, pipeline *alertPipeline) *tupleManager {
	rulesPath := cfg.RulesPath
	if rulesPath == "" {
		rulesPath = defaultConfigPath()
	}
	startSuppressionWatcher(ctx, wg, rulesPath, logger)

	if cfg.Mitre.Enabled {
		mgr := newMitreManager(cfg.Mitre, logger)
		mgr.Start(ctx, wg)
	}
	if cfg.ThreatIntel.Enabled {
		tim := newThreatIntelManager(cfg.ThreatIntel, logger)
		tim.Start(ctx, wg)
		if pipeline != nil {
			pipeline.threatIntel = tim
		}
	}
	if cfg.Baseline.Enabled {
		bd := newBaselineDetector(cfg.Baseline, "", logger)
		bd.Start(ctx, wg)
		if pipeline != nil {
			pipeline.baseline = bd
		}
	}
	if cfg.Honey.Enabled {
		hm := newHoneyMonitor(cfg.Honey, logger)
		hm.Start(ctx, wg)
	}
	if cfg.FirstSeen.Enabled {
		return newTupleManager(cfg.FirstSeen, "", logger)
	}
	return nil
}
