package sieg

import (
	"strings"
	"time"
)

// #1 — Alert enrichment from threat intel.
//
// When a fired alert's `original` event contains a field whose value
// matches a threat-intel indicator set, attach the indicator's
// metadata (confidence, threat_type, first_seen, reference) to the
// alert payload. SOC analysts see context inline instead of pivoting
// out to look up the indicator.

// fieldsToCheck lists the event fields we'll probe against threat-
// intel sets. Each maps to a TI indicator kind. Order doesn't matter;
// the first hit wins (an alert can carry only one enrichment block).
var alertEnrichmentFieldKinds = []struct {
	field string
	kind  string
}{
	{"remote_host", "ip:port"},
	{"remote_host", "domain"},
	{"remote", "ip:port"},
	{"remote", "domain"},
	{"sha256", "sha256"},
	{"hash", "sha256"},
}

// enrichAlertFromThreatIntel decorates the alert payload in place. No-op
// when no TI set is loaded or no field matches. Best-effort — never
// blocks the alertHooks fanout. Returns true if enrichment was applied.
func enrichAlertFromThreatIntel(alert map[string]any, mgr *threatIntelManager) bool {
	if alert == nil || mgr == nil {
		return false
	}
	orig, _ := alert["original"].(map[string]any)
	if orig == nil {
		return false
	}
	mgr.mu.RLock()
	feedNames := make([]string, 0, len(mgr.sets))
	for name := range mgr.sets {
		feedNames = append(feedNames, name)
	}
	mgr.mu.RUnlock()
	for _, fk := range alertEnrichmentFieldKinds {
		raw := strFieldFromAny(orig[fk.field])
		if raw == "" {
			continue
		}
		// For ip:port we accept either bare IP or IP:port. Strip the
		// port if present and look up by both forms — TI feeds vary.
		candidates := []string{raw}
		if fk.kind == "ip:port" {
			if i := strings.IndexByte(raw, ':'); i > 0 {
				candidates = append(candidates, raw[:i])
			}
		}
		for _, feed := range feedNames {
			for _, val := range candidates {
				ent, ok := mgr.Match(feed, fk.kind, val)
				if !ok {
					continue
				}
				alert["threatintel"] = map[string]any{
					"matched_field":  fk.field,
					"matched_value":  val,
					"feed":           feed,
					"kind":           fk.kind,
					"confidence":     ent.Confidence,
					"threat_type":    ent.ThreatType,
					"first_seen":     ent.FirstSeen.Format(time.RFC3339),
					"reference":      ent.Reference,
				}
				return true
			}
		}
	}
	return false
}
