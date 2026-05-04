package sieg

import (
	"fmt"
	"strings"
)

// triage_filters: helpers for the --field structured filter and --explain
// rule-attribution display. Kept in one place because both depend on the
// alert/rules engine's matcher and are command-scoped (only used by the
// triage command, set at entry time).

// triageExplain is set when --explain is passed. Read by printTriage to
// decide whether to load rules and annotate alert rows.
var triageExplain = false

// triageCfgPath is the config path the user passed via --config so
// loadRulesForExplain can find rules.json.
var triageCfgPath = ""

// triageFieldFilters is the compiled list of --field filters. Empty when
// none were supplied.
var triageFieldFilters []fieldFilter

type fieldFilter struct {
	key string
	m   matcher
}

// fieldFilterList implements flag.Value. Each --field flag adds one entry.
type fieldFilterList []string

func (f *fieldFilterList) String() string { return strings.Join(*f, ",") }
func (f *fieldFilterList) Set(s string) error {
	if !strings.Contains(s, "=") {
		return fmt.Errorf("expected key=value (got %q)", s)
	}
	*f = append(*f, s)
	return nil
}

// compiled converts the raw --field strings into fieldFilters. A spec of the
// form "key=value" parses the value through parseMatcher, so the same
// "*=substring" / "~=regex" prefixes the rule engine accepts work here too.
func (f fieldFilterList) compiled() []fieldFilter {
	out := make([]fieldFilter, 0, len(f))
	for _, s := range f {
		i := strings.Index(s, "=")
		if i < 0 {
			continue
		}
		key := s[:i]
		val := s[i+1:]
		m, err := parseMatcher(val)
		if err != nil {
			fatalf("--field %s: %v", s, err)
		}
		out = append(out, fieldFilter{key: key, m: m})
	}
	return out
}

// passesFieldFilters reports whether an event satisfies all configured
// --field filters. Empty filter list = always passes.
func passesFieldFilters(data map[string]any) bool {
	for _, f := range triageFieldFilters {
		if !f.m.test(data[f.key]) {
			return false
		}
	}
	return true
}

// explainAlert finds which rule fields matched in the original event of an
// alert. Returns a "key=op:value" comma-separated string, or "" if rules
// can't be loaded or the rule isn't found. Best-effort; failures are silent
// because --explain is a debug aid, not a contract.
func explainAlert(alertEvent map[string]any) string {
	if triageCfgPath == "" {
		return ""
	}
	cfg := loadConfig(triageCfgPath)
	if cfg.RulesPath == "" {
		return ""
	}
	rules, err := loadRules(cfg.RulesPath)
	if err != nil {
		return ""
	}
	wantName, _ := alertEvent["rule"].(string)
	mt, _ := alertEvent["matched_type"].(string)
	orig, _ := alertEvent["original"].(map[string]any)
	if wantName == "" || orig == nil {
		return ""
	}
	for _, r := range rules {
		if r.Name != wantName {
			continue
		}
		var hits []string
		for k, m := range r.Match {
			var v any
			if k == "type" {
				v = mt
			} else {
				v = orig[k]
			}
			if m.test(v) {
				hits = append(hits, fmt.Sprintf("%s=%s", k, fieldString(v)))
			}
		}
		return strings.Join(hits, ", ")
	}
	return ""
}
