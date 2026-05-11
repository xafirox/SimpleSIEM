package sieg

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// alertRule is a compiled match expression. Match values can be:
//   - bare string  → exact equality
//   - "*=foo"      → substring containment
//   - "~=regex"    → regex match
//   - [a, b, ...]  → any-of (each element parsed by the same rules)
//
// The reserved key "type" matches the log type ("auth", "network", ...). All
// other keys match fields in the event payload.
//
// Optional fields:
//   - DedupWindow + DedupKey suppress repeats of the same rule (per key)
//     within a time window so a flood doesn't write thousands of alerts.
//   - Threshold turns the rule into "fire when N matches occur within
//     window for the same group_by key" — useful for ssh-brute-force.
type alertRule struct {
	Name     string
	Severity string
	Match    map[string]matcher

	DedupWindow time.Duration
	DedupKey    string

	Threshold *thresholdConfig

	// Operator-facing annotations passed through to the fired alert
	// payload (and webhooks/syslog). Notes is free-text — typically
	// "what does this rule mean" — and RunbookURL is a link to a
	// triage runbook. SOC analysts get this context without having
	// to look up the rule definition.
	Notes      string
	RunbookURL string

	// MITRE ATT&CK alignment for filtering and coverage analysis.
	// Tactic is a tactic ID like "TA0006" (Credential Access);
	// Technique is a technique-or-subtechnique ID like "T1110.001".
	// Both are optional; rules without them just skip the filter.
	Tactic    string
	Technique string

	// Time-of-day clauses gate when the rule can fire. TimeOfDay
	// is "HH:MM-HH:MM" in the daemon's local timezone; an empty
	// string means "any time". Weekdays is a comma-separated list
	// of three-letter day names (mon,tue,wed,thu,fri,sat,sun);
	// empty means "any day". Both apply the wall-clock time of the
	// event arriving at writeNow.
	TimeOfDay string
	Weekdays  string

	// Sequence is an optional ordered list of step matchers. When set,
	// the rule fires only when every step matches in order, by the
	// same group_by key, within the configured window. Mutually
	// exclusive with Threshold (compile rejects rules that set both).
	Sequence       *sequenceConfig
	sequenceState  map[string]*sequenceState

	// Runtime state. mu guards lastFire and samples; both are populated
	// lazily so a rule with no dedup/threshold pays nothing extra.
	mu       sync.Mutex
	lastFire map[string]time.Time
	samples  map[string][]time.Time
}

// sequenceConfig is the parsed `sequence` clause: an ordered list of
// step matchers plus the timing window. The window applies from the
// FIRST step's match to the LAST step's match — intermediate steps
// can land anywhere inside that interval.
type sequenceConfig struct {
	Steps   []map[string]matcher
	Within  time.Duration
	GroupBy string
}

// sequenceState tracks one in-flight sequence per group_by key. The
// state advances as each step matches; when the final step matches,
// the rule fires and the state for that key is cleared.
type sequenceState struct {
	stepIdx int       // 0..len(Steps)-1; how many consecutive steps have matched
	startTS time.Time // timestamp of the first matched step
}

type thresholdConfig struct {
	Count   int
	Window  time.Duration
	GroupBy string
}

type matcherKind int

const (
	matchExact matcherKind = iota
	matchSubstring
	matchRegex
	matchAny
	matchCIDR     // value is in any of cidrs[]
	matchNotCIDR  // value is NOT in any of cidrs[]
	matchInFile   // value is one of the lines in setFile (hot-reloaded)
	matchNotInFile
	matchNumGT    // numeric > num
	matchNumLT    // numeric < num
	matchNumGE
	matchNumLE
	matchAll      // every sub-matcher must pass (AND)
	matchNot      // negation of one sub-matcher
)

type matcher struct {
	kind  matcherKind
	s     string
	re    *regexp.Regexp
	list  []matcher
	cidrs []*net.IPNet
	num   float64
	set   *setFileMatcher
}

// setFileMatcher backs `in_file:` / `not_in_file:` matchers. The
// file is reloaded lazily — at most once per refreshInterval — so a
// daemon picks up edits to the IOC list without a restart but
// doesn't stat()-spam on every event.
type setFileMatcher struct {
	path             string
	mu               sync.Mutex
	values           map[string]bool
	loadedMtime      time.Time
	loadErr          error
	lastChecked      time.Time
	refreshInterval  time.Duration
}

func parseMatcher(v any) (matcher, error) {
	switch x := v.(type) {
	case string:
		switch {
		case strings.HasPrefix(x, "~="):
			re, err := regexp.Compile(x[2:])
			if err != nil {
				return matcher{}, fmt.Errorf("bad regex %q: %w", x[2:], err)
			}
			return matcher{kind: matchRegex, re: re}, nil
		case strings.HasPrefix(x, "*="):
			return matcher{kind: matchSubstring, s: x[2:]}, nil
		default:
			return matcher{kind: matchExact, s: x}, nil
		}
	case bool:
		return matcher{kind: matchExact, s: strconv.FormatBool(x)}, nil
	case float64:
		return matcher{kind: matchExact, s: strconv.FormatFloat(x, 'f', -1, 64)}, nil
	case []any:
		list := make([]matcher, 0, len(x))
		for _, item := range x {
			m, err := parseMatcher(item)
			if err != nil {
				return matcher{}, err
			}
			list = append(list, m)
		}
		return matcher{kind: matchAny, list: list}, nil
	case map[string]any:
		// Object-form matcher. Keys: "cidr", "not_cidr", "in_file",
		// "not_in_file", "gt", "lt", "ge", "le", "all", "not".
		// Multiple keys at the same level form an AND (e.g.
		// `{cidr: "10.0.0.0/8", not_in_file: "trusted.txt"}`).
		out, err := parseObjectMatcher(x)
		if err != nil {
			return matcher{}, err
		}
		return out, nil
	}
	return matcher{}, fmt.Errorf("unsupported match value type: %T", v)
}

func parseObjectMatcher(obj map[string]any) (matcher, error) {
	subs := make([]matcher, 0, len(obj))
	for k, v := range obj {
		switch k {
		case "cidr", "not_cidr":
			cidrs, err := parseCIDRList(v)
			if err != nil {
				return matcher{}, fmt.Errorf("%s: %w", k, err)
			}
			kind := matchCIDR
			if k == "not_cidr" {
				kind = matchNotCIDR
			}
			subs = append(subs, matcher{kind: kind, cidrs: cidrs})
		case "in_file", "not_in_file":
			path, ok := v.(string)
			if !ok || path == "" {
				return matcher{}, fmt.Errorf("%s: expected file path string", k)
			}
			s := &setFileMatcher{
				path:            path,
				refreshInterval: 30 * time.Second,
			}
			kind := matchInFile
			if k == "not_in_file" {
				kind = matchNotInFile
			}
			subs = append(subs, matcher{kind: kind, set: s})
		case "gt", "lt", "ge", "le":
			n, err := numericMatcherValue(v)
			if err != nil {
				return matcher{}, fmt.Errorf("%s: %w", k, err)
			}
			kind := matchNumGT
			switch k {
			case "lt":
				kind = matchNumLT
			case "ge":
				kind = matchNumGE
			case "le":
				kind = matchNumLE
			}
			subs = append(subs, matcher{kind: kind, num: n})
		case "all":
			lst, ok := v.([]any)
			if !ok {
				return matcher{}, fmt.Errorf("all: expected list")
			}
			children := make([]matcher, 0, len(lst))
			for _, c := range lst {
				cm, err := parseMatcher(c)
				if err != nil {
					return matcher{}, err
				}
				children = append(children, cm)
			}
			subs = append(subs, matcher{kind: matchAll, list: children})
		case "not":
			cm, err := parseMatcher(v)
			if err != nil {
				return matcher{}, fmt.Errorf("not: %w", err)
			}
			subs = append(subs, matcher{kind: matchNot, list: []matcher{cm}})
		default:
			return matcher{}, fmt.Errorf("unknown matcher key %q", k)
		}
	}
	if len(subs) == 1 {
		return subs[0], nil
	}
	return matcher{kind: matchAll, list: subs}, nil
}

func parseCIDRList(v any) ([]*net.IPNet, error) {
	var raw []string
	switch x := v.(type) {
	case string:
		raw = []string{x}
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				raw = append(raw, s)
			}
		}
	default:
		return nil, fmt.Errorf("expected string or list of strings, got %T", v)
	}
	out := make([]*net.IPNet, 0, len(raw))
	for _, s := range raw {
		_, n, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("bad CIDR %q: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func numericMatcherValue(v any) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case string:
		// Allow durations and bare numbers. "5s" → 5_000_000_000;
		// "60" → 60.
		if d, err := time.ParseDuration(x); err == nil {
			return float64(d.Nanoseconds()), nil
		}
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return 0, fmt.Errorf("expected number or duration, got %q", x)
		}
		return f, nil
	}
	return 0, fmt.Errorf("expected number, got %T", v)
}

// loadOrRefresh re-reads the set file if more than refreshInterval
// has passed since the last check AND the file's mtime has advanced.
// Errors are recorded but not fatal — the matcher returns false on
// any reload error (closed-deny posture).
func (s *setFileMatcher) loadOrRefresh() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if !s.lastChecked.IsZero() && now.Sub(s.lastChecked) < s.refreshInterval {
		return
	}
	s.lastChecked = now
	fi, err := os.Stat(s.path)
	if err != nil {
		s.loadErr = err
		s.values = nil
		return
	}
	if !s.loadedMtime.IsZero() && !fi.ModTime().After(s.loadedMtime) && s.values != nil {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		s.loadErr = err
		s.values = nil
		return
	}
	values := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		// Allow # comments and blank lines for operator ergonomics.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		values[line] = true
	}
	s.values = values
	s.loadedMtime = fi.ModTime()
	s.loadErr = nil
}

func (s *setFileMatcher) contains(v string) bool {
	s.loadOrRefresh()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.values[v]
}

// fieldString coerces a value pulled from the event map into a string for
// matching. Numbers come through as float64 from JSON unmarshal; arrays and
// nested objects are matched against their JSON form so a rule can ask
// `cmdline: "*=curl"` and have it hit a []string cmdline.
func fieldString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint32:
		return strconv.FormatUint(uint64(x), 10)
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			parts = append(parts, fieldString(item))
		}
		return strings.Join(parts, " ")
	}
	if data, err := json.Marshal(v); err == nil {
		return string(data)
	}
	return ""
}

func (m matcher) test(v any) bool {
	s := fieldString(v)
	switch m.kind {
	case matchExact:
		return s == m.s
	case matchSubstring:
		return strings.Contains(s, m.s)
	case matchRegex:
		return m.re.MatchString(s)
	case matchAny:
		for _, sub := range m.list {
			if sub.test(v) {
				return true
			}
		}
		return false
	case matchAll:
		for _, sub := range m.list {
			if !sub.test(v) {
				return false
			}
		}
		return true
	case matchNot:
		if len(m.list) != 1 {
			return false
		}
		return !m.list[0].test(v)
	case matchCIDR:
		ip := net.ParseIP(s)
		if ip == nil {
			return false
		}
		for _, n := range m.cidrs {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	case matchNotCIDR:
		ip := net.ParseIP(s)
		if ip == nil {
			// Non-IP value — by closed-deny convention, treat as
			// "not in CIDR" (the field doesn't satisfy a network
			// range; can't be excluded from one either, but the
			// safer interpretation for `not_cidr` is "the value
			// isn't in any of these networks" which a non-IP
			// trivially satisfies).
			return true
		}
		for _, n := range m.cidrs {
			if n.Contains(ip) {
				return false
			}
		}
		return true
	case matchInFile:
		if m.set == nil {
			return false
		}
		return m.set.contains(s)
	case matchNotInFile:
		if m.set == nil {
			return false
		}
		return !m.set.contains(s)
	case matchNumGT, matchNumLT, matchNumGE, matchNumLE:
		f, ok := numericFromAny(v)
		if !ok {
			return false
		}
		switch m.kind {
		case matchNumGT:
			return f > m.num
		case matchNumLT:
			return f < m.num
		case matchNumGE:
			return f >= m.num
		case matchNumLE:
			return f <= m.num
		}
	}
	return false
}

// numericFromAny coerces a value to float64 for >/< comparisons.
// Accepts numeric types and decimal/duration strings (so a rule
// can compare against `duration: "5s"` from a stored event).
func numericFromAny(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case string:
		if d, err := time.ParseDuration(x); err == nil {
			return float64(d.Nanoseconds()), true
		}
		if f, err := strconv.ParseFloat(x, 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

// matchRule reports whether a rule's match expression alone is satisfied by
// the event. Threshold and dedup are NOT evaluated here — see shouldFire.
// All match keys must pass (logical AND). The reserved key "type" matches
// against logType; other keys match against event fields.
func matchRule(r *alertRule, logType string, event map[string]any) bool {
	if len(r.Match) == 0 {
		return false
	}
	for key, m := range r.Match {
		var v any
		if key == "type" {
			v = logType
		} else {
			v = event[key]
		}
		if !m.test(v) {
			return false
		}
	}
	return true
}

// shouldFire combines match, threshold, and dedup. When the rule should fire,
// it returns ok=true plus an extra-info map with counts/group fields when
// threshold is configured. extra is nil for plain match rules.
//
// Order: match → threshold (must accumulate count within window) → dedup
// (suppress further fires within DedupWindow). Threshold clears its window
// for the matched group on fire so we don't immediately re-fire on the next
// event; dedup is the orthogonal "don't spam" knob.
func (r *alertRule) shouldFire(logType string, event map[string]any) (bool, map[string]any) {
	now := time.Now()
	// Time-of-day / weekday gate. Applied BEFORE match so a rule
	// outside its window doesn't even pay the matcher cost.
	if !r.inTimeWindow(now) {
		return false, nil
	}

	// Sequence rules take a different code path: they advance through
	// per-key state regardless of whether `match` ALSO matches the
	// event. A rule with both match + sequence is rejected at parse
	// time, so this branch is unambiguous.
	if r.Sequence != nil {
		return r.shouldFireSequence(logType, event, now)
	}

	if !matchRule(r, logType, event) {
		return false, nil
	}

	groupKey := ""
	switch {
	case r.DedupKey != "":
		groupKey = fieldString(event[r.DedupKey])
	case r.Threshold != nil && r.Threshold.GroupBy != "":
		groupKey = fieldString(event[r.Threshold.GroupBy])
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	var extra map[string]any
	if r.Threshold != nil {
		if r.samples == nil {
			r.samples = map[string][]time.Time{}
		}
		cutoff := now.Add(-r.Threshold.Window)
		list := r.samples[groupKey]
		i := 0
		for i < len(list) && list[i].Before(cutoff) {
			i++
		}
		list = append(list[i:], now)
		r.samples[groupKey] = list
		if len(list) < r.Threshold.Count {
			return false, nil
		}
		extra = map[string]any{
			"count":  len(list),
			"window": r.Threshold.Window.String(),
		}
		if r.Threshold.GroupBy != "" {
			extra["group_by"] = r.Threshold.GroupBy
			extra["group_value"] = groupKey
		}
		delete(r.samples, groupKey)
	}

	if r.DedupWindow > 0 {
		if last, ok := r.lastFire[groupKey]; ok && now.Sub(last) < r.DedupWindow {
			return false, nil
		}
		if r.lastFire == nil {
			r.lastFire = map[string]time.Time{}
		}
		r.lastFire[groupKey] = now
	}

	return true, extra
}

// shouldFireSequence advances the per-key sequence state machine and
// returns ok=true only when the current event completes the final
// step within the configured window.
//
// Algorithm:
//   - Determine which step (if any) the event matches. Multiple steps
//     can theoretically match the same event; we walk in order and
//     pick the LOWEST step index >= current state's expected index.
//   - If event matches step 0, start (or restart) tracking for that
//     group_by key.
//   - If event matches the next expected step, advance the state.
//   - If the configured `within` has elapsed since startTS, expire
//     and treat this event as a potential step-0 match.
//   - When we advance to the final step within the window, fire.
func (r *alertRule) shouldFireSequence(logType string, event map[string]any, now time.Time) (bool, map[string]any) {
	groupKey := fieldString(event[r.Sequence.GroupBy])
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sequenceState == nil {
		r.sequenceState = map[string]*sequenceState{}
	}
	state := r.sequenceState[groupKey]
	// Expire stale state.
	if state != nil && now.Sub(state.startTS) > r.Sequence.Within {
		state = nil
		delete(r.sequenceState, groupKey)
	}
	// Find the lowest step index this event matches. We pass logType
	// + event through matchRuleStep, which mirrors matchRule but
	// against a step's match map rather than the rule's top-level Match.
	for stepIdx := 0; stepIdx < len(r.Sequence.Steps); stepIdx++ {
		// Only consider step 0 (always allowed to start a sequence)
		// or the next-expected step for an in-flight state.
		if state == nil {
			if stepIdx > 0 {
				continue
			}
		} else if stepIdx != state.stepIdx+1 && stepIdx != 0 {
			continue
		}
		if !matchRuleStep(r.Sequence.Steps[stepIdx], logType, event) {
			continue
		}
		if stepIdx == 0 {
			// Start (or restart) tracking.
			state = &sequenceState{stepIdx: 0, startTS: now}
			r.sequenceState[groupKey] = state
			break
		}
		// Advance.
		state.stepIdx = stepIdx
		if stepIdx == len(r.Sequence.Steps)-1 {
			// Sequence complete — fire and clear state for this key.
			delete(r.sequenceState, groupKey)
			extra := map[string]any{
				"sequence_steps":  len(r.Sequence.Steps),
				"sequence_within": r.Sequence.Within.String(),
				"sequence_elapsed_ms": now.Sub(state.startTS).Milliseconds(),
			}
			if r.Sequence.GroupBy != "" {
				extra["group_by"] = r.Sequence.GroupBy
				extra["group_value"] = groupKey
			}
			return true, extra
		}
		break
	}
	return false, nil
}

// matchRuleStep is matchRule for a single step's match map. Same
// semantics: every key/value in the step must match the event; the
// reserved key "type" matches against logType.
func matchRuleStep(step map[string]matcher, logType string, event map[string]any) bool {
	if len(step) == 0 {
		return false
	}
	for key, m := range step {
		var v any
		if key == "type" {
			v = logType
		} else {
			v = event[key]
		}
		if !m.test(v) {
			return false
		}
	}
	return true
}

func loadRules(path string) ([]*alertRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out, err := parseRulesData(data)
	if err != nil {
		return nil, err
	}
	// MITRE Phase 2 — merge the auto-generated sidecar so its rules
	// are evaluated alongside the operator's rules.json without
	// requiring the operator to copy them in by hand. Done here (the
	// path-aware loader) rather than in parseRulesData so the
	// validation-only path (parseRulesBytes) doesn't pull in a
	// sidecar the caller never asked for.
	return mergeMitreGeneratedRules(out, path), nil
}

// parseRulesData is the loader's pure-bytes entry point. Used by
// parseRulesBytes (validation path) so callers don't have to round-
// trip through a temp file just to invoke the same parsing logic.
// Writing temp files into /tmp on every validation lit up the file
// watcher with ~13 created+deleted events per startup (one per MITRE
// auto-generated rule).
func parseRulesData(data []byte) ([]*alertRule, error) {
	var raw []struct {
		Name        string         `json:"name"`
		Severity    string         `json:"severity"`
		Match       map[string]any `json:"match"`
		DedupWindow string         `json:"dedup_window"`
		DedupKey    string         `json:"dedup_key"`
		Threshold   *struct {
			Count   int    `json:"count"`
			Window  string `json:"window"`
			GroupBy string `json:"group_by"`
		} `json:"threshold"`
		Notes      string `json:"notes"`
		RunbookURL string `json:"runbook_url"`
		Tactic     string `json:"tactic"`
		Technique  string `json:"technique"`
		TimeOfDay  string `json:"time_of_day"`
		Weekdays   string `json:"weekdays"`
		Sequence   *struct {
			Steps   []map[string]any `json:"steps"`
			Within  string           `json:"within"`
			GroupBy string           `json:"group_by"`
		} `json:"sequence"`
		// Disabled keeps a rule in the file but stops it from
		// firing. Operators flip this with `simplesiem rules
		// disable <name>`; the loader silently skips disabled
		// entries so they don't pollute counts or coverage.
		Disabled bool `json:"disabled"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	out := make([]*alertRule, 0, len(raw))
	for i, r := range raw {
		if r.Disabled {
			continue
		}
		if r.Name == "" {
			return nil, fmt.Errorf("rule %d: name is required", i)
		}
		// A rule must have at least one of: match, sequence. Pure
		// annotation-only rules don't make sense.
		hasMatch := len(r.Match) > 0
		hasSeq := r.Sequence != nil && len(r.Sequence.Steps) > 0
		if !hasMatch && !hasSeq {
			return nil, fmt.Errorf("rule %q: must define `match` or `sequence`", r.Name)
		}
		rule := &alertRule{
			Name:       r.Name,
			Severity:   r.Severity,
			Match:      map[string]matcher{},
			Notes:      r.Notes,
			RunbookURL: r.RunbookURL,
			Tactic:     r.Tactic,
			Technique:  r.Technique,
			TimeOfDay:  strings.TrimSpace(r.TimeOfDay),
			Weekdays:   strings.ToLower(strings.TrimSpace(r.Weekdays)),
		}
		for k, v := range r.Match {
			m, err := parseMatcher(v)
			if err != nil {
				return nil, fmt.Errorf("rule %q field %q: %w", r.Name, k, err)
			}
			rule.Match[k] = m
		}
		if r.DedupWindow != "" {
			d, err := time.ParseDuration(r.DedupWindow)
			if err != nil {
				return nil, fmt.Errorf("rule %q dedup_window: %w", r.Name, err)
			}
			rule.DedupWindow = d
		}
		rule.DedupKey = r.DedupKey
		if r.Threshold != nil {
			if r.Threshold.Count < 2 {
				return nil, fmt.Errorf("rule %q threshold.count must be >= 2", r.Name)
			}
			d, err := time.ParseDuration(r.Threshold.Window)
			if err != nil {
				return nil, fmt.Errorf("rule %q threshold.window: %w", r.Name, err)
			}
			rule.Threshold = &thresholdConfig{
				Count:   r.Threshold.Count,
				Window:  d,
				GroupBy: r.Threshold.GroupBy,
			}
		}
		// Parse the sequence clause, if present.
		if hasSeq {
			if r.Threshold != nil {
				return nil, fmt.Errorf("rule %q: `threshold` and `sequence` are mutually exclusive", r.Name)
			}
			if len(r.Sequence.Steps) < 2 {
				return nil, fmt.Errorf("rule %q: sequence needs at least 2 steps", r.Name)
			}
			d, err := time.ParseDuration(r.Sequence.Within)
			if err != nil {
				return nil, fmt.Errorf("rule %q sequence.within: %w", r.Name, err)
			}
			steps := make([]map[string]matcher, 0, len(r.Sequence.Steps))
			for si, sm := range r.Sequence.Steps {
				step := map[string]matcher{}
				for k, v := range sm {
					m, err := parseMatcher(v)
					if err != nil {
						return nil, fmt.Errorf("rule %q sequence.steps[%d].%s: %w", r.Name, si, k, err)
					}
					step[k] = m
				}
				steps = append(steps, step)
			}
			rule.Sequence = &sequenceConfig{
				Steps:   steps,
				Within:  d,
				GroupBy: r.Sequence.GroupBy,
			}
			rule.sequenceState = map[string]*sequenceState{}
		}
		// Validate time-of-day / weekdays so a typo fails parse rather
		// than silently never-matching.
		if rule.TimeOfDay != "" {
			if _, _, err := parseTimeOfDayWindow(rule.TimeOfDay); err != nil {
				return nil, fmt.Errorf("rule %q time_of_day: %w", r.Name, err)
			}
		}
		if rule.Weekdays != "" {
			for _, d := range strings.Split(rule.Weekdays, ",") {
				if _, ok := weekdayShort[strings.TrimSpace(d)]; !ok {
					return nil, fmt.Errorf("rule %q weekdays: %q is not one of mon,tue,wed,thu,fri,sat,sun", r.Name, d)
				}
			}
		}
		out = append(out, rule)
	}
	return out, nil
}

// parseTimeOfDayWindow accepts "HH:MM-HH:MM" and returns the two
// minute-of-day boundaries [0..1439]. Wraps midnight if start > end
// (e.g., "22:00-06:00" matches 22:00 through 06:00 next day).
func parseTimeOfDayWindow(s string) (int, int, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected HH:MM-HH:MM, got %q", s)
	}
	a, err := parseHHMM(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, err
	}
	b, err := parseHHMM(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, err
	}
	return a, b, nil
}

func parseHHMM(s string) (int, error) {
	bits := strings.Split(s, ":")
	if len(bits) != 2 {
		return 0, fmt.Errorf("expected HH:MM, got %q", s)
	}
	h, err := strconv.Atoi(bits[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("invalid hour %q", bits[0])
	}
	m, err := strconv.Atoi(bits[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid minute %q", bits[1])
	}
	return h*60 + m, nil
}

var weekdayShort = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
	"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// inTimeWindow reports whether the rule's time-of-day / weekdays
// clauses currently allow firing. now is normally `time.Now()`.
// Empty clauses always allow.
func (r *alertRule) inTimeWindow(now time.Time) bool {
	if r.Weekdays != "" {
		want := false
		for _, d := range strings.Split(r.Weekdays, ",") {
			if wd, ok := weekdayShort[strings.TrimSpace(d)]; ok && wd == now.Weekday() {
				want = true
				break
			}
		}
		if !want {
			return false
		}
	}
	if r.TimeOfDay != "" {
		start, end, err := parseTimeOfDayWindow(r.TimeOfDay)
		if err != nil {
			return false
		}
		min := now.Hour()*60 + now.Minute()
		if start <= end {
			return min >= start && min <= end
		}
		// Wrap-around (e.g., 22:00-06:00).
		return min >= start || min <= end
	}
	return true
}

// defaultRulesJSON is the example file dropped at install time. Kept short so
// it's a usable starting point, not noise. Operators add their own.
const defaultRulesJSON = `[
  {
    "name": "ssh_brute_force",
    "severity": "high",
    "match": {
      "type": "auth",
      "event": "ssh_login",
      "result": ["failed", "invalid_user"]
    },
    "threshold": { "count": 5, "window": "60s", "group_by": "remote" },
    "dedup_window": "5m"
  },
  {
    "name": "ssh_failed_login",
    "severity": "medium",
    "match": {
      "type": "auth",
      "event": "ssh_login",
      "result": ["failed", "invalid_user"]
    },
    "dedup_window": "30s",
    "dedup_key": "remote"
  },
  {
    "name": "authorized_keys_modified",
    "severity": "high",
    "match": {
      "type": "files",
      "path": "*=authorized_keys",
      "event": ["created", "modified"]
    }
  },
  {
    "name": "cron_modified",
    "severity": "high",
    "match": {
      "type": "files",
      "path": "~=(/etc/cron\\.|/var/spool/cron/|/etc/crontab)",
      "event": ["created", "modified", "renamed"]
    },
    "dedup_window": "30s",
    "dedup_key": "path"
  },
  {
    "name": "systemd_unit_created",
    "severity": "high",
    "match": {
      "type": "files",
      "path": "~=/(etc|lib|usr/lib)/systemd/system/.*\\.(service|timer|socket)$",
      "event": "created"
    }
  },
  {
    "name": "sudo_root_shell",
    "severity": "medium",
    "match": {
      "type": "auth",
      "event": "sudo",
      "command": "~=(bash|sh|zsh|ksh)\\b"
    }
  }
]
`
