package sieg

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Imperative rule builder — stepwise verbs replace hand-edits of
// rules.json. Operators never type JSON; every command is a single
// verb that mutates one field of one rule object in rules.json.
// Drafts start disabled; `rules enable <id>` runs the same parser the
// daemon uses + a required-field audit, and refuses to activate a
// rule that would fail at load time.
//
// All writes go through writeRulesArray, which atomically replaces
// rules.json after running parseRulesBytes against the new content.
// configWatcher / the rule-engine reloader picks up the change within
// ~1 s of the rename landing.

// validSeverities is the canonical set the engine accepts. The CLI
// rejects anything else at `set` time so an operator can't end up with
// a rule that fails enable for a typo two commands later.
var validSeverities = map[string]bool{
	"low": true, "medium": true, "high": true, "critical": true,
}

func runRulesNew(args []string) {
	if len(args) != 1 {
		fatalf("usage: rules new <id>")
	}
	mustAdmin()
	id := args[0]
	if !validRuleID(id) {
		fatalf("rule id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
	}
	path := resolveRulesPath()
	arr, err := loadRulesArray(path)
	if err != nil {
		fatalf("%v", err)
	}
	for _, r := range arr {
		if name, _ := r["name"].(string); name == id {
			fatalf("rule %q already exists; `rules show %s` to inspect, `rules delete %s` to start over", id, id, id)
		}
	}
	arr = append(arr, map[string]any{
		"name":     id,
		"disabled": true,
	})
	if err := writeRulesArrayLoose(path, arr); err != nil {
		fatalf("write rules: %v", err)
	}
	fmt.Printf("rule %q created (disabled). Build it up with `rules set %s ...`, then `rules enable %s`.\n", id, id, id)
}

var ruleIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validRuleID(s string) bool { return ruleIDRe.MatchString(s) }

// writeRulesArrayLoose is writeRulesArray without the parseRulesBytes
// validation step — necessary while a draft is still being assembled
// (a rule with `disabled: true` and no severity set is intentionally
// invalid until enable). The loader silently skips disabled entries
// so an in-progress draft never reaches the runtime engine.
func writeRulesArrayLoose(path string, arr []map[string]any) error {
	body, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return atomicWriteFile(path, body, 0o640)
}

// withRuleEdit loads rules.json, locates the rule by id, runs the
// caller-supplied mutation against the rule's map, then atomically
// writes the result back. Centralises the load/find/save dance so
// every imperative command stays focused on its one field.
func withRuleEdit(id string, mutate func(rule map[string]any)) {
	mustAdmin()
	path := resolveRulesPath()
	arr, err := loadRulesArray(path)
	if err != nil {
		fatalf("%v", err)
	}
	found := false
	for _, r := range arr {
		if name, _ := r["name"].(string); name == id {
			mutate(r)
			found = true
			break
		}
	}
	if !found {
		fatalf("no rule named %q (run `rules new %s` first)", id, id)
	}
	if err := writeRulesArrayLoose(path, arr); err != nil {
		fatalf("write rules: %v", err)
	}
}

func runRulesSet(args []string) {
	if len(args) < 3 {
		fatalf("usage: rules set <id> <field> <value>\n\nfields: severity dedup-window dedup-key notes runbook-url tactic technique time-of-day weekdays")
	}
	id, field := args[0], args[1]
	rest := strings.Join(args[2:], " ")
	switch field {
	case "severity":
		v := strings.ToLower(rest)
		if !validSeverities[v] {
			fatalf("severity must be one of: low, medium, high, critical")
		}
		withRuleEdit(id, func(r map[string]any) { r["severity"] = v })
		fmt.Printf("set %s.severity = %s\n", id, v)
	case "dedup-window":
		if _, err := parseDurationSeconds(rest); err != nil {
			fatalf("dedup-window must be a duration (e.g. 5m, 30s)")
		}
		withRuleEdit(id, func(r map[string]any) { r["dedup_window"] = rest })
		fmt.Printf("set %s.dedup_window = %s\n", id, rest)
	case "dedup-key":
		withRuleEdit(id, func(r map[string]any) { r["dedup_key"] = rest })
		fmt.Printf("set %s.dedup_key = %s\n", id, rest)
	case "notes":
		withRuleEdit(id, func(r map[string]any) { r["notes"] = rest })
		fmt.Printf("set %s.notes\n", id)
	case "runbook-url":
		if !strings.HasPrefix(rest, "http://") && !strings.HasPrefix(rest, "https://") {
			fatalf("runbook-url must start with http:// or https://")
		}
		withRuleEdit(id, func(r map[string]any) { r["runbook_url"] = rest })
		fmt.Printf("set %s.runbook_url = %s\n", id, rest)
	case "tactic":
		if !regexp.MustCompile(`^TA[0-9]{4}$`).MatchString(rest) {
			fatalf("tactic must be a MITRE tactic ID like TA0006")
		}
		withRuleEdit(id, func(r map[string]any) { r["tactic"] = rest })
		fmt.Printf("set %s.tactic = %s\n", id, rest)
	case "technique":
		if !regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`).MatchString(rest) {
			fatalf("technique must be a MITRE technique ID like T1110 or T1110.001")
		}
		withRuleEdit(id, func(r map[string]any) { r["technique"] = rest })
		fmt.Printf("set %s.technique = %s\n", id, rest)
	case "time-of-day":
		if !regexp.MustCompile(`^[0-2][0-9]:[0-5][0-9]-[0-2][0-9]:[0-5][0-9]$`).MatchString(rest) {
			fatalf("time-of-day must be HH:MM-HH:MM (e.g. 22:00-06:00)")
		}
		withRuleEdit(id, func(r map[string]any) { r["time_of_day"] = rest })
		fmt.Printf("set %s.time_of_day = %s\n", id, rest)
	case "weekdays":
		valid := map[string]bool{"mon": true, "tue": true, "wed": true, "thu": true, "fri": true, "sat": true, "sun": true}
		for _, d := range strings.Split(strings.ToLower(rest), ",") {
			if !valid[strings.TrimSpace(d)] {
				fatalf("weekdays must be a comma-separated list of mon,tue,wed,thu,fri,sat,sun")
			}
		}
		withRuleEdit(id, func(r map[string]any) { r["weekdays"] = strings.ToLower(rest) })
		fmt.Printf("set %s.weekdays = %s\n", id, strings.ToLower(rest))
	default:
		fatalf("unknown field %q. valid: severity dedup-window dedup-key notes runbook-url tactic technique time-of-day weekdays", field)
	}
}

func runRulesUnset(args []string) {
	if len(args) != 2 {
		fatalf("usage: rules unset <id> <field>")
	}
	field := args[1]
	jsonField := map[string]string{
		"severity":     "severity",
		"dedup-window": "dedup_window",
		"dedup-key":    "dedup_key",
		"notes":        "notes",
		"runbook-url":  "runbook_url",
		"tactic":       "tactic",
		"technique":    "technique",
		"time-of-day":  "time_of_day",
		"weekdays":     "weekdays",
	}[field]
	if jsonField == "" {
		fatalf("unknown field %q", field)
	}
	withRuleEdit(args[0], func(r map[string]any) { delete(r, jsonField) })
	fmt.Printf("unset %s.%s\n", args[0], jsonField)
}

// runRulesMatch handles `rules match <id> <key> [opts] <value>` —
// equality by default, regex / substr / cidr / in-file / gt-lt-ge-le /
// any-of via flags. The flags are mutually exclusive; passing more
// than one is a hard error so the operator never gets a silently-
// dropped operator.
func runRulesMatch(args []string) {
	if len(args) < 2 {
		fatalf("usage: rules match <id> <key> [--regex|--substr|--cidr|--not-cidr|--in-file|--not-in-file|--gt N|--lt N|--ge N|--le N|--any v1,v2,v3] <value>")
	}
	id, key := args[0], args[1]
	rest := args[2:]
	value, op, err := parseMatchOperator(rest)
	if err != nil {
		fatalf("%v", err)
	}
	withRuleEdit(id, func(r map[string]any) {
		m, ok := r["match"].(map[string]any)
		if !ok {
			m = map[string]any{}
			r["match"] = m
		}
		m[key] = value
	})
	fmt.Printf("matched %s.%s (%s)\n", id, key, op)
}

func runRulesUnmatch(args []string) {
	if len(args) != 2 {
		fatalf("usage: rules unmatch <id> <key>")
	}
	id, key := args[0], args[1]
	withRuleEdit(id, func(r map[string]any) {
		if m, ok := r["match"].(map[string]any); ok {
			delete(m, key)
			if len(m) == 0 {
				delete(r, "match")
			}
		}
	})
	fmt.Printf("unmatched %s.%s\n", id, key)
}

// parseMatchOperator interprets the operator flags + value at the tail
// of `rules match` / `rules sequence-step`. Returns the JSON shape the
// rule loader expects + a human label for the printed confirmation.
//
// Recognised forms:
//
//	(no flag) <value>       equality
//	--regex <pattern>       ~=<pattern>
//	--substr <s>            *=<s>
//	--cidr <range>          {cidr: range}
//	--not-cidr <range>      {not_cidr: range}
//	--in-file <path>        {in_file: path}
//	--not-in-file <path>    {not_in_file: path}
//	--gt N                  {gt: N}    (also --lt --ge --le)
//	--any v1,v2,v3          any-of array
func parseMatchOperator(args []string) (any, string, error) {
	if len(args) == 0 {
		return nil, "", fmt.Errorf("missing value")
	}
	first := args[0]
	if !strings.HasPrefix(first, "--") {
		// Plain equality. Support multi-word values by joining the rest.
		return strings.Join(args, " "), "equality", nil
	}
	if len(args) < 2 {
		return nil, "", fmt.Errorf("operator %s requires a value", first)
	}
	value := strings.Join(args[1:], " ")
	switch first {
	case "--regex":
		if _, err := regexp.Compile(value); err != nil {
			return nil, "", fmt.Errorf("invalid regex: %w", err)
		}
		return "~=" + value, "regex", nil
	case "--substr":
		return "*=" + value, "substring", nil
	case "--cidr":
		if _, _, err := net.ParseCIDR(value); err != nil {
			return nil, "", fmt.Errorf("invalid CIDR: %w", err)
		}
		return map[string]any{"cidr": value}, "cidr", nil
	case "--not-cidr":
		if _, _, err := net.ParseCIDR(value); err != nil {
			return nil, "", fmt.Errorf("invalid CIDR: %w", err)
		}
		return map[string]any{"not_cidr": value}, "not-cidr", nil
	case "--in-file":
		return map[string]any{"in_file": value}, "in-file", nil
	case "--not-in-file":
		return map[string]any{"not_in_file": value}, "not-in-file", nil
	case "--gt":
		n, err := numericMatch(value)
		if err != nil {
			return nil, "", err
		}
		return map[string]any{"gt": n}, "gt", nil
	case "--lt":
		n, err := numericMatch(value)
		if err != nil {
			return nil, "", err
		}
		return map[string]any{"lt": n}, "lt", nil
	case "--ge":
		n, err := numericMatch(value)
		if err != nil {
			return nil, "", err
		}
		return map[string]any{"ge": n}, "ge", nil
	case "--le":
		n, err := numericMatch(value)
		if err != nil {
			return nil, "", err
		}
		return map[string]any{"le": n}, "le", nil
	case "--any":
		parts := strings.Split(value, ",")
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			out = append(out, p)
		}
		if len(out) < 2 {
			return nil, "", fmt.Errorf("--any requires at least 2 comma-separated values")
		}
		return out, "any-of", nil
	}
	return nil, "", fmt.Errorf("unknown match operator %q (want --regex|--substr|--cidr|--not-cidr|--in-file|--not-in-file|--gt|--lt|--ge|--le|--any)", first)
}

func numericMatch(s string) (any, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}
	// Duration strings are accepted by the engine for time-shaped
	// fields (e.g. duration_s: { gt: "5s" }).
	if _, err := parseDurationSeconds(s); err == nil {
		return s, nil
	}
	return nil, fmt.Errorf("numeric value must be int, float, or duration (got %q)", s)
}

func runRulesThreshold(args []string) {
	if len(args) < 3 || len(args) > 4 {
		fatalf("usage: rules threshold <id> <count> <window> [<group_by>]")
	}
	id, countStr, window := args[0], args[1], args[2]
	count, err := strconv.Atoi(countStr)
	if err != nil || count <= 0 {
		fatalf("count must be a positive integer")
	}
	if _, err := parseDurationSeconds(window); err != nil {
		fatalf("window must be a duration (e.g. 60s, 5m)")
	}
	groupBy := ""
	if len(args) == 4 {
		groupBy = args[3]
	}
	block := map[string]any{
		"count":  count,
		"window": window,
	}
	if groupBy != "" {
		block["group_by"] = groupBy
	}
	withRuleEdit(id, func(r map[string]any) { r["threshold"] = block })
	if groupBy != "" {
		fmt.Printf("set %s.threshold = %d in %s grouped by %s\n", id, count, window, groupBy)
	} else {
		fmt.Printf("set %s.threshold = %d in %s\n", id, count, window)
	}
}

func runRulesUnthreshold(args []string) {
	if len(args) != 1 {
		fatalf("usage: rules unthreshold <id>")
	}
	withRuleEdit(args[0], func(r map[string]any) { delete(r, "threshold") })
	fmt.Printf("cleared %s.threshold\n", args[0])
}

// runRulesSequenceStep appends a step matcher to the sequence block.
// Each step is a map of field=value pairs. Steps are evaluated in
// order, by the same group_by key, within the configured window.
//
// Operators write each step as space-separated `key=value` pairs:
//
//	rules sequence-step ssh-then-shell type=auth event=ssh_login result=success
//	rules sequence-step ssh-then-shell type=process event=process_start
//
// Match-operator flags (--regex, --cidr, ...) are NOT yet supported on
// sequence steps — operators wanting an operator on a step field can
// fall back to `rules add <file>` with the JSON form.
func runRulesSequenceStep(args []string) {
	if len(args) < 2 {
		fatalf("usage: rules sequence-step <id> <key>=<value> [<key>=<value>...]\n\n  example: rules sequence-step ssh-then-shell type=auth event=ssh_login result=success")
	}
	id := args[0]
	step := map[string]any{}
	for _, kv := range args[1:] {
		eq := strings.Index(kv, "=")
		if eq <= 0 {
			fatalf("step matcher must be key=value (got %q)", kv)
		}
		step[kv[:eq]] = kv[eq+1:]
	}
	if len(step) == 0 {
		fatalf("at least one key=value is required")
	}
	withRuleEdit(id, func(r map[string]any) {
		seq, ok := r["sequence"].(map[string]any)
		if !ok {
			seq = map[string]any{}
			r["sequence"] = seq
		}
		stepsRaw, _ := seq["steps"].([]any)
		stepsRaw = append(stepsRaw, step)
		seq["steps"] = stepsRaw
	})
	fmt.Printf("appended step to %s.sequence (%d field(s))\n", id, len(step))
}

func runRulesSequenceClear(args []string) {
	if len(args) != 1 {
		fatalf("usage: rules sequence-clear <id>")
	}
	withRuleEdit(args[0], func(r map[string]any) { delete(r, "sequence") })
	fmt.Printf("cleared %s.sequence\n", args[0])
}

func runRulesSequenceSet(args []string) {
	if len(args) != 3 {
		fatalf("usage: rules sequence-set <id> <within|group-by> <value>")
	}
	id := args[0]
	switch args[1] {
	case "within":
		if _, err := parseDurationSeconds(args[2]); err != nil {
			fatalf("within must be a duration (e.g. 60s, 5m)")
		}
		withRuleEdit(id, func(r map[string]any) {
			seq, ok := r["sequence"].(map[string]any)
			if !ok {
				seq = map[string]any{}
				r["sequence"] = seq
			}
			seq["within"] = args[2]
		})
		fmt.Printf("set %s.sequence.within = %s\n", id, args[2])
	case "group-by":
		withRuleEdit(id, func(r map[string]any) {
			seq, ok := r["sequence"].(map[string]any)
			if !ok {
				seq = map[string]any{}
				r["sequence"] = seq
			}
			seq["group_by"] = args[2]
		})
		fmt.Printf("set %s.sequence.group_by = %s\n", id, args[2])
	default:
		fatalf("usage: rules sequence-set <id> <within|group-by> <value>")
	}
}

// runRulesEnableValidated runs a full required-field audit before
// flipping disabled off. Refuses on missing fields and surfaces ALL
// problems at once so the operator doesn't have to play whack-a-mole.
func runRulesEnableValidated(args []string) {
	if len(args) != 1 {
		fatalf("usage: rules enable <id>")
	}
	id := args[0]
	mustAdmin()
	path := resolveRulesPath()
	arr, err := loadRulesArray(path)
	if err != nil {
		fatalf("%v", err)
	}
	var rule map[string]any
	for _, r := range arr {
		if name, _ := r["name"].(string); name == id {
			rule = r
			break
		}
	}
	if rule == nil {
		fatalf("no rule named %q", id)
	}
	if problems := auditRule(rule); len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "cannot enable: rule %q is not yet complete:\n", id)
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "  - %s\n", p)
		}
		fmt.Fprintln(os.Stderr, "\nfix the items above, then run `rules enable` again.")
		os.Exit(1)
	}
	delete(rule, "disabled")
	// Final integrity check: round-trip the whole array through the
	// daemon's own parser. This catches anything the audit missed.
	body, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		fatalf("marshal: %v", err)
	}
	if _, err := parseRulesBytes(body); err != nil {
		fatalf("rule failed daemon-parser validation (file unchanged): %v", err)
	}
	body = append(body, '\n')
	if err := atomicWriteFile(path, body, 0o640); err != nil {
		fatalf("write rules: %v", err)
	}
	fmt.Printf("rule %q ENABLED — daemon will hot-reload within ~1s\n", id)
}

// runRulesValidate is a dry-run audit: prints any problems (or "OK")
// without modifying the rule. Lets an operator iterate without flipping
// state.
func runRulesValidate(args []string) {
	if len(args) != 1 {
		fatalf("usage: rules validate <id>")
	}
	id := args[0]
	path := resolveRulesPath()
	arr, err := loadRulesArray(path)
	if err != nil {
		fatalf("%v", err)
	}
	var rule map[string]any
	for _, r := range arr {
		if name, _ := r["name"].(string); name == id {
			rule = r
			break
		}
	}
	if rule == nil {
		fatalf("no rule named %q", id)
	}
	problems := auditRule(rule)
	if len(problems) == 0 {
		fmt.Printf("rule %q is complete and would enable cleanly.\n", id)
		return
	}
	fmt.Printf("rule %q has %d problem(s):\n", id, len(problems))
	for _, p := range problems {
		fmt.Printf("  - %s\n", p)
	}
	os.Exit(1)
}

// auditRule returns a list of human-readable required-field problems
// for one rule. Empty result means the rule is enable-ready.
//
// Required:
//   - severity (low|medium|high|critical)
//   - either match (≥1 key) OR sequence (≥1 step) — sequence rules
//     don't need a top-level match.
//   - if threshold is set: count > 0 + window parseable as a duration
//   - if sequence is set: ≥1 step + within parseable
func auditRule(rule map[string]any) []string {
	var out []string
	if name, _ := rule["name"].(string); name == "" {
		out = append(out, "name: missing (use `rules new <id>` to create the draft)")
	}
	sev, _ := rule["severity"].(string)
	if sev == "" {
		out = append(out, "severity: not set (run `rules set <id> severity <low|medium|high|critical>`)")
	} else if !validSeverities[strings.ToLower(sev)] {
		out = append(out, fmt.Sprintf("severity: %q is not one of low|medium|high|critical", sev))
	}
	hasMatch := false
	if m, ok := rule["match"].(map[string]any); ok && len(m) > 0 {
		hasMatch = true
	}
	hasSequence := false
	if s, ok := rule["sequence"].(map[string]any); ok {
		steps, _ := s["steps"].([]any)
		within, _ := s["within"].(string)
		if len(steps) >= 1 {
			hasSequence = true
		} else {
			out = append(out, "sequence: started but has no steps (run `rules sequence-step <id> key=value...`)")
		}
		if within == "" {
			out = append(out, "sequence: within not set (run `rules sequence-set <id> within <duration>`)")
		} else if _, err := parseDurationSeconds(within); err != nil {
			out = append(out, "sequence.within: not a duration ("+within+")")
		}
	}
	if !hasMatch && !hasSequence {
		out = append(out, "match: at least one match key OR a sequence is required (run `rules match <id> <key> <value>` or `rules sequence-step <id> key=value...`)")
	}
	if t, ok := rule["threshold"].(map[string]any); ok {
		count, _ := numToInt(t["count"])
		window, _ := t["window"].(string)
		if count <= 0 {
			out = append(out, "threshold.count: must be a positive integer")
		}
		if window == "" {
			out = append(out, "threshold.window: not set")
		} else if _, err := parseDurationSeconds(window); err != nil {
			out = append(out, "threshold.window: not a duration ("+window+")")
		}
	}
	// Catch-all: round-trip through the daemon parser so any
	// schema-level surprise the audit missed shows up here. A
	// passing rule must serialise + parse cleanly. We force-clear
	// `disabled` for this check so the parser doesn't silently
	// skip the rule (loadRules drops disabled entries during
	// normal load).
	probe := map[string]any{}
	for k, v := range rule {
		if k == "disabled" {
			continue
		}
		probe[k] = v
	}
	body, err := json.Marshal([]map[string]any{probe})
	if err != nil {
		out = append(out, "marshal: "+err.Error())
		return out
	}
	parsed, err := parseRulesBytes(body)
	if err != nil {
		out = append(out, "schema: "+err.Error())
	} else if len(parsed) == 0 {
		out = append(out, "schema: rule did not produce a runnable definition (likely missing match keys or threshold)")
	}
	return out
}

func numToInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}
