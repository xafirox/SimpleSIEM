package sieg

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"
)

// runRulesCmd dispatches rule subcommands. Today: check (parse + compile)
// and test (replay JSONL events and report fires). Both are read-only and
// don't require root or a running daemon.
func runRulesCmd(args []string) {
	if len(args) == 0 {
		rulesUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "check":
		runRulesCheck(args[1:])
	case "test":
		runRulesTest(args[1:])
	case "replay":
		runRulesReplay(args[1:])
	case "stats":
		runRulesStats(args[1:])
	case "coverage":
		runRulesCoverage(args[1:])
	case "tune":
		runRulesTune(args[1:])
	case "suppress":
		runRulesSuppressCmd(args[1:])
	case "backtest":
		runRulesBacktestCmd(args[1:])
	case "fixture-test":
		runRulesTestCmd(args[1:])
	case "suggest-suppression":
		runRulesSuggestSuppression(args[1:])
	case "list":
		runRulesList(args[1:])
	case "show":
		runRulesShow(args[1:])
	case "add":
		runRulesAdd(args[1:])
	case "delete", "remove":
		runRulesDelete(args[1:])
	case "enable":
		runRulesEnableValidated(args[1:])
	case "disable":
		runRulesEnableDisable(args[1:], false)
	case "new":
		runRulesNew(args[1:])
	case "set":
		runRulesSet(args[1:])
	case "unset":
		runRulesUnset(args[1:])
	case "match":
		runRulesMatch(args[1:])
	case "unmatch":
		runRulesUnmatch(args[1:])
	case "threshold":
		runRulesThreshold(args[1:])
	case "unthreshold":
		runRulesUnthreshold(args[1:])
	case "sequence-step":
		runRulesSequenceStep(args[1:])
	case "sequence-clear":
		runRulesSequenceClear(args[1:])
	case "sequence-set":
		runRulesSequenceSet(args[1:])
	case "validate":
		runRulesValidate(args[1:])
	case "help", "-h", "--help":
		rulesUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown rules subcommand: %s\n", args[0])
		rulesUsage()
		os.Exit(2)
	}
}

func rulesUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem rules <subcommand> [flags]

build a rule (stepwise — never type JSON; new rules start disabled):
  new <id>                               create a draft rule (disabled until enable)
  set <id> severity <low|medium|high|critical>
  set <id> dedup-window <duration>       e.g. 5m, 30s
  set <id> dedup-key <field>             group dedup by this event field
  set <id> notes "<text>"                one-line description for alerts
  set <id> runbook-url <url>             triage link surfaced on alerts
  set <id> tactic <ID>                   MITRE ATT&CK tactic (e.g. TA0006)
  set <id> technique <ID>                MITRE ATT&CK technique (e.g. T1110.001)
  set <id> time-of-day <HH:MM-HH:MM>     daemon local-time gate
  set <id> weekdays <mon,tue,...>        comma-separated weekday gate
  unset <id> <field>                     remove a top-level field

  match <id> <key> <value>               equality match (default)
  match <id> <key> --regex <pattern>     regex match
  match <id> <key> --substr <s>          substring match
  match <id> <key> --cidr <range>        CIDR match (also --not-cidr)
  match <id> <key> --in-file <path>      file-list match (also --not-in-file)
  match <id> <key> --gt <num>            numeric > (also --lt, --ge, --le)
  match <id> <key> --any v1,v2,v3        any-of (comma-separated)
  unmatch <id> <key>                     remove a match key

  threshold <id> <count> <window> [<group_by>]      add/replace threshold block
  unthreshold <id>                                  drop the threshold block

  sequence-step <id> <key>=<value> [<key>=<value>...]   append a sequence step
  sequence-clear <id>                                   drop every sequence step
  sequence-set <id> within <duration>                   sequence window
  sequence-set <id> group-by <field>                    sequence grouping field

activate / deactivate / inspect:
  validate <id>                          dry-run validation (required fields, schema, parse)
  enable <id>                            validate then activate (refuses on error)
  disable <id>                           keep in file but stop firing
  delete <id>                            remove from rules.json
  list                                   one line per rule (id, severity, match-key count, state)
  show <id>                              print the full rule JSON

read-only / triage:
  check                                  parse + compile rules.json; nonzero exit on error
  test <file|->                          replay JSONL events through rules + report fires
  replay [--since 7d] [--type T] ...     replay over historical events on disk
  stats [--since 24h] [--host H]         aggregate fire counts from the alerts log
  coverage [--since 7d]                  group rules by MITRE ATT&CK + per-group fires
  backtest --rule <file> [--against 30d] dry-run a draft rule against history
  tune [--apply]                         classify dead / runaway / mis-severity rules
  fixture-test                           replay auto-captured fixtures against current rules
  suggest-suppression [--since 30d]      surface ack patterns ready to become suppressions

power-user:
  add <file|->                           append every rule object in <file> (- for stdin) — JSON
  suppress <list|add|remove>             scoped, time-bounded suppressions sidecar

example session:
  sudo simplesiem rules new ssh-brute
  sudo simplesiem rules set ssh-brute severity high
  sudo simplesiem rules match ssh-brute type auth
  sudo simplesiem rules match ssh-brute event ssh_login
  sudo simplesiem rules match ssh-brute result --any failed,invalid_user
  sudo simplesiem rules threshold ssh-brute 5 60s remote
  sudo simplesiem rules set ssh-brute dedup-window 5m
  sudo simplesiem rules set ssh-brute tactic TA0006
  sudo simplesiem rules set ssh-brute technique T1110.001
  sudo simplesiem rules enable ssh-brute`)
}

// runRulesCoverage groups rules by MITRE tactic + technique and
// reports per-rule fire counts in the time window. Rules without
// `tactic`/`technique` annotations land in an "untagged" group so
// operators see what's missing tags. Pure read-only over the
// configured rules file + alerts log.
func runRulesCoverage(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "rules": true, "since": true})
	fs := flag.NewFlagSet("rules coverage", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	rulesPath := fs.String("rules", "", "rules file (default: from config)")
	since := fs.String("since", "7d", "fire-count window (1h, 30m, 7d, RFC3339)")
	_ = fs.Parse(args)

	start, err := parseSince(*since)
	if err != nil {
		fatalf("--since: %v", err)
	}
	cfg := loadConfig(*cfgPath)
	rp := *rulesPath
	if rp == "" {
		rp = cfg.RulesPath
	}
	rules, err := loadRules(rp)
	if err != nil {
		fatalf("loadRules: %v", err)
	}

	// Walk alerts log to count fires per rule in the window.
	end := time.Now().UTC()
	events := loadEventsInRangeMulti(searchRoots(cfg, ""), start, end, "alerts")
	fires := map[string]int{}
	for _, e := range events {
		ev, _ := e.Data["event"].(string)
		if ev != "rule_match" {
			continue
		}
		if name, _ := e.Data["rule"].(string); name != "" {
			fires[name]++
		}
	}

	// Group rules by tactic/technique. Empty annotations bucket as
	// "(untagged)" so the gap is visible.
	type groupKey struct {
		tactic    string
		technique string
	}
	groups := map[groupKey][]*alertRule{}
	for _, r := range rules {
		k := groupKey{tactic: r.Tactic, technique: r.Technique}
		groups[k] = append(groups[k], r)
	}

	// Sort keys for stable output: tagged groups first (by technique),
	// untagged last.
	keys := make([]groupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if (keys[i].technique == "") != (keys[j].technique == "") {
			return keys[i].technique != "" // tagged first
		}
		if keys[i].tactic != keys[j].tactic {
			return keys[i].tactic < keys[j].tactic
		}
		return keys[i].technique < keys[j].technique
	})

	fmt.Printf("MITRE ATT&CK coverage — %d rules across %d group(s), fires from %s -> %s (%s)\n",
		len(rules), len(groups),
		displayTS(start).Format("2006-01-02 15:04:05"),
		displayTS(end).Format("2006-01-02 15:04:05"),
		displayTZ())
	for _, k := range keys {
		label := ""
		if k.technique != "" {
			label = k.technique
			if k.tactic != "" {
				label += " (" + k.tactic + ")"
			}
		} else if k.tactic != "" {
			label = k.tactic
		} else {
			label = "(untagged)"
		}
		groupRules := groups[k]
		sort.Slice(groupRules, func(i, j int) bool { return groupRules[i].Name < groupRules[j].Name })
		groupFires := 0
		for _, r := range groupRules {
			groupFires += fires[r.Name]
		}
		fmt.Printf("\n  %s — %d rule(s), %d fires\n", label, len(groupRules), groupFires)
		for _, r := range groupRules {
			fmt.Printf("    %-32s sev=%-7s fires=%d\n", r.Name, r.Severity, fires[r.Name])
		}
	}
}

// runRulesStats walks the on-disk alerts log for the configured time
// window and reports per-rule fire counts. Used to identify dead rules
// (zero fires) and chronically-firing noise (top of the table).
//
// Stateless: reads `<log_dir>/<host>/alerts/*.jsonl` directly, no
// daemon-side runtime state. Works in every mode that holds alerts on
// disk (standalone, server, master).
func runRulesStats(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "since": true, "host": true})
	fs := flag.NewFlagSet("rules stats", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	since := fs.String("since", "24h", "time window (1h, 30m, 7d, RFC3339)")
	hostFilter := fs.String("host", "", "in server/master mode, restrict to one agent ID")
	_ = fs.Parse(args)

	start, err := parseSince(*since)
	if err != nil {
		fatalf("--since: %v", err)
	}
	cfg := loadConfig(*cfgPath)
	end := time.Now().UTC()
	roots := searchRoots(cfg, *hostFilter)
	events := loadEventsInRangeMulti(roots, start, end, "alerts")

	type tally struct {
		rule  string
		sev   string
		fires int
		first time.Time
		last  time.Time
	}
	tallies := map[string]*tally{}
	totalFires := 0
	rulesSeen := map[string]bool{}
	for _, e := range events {
		ev, _ := e.Data["event"].(string)
		if ev != "rule_match" {
			continue
		}
		name, _ := e.Data["rule"].(string)
		if name == "" {
			continue
		}
		rulesSeen[name] = true
		sev, _ := e.Data["severity"].(string)
		t, ok := tallies[name]
		if !ok {
			t = &tally{rule: name, sev: sev, first: e.TS, last: e.TS}
			tallies[name] = t
		}
		t.fires++
		if e.TS.Before(t.first) {
			t.first = e.TS
		}
		if e.TS.After(t.last) {
			t.last = e.TS
		}
		totalFires++
	}

	// Cross-reference with the configured rules so dead rules are
	// visible too (zero-fire rows). Skip silently if the rules file
	// can't be loaded — operator may have deleted it.
	if rules, err := loadRules(cfg.RulesPath); err == nil {
		for _, r := range rules {
			if _, seen := tallies[r.Name]; !seen {
				tallies[r.Name] = &tally{rule: r.Name, sev: r.Severity}
			}
		}
	}

	fmt.Printf("Alert window: %s -> %s   (%d alerts across %d rule(s), %s)\n",
		displayTS(start).Format("2006-01-02 15:04:05"),
		displayTS(end).Format("2006-01-02 15:04:05"),
		totalFires, len(tallies), displayTZ())
	if len(tallies) == 0 {
		fmt.Println("(no rules configured and no alerts in the window)")
		return
	}
	var ordered []*tally
	for _, t := range tallies {
		ordered = append(ordered, t)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].fires != ordered[j].fires {
			return ordered[i].fires > ordered[j].fires
		}
		return ordered[i].rule < ordered[j].rule
	})
	for _, t := range ordered {
		extras := ""
		if t.fires > 0 {
			extras = fmt.Sprintf("  first=%s last=%s",
				displayTS(t.first).Format("2006-01-02 15:04:05"),
				displayTS(t.last).Format("2006-01-02 15:04:05"))
		} else {
			extras = "  (no fires in window)"
		}
		fmt.Printf("  %-30s sev=%-7s %5d%s\n", t.rule, t.sev, t.fires, extras)
	}
}

func runRulesCheck(args []string) {
	fs := flag.NewFlagSet("rules check", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	rulesPath := fs.String("rules", "", "rules file (default: from config)")
	_ = fs.Parse(args)

	path := *rulesPath
	if path == "" {
		cfg := loadConfig(*cfgPath)
		path = cfg.RulesPath
	}
	if path == "" {
		fatalf("no rules path; pass --rules <file>")
	}
	rules, err := loadRules(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", path, err)
		os.Exit(1)
	}
	fmt.Printf("OK %s — %d rules loaded\n", path, len(rules))
	for _, r := range rules {
		extras := ""
		if r.Threshold != nil {
			extras += fmt.Sprintf(" threshold=%d/%s", r.Threshold.Count, r.Threshold.Window)
		}
		if r.DedupWindow > 0 {
			extras += fmt.Sprintf(" dedup=%s", r.DedupWindow)
		}
		fmt.Printf("  %-30s sev=%-7s match-keys=%d%s\n", r.Name, r.Severity, len(r.Match), extras)
	}
}

func runRulesTest(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "rules": true})
	fs := flag.NewFlagSet("rules test", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	rulesPath := fs.String("rules", "", "rules file (default: from config)")
	withState := fs.Bool("with-threshold", false,
		"keep threshold/dedup state across events (default: match-only)")
	_ = fs.Parse(args)

	if fs.NArg() == 0 {
		fatalf("usage: rules test <events.jsonl>  (use - for stdin)")
	}
	src := fs.Arg(0)

	path := *rulesPath
	if path == "" {
		cfg := loadConfig(*cfgPath)
		path = cfg.RulesPath
	}
	rules, err := loadRules(path)
	if err != nil {
		fatalf("loadRules: %v", err)
	}

	var r *bufio.Reader
	if src == "-" {
		r = bufio.NewReader(os.Stdin)
	} else {
		f, err := os.Open(src)
		if err != nil {
			fatalf("open: %v", err)
		}
		defer f.Close()
		r = bufio.NewReader(f)
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	totalEvents := 0
	totalFires := 0
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			fmt.Fprintf(os.Stderr, "line %d: skipped (not JSON)\n", lineNo)
			continue
		}
		totalEvents++
		logType, _ := event["type"].(string)
		for _, rule := range rules {
			fired := false
			if *withState {
				ok, _ := rule.shouldFire(logType, event)
				fired = ok
			} else {
				fired = matchRule(rule, logType, event)
			}
			if !fired {
				continue
			}
			totalFires++
			fmt.Printf("line %d: rule=%s severity=%s matched_type=%s event=%s\n",
				lineNo, rule.Name, rule.Severity, logType, fieldString(event["event"]))
		}
	}
	fmt.Println()
	mode := "match-only"
	if *withState {
		mode = "with threshold/dedup state"
	}
	fmt.Printf("Tested %d events, %d rule fires (%s).\n", totalEvents, totalFires, mode)
}

// runRulesReplay walks the local log_dir for events in --since
// window, runs each through the configured rules, and reports fire
// counts grouped by rule name and severity. The local rule engine
// is not consulted — this is a pure CLI replay against a fresh
// rule set that the operator may have just edited but not yet
// pushed to the daemon. Lets the operator iterate on rule tuning
// in seconds rather than waiting for production traffic to retest.
//
// Output:
//
//	Replay window: 2026-04-25T00:00:00 -> 2026-05-02T00:00:00 (7d)
//	Scanned: 142,431 events across 6 hosts and 7 types.
//	Fires:
//	  failed-ssh-bruteforce        sev=high      127
//	  unusual-process-spawn        sev=medium     14
//	  total                                      141
//
// Rules are evaluated stateless by default (the same as
// `rules test` without `--with-threshold`) so a rule with a
// `threshold` clause counts each individual matching event rather
// than only the events that crossed the threshold. To replay with
// stateful threshold/dedup tracking, pass `--with-threshold`.
func runRulesReplay(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "rules": true, "since": true, "type": true, "host": true})
	fs := flag.NewFlagSet("rules replay", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	rulesPath := fs.String("rules", "", "rules file (default: from config)")
	since := fs.String("since", "1h", "time window (1h, 30m, 7d, RFC3339)")
	typeFilter := fs.String("type", "", "log type to replay (default: all)")
	hostFilter := fs.String("host", "", "in server/master mode, restrict to one agent ID")
	withState := fs.Bool("with-threshold", false, "keep threshold/dedup state across events (default: stateless)")
	verbose := fs.Bool("v", false, "print one line per fire (off by default — counts only)")
	_ = fs.Parse(args)

	start, err := parseSince(*since)
	if err != nil {
		fatalf("--since: %v", err)
	}
	cfg := loadConfig(*cfgPath)
	rp := *rulesPath
	if rp == "" {
		rp = cfg.RulesPath
	}
	rules, err := loadRules(rp)
	if err != nil {
		fatalf("loadRules: %v", err)
	}
	if len(rules) == 0 {
		fmt.Fprintln(os.Stderr, "no rules to replay")
		return
	}

	end := time.Now().UTC()
	roots := searchRoots(cfg, *hostFilter)
	events := loadEventsInRangeMulti(roots, start, end, *typeFilter)

	type tally struct {
		rule  string
		sev   string
		fires int
	}
	tallies := map[string]*tally{}
	totalFires := 0
	for _, e := range events {
		for _, rule := range rules {
			fired := false
			if *withState {
				ok, _ := rule.shouldFire(e.Type, e.Data)
				fired = ok
			} else {
				fired = matchRule(rule, e.Type, e.Data)
			}
			if !fired {
				continue
			}
			totalFires++
			t, ok := tallies[rule.Name]
			if !ok {
				t = &tally{rule: rule.Name, sev: rule.Severity}
				tallies[rule.Name] = t
			}
			t.fires++
			if *verbose {
				ts := displayTS(e.TS).Format("2006-01-02 15:04:05")
				fmt.Printf("  %s  %-30s sev=%-7s type=%s event=%s\n",
					ts, rule.Name, rule.Severity, e.Type, fieldString(e.Data["event"]))
			}
		}
	}
	mode := "stateless"
	if *withState {
		mode = "with threshold/dedup state"
	}
	fmt.Printf("Replay window: %s -> %s   (%d events, %s, %s)\n",
		displayTS(start).Format("2006-01-02 15:04:05"),
		displayTS(end).Format("2006-01-02 15:04:05"),
		len(events), displayTZ(), mode)
	if len(events) == 0 {
		fmt.Println("(no events in window)")
		return
	}
	fmt.Printf("Fires (%d total across %d rule(s)):\n", totalFires, len(tallies))
	if totalFires == 0 {
		fmt.Println("  (none — rules did not match any event in the window)")
		return
	}
	// Sort by fire count descending for readable output.
	var ordered []*tally
	for _, t := range tallies {
		ordered = append(ordered, t)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].fires > ordered[j].fires })
	for _, t := range ordered {
		fmt.Printf("  %-30s sev=%-7s %d\n", t.rule, t.sev, t.fires)
	}
}
