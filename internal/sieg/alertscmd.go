package sieg

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

// runAlertsCmd prints recent alert events as a coloured table. It's a
// thin wrapper over loadEventsInRange filtered to the alerts log type —
// the value-add over `triage --since 1h --type alerts` is the formatting:
// severity-coloured rows, original event summary inlined, and an exit
// code that signals whether anything was found (useful for cron checks).
//
// `simplesiem alerts ack <hash>` writes an acknowledgement record to a
// sidecar index so operators can mark alerts as triaged. `--unacked-only`
// filters the table to alerts whose `_hash` isn't in the index. The
// ack store is intentionally a flat append-only JSONL — operators can
// rsync/diff/grep it like any other event log.
func runAlertsCmd(args []string) {
	if len(args) > 0 && args[0] == "ack" {
		runAlertsAck(args[1:])
		return
	}

	fs := flag.NewFlagSet("alerts", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	since := fs.String("since", "1h", "time window (1h, 30m, 7d, RFC3339)")
	severity := fs.String("severity", "", "filter by severity: low/medium/high/critical")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	hostFilter := fs.String("host", "", "in server mode, restrict to one agent ID")
	unackedOnly := fs.Bool("unacked-only", false, "hide alerts that have been ack'd via `alerts ack <hash>`")
	technique := fs.String("technique", "", "filter by MITRE ATT&CK technique ID (e.g. T1059 or T1059.001; prefix match)")
	tactic := fs.String("tactic", "", "filter by MITRE ATT&CK tactic ID (e.g. TA0006)")
	_ = fs.Parse(args)
	if *noColor {
		disableColor()
	}

	start, err := parseSince(*since)
	if err != nil {
		fatalf("--since: %v", err)
	}
	cfg := loadConfig(*cfgPath)
	base := cfg.LogDir
	if _, err := os.Stat(base); err != nil {
		fmt.Fprintln(os.Stderr, "no logs at", base)
		os.Exit(1)
	}
	end := time.Now().UTC()
	events := loadEventsInRangeMulti(searchRoots(cfg, *hostFilter), start, end, "alerts")
	if *severity != "" {
		filtered := events[:0]
		for _, e := range events {
			if strings.EqualFold(strField(e.Data, "severity"), *severity) {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}
	if *technique != "" {
		filtered := events[:0]
		for _, e := range events {
			if strings.HasPrefix(strField(e.Data, "technique"), *technique) {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}
	if *tactic != "" {
		filtered := events[:0]
		for _, e := range events {
			if strings.EqualFold(strField(e.Data, "tactic"), *tactic) {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}

	var acked map[string]bool
	if *unackedOnly {
		acked = loadAckIndex(cfg.LogDir)
		filtered := events[:0]
		for _, e := range events {
			if !acked[strField(e.Data, "_hash")] {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}

	suffix := ""
	if *unackedOnly {
		suffix = "  (unacked only)"
	}
	// Header: "1 alerts in 2026-05-05T10:00-04:00 -> 2026-05-05T11:00-04:00  (times shown in EDT)".
	// The displayTS hop converts UTC -> host-local; the explicit "times
	// shown in TZ" footer + the per-row TZ suffix together remove any
	// doubt about whether the operator is reading UTC or local clock.
	fmt.Printf("%d alerts in %s -> %s  (times shown in %s)%s\n",
		len(events), displayTS(start).Format(time.RFC3339), displayTS(end).Format(time.RFC3339), displayTZ(), suffix)
	if len(events) == 0 {
		return
	}
	fmt.Println(strings.Repeat("-", 78))
	tz := displayTZ()
	for _, e := range events {
		sev := strField(e.Data, "severity")
		rule := strField(e.Data, "rule")
		mt := strField(e.Data, "matched_type")
		me := strField(e.Data, "matched_event")
		host := strField(e.Data, "host")
		hash := strField(e.Data, "_hash")
		ts := displayTS(e.TS).Format("2006-01-02 15:04:05") + " " + tz
		hostPart := ""
		if host != "" {
			hostPart = " host=" + host
		}
		hashPart := ""
		if len(hash) >= 12 {
			hashPart = "  id=" + hash[:12]
		}
		header := fmt.Sprintf("%s  [%-6s]  %s  on %s/%s%s%s",
			ts, strings.ToUpper(sev), rule, mt, me, hostPart, hashPart)
		if code := severityColor(sev); code != "" {
			header = colorize(header, code)
		}
		fmt.Println(header)
		// Original event summary as a sub-row when available.
		if orig, ok := e.Data["original"].(map[string]any); ok {
			sub := Event{TS: e.TS, Type: mt, Data: orig}
			fmt.Println("    ", colorize(eventSummary(sub), colDim))
		}
		if count := numField(e.Data, "count"); count > 0 {
			extra := fmt.Sprintf("count=%d window=%s", count, strField(e.Data, "window"))
			if gv := strField(e.Data, "group_value"); gv != "" {
				extra += fmt.Sprintf(" %s=%s", strField(e.Data, "group_by"), gv)
			}
			fmt.Println("    ", colorize(extra, colDim))
		}
		// MITRE tags + operator annotations as sub-rows when present.
		if t := strField(e.Data, "technique"); t != "" {
			line := "att&ck: " + t
			if tac := strField(e.Data, "tactic"); tac != "" {
				line += " (" + tac + ")"
			}
			fmt.Println("    ", colorize(line, colDim))
		}
		if n := strField(e.Data, "notes"); n != "" {
			fmt.Println("    ", colorize("notes: "+n, colDim))
		}
		if u := strField(e.Data, "runbook_url"); u != "" {
			fmt.Println("    ", colorize("runbook: "+u, colDim))
		}
	}
}

// runAlertsAck writes an acknowledgement record for one or more alert
// hashes. The `id` arguments are alert `_hash` values (the 96-char SHA-384
// or a unique prefix; we accept ≥8 chars). When a prefix is supplied, we
// look it up against alerts in the last 30 days and resolve to the full
// hash before writing.
func runAlertsAck(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "note": true, "by": true})
	fs := flag.NewFlagSet("alerts ack", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	note := fs.String("note", "", "optional triage note attached to the ack")
	by := fs.String("by", "", "operator name (default: $USER or 'unknown')")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: simplesiem alerts ack <hash-or-prefix> [<hash-or-prefix> ...]")
	}
	cfg := loadConfig(*cfgPath)
	if cfg.LogDir == "" {
		fatalf("log_dir is empty in config")
	}
	if _, err := os.Stat(cfg.LogDir); err != nil {
		fatalf("log_dir not readable: %v", err)
	}
	whoami := *by
	if whoami == "" {
		if u, err := user.Current(); err == nil {
			whoami = u.Username
		} else {
			whoami = "unknown"
		}
	}

	// Build a hash → full-hash resolver from the alerts in the last
	// 30 days so prefix lookups work without remembering the full
	// 96-char SHA-384.
	resolved := map[string]string{}
	for _, prefix := range fs.Args() {
		if len(prefix) < 8 {
			fatalf("ack id %q too short (need ≥8 hex chars to disambiguate)", prefix)
		}
		full, err := resolveAlertHash(cfg, prefix)
		if err != nil {
			fatalf("resolve %q: %v", prefix, err)
		}
		resolved[prefix] = full
	}

	now := time.Now().UTC()
	dir := filepath.Join(cfg.LogDir, "_acks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fatalf("mkdir _acks: %v", err)
	}
	path := filepath.Join(dir, now.Format("2006-01-02")+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		fatalf("open ack log: %v", err)
	}
	defer f.Close()
	for prefix, full := range resolved {
		rec := map[string]any{
			"alert_hash": full,
			"ack_ts":     now.Format(time.RFC3339Nano),
			"by":         whoami,
		}
		if *note != "" {
			rec["note"] = *note
		}
		data, _ := json.Marshal(rec)
		if _, err := f.Write(append(data, '\n')); err != nil {
			fatalf("write ack: %v", err)
		}
		// #1 rules tune feedback: record the ack so severity-vs-ack-rate
		// classification has data. Best-effort.
		recordRuleAck(full, *note)
		fmt.Printf("ack: %s -> %s by %s\n", prefix, full[:16]+"…", whoami)
	}
}

// resolveAlertHash matches a hex prefix to a full alert _hash by walking
// the alerts log for the last 30 days. Returns an error if no alert or
// multiple alerts match.
func resolveAlertHash(cfg Config, prefix string) (string, error) {
	if len(prefix) >= 96 {
		return prefix, nil // already a full SHA-384 hex
	}
	end := time.Now().UTC()
	start := end.Add(-30 * 24 * time.Hour)
	events := loadEventsInRangeMulti(searchRoots(cfg, ""), start, end, "alerts")
	matches := map[string]bool{}
	for _, e := range events {
		h := strField(e.Data, "_hash")
		if strings.HasPrefix(h, prefix) {
			matches[h] = true
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no alert in the last 30 days matches prefix %q", prefix)
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("prefix %q is ambiguous (%d matches); supply more characters", prefix, len(matches))
	}
	for h := range matches {
		return h, nil
	}
	return "", nil
}

// loadAckIndex reads every `<log_dir>/_acks/*.jsonl` and returns the
// set of alert _hash values that have been ack'd. Best-effort: any
// parse error on a single line is skipped silently rather than failing
// the alerts query.
func loadAckIndex(logDir string) map[string]bool {
	out := map[string]bool{}
	dir := filepath.Join(logDir, "_acks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			var rec map[string]any
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				continue
			}
			if h, _ := rec["alert_hash"].(string); h != "" {
				out[h] = true
			}
		}
		f.Close()
	}
	return out
}
