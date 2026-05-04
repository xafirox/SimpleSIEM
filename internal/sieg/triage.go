package sieg

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Event is one parsed log entry used for triage output.
type Event struct {
	TS   time.Time
	Type string
	Raw  string
	Data map[string]any
}

// runTriage finds events matching one or more pivot criteria and prints every
// stored event within ±window of each pivot, merged across all log types in
// strict chronological order. The pivot line is marked with ">>".
func runTriage(args []string) {
	fs := flag.NewFlagSet("triage", flag.ExitOnError)
	atFlag := fs.String("at", "", "pivot on this time ('now', RFC3339, '2pm today', '14:30', '2026-04-24 2pm')")
	fileFlag := fs.String("file", "", "pivot on file events whose path contains this string")
	pidFlag := fs.Int("pid", 0, "pivot on events involving this PID")
	grepFlag := fs.String("grep", "", "pivot on events whose raw JSON matches this regex")
	sinceFlag := fs.String("since", "", "show ALL events from <dur> ago to now, no pivot (30m, 1h, 7d)")
	startFlag := fs.String("start", "", "range mode: start time (same formats as --at)")
	endFlag := fs.String("end", "", "range mode: end time (same formats as --at; defaults to now)")
	typFlag := fs.String("type", "", "restrict pivot search to this log type")
	windowFlag := fs.Duration("window", 30*time.Second, "time window before/after each pivot (implies --at now when used alone)")
	maxPivots := fs.Int("max-pivots", 10, "stop after this many pivots")
	scanDays := fs.Int("scan-days", 30, "how far back to scan for pivots")
	jsonOut := fs.Bool("json", false, "emit raw JSONL instead of the formatted table (for piping into jq)")
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	explain := fs.Bool("explain", false, "for alert events, show which rule fields matched")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	hostFilter := fs.String("host", "", "in server mode, restrict to one agent ID (default: all hosts)")
	var fieldFlags fieldFilterList
	fs.Var(&fieldFlags, "field", "structured filter, e.g. --field path=*=authorized_keys (repeatable)")
	_ = fs.Parse(args)
	if *noColor {
		disableColor()
	}
	triageExplain = *explain
	triageCfgPath = *cfgPath
	triageFieldFilters = fieldFlags.compiled()

	// Detect whether --window was explicitly set so `triage --window 2h`
	// alone can act as a pivot on 'now' (±window), rather than erroring.
	windowSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "window" {
			windowSet = true
		}
	})

	// --since / --start / --end are no-pivot range modes: emit every event
	// in [start, end], sorted, without a pivot. --since is "last N relative
	// to now"; --start/--end are explicit. They're mutually exclusive.
	if *sinceFlag != "" || *startFlag != "" || *endFlag != "" {
		if *sinceFlag != "" && (*startFlag != "" || *endFlag != "") {
			fatalf("use --since OR --start/--end, not both")
		}
		var start, end time.Time
		var err error
		if *sinceFlag != "" {
			start, err = parseSince(*sinceFlag)
			if err != nil {
				fatalf("--since: %v", err)
			}
			end = time.Now().UTC()
		} else {
			if *startFlag == "" {
				fatalf("--end requires --start")
			}
			start, err = parseTimeRef(*startFlag)
			if err != nil {
				fatalf("--start: %v", err)
			}
			if *endFlag == "" {
				end = time.Now().UTC()
			} else {
				end, err = parseTimeRef(*endFlag)
				if err != nil {
					fatalf("--end: %v", err)
				}
			}
			if !end.After(start) {
				fatalf("--end must be after --start")
			}
		}
		cfg := loadConfig(*cfgPath)
		base := cfg.LogDir
		if _, err := os.Stat(base); err != nil {
			fmt.Fprintln(os.Stderr, "no logs at", base)
			os.Exit(1)
		}
		events := loadEventsInRangeMulti(searchRoots(cfg, *hostFilter), start, end, *typFlag)
		if len(triageFieldFilters) > 0 {
			filtered := events[:0]
			for _, e := range events {
				if passesFieldFilters(e.Data) {
					filtered = append(filtered, e)
				}
			}
			events = filtered
		}
		if *jsonOut {
			for _, e := range events {
				if e.Raw != "" {
					fmt.Println(e.Raw)
				}
			}
			return
		}
		printRange(start, end, events)
		return
	}

	// Pivot-flag validation. `--window <dur>` alone is treated as a pivot on
	// 'now' (events within ±dur of now) since users reach for it naturally.
	// The message points users at --since for no-pivot range queries.
	if *atFlag == "" && *fileFlag == "" && *pidFlag == 0 && *grepFlag == "" && len(triageFieldFilters) == 0 {
		if windowSet {
			*atFlag = "now"
		} else {
			fmt.Fprintln(os.Stderr, `triage needs either a pivot or a time range. Use one of:

  --at <time>      show events around a specific time
                   ('now', RFC3339, '2pm today', '14:30', '2026-04-24 2pm')
  --window <dur>   show events within ±<dur> of now (e.g. 2h, 30m)
  --file <path>    find file events matching this path
  --pid <n>        find events for this PID
  --grep <regex>   find events matching this regex
  --since <dur>    show ALL events in the last <dur>, no pivot  (e.g. 30m, 1h, 7d)

Combine --at with --window to center on a time, e.g.:
  triage --at "2pm today" --window 30s

For raw JSONL output (no timeline formatting), use 'simplesiem query' instead.
See 'simplesiem triage -h' for all flags.`)
			os.Exit(2)
		}
	}

	cfg := loadConfig(*cfgPath)
	base := cfg.LogDir
	if _, err := os.Stat(base); err != nil {
		fmt.Fprintln(os.Stderr, "no logs at", base)
		os.Exit(1)
	}

	var pivots []Event
	switch {
	case *atFlag != "":
		t, err := parseTimeRef(*atFlag)
		if err != nil {
			fatalf("--at: %v", err)
		}
		pivots = []Event{{
			TS:   t,
			Type: "marker",
			Raw:  "",
			Data: map[string]any{"event": "time_marker"},
		}}
	default:
		pivots = findPivotsMulti(searchRoots(cfg, *hostFilter), *fileFlag, *pidFlag, *grepFlag, *typFlag, *maxPivots, *scanDays)
		if len(pivots) == 0 {
			fmt.Fprintln(os.Stderr, "no matching events found in the last", *scanDays, "days")
			os.Exit(1)
		}
	}

	roots := searchRoots(cfg, *hostFilter)
	for i, p := range pivots {
		if *jsonOut {
			emitTriageJSONMulti(roots, p, *windowFlag, *typFlag)
			continue
		}
		if i > 0 {
			fmt.Println()
			fmt.Println(strings.Repeat("=", 78))
		}
		printTriageMulti(roots, p, *windowFlag, *typFlag)
	}
}

// printRange renders every event in [start, end] as a chronological table.
// Used by the no-pivot --since mode. Consecutive rows with identical type +
// summary are coalesced into "(×N over D)" so noisy processes (apt writing
// the same temp file thousands of times) don't drown the output.
func printRange(start, end time.Time, events []Event) {
	fmt.Printf("Range:  %s  ->  %s   (%d events, %s)\n",
		displayTS(start).Format(time.RFC3339), displayTS(end).Format(time.RFC3339), len(events), displayTZ())
	fmt.Println(strings.Repeat("-", 78))
	if len(events) == 0 {
		fmt.Println("  (no events in range)")
		return
	}

	var firstTS, lastTS time.Time
	var lastType, lastSummary string
	count := 0

	flush := func() {
		if count == 0 {
			return
		}
		tsCol := displayTS(firstTS).Format("2006-01-02 15:04:05.000")
		suffix := ""
		if count > 1 {
			span := lastTS.Sub(firstTS)
			if span > 0 {
				suffix = fmt.Sprintf("  (×%d over %s)", count, formatSpan(span))
			} else {
				suffix = fmt.Sprintf("  (×%d)", count)
			}
		}
		fmt.Printf("   %s  %-9s  %s%s\n", tsCol, lastType, lastSummary, suffix)
	}

	for _, e := range events {
		summary := eventSummary(e)
		// Alerts get severity colour and an inline --explain sub-line so
		// they don't get coalesced into a generic count even when several
		// fire on identical fields (the original event differs per row).
		if e.Type == "alerts" {
			flush()
			coloured := summary
			if sev := strField(e.Data, "severity"); sev != "" {
				if code := severityColor(sev); code != "" {
					coloured = colorize(summary, code)
				}
			}
			tsCol := displayTS(e.TS).Format("2006-01-02 15:04:05.000")
			fmt.Printf("   %s  %-9s  %s\n", tsCol, e.Type, coloured)
			if triageExplain {
				if reason := explainAlert(e.Data); reason != "" {
					fmt.Printf("        matched: %s\n", colorize(reason, colDim))
				}
			}
			firstTS, lastTS = time.Time{}, time.Time{}
			lastType, lastSummary = "", ""
			count = 0
			continue
		}
		if count > 0 && e.Type == lastType && summary == lastSummary {
			lastTS = e.TS
			count++
			continue
		}
		flush()
		firstTS, lastTS = e.TS, e.TS
		lastType, lastSummary = e.Type, summary
		count = 1
	}
	flush()
}

func formatSpan(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return d.Round(time.Second).String()
	}
}

// parseTimeRef accepts:
//   - "now"
//   - RFC3339 / RFC3339Nano (e.g. 2026-04-24T13:48:35Z)
//   - friendly forms interpreted in the machine's local zone:
//     "2pm today", "2:30pm yesterday", "14:30", "2pm",
//     "2026-04-24", "2026-04-24 14:30", "2026-04-24 2pm"
//
// Friendly forms are converted to UTC so downstream comparisons stay in a
// single zone.
func parseTimeRef(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	if strings.EqualFold(s, "now") {
		return time.Now().UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, ok := parseFriendlyTime(s); ok {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("not a valid time: %q (try '2pm today', '14:30', '2026-04-24T13:48:35Z', or 'now')", s)
}

// parseFriendlyTime handles the human-friendly inputs listed on parseTimeRef.
// Returns (time in local zone, true) on success. Day words ("today",
// "yesterday", "tomorrow") anchor the clock; an explicit YYYY-MM-DD overrides.
func parseFriendlyTime(s string) (time.Time, bool) {
	now := time.Now()
	low := strings.ToLower(s)
	dayOffset := 0
	switch {
	case strings.Contains(low, "today"):
		low = strings.ReplaceAll(low, "today", " ")
	case strings.Contains(low, "yesterday"):
		dayOffset = -1
		low = strings.ReplaceAll(low, "yesterday", " ")
	case strings.Contains(low, "tomorrow"):
		dayOffset = 1
		low = strings.ReplaceAll(low, "tomorrow", " ")
	}

	var datePart, timePart string
	for _, p := range strings.Fields(low) {
		if looksLikeDate(p) {
			datePart = p
		} else if timePart == "" {
			timePart = p
		} else {
			timePart += p // glue "2 pm" -> "2pm"
		}
	}

	anchor := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	anchor = anchor.AddDate(0, 0, dayOffset)
	if datePart != "" {
		d, err := time.ParseInLocation("2006-01-02", datePart, time.Local)
		if err != nil {
			return time.Time{}, false
		}
		anchor = d
	}

	if timePart == "" {
		if datePart == "" {
			return time.Time{}, false
		}
		return anchor, true
	}

	h, m, sec, ok := parseClock(timePart)
	if !ok {
		return time.Time{}, false
	}
	return time.Date(anchor.Year(), anchor.Month(), anchor.Day(), h, m, sec, 0, time.Local), true
}

func looksLikeDate(s string) bool {
	// YYYY-MM-DD
	if len(s) == 10 && s[4] == '-' && s[7] == '-' {
		_, err := time.Parse("2006-01-02", s)
		return err == nil
	}
	return false
}

// parseClock accepts "14", "14:30", "14:30:45", "2pm", "2:30pm", "2:30:45pm",
// and the "am" variants. Case-insensitive; whitespace already stripped.
func parseClock(s string) (h, m, sec int, ok bool) {
	low := strings.ToLower(strings.TrimSpace(s))
	ampm := ""
	switch {
	case strings.HasSuffix(low, "am"):
		ampm = "am"
		low = strings.TrimSpace(strings.TrimSuffix(low, "am"))
	case strings.HasSuffix(low, "pm"):
		ampm = "pm"
		low = strings.TrimSpace(strings.TrimSuffix(low, "pm"))
	}
	parts := strings.Split(low, ":")
	if len(parts) < 1 || len(parts) > 3 {
		return 0, 0, 0, false
	}
	hh, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, false
	}
	if len(parts) > 1 {
		m, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, 0, false
		}
	}
	if len(parts) > 2 {
		sec, err = strconv.Atoi(parts[2])
		if err != nil {
			return 0, 0, 0, false
		}
	}
	switch ampm {
	case "am":
		if hh == 12 {
			hh = 0
		}
		if hh < 0 || hh > 11 {
			return 0, 0, 0, false
		}
	case "pm":
		if hh == 12 {
			// 12pm stays 12
		} else if hh >= 1 && hh <= 11 {
			hh += 12
		} else {
			return 0, 0, 0, false
		}
	}
	if hh < 0 || hh > 23 || m < 0 || m > 59 || sec < 0 || sec > 59 {
		return 0, 0, 0, false
	}
	return hh, m, sec, true
}

// defaultLogTypes lists the per-type subdirectories triage scans by default.
// "alerts" is included so rule_match events show up in the timeline without
// the user having to ask for them explicitly.
var defaultLogTypes = []string{"network", "files", "auth", "processes", "traffic", "meta", "errors", "alerts"}

// findPivots scans recent logs for events matching the given criteria and
// returns them sorted chronologically.
func findPivots(base, fileMatch string, pidMatch int, grep, typ string, maxN, days int) []Event {
	types := defaultLogTypes
	if typ != "" {
		types = []string{typ}
	} else if fileMatch != "" {
		// File searches almost always want file events; put them first.
		types = []string{"files", "network", "processes", "auth", "traffic", "meta", "errors", "alerts"}
	}

	var re *regexp.Regexp
	if grep != "" {
		var err error
		re, err = regexp.Compile(grep)
		if err != nil {
			fatalf("--grep: invalid regex: %v", err)
		}
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	var out []Event
	for _, t := range types {
		paths := listLogFilesForType(base, t)
		// Iterate newest-first by reversing the date-ordered list.
		for i := len(paths) - 1; i >= 0; i-- {
			path := paths[i]
			d := dateFromLogName(filepath.Base(path))
			if d.IsZero() || d.Before(cutoff) {
				continue
			}
			f, err := openLogReader(path)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			for scanner.Scan() {
				line := scanner.Text()
				if fileMatch != "" && !strings.Contains(line, fileMatch) {
					continue
				}
				if re != nil && !re.MatchString(line) {
					continue
				}
				var data map[string]any
				if err := json.Unmarshal([]byte(line), &data); err != nil {
					continue
				}
				if pidMatch != 0 && !numEquals(data["pid"], pidMatch) {
					continue
				}
				if !passesFieldFilters(data) {
					continue
				}
				if fileMatch != "" {
					if p, ok := data["path"].(string); ok && !strings.Contains(p, fileMatch) {
						if _, hasPath := data["path"]; hasPath {
							continue
						}
					}
				}
				ts := parseEventTS(data)
				if ts.IsZero() {
					continue
				}
				out = append(out, Event{TS: ts, Type: t, Raw: line, Data: data})
				if len(out) >= maxN {
					f.Close()
					goto done
				}
			}
			f.Close()
		}
	}
done:
	sort.Slice(out, func(i, j int) bool { return out[i].TS.Before(out[j].TS) })
	return out
}

// loadEventsInRange returns every log event in [start,end] sorted by
// timestamp. If typeFilter is non-empty, only events of that type are
// returned. Reads .jsonl, .jsonl.gz, and rotated .jsonl.N chunks
// transparently via openLogReader.
func loadEventsInRange(base string, start, end time.Time, typeFilter string) []Event {
	types := defaultLogTypes
	if typeFilter != "" {
		types = []string{typeFilter}
	}
	startDay := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC)
	endDay := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, time.UTC)
	var out []Event
	for _, t := range types {
		for _, path := range listLogFilesForType(base, t) {
			d := dateFromLogName(filepath.Base(path))
			if d.IsZero() || d.Before(startDay) || d.After(endDay) {
				continue
			}
			f, err := openLogReader(path)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			for scanner.Scan() {
				line := scanner.Text()
				var data map[string]any
				if err := json.Unmarshal([]byte(line), &data); err != nil {
					continue
				}
				ts := parseEventTS(data)
				if ts.IsZero() || ts.Before(start) || ts.After(end) {
					continue
				}
				out = append(out, Event{TS: ts, Type: t, Raw: line, Data: data})
			}
			f.Close()
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS.Before(out[j].TS) })
	return out
}

func parseEventTS(data map[string]any) time.Time {
	s, _ := data["ts"].(string)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

func formatDelta(d time.Duration) string {
	ms := d.Milliseconds()
	switch {
	case ms == 0:
		return "       0ms"
	case ms > 0:
		return fmt.Sprintf("   +%5dms", ms)
	default:
		return fmt.Sprintf("   %6dms", ms)
	}
}

func numEquals(v any, n int) bool {
	switch x := v.(type) {
	case float64:
		return int(x) == n
	case int:
		return x == n
	case int64:
		return int(x) == n
	case int32:
		return int(x) == n
	}
	return false
}

// eventSummary formats a concise, type-aware one-liner so triage output is
// scannable without reading every raw JSON line.
func eventSummary(e Event) string {
	ev := strField(e.Data, "event")
	switch e.Type {
	case "network":
		remote := strField(e.Data, "remote")
		host := strField(e.Data, "remote_host")
		user := strField(e.Data, "user")
		proc := strField(e.Data, "process")

		// Target: prefer reverse-DNS; fall back to cmdline-extracted hints.
		if host == "" {
			if hosts, ok := e.Data["cmdline_hosts"].([]any); ok && len(hosts) > 0 {
				var parts []string
				for _, h := range hosts {
					if s, ok := h.(string); ok {
						parts = append(parts, s)
					}
				}
				if len(parts) > 0 {
					host = strings.Join(parts, ",") + " (cmdline)"
				}
			}
		}
		target := renderTarget(host, remote)

		// Actor: prefer user/process; fall back to bare pid if the OS didn't
		// give us an owner (common for very short-lived children, kernel
		// sockets, or connections from another container's namespace).
		actor := ""
		switch {
		case user != "" && proc != "":
			actor = fmt.Sprintf("%s/%s", user, proc)
		case proc != "":
			actor = proc
		case user != "":
			actor = user
		}
		if pid := numField(e.Data, "pid"); pid > 0 {
			if actor == "" {
				actor = fmt.Sprintf("pid=%d (owner unknown)", pid)
			} else {
				actor = fmt.Sprintf("%s pid=%d", actor, pid)
			}
		}
		if actor == "" {
			actor = "(no owner)"
		}

		// Append a short cmdline when available — this is what turns a bare
		// IP into "oh, that was curl -o foo https://...".
		cmdTail := ""
		if cmd, ok := e.Data["cmdline"].([]any); ok && len(cmd) > 0 {
			var parts []string
			for _, c := range cmd {
				if s, ok := c.(string); ok {
					parts = append(parts, s)
				}
			}
			joined := strings.Join(parts, " ")
			if len(joined) > 80 {
				joined = joined[:77] + "..."
			}
			if joined != "" {
				cmdTail = " [" + joined + "]"
			}
		}

		if target == "" {
			return fmt.Sprintf("%s by %s%s", ev, actor, cmdTail)
		}
		return fmt.Sprintf("%s %s by %s%s", ev, target, actor, cmdTail)
	case "files":
		user := strField(e.Data, "user")
		if user == "" {
			if uid := numField(e.Data, "uid"); uid > 0 {
				user = fmt.Sprintf("uid=%d", uid)
			}
		}
		by := ""
		if user != "" {
			by = " by " + user
		}
		if dst := strField(e.Data, "dest"); dst != "" {
			return fmt.Sprintf("%s %s -> %s%s", ev, strField(e.Data, "path"), dst, by)
		}
		return fmt.Sprintf("%s %s%s", ev, strField(e.Data, "path"), by)
	case "auth":
		switch ev {
		case "ssh_login":
			return fmt.Sprintf("ssh_login %s user=%s from %s:%s method=%s",
				strField(e.Data, "result"), strField(e.Data, "user"),
				strField(e.Data, "remote"), strField(e.Data, "port"),
				strField(e.Data, "method"))
		case "ssh_disconnect":
			return fmt.Sprintf("ssh_disconnect user=%s from %s:%s",
				strField(e.Data, "user"), strField(e.Data, "remote"), strField(e.Data, "port"))
		case "sudo":
			cmd := strField(e.Data, "command")
			if cmd == "" {
				return fmt.Sprintf("sudo %s user=%s",
					strField(e.Data, "result"), strField(e.Data, "user"))
			}
			return fmt.Sprintf("sudo %s by %s -> %s: %s",
				strField(e.Data, "result"), strField(e.Data, "user"),
				strField(e.Data, "target"), cmd)
		case "su":
			return fmt.Sprintf("su %s by %s -> %s",
				strField(e.Data, "result"), strField(e.Data, "user"), strField(e.Data, "target"))
		}
		return fmt.Sprintf("%s user=%s terminal=%s host=%s",
			ev, strField(e.Data, "user"), strField(e.Data, "terminal"), strField(e.Data, "host"))
	case "processes":
		parent := strField(e.Data, "parent_name")
		ppid := numField(e.Data, "ppid")
		suffix := ""
		switch {
		case parent != "" && ppid > 0:
			suffix = fmt.Sprintf(" parent=%s(%d)", parent, ppid)
		case ppid > 0:
			suffix = fmt.Sprintf(" ppid=%d", ppid)
		}
		return fmt.Sprintf("%s pid=%v %s user=%s%s",
			ev, e.Data["pid"], strField(e.Data, "name"), strField(e.Data, "user"), suffix)
	case "traffic":
		if ev == "host_io" {
			base := fmt.Sprintf("host_io sent=%s recv=%s",
				formatBytes(e.Data["bytes_sent"]),
				formatBytes(e.Data["bytes_recv"]))
			if dests := formatDestinations(e.Data["destinations"], 5); dests != "" {
				base += " -> " + dests
			}
			return base
		}
		if ev == "active_connection" {
			user := strField(e.Data, "user")
			proc := strField(e.Data, "process")
			remote := strField(e.Data, "remote")
			host := strField(e.Data, "remote_host")
			target := remote
			if host != "" && remote != "" {
				target = fmt.Sprintf("%s (%s)", host, remote)
			} else if host != "" {
				target = host
			}
			who := ""
			switch {
			case user != "" && proc != "":
				who = user + "/" + proc
			case proc != "":
				who = proc
			case user != "":
				who = user
			default:
				who = "(no owner)"
			}
			suffix := ""
			if count := numField(e.Data, "count"); count > 1 {
				suffix = fmt.Sprintf(" ×%d", count)
			}
			return fmt.Sprintf("active_connection %s -> %s%s", who, target, suffix)
		}
		return fmt.Sprintf("%s user=%s proc=%s conns=%v",
			ev, strField(e.Data, "user"), strField(e.Data, "process"), e.Data["connections"])
	case "meta":
		return ev
	case "errors":
		return fmt.Sprintf("%s: %s", strField(e.Data, "collector"), strField(e.Data, "error"))
	case "marker":
		return "(time marker)"
	case "alerts":
		sev := strField(e.Data, "severity")
		if sev == "" {
			sev = "?"
		}
		base := fmt.Sprintf("[%s] rule=%s on %s/%s",
			sev,
			strField(e.Data, "rule"),
			strField(e.Data, "matched_type"),
			strField(e.Data, "matched_event"))
		if count := numField(e.Data, "count"); count > 0 {
			base += fmt.Sprintf(" (%d in %s", count, strField(e.Data, "window"))
			if gv := strField(e.Data, "group_value"); gv != "" {
				base += fmt.Sprintf(" by %s=%s", strField(e.Data, "group_by"), gv)
			}
			base += ")"
		}
		return base
	}
	return ev
}

func strField(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

// numField returns the numeric value of m[k] as int64, coercing from any of
// the forms JSON unmarshalling produces (float64 being the default for
// numbers in a map[string]any).
func numField(m map[string]any, k string) int64 {
	switch v := m[k].(type) {
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case int64:
		return v
	case int32:
		return int64(v)
	case uint64:
		return int64(v)
	}
	return 0
}

// providerLabel maps a hostname to a human-recognisable provider name based
// on well-known reverse-DNS suffixes. Returns "" when no rule matches. The
// goal is to turn opaque PTR records like ym-in-f113.1e100.net into "Google"
// at a glance — not to be exhaustive. Add suffixes here as new providers
// show up in real traffic.
func providerLabel(host string) string {
	h := strings.ToLower(host)
	suffixes := []struct {
		suf, label string
	}{
		{".1e100.net", "Google"},
		{".googleusercontent.com", "Google"},
		{".googlevideo.com", "Google (YouTube)"},
		{".gstatic.com", "Google"},
		{".google.com", "Google"},
		{".doubleclick.net", "Google Ads"},
		{".youtube.com", "Google (YouTube)"},
		{".ytimg.com", "Google (YouTube)"},
		{".amazonaws.com", "AWS"},
		{".compute.amazonaws.com", "AWS EC2"},
		{".cloudfront.net", "AWS CloudFront"},
		{".s3.amazonaws.com", "AWS S3"},
		{".cloudflare.com", "Cloudflare"},
		{".cloudflare.net", "Cloudflare"},
		{".cloudflare-dns.com", "Cloudflare DNS"},
		{".akamai.net", "Akamai"},
		{".akamaized.net", "Akamai"},
		{".akamaiedge.net", "Akamai"},
		{".akamaihd.net", "Akamai"},
		{".fbcdn.net", "Meta/Facebook"},
		{".facebook.com", "Meta/Facebook"},
		{".instagram.com", "Meta/Instagram"},
		{".whatsapp.net", "Meta/WhatsApp"},
		{".apple.com", "Apple"},
		{".icloud.com", "Apple iCloud"},
		{".mzstatic.com", "Apple"},
		{".microsoft.com", "Microsoft"},
		{".msft.net", "Microsoft"},
		{".azure.com", "Microsoft Azure"},
		{".azureedge.net", "Microsoft Azure"},
		{".windows.net", "Microsoft Azure"},
		{".windowsupdate.com", "Microsoft Update"},
		{".office.com", "Microsoft 365"},
		{".office365.com", "Microsoft 365"},
		{".live.com", "Microsoft"},
		{".github.com", "GitHub"},
		{".githubusercontent.com", "GitHub"},
		{".githubassets.com", "GitHub"},
		{".gitlab.com", "GitLab"},
		{".bitbucket.org", "Bitbucket"},
		{".ubuntu.com", "Canonical/Ubuntu"},
		{".canonical.com", "Canonical/Ubuntu"},
		{".launchpad.net", "Canonical/Ubuntu"},
		{".debian.org", "Debian"},
		{".redhat.com", "Red Hat"},
		{".fedoraproject.org", "Fedora"},
		{".centos.org", "CentOS"},
		{".archlinux.org", "Arch Linux"},
		{".docker.io", "Docker Hub"},
		{".docker.com", "Docker"},
		{".npmjs.com", "npm Registry"},
		{".npmjs.org", "npm Registry"},
		{".pypi.org", "PyPI"},
		{".pythonhosted.org", "PyPI"},
		{".rubygems.org", "RubyGems"},
		{".crates.io", "crates.io"},
		{".digitalocean.com", "DigitalOcean"},
		{".linode.com", "Linode"},
		{".oraclecloud.com", "Oracle Cloud"},
		{".oracle.com", "Oracle"},
		{".heroku.com", "Heroku"},
		{".herokuapp.com", "Heroku"},
		{".vercel.app", "Vercel"},
		{".netlify.app", "Netlify"},
		{".cloudflareinsights.com", "Cloudflare"},
		{".fastly.net", "Fastly"},
		{".fastlylb.net", "Fastly"},
		{".stackoverflow.com", "Stack Overflow"},
		{".reddit.com", "Reddit"},
		{".twitter.com", "Twitter/X"},
		{".x.com", "Twitter/X"},
		{".discord.com", "Discord"},
		{".discord.gg", "Discord"},
		{".slack.com", "Slack"},
		{".zoom.us", "Zoom"},
		{".dropbox.com", "Dropbox"},
		{".anthropic.com", "Anthropic"},
		{".openai.com", "OpenAI"},
	}
	for _, s := range suffixes {
		if h == s.suf[1:] || strings.HasSuffix(h, s.suf) {
			return s.label
		}
	}
	return ""
}

// renderTarget formats a remote destination for human display. When the
// hostname matches a known provider, the provider name leads — the original
// PTR is kept in parens so forensics still has it. Empty inputs return "".
func renderTarget(host, remote string) string {
	if host == "" && remote == "" {
		return ""
	}
	if host == "" {
		return remote + " (no PTR)"
	}
	label := providerLabel(host)
	if label != "" {
		if remote != "" {
			return fmt.Sprintf("%s [%s] (%s)", label, host, remote)
		}
		return fmt.Sprintf("%s [%s]", label, host)
	}
	if remote != "" {
		return fmt.Sprintf("%s (%s)", host, remote)
	}
	return host
}

// formatDestinations renders host_io's embedded flow list as
// "proc/host (×N), proc2/host2 (×M), ... (+K more)". Each entry collapses
// user/process and remote/remote_host the way the active_connection summary
// does so the two look consistent. Sorted by count desc so the noisiest
// talkers show first. top bounds how many distinct entries are listed.
func formatDestinations(v any, top int) string {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return ""
	}
	type dest struct {
		label string
		count int64
	}
	dests := make([]dest, 0, len(list))
	for _, item := range list {
		d, ok := item.(map[string]any)
		if !ok {
			continue
		}
		user := strField(d, "user")
		proc := strField(d, "process")
		remote := strField(d, "remote")
		host := strField(d, "remote_host")
		who := ""
		switch {
		case user != "" && proc != "":
			who = user + "/" + proc
		case proc != "":
			who = proc
		case user != "":
			who = user
		}
		target := renderTarget(host, remote)
		label := target
		if who != "" {
			label = who + " -> " + target
		}
		dests = append(dests, dest{label: label, count: numField(d, "count")})
	}
	if len(dests) == 0 {
		return ""
	}
	sort.Slice(dests, func(i, j int) bool { return dests[i].count > dests[j].count })
	shown := dests
	extra := 0
	if top > 0 && len(dests) > top {
		shown = dests[:top]
		extra = len(dests) - top
	}
	parts := make([]string, 0, len(shown))
	for _, d := range shown {
		if d.count > 1 {
			parts = append(parts, fmt.Sprintf("%s ×%d", d.label, d.count))
		} else {
			parts = append(parts, d.label)
		}
	}
	s := strings.Join(parts, ", ")
	if extra > 0 {
		s += fmt.Sprintf(" (+%d more)", extra)
	}
	return s
}

// formatBytes renders an int-like count of bytes as human-readable KB/MB/GB.
// Avoids Go's default scientific-notation formatting of large float64s.
func formatBytes(v any) string {
	n := numField(map[string]any{"n": v}, "n")
	if n < 0 {
		n = 0
	}
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
