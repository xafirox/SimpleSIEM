package sieg

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// runTail follows live events as they're appended to the daily JSONL files
// and prints them. The default output uses the same eventSummary formatter
// as triage, with severity-coloured rows for alerts when stdout is a TTY.
// --json emits raw lines for piping into jq, Splunk HEC, etc.
//
// Implementation: per-type file handle, polled every 250ms. Reopens on date
// rollover and on size-cap rotation (filename matches but inode changed).
func runTail(args []string) {
	fs := flag.NewFlagSet("tail", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	typFlag := fs.String("type", "", "comma-separated log types (default: all)")
	grepFlag := fs.String("grep", "", "regex filter on raw JSON line")
	jsonOut := fs.Bool("json", false, "emit raw JSONL instead of formatted lines")
	alertsOnly := fs.Bool("alerts", false, "shorthand for --type alerts")
	noColor := fs.Bool("no-color", false, "disable ANSI colour even on a TTY")
	hostFilter := fs.String("host", "", "in server mode, restrict to one agent ID")
	_ = fs.Parse(args)
	if *noColor {
		disableColor()
	}

	cfg := loadConfig(*cfgPath)
	base := cfg.LogDir
	if _, err := os.Stat(base); err != nil {
		fmt.Fprintln(os.Stderr, "no logs at", base)
		os.Exit(1)
	}
	roots := searchRoots(cfg, *hostFilter)

	var types []string
	switch {
	case *alertsOnly:
		types = []string{"alerts"}
	case *typFlag != "":
		for _, t := range strings.Split(*typFlag, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				types = append(types, t)
			}
		}
	default:
		seen := map[string]struct{}{}
		for _, r := range roots {
			entries, _ := os.ReadDir(r.base)
			for _, e := range entries {
				if e.IsDir() {
					if _, ok := seen[e.Name()]; !ok {
						seen[e.Name()] = struct{}{}
						types = append(types, e.Name())
					}
				}
			}
		}
		sort.Strings(types)
	}
	if len(types) == 0 {
		fmt.Fprintln(os.Stderr, "no log types found under", base)
		os.Exit(1)
	}

	var re *regexp.Regexp
	if *grepFlag != "" {
		var err error
		re, err = regexp.Compile(*grepFlag)
		if err != nil {
			fatalf("--grep: %v", err)
		}
	}

	// One tailReader per (root, type). In server mode this means multiple
	// readers for the same type — one per host. tailReader keys are
	// composite so they don't collide.
	type key struct {
		base string
		host string
		typ  string
	}
	tailers := map[key]*tailReader{}
	for _, r := range roots {
		for _, t := range types {
			tailers[key{r.base, r.host, t}] = &tailReader{base: r.base, host: r.host, logType: t}
		}
	}

	// Print a small header so users know what they're following.
	scope := strings.Join(types, ", ")
	if cfg.Mode == "server" && *hostFilter == "" {
		scope += " (all hosts)"
	} else if *hostFilter != "" {
		scope += " (host=" + *hostFilter + ")"
	}
	fmt.Fprintf(os.Stderr, "tailing: %s  (times in %s)\n", scope, displayTZ())

	// Agent-mode tail returns near-empty by default — every collector
	// event ships to the server over mTLS, so on the agent host only
	// `_agent` meta/errors live locally. Without this hint a first-
	// time user runs `tail`, sees nothing flow even while opening
	// browser tabs to google.com (the as7-test scenario), and
	// reasonably assumes the agent stopped collecting. Print to
	// stderr so the warning doesn't pollute pipelines reading stdout.
	if normaliseMode(cfg.Mode) == "agent" && *hostFilter != "_agent" {
		hostname, _ := os.Hostname()
		id := cfg.Agent.ID
		if id == "" {
			id = hostname
		}
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Note: this host is in AGENT mode. Collected events ship to the server")
		fmt.Fprintln(os.Stderr, "over mTLS, so this `tail` mostly shows _agent lifecycle / shipping")
		fmt.Fprintln(os.Stderr, "diagnostics. To see live collector events for this host:")
		fmt.Fprintln(os.Stderr, "  - on the SERVER:  simplesiem tail --host", id)
		fmt.Fprintln(os.Stderr, "  - locally only:   simplesiem tail --host _agent")
		fmt.Fprintln(os.Stderr)
	}

	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for range tick.C {
		for _, tr := range tailers {
			tr.poll(re, *jsonOut)
		}
	}
}

type tailReader struct {
	base    string
	host    string // optional, for server-mode display
	logType string

	f   *os.File
	day string
}

func (t *tailReader) poll(re *regexp.Regexp, jsonOut bool) {
	today := time.Now().UTC().Format("2006-01-02")
	if t.f == nil || t.day != today {
		if t.f != nil {
			t.f.Close()
			t.f = nil
		}
		path := filepath.Join(t.base, t.logType, today+".jsonl")
		f, err := os.Open(path)
		if err != nil {
			return // file may not exist yet; try next tick
		}
		// First open of a daily file: seek to end so we don't replay the
		// whole day. After that, stay at last read position.
		if t.day == "" {
			_, _ = f.Seek(0, io.SeekEnd)
		}
		t.f = f
		t.day = today
	}
	scanner := bufio.NewScanner(t.f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if re != nil && !re.Match(line) {
			continue
		}
		if jsonOut {
			os.Stdout.Write(line)
			os.Stdout.Write([]byte{'\n'})
			continue
		}
		t.printPretty(line)
	}
}

func (t *tailReader) printPretty(line []byte) {
	var data map[string]any
	if err := json.Unmarshal(line, &data); err != nil {
		fmt.Println(string(line))
		return
	}
	ts := parseEventTS(data)
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	ev := Event{TS: ts, Type: t.logType, Raw: string(line), Data: data}
	summary := eventSummary(ev)
	// Per-line timestamp in HOST-LOCAL time (displayTS) with the TZ
	// abbreviation appended. The header at startup already says "times
	// in <TZ>" but operators piping `tail` into a file or scrolling
	// past the header read the per-line column directly, and users
	// flagged it as "not in local time" because there was no TZ
	// marker on each line. Now every row carries it.
	tsCol := displayTS(ts).Format("15:04:05.000") + " " + displayTZ()
	hostCol := ""
	if t.host != "" {
		hostCol = fmt.Sprintf("%-12s ", t.host)
	}
	prefix := fmt.Sprintf("%s  %s%-9s  ", tsCol, hostCol, t.logType)
	// Visual indicators for syslog frames: [UNAUTH] for unauthenticated
	// frames stored in the quarantine bucket; [ATTACK] when the
	// attack-pattern detector flagged the frame. Indicators are
	// independent — a frame can have both.
	if t.logType == "syslog" {
		auth, ok := data["authenticated"].(bool)
		if ok && !auth {
			summary = colorize("[UNAUTH] ", colYellow) + summary
		}
		if _, has := data["attack_indicators"]; has {
			summary = colorize("[ATTACK] ", colRed) + summary
		}
	}
	if t.logType == "alerts" {
		sev, _ := data["severity"].(string)
		if code := severityColor(sev); code != "" {
			summary = colorize(summary, code)
		}
	} else if t.logType == "errors" {
		summary = colorize(summary, colRed)
	} else if t.logType == "meta" {
		summary = colorize(summary, colDim)
	}
	fmt.Println(prefix + summary)
}
