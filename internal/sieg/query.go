package sieg

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// safeIsRunning calls the OS-specific isRunning helper but recovers if it
// panics — the helper is best-effort by design and not all install layouts
// are recognised. Only used by the status command.
func safeIsRunning() (running bool) {
	defer func() { _ = recover() }()
	return isRunning()
}

// showRecentServerErrors prints up to maxN recent entries from
// <log_dir>/_server/errors/<today>.jsonl so an operator running
// `simplesiem status` against a server that isn't accepting events sees
// the rejection reasons (allowlist, auth, decode, CN mismatch) inline.
// Silent if there's nothing to show — this is diagnostic noise only
// when there's a problem.
// agentOutageState scans the agent's local meta log for the most recent
// server_unreachable_started and server_recovered entries and returns
// their timestamps + the reason from the most recent unreachable_started.
// The fourth return value is false if the meta log can't be opened (fresh
// install, log rotated, etc.).
//
// Scope is the CURRENT daemon session — events older than the most
// recent `meta:start` (= this daemon instance's startup) are ignored.
// Without that scope, a stale server_unreachable_started from a
// previous daemon's graceful shutdown (where the in-flight send is
// "context canceled" by the shutdown signal) would make the new
// daemon's status falsely report DEGRADED forever.
//
// Used by `status` to surface the agent's current link health: if the
// last unreachable start has no matching recovered, the agent is in
// quasi-standalone mode RIGHT NOW; the reason text helps the operator
// see whether it's a network problem, cert problem, or allowlist
// problem without having to dig through logs.
func agentOutageState(base string) (start, recovered time.Time, reason string, ok bool) {
	today := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(base, "_agent", "meta", today+".jsonl")
	r, err := openLogReader(path)
	if err != nil {
		return time.Time{}, time.Time{}, "", false
	}
	defer r.Close()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var sessionStart time.Time
	for scanner.Scan() {
		var obj map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &obj); err != nil {
			continue
		}
		ev, _ := obj["event"].(string)
		ts, _ := obj["ts"].(string)
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		// Track the most recent daemon session marker; reset all
		// outage state on each new session start so events from a
		// previous instance don't bleed into the current view.
		if ev == "start" {
			sessionStart = t
			start = time.Time{}
			recovered = time.Time{}
			reason = ""
			continue
		}
		// Only consider transitions that happened within the current
		// session (i.e., after the most recent start event).
		if !sessionStart.IsZero() && t.Before(sessionStart) {
			continue
		}
		switch ev {
		case "server_unreachable_started":
			start = t
			if r, _ := obj["reason"].(string); r != "" {
				reason = r
			}
		case "server_recovered":
			recovered = t
		}
	}
	// If still degraded, also include the most recent shipper send
	// error from today's errors log — that picks up any failure-mode
	// CHANGE that happened after the initial outage_started log line
	// (e.g., started as connection-refused, then turned into a TLS or
	// 403 error).
	if !start.IsZero() && start.After(recovered) {
		if r2 := lastShipperError(base); r2 != "" {
			reason = r2
		}
	}
	return start, recovered, reason, true
}

// daemonLooksWedged returns (true, "<duration>") when the daemon claims
// to be running but the most recent write to any of the canonical meta
// directories is older than 5 minutes. That's a strong signal of the
// "kill -9 + restart but nothing actually came back" failure mode —
// status used to say "running" cheerfully even when the daemon was
// dead and only its PID file lingered. Now we cross-check against
// fresh disk activity so the operator sees a red SILENT label instead.
//
// The 5-minute floor is generous: even an idle agent should write a
// meta heartbeat or a process collector cycle within that window.
func daemonLooksWedged(cfg Config) (bool, string) {
	mode := normaliseMode(cfg.Mode)
	candidates := []string{
		filepath.Join(cfg.LogDir, "meta"),
	}
	switch mode {
	case "agent":
		candidates = append(candidates, filepath.Join(cfg.LogDir, "_agent", "meta"))
	case "server":
		candidates = append(candidates, filepath.Join(cfg.LogDir, "_server", "meta"))
	}
	today := time.Now().UTC().Format("2006-01-02")
	mostRecent := time.Time{}
	for _, dir := range candidates {
		path := filepath.Join(dir, today+".jsonl")
		if info, err := os.Stat(path); err == nil {
			if info.ModTime().After(mostRecent) {
				mostRecent = info.ModTime()
			}
		}
	}
	if mostRecent.IsZero() {
		// No file at all — could be a fresh boot. Don't accuse.
		return false, ""
	}
	age := time.Since(mostRecent)
	if age > 5*time.Minute {
		return true, age.Round(time.Second).String()
	}
	return false, ""
}

// lastShipperError returns the most recent agent_shipper error message
// from today's errors log, or "" if none. Used by agentOutageState.
func lastShipperError(base string) string {
	today := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(base, "_agent", "errors", today+".jsonl")
	r, err := openLogReader(path)
	if err != nil {
		return ""
	}
	defer r.Close()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var last string
	for scanner.Scan() {
		var obj map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &obj); err != nil {
			continue
		}
		col, _ := obj["collector"].(string)
		if col != "agent_shipper" && col != "agent_heartbeat" {
			continue
		}
		if e, _ := obj["error"].(string); e != "" {
			last = e
		}
	}
	return last
}

func showRecentServerErrors(base string, maxN int) {
	today := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(base, "_server", "errors", today+".jsonl")
	r, err := openLogReader(path)
	if err != nil {
		return
	}
	defer r.Close()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) == 0 {
		return
	}
	if len(lines) > maxN {
		lines = lines[len(lines)-maxN:]
	}
	fmt.Println()
	fmt.Printf("recent _server/errors (last %d, today only):\n", len(lines))
	for _, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		ts, _ := obj["ts"].(string)
		errMsg, _ := obj["error"].(string)
		// Trim trailing-Z and milliseconds for compactness.
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			ts = displayTS(t).Format("15:04:05")
		}
		fmt.Printf("  %s  %s\n", ts, errMsg)
	}
}

func parseSince(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	last := s[len(s)-1]
	if last >= 'a' && last <= 'z' {
		units := map[byte]time.Duration{
			's': time.Second, 'm': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour,
		}
		if unit, ok := units[last]; ok {
			if n, err := strconv.Atoi(s[:len(s)-1]); err == nil {
				return time.Now().UTC().Add(-time.Duration(n) * unit), nil
			}
		}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid --since: %q (use 30m, 2h, 7d, or RFC3339)", s)
}

func runQuery(args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	typ := fs.String("type", "", "log type: network/files/auth/processes/traffic/meta/errors/alerts")
	since := fs.String("since", "", "relative (1h, 30m, 7d) or RFC3339 timestamp")
	until := fs.String("until", "", "upper bound: 'now', RFC3339, '2pm today', '14:30', '2026-04-24 2pm'")
	grep := fs.String("grep", "", "regex filter on raw JSON line")
	limit := fs.Int("limit", 0, "max lines emitted (0 = no limit)")
	hostFilter := fs.String("host", "", "in server mode, restrict to one agent ID")
	var fieldFlags fieldFilterList
	fs.Var(&fieldFlags, "field", "structured filter, e.g. --field path=*=authorized_keys (repeatable)")
	dedupe := fs.Bool("dedupe", false, "drop duplicate events by _hash (useful in master mode where realms replicate the same event into multiple from-<peer>.jsonl files)")
	format := fs.String("format", "json", "output format: json (one-line-per-event NDJSON, default), csv, or tsv")
	csvFields := fs.String("csv-fields", "", "comma-separated field list for csv/tsv output (default: ts,type,host,event)")
	_ = fs.Parse(args)
	fields := fieldFlags.compiled()
	var seen map[string]struct{}
	if *dedupe {
		seen = map[string]struct{}{}
	}
	// Validate --format / --csv-fields up-front so a typo fails before
	// the operator sees half a corpus dump.
	switch *format {
	case "json", "csv", "tsv":
	default:
		fmt.Fprintf(os.Stderr, "--format must be one of: json, csv, tsv\n")
		os.Exit(2)
	}
	csvCols := []string{"ts", "type", "host", "event"}
	if strings.TrimSpace(*csvFields) != "" {
		csvCols = strings.Split(*csvFields, ",")
		for i := range csvCols {
			csvCols[i] = strings.TrimSpace(csvCols[i])
		}
	}

	cfg := loadConfig(*cfgPath)
	base := cfg.LogDir
	if _, err := os.Stat(base); err != nil {
		fmt.Fprintln(os.Stderr, "no logs at", base)
		return
	}
	roots := searchRoots(cfg, *hostFilter)
	var types []string
	if *typ != "" {
		types = []string{*typ}
	} else {
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
	sinceT, err := parseSince(*since)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var untilT time.Time
	if *until != "" {
		untilT, err = parseTimeRef(*until)
		if err != nil {
			fmt.Fprintln(os.Stderr, "--until:", err)
			os.Exit(2)
		}
		if !sinceT.IsZero() && !untilT.After(sinceT) {
			fmt.Fprintln(os.Stderr, "--until must be after --since")
			os.Exit(2)
		}
	}
	var re *regexp.Regexp
	if *grep != "" {
		re, err = regexp.Compile(*grep)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}

	emitted := 0
	out := bufio.NewWriter(os.Stdout)
	// Defers run LIFO: out.Flush runs first so emitted stdout reaches
	// the terminal before the trailing agent-mode hint hits stderr.
	defer printAgentQueryHint(cfg, *hostFilter, &emitted)
	defer out.Flush()

	// CSV / TSV header row up-front so spreadsheets can autodetect.
	sep := ","
	if *format == "tsv" {
		sep = "\t"
	}
	if *format == "csv" || *format == "tsv" {
		for i, c := range csvCols {
			if i > 0 {
				out.WriteString(sep)
			}
			out.WriteString(csvEscape(c, *format))
		}
		out.WriteByte('\n')
	}

	for _, t := range types {
		var paths []string
		for _, r := range roots {
			paths = append(paths, listLogFilesForType(r.base, t)...)
		}
		for _, path := range paths {
			fileDate := dateFromLogName(filepath.Base(path))
			if fileDate.IsZero() {
				continue
			}
			if !sinceT.IsZero() {
				dayFloor := time.Date(sinceT.Year(), sinceT.Month(), sinceT.Day(), 0, 0, 0, 0, time.UTC)
				if fileDate.Before(dayFloor) {
					continue
				}
			}
			if !untilT.IsZero() {
				dayCeil := time.Date(untilT.Year(), untilT.Month(), untilT.Day(), 0, 0, 0, 0, time.UTC)
				if fileDate.After(dayCeil) {
					continue
				}
			}
			fh, err := openLogReader(path)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(fh)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			for scanner.Scan() {
				line := scanner.Bytes()
				if !sinceT.IsZero() || !untilT.IsZero() {
					var obj struct {
						TS string `json:"ts"`
					}
					if err := json.Unmarshal(line, &obj); err == nil {
						t, err := time.Parse(time.RFC3339Nano, obj.TS)
						if err != nil {
							t, err = time.Parse(time.RFC3339, obj.TS)
						}
						if err == nil {
							if !sinceT.IsZero() && t.Before(sinceT) {
								continue
							}
							if !untilT.IsZero() && t.After(untilT) {
								continue
							}
						}
					}
				}
				if re != nil && !re.Match(line) {
					continue
				}
				if len(fields) > 0 {
					var data map[string]any
					if err := json.Unmarshal(line, &data); err != nil {
						continue
					}
					ok := true
					for _, ff := range fields {
						if !ff.m.test(data[ff.key]) {
							ok = false
							break
						}
					}
					if !ok {
						continue
					}
				}
				if seen != nil {
					var hashOnly struct {
						Hash string `json:"_hash"`
					}
					if err := json.Unmarshal(line, &hashOnly); err == nil && hashOnly.Hash != "" {
						if _, dup := seen[hashOnly.Hash]; dup {
							continue
						}
						seen[hashOnly.Hash] = struct{}{}
					}
				}
				if *format == "csv" || *format == "tsv" {
					var ev map[string]any
					_ = json.Unmarshal(line, &ev)
					for i, c := range csvCols {
						if i > 0 {
							out.WriteString(sep)
						}
						out.WriteString(csvEscape(fieldString(ev[c]), *format))
					}
					out.WriteByte('\n')
				} else {
					out.Write(line)
					out.WriteByte('\n')
				}
				emitted++
				if *limit > 0 && emitted >= *limit {
					fh.Close()
					return
				}
			}
			fh.Close()
		}
	}
}

// printAgentQueryHint surfaces a useful hint when an operator runs
// `simplesiem query` on an agent host. In agent mode, every collected
// event ships to the server(s) over mTLS — the only local store is
// `_agent/` (lifecycle + shipping diagnostics). Without the hint, a
// first-time user runs `query`, sees little or nothing, and reasonably
// assumes the daemon is broken.
//
// Suppressed only when the operator explicitly asked for _agent
// diagnostics (`--host _agent`) — that's the one query that returns
// useful local data on an agent and doesn't need redirection to the
// server.
//
// Prints to stderr so pipelines that consume stdout aren't polluted.
func printAgentQueryHint(cfg Config, hostFilter string, emitted *int) {
	if normaliseMode(cfg.Mode) != "agent" {
		return
	}
	if hostFilter == "_agent" {
		return
	}
	hostname, _ := os.Hostname()
	id := cfg.Agent.ID
	if id == "" {
		id = hostname
	}
	servers := []string{}
	if cfg.Agent.ServerURL != "" {
		servers = append(servers, cfg.Agent.ServerURL)
	}
	servers = append(servers, cfg.Agent.FailoverServers...)
	fmt.Fprintln(os.Stderr)
	if *emitted == 0 {
		fmt.Fprintln(os.Stderr, "No events found locally — this host is in AGENT mode, so collected")
		fmt.Fprintln(os.Stderr, "events ship to the server(s) over mTLS instead of being stored here.")
	} else {
		fmt.Fprintf(os.Stderr, "Note: this host is in AGENT mode. The %d event(s) above are agent\n", *emitted)
		fmt.Fprintln(os.Stderr, "lifecycle / shipping diagnostics from `_agent/`. Collected events from")
		fmt.Fprintln(os.Stderr, "this host live on the server(s) below, not here.")
	}
	fmt.Fprintln(os.Stderr)
	if len(servers) == 0 {
		fmt.Fprintln(os.Stderr, "  agent.server_url is unset — no server is configured for this agent.")
		fmt.Fprintln(os.Stderr, "  Run: sudo simplesiem convert agent --server <url> --key <PSK>")
		return
	}
	fmt.Fprintln(os.Stderr, "Servers this agent ships to:")
	for _, s := range servers {
		fmt.Fprintln(os.Stderr, "  -", s)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "On any of those servers, run:\n  simplesiem query --host %s [--type ... --since ... --grep ...]\n", id)
	fmt.Fprintln(os.Stderr, "  (or `triage --host", id+"` for a timeline)")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Local diagnostics only (no server round-trip):")
	fmt.Fprintln(os.Stderr, "  simplesiem query --host _agent")
}

// csvEscape quotes a CSV/TSV field per RFC 4180 conventions: wrap in
// double quotes if the field contains the separator, a quote, or a
// newline; double up internal quotes. TSV is treated like CSV with a
// tab separator (technically TSV bans literal tabs in field values
// rather than quoting; we still quote-and-escape because operators
// import these into spreadsheets that handle CSV-style escaping).
func csvEscape(s, format string) string {
	sep := ","
	if format == "tsv" {
		sep = "\t"
	}
	if !strings.ContainsAny(s, sep+"\"\n\r") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		if r == '"' {
			b.WriteString(`""`)
		} else {
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	_ = fs.Parse(args)
	if *noColor {
		disableColor()
	}
	cfg := loadConfig(*cfgPath)
	base := cfg.LogDir

	// Daemon status: best-effort probe via the OS-specific isRunning helper.
	// Wrapped to swallow nil-pointer / not-installed cases gracefully.
	running := safeIsRunning()
	statusLabel := colorize("not running", colYellow)
	if running {
		statusLabel = colorize("running", colGreen)
		// Sanity-check: daemon claims running but has it ACTUALLY
		// written anything recently? If not, the operator is
		// looking at a zombie / wedged daemon, which is the most
		// confusing failure mode (status says fine, no events flow).
		if stale, since := daemonLooksWedged(cfg); stale {
			statusLabel = colorize("running but SILENT (no writes for "+since+")", colRed)
		}
	}
	fmt.Printf("daemon:         %s\n", statusLabel)
	fmt.Printf("mode:           %s\n", normaliseMode(cfg.Mode))
	fmt.Printf("log_dir:        %s\n", base)
	fmt.Printf("retention_days: %d\n", cfg.RetentionDays)
	if normaliseMode(cfg.Mode) == "agent" {
		// agent_id falls back to the local hostname when unset in config,
		// matching what the daemon uses at runtime. Showing blank here
		// confused operators into thinking enrollment didn't set it.
		id := cfg.Agent.ID
		if id == "" {
			if h, err := os.Hostname(); err == nil {
				id = h + "  (default: hostname)"
			}
		}
		fmt.Printf("agent_id:       %s\n", id)
		fmt.Printf("server_url:     %s\n", cfg.Agent.ServerURL)
		if len(cfg.Agent.FailoverServers) > 0 {
			fmt.Printf("failover:       %d peer(s) — %s\n",
				len(cfg.Agent.FailoverServers),
				strings.Join(cfg.Agent.FailoverServers, ", "))
		}
		// Surface degraded state by reading the most recent
		// server_unreachable_started / server_recovered pair from the
		// agent's local meta log. If unreachable is more recent (or
		// recovered is missing), the agent is currently in
		// quasi-standalone mode — call that out so an operator
		// running `simplesiem status` immediately sees the link is
		// down without having to triage the meta stream.
		if startTS, recoveredTS, reason, ok := agentOutageState(base); ok && !startTS.IsZero() {
			// Only meaningful when an outage has been seen at least
			// once today. A fresh agent that never had an outage shows
			// no link line (no news = healthy by default).
			if recoveredTS.IsZero() || startTS.After(recoveredTS) {
				since := time.Since(startTS).Round(time.Second)
				fmt.Printf("link:           %s — server unreachable for %s; events writing locally + spooling for forwarding\n",
					colorize("DEGRADED", colYellow), since)
				fmt.Printf("                 outage started: %s (%s)\n", displayTS(startTS).Format(time.RFC3339), displayTZ())
				if reason != "" {
					// Truncate long error messages to keep status compact;
					// operators chasing a stuck-degraded state usually only
					// need the head of the message anyway (the curl-style
					// `Post "..." dial tcp ...` prefix).
					if len(reason) > 200 {
						reason = reason[:200] + "..."
					}
					fmt.Printf("                 last error: %s\n", reason)
				}
				fmt.Println("                 (triage --type meta to see the full server_unreachable_started entry)")
			} else {
				fmt.Printf("link:           %s — last recovered %s ago\n",
					colorize("OK", colGreen), time.Since(recoveredTS).Round(time.Second))
			}
		}
	}
	if normaliseMode(cfg.Mode) == "server" {
		hosts := listHosts(cfg.LogDir)
		fmt.Printf("listen:         %s\n", cfg.Server.Listen)
		fmt.Printf("hosts:          %d (%s)\n", len(hosts), strings.Join(hosts, ", "))
		// Realm: name + peer count. "default" + 0 peers is a single-server
		// realm (legacy behaviour); >0 peers is an HA group.
		realm := cfg.Server.Realm.Name
		if realm == "" {
			realm = "default"
		}
		peerCount := len(cfg.Server.Realm.Peers)
		if peerCount == 0 {
			fmt.Printf("realm:          %q (single-server, no failover)\n", realm)
		} else {
			fmt.Printf("realm:          %q with %d peer(s) — %s\n",
				realm, peerCount, strings.Join(cfg.Server.Realm.Peers, ", "))
		}
		if cfg.Server.Realm.MasterURL != "" {
			fmt.Printf("master:         %s — realm config managed by master, local edits refused\n",
				cfg.Server.Realm.MasterURL)
		}
		// Local-collection diagnostic — the most common cause of "the
		// server isn't logging events" is a config that disables this.
		if cfg.Server.CollectLocally {
			localID := pickServerLocalID(cfg.Server.LocalID)
			fmt.Printf("collect_locally: %s (events under %s/)\n", colorize("ON", colGreen), localID)
		} else {
			fmt.Printf("collect_locally: %s — server is not monitoring its own host\n", colorize("OFF", colYellow))
		}
		// Allowlist diagnostic — the second most common cause is an
		// allowlist that doesn't include the agent the operator is
		// trying to use.
		if len(cfg.Server.AgentAllowlist) > 0 {
			fmt.Printf("agent_allowlist: %s — only these IDs accepted: %s\n",
				colorize("strict", colYellow),
				strings.Join(cfg.Server.AgentAllowlist, ", "))
		} else {
			// Loud warning: empty allowlist is "any valid cert" mode.
			// Operators removing the last agent from the list assume
			// they revoked it; in fact they disabled the allowlist
			// gate entirely and any CA-signed cert now works.
			fmt.Printf("agent_allowlist: %s — empty list = open mode: any cert signed by the\n",
				colorize("OPEN MODE", colRed))
			fmt.Println("                 configured CA is accepted. To revoke a specific agent,")
			fmt.Println("                 keep the list non-empty (add a placeholder ID if needed).")
		}
		// SAN drift: cert doesn't cover one of this host's current
		// IPs/hostname. Cheapest visibility — a one-line yellow note
		// in status. Without it, the only signal is failing agent
		// connections (mute) or grepping _server/meta.
		if drift := certSANDrift(cfg.Server.Cert); len(drift) > 0 {
			fmt.Printf("cert_san:        %s — current host IP/name(s) not in server cert SAN: %s\n",
				colorize("DRIFT", colYellow), strings.Join(drift, ", "))
			fmt.Println("                 agents dialing by these will fail TLS. Refresh with:")
			fmt.Println("                   sudo simplesiem certs server $(hostname) --force")
			fmt.Println("                   sudo simplesiem stop && sudo simplesiem start")
		}
		// Surface recent _server errors so an operator running `status`
		// after "events aren't flowing" sees the actual rejection
		// reasons (auth failures, allowlist rejections, decode errors)
		// inline instead of hunting through JSONL files.
		showRecentServerErrors(base, 5)
	}
	if normaliseMode(cfg.Mode) == "master" {
		hosts := listHosts(cfg.LogDir)
		fmt.Printf("master_id:      %s\n", cfg.Master.MasterID)
		fmt.Printf("hosts:          %d (%s)\n", len(hosts), strings.Join(hosts, ", "))
		if len(cfg.Master.Servers) == 0 {
			fmt.Printf("servers:        %s — no servers registered. Run: simplesiem master enroll <url> --key <PSK>\n",
				colorize("none", colYellow))
		} else {
			fmt.Printf("servers:        %d registered\n", len(cfg.Master.Servers))
			for _, srv := range cfg.Master.Servers {
				fmt.Printf("                  %s\n", srv)
			}
		}
		interval := cfg.Master.SyncIntervalSeconds
		if interval <= 0 {
			interval = 60
		}
		fmt.Printf("sync_interval:  %ds\n", interval)
		// Master collector listener: optional, off by default.
		if cfg.Master.CollectorListen != "" {
			fmt.Printf("collector_listen: %s\n", cfg.Master.CollectorListen)
			switch {
			case cfg.Master.CollectorCN != "":
				fmt.Printf("collector_slot: %s — paired with %s\n", colorize("associated", colGreen), cfg.Master.CollectorCN)
			case cfg.Master.CollectorPendingEnroll:
				fmt.Printf("collector_slot: %s — accepting next enrollment\n", colorize("open", colYellow))
			default:
				fmt.Printf("collector_slot: closed (run `simplesiem master collector accept-next` to open)\n")
			}
		}
	}
	if normaliseMode(cfg.Mode) == "collector" {
		fmt.Printf("collector_id:   %s\n", cfg.Collector.CollectorID)
		fmt.Printf("source_url:     %s\n", cfg.Collector.SourceURL)
		fmt.Printf("authority:      %s\n", cfg.Collector.AuthorityHint)
		interval := cfg.Collector.PullIntervalSeconds
		if interval <= 0 {
			interval = 86400
		}
		fmt.Printf("pull_interval:  %s\n", time.Duration(interval)*time.Second)
		if len(cfg.Collector.FailoverServers) > 0 {
			fmt.Printf("failover:       %d peer(s) — %s\n",
				len(cfg.Collector.FailoverServers),
				strings.Join(cfg.Collector.FailoverServers, ", "))
		}
		if cfg.Collector.SourceURL == "" {
			fmt.Printf("link:           %s — run: sudo simplesiem collector enroll <url> --key <PSK>\n",
				colorize("UNCONFIGURED", colYellow))
		}
	}

	// Rule count from rules.json.
	if cfg.RulesPath != "" {
		if rules, err := loadRules(cfg.RulesPath); err == nil {
			fmt.Printf("rules:          %d (%s)\n", len(rules), cfg.RulesPath)
		} else if os.IsNotExist(err) {
			fmt.Printf("rules:          0 (no file at %s)\n", cfg.RulesPath)
		} else {
			fmt.Printf("rules:          %s\n", colorize("INVALID: "+err.Error(), colRed))
		}
	}

	// Storage quota — local volume(s) holding the log directory plus
	// any failover locations. Renders one line per volume with the
	// current state (OK / WARN / HALTED). For server and master modes,
	// remote-host warnings discovered in the meta logs are listed
	// underneath so an operator running `status` on the server sees
	// at-a-glance whether any peer / agent is approaching its halt
	// threshold.
	printStorageStatus(cfg)

	entries, err := os.ReadDir(base)
	if err != nil {
		fmt.Println("(no logs yet)")
		return
	}
	var types []string
	for _, e := range entries {
		if e.IsDir() {
			types = append(types, e.Name())
		}
	}
	sort.Strings(types)

	totalBytes := int64(0)
	oldestDate := time.Time{}
	fmt.Println()
	// Layout differs by mode: standalone has <base>/<type>/<date>.jsonl;
	// server has <base>/<host>/<type>/<date>.jsonl. The walker recurses
	// one extra level when the top-level entry is a host directory (no
	// direct .jsonl children) so size/latest aggregates work in both
	// modes.
	// "latest" is the mtime of the newest .jsonl(.gz) file under each
	// type — file mtimes update on every event append, so this gives
	// the operator a per-second freshness signal ("(2m 14s ago)") to
	// distinguish "logging stalled an hour ago" from "events still
	// flowing" without having to grep the JSONL.
	fmt.Printf("entry         files    size       latest (%s)\n", displayTZ())
	fmt.Println(strings.Repeat("-", 78))
	now := time.Now()
	for _, t := range types {
		entryDir := filepath.Join(base, t)
		typeBytes := int64(0)
		dates := []time.Time{}
		var newestMTime time.Time
		var newestDate time.Time
		_ = filepath.WalkDir(entryDir, func(path string, d iofs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".jsonl.gz") {
				return nil
			}
			dt := dateFromLogName(name)
			if !dt.IsZero() {
				dates = append(dates, dt)
			}
			if info, err := d.Info(); err == nil {
				typeBytes += info.Size()
				// Track the mtime of the file with the newest filename
				// date (not the newest mtime overall — gzipped historical
				// files can have fresher mtimes from the rotation pass
				// itself, which would mislead a freshness check).
				if !dt.IsZero() && (newestDate.IsZero() || dt.After(newestDate)) {
					newestDate = dt
					newestMTime = info.ModTime()
				}
			}
			return nil
		})
		sort.Slice(dates, func(i, j int) bool { return dates[i].Before(dates[j]) })
		latest := "-"
		fileCount := len(dates)
		if fileCount > 0 {
			latest = formatLatest(newestMTime, now)
			if oldestDate.IsZero() || dates[0].Before(oldestDate) {
				oldestDate = dates[0]
			}
		}
		totalBytes += typeBytes
		fmt.Printf("  %-12s %3d   %10s   %s\n",
			t, fileCount, humanBytes(typeBytes), latest)
	}
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("  total        %3s   %10s\n", "", humanBytes(totalBytes))
	if !oldestDate.IsZero() {
		fmt.Printf("\nretention floor: %s (%d days kept)\n",
			oldestDate.Format("2006-01-02"),
			int(time.Since(oldestDate).Hours()/24))
	}

	// Recent collector health: scan today's meta log for the latest of
	// collector_silent / collector_recovered per collector.
	healthByCollector := map[string]string{}
	healthFile := filepath.Join(base, "meta", time.Now().UTC().Format("2006-01-02")+".jsonl")
	if r, err := openLogReader(healthFile); err == nil {
		dec := bufio.NewScanner(r)
		dec.Buffer(make([]byte, 64*1024), 1024*1024)
		for dec.Scan() {
			var m map[string]any
			if err := json.Unmarshal(dec.Bytes(), &m); err != nil {
				continue
			}
			ev, _ := m["event"].(string)
			coll, _ := m["collector"].(string)
			switch ev {
			case "collector_silent":
				healthByCollector[coll] = colorize("silent", colRed)
			case "collector_recovered":
				healthByCollector[coll] = colorize("recovered", colGreen)
			}
		}
		r.Close()
	}
	if len(healthByCollector) > 0 {
		fmt.Println("\ncollector health (today):")
		var names []string
		for n := range healthByCollector {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Printf("  %-12s %s\n", n, healthByCollector[n])
		}
	}

	// Alerts count in last 24h.
	since := time.Now().UTC().Add(-24 * time.Hour)
	alerts := loadEventsInRange(base, since, time.Now().UTC(), "alerts")
	if len(alerts) > 0 {
		fmt.Printf("\nalerts (24h): %d", len(alerts))
		bySev := map[string]int{}
		for _, a := range alerts {
			bySev[strField(a.Data, "severity")]++
		}
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if n := bySev[sev]; n > 0 {
				fmt.Printf("  %s=%d", colorize(sev, severityColor(sev)), n)
			}
		}
		fmt.Println()
	}
}

func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	const u = 1024
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
