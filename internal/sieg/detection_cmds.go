package sieg

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// contextWithSigint returns a context cancelled on Ctrl-C / SIGTERM so
// long-running CLI subcommands (e.g. threatintel fetch over a slow
// network) can be cancelled cleanly without leaving a half-written
// cache file.
func contextWithSigint() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()
	return ctx, cancel
}

// Stepwise CLIs for the multi-field config blocks that previously
// required hand-edits of config.json:
//
//   threatintel feed     — feed objects (name, kind, url, intervals, kinds)
//   firstseen tuple      — tuple specs (name + ordered field list)
//
// Plus the unrevoke counterpart and the tune extensions for the
// scalar knobs in baseline / incidents / firstseen / threatintel.
//
// Every verb mutates one field of one block, written through
// configReadMap / configWriteMap so the edit is atomic + schema-
// validated + hot-reloaded.

// ----- threatintel feed --------------------------------------------------

func runThreatIntelCmd(args []string) {
	if len(args) == 0 {
		threatIntelUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "status":
		runThreatIntelStatus(args[1:])
	case "fetch":
		runThreatIntelFetch(args[1:])
	case "feed":
		runThreatIntelFeed(args[1:])
	case "help", "-h", "--help":
		threatIntelUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown threatintel subcommand: %s\n", args[0])
		threatIntelUsage()
		os.Exit(2)
	}
}

func threatIntelUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem threatintel <subcommand> [args]

  status                                 print fetch / cache state for every feed
  fetch [--force]                        manually pull every enabled feed now;
                                         --force ignores the per-feed interval and
                                         re-fetches even if the cache is fresh
  feed <subcommand>                      stepwise feed builder (see below)

feed subcommands:
  feed list                              one line per feed (name, kind, state)
  feed show <id>                         print the full feed JSON
  feed new <id>                          create draft feed (disabled until enable)
  feed set <id> kind <X>                 e.g. abuse.ch.threatfox
  feed set <id> url <https://...>        feed endpoint
  feed set <id> interval-hours <N>       fetch cadence
  feed set <id> min-confidence <0..100>  drop indicators below this
  feed set <id> max-age-days <N>         drop indicators older than this
  feed set <id> auth-key <key>           feed-specific API key (e.g. abuse.ch's
                                         Auth-Key — get a free one at
                                         https://auth.abuse.ch/)
  feed kinds <id> add <kind>             append an indicator kind (ip:port, domain, sha256, ...)
  feed kinds <id> remove <kind>          drop an indicator kind
  feed kinds <id> set <k1>,<k2>,...      replace the indicator-kinds list
  feed validate <id>                     dry-run audit (URL, kinds, intervals)
  feed enable <id>                       validate then activate (refuses on error)
  feed disable <id>                      keep in file but stop fetching
  feed delete <id>                       remove from cfg.threatintel.feeds

example session:
  sudo simplesiem threatintel feed new abuse-ch
  sudo simplesiem threatintel feed set abuse-ch kind abuse.ch.threatfox
  sudo simplesiem threatintel feed set abuse-ch url https://threatfox-api.abuse.ch/api/v1/
  sudo simplesiem threatintel feed set abuse-ch interval-hours 6
  sudo simplesiem threatintel feed set abuse-ch min-confidence 75
  sudo simplesiem threatintel feed kinds abuse-ch set ip:port,domain,sha256
  sudo simplesiem threatintel feed enable abuse-ch`)
}

// runThreatIntelFetch performs a synchronous fetch against every enabled
// feed in cfg.threatintel. Standalone — does not require IPC with the
// running daemon. The cache files written under <state>/threatintel/
// are picked up by the daemon's manager on its next hourly tick (or
// immediately on `simplesiem restart`).
func runThreatIntelFetch(args []string) {
	force := false
	for _, a := range args {
		if a == "--force" || a == "-f" {
			force = true
		}
	}
	cfg := loadConfig(defaultConfigPath())
	if !cfg.ThreatIntel.Enabled {
		fmt.Fprintln(os.Stderr, "cfg.threatintel.enabled is false; nothing to fetch.")
		os.Exit(1)
	}
	if len(cfg.ThreatIntel.Feeds) == 0 {
		fmt.Fprintln(os.Stderr, "no feeds configured. Add one with `simplesiem threatintel feed new <id>`.")
		os.Exit(1)
	}
	mgr := newThreatIntelManager(cfg.ThreatIntel, nil)
	// Warm the in-memory state from disk so shouldFetch sees the
	// current cache age. force=true bypasses that check entirely.
	for _, f := range cfg.ThreatIntel.Feeds {
		if set, err := mgr.loadCachedSet(f.Name); err == nil {
			mgr.mu.Lock()
			mgr.sets[f.Name] = set
			mgr.mu.Unlock()
		}
	}
	ctx, cancel := contextWithSigint()
	defer cancel()
	failed := 0
	for _, f := range cfg.ThreatIntel.Feeds {
		if !force && !mgr.shouldFetch(f) {
			fmt.Printf("  %-20s SKIP (cache is fresh; pass --force to re-fetch)\n", f.Name)
			continue
		}
		fmt.Printf("  %-20s fetching %s ... ", f.Name, f.URL)
		if err := mgr.fetchOne(ctx, f); err != nil {
			fmt.Printf("FAIL: %v\n", err)
			failed++
			continue
		}
		mgr.mu.RLock()
		set := mgr.sets[f.Name]
		mgr.mu.RUnlock()
		count := 0
		if set != nil {
			for _, b := range set.Entries {
				count += len(b)
			}
		}
		fmt.Printf("OK (%d indicators)\n", count)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d feed(s) failed; see error above. Cache for failing feeds is unchanged.\n", failed)
		os.Exit(1)
	}
	fmt.Println("\nCache updated. Running daemon picks up new indicators within the hour, or restart for immediate effect.")
}

func runThreatIntelFeed(args []string) {
	if len(args) == 0 {
		threatIntelUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		threatIntelFeedList()
	case "show":
		threatIntelFeedShow(args[1:])
	case "new":
		threatIntelFeedNew(args[1:])
	case "set":
		threatIntelFeedSet(args[1:])
	case "kinds":
		threatIntelFeedKinds(args[1:])
	case "validate":
		threatIntelFeedValidate(args[1:])
	case "enable":
		threatIntelFeedEnable(args[1:])
	case "disable":
		threatIntelFeedSetDisabled(args[1:], true)
	case "delete", "remove":
		threatIntelFeedDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown threatintel feed subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

// loadFeeds reads cfg.threatintel.feeds as a []map[string]any so each
// feed keeps its on-disk shape (and an unknown-future field stays put
// rather than getting trimmed by the strongly-typed struct).
func loadFeeds() (map[string]any, []any) {
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	ti := getOrCreateMap(m, "threatintel")
	rawFeeds, _ := ti["feeds"].([]any)
	return m, rawFeeds
}

func saveFeeds(m map[string]any, feeds []any) {
	ti := getOrCreateMap(m, "threatintel")
	if len(feeds) == 0 {
		delete(ti, "feeds")
	} else {
		ti["feeds"] = feeds
	}
	if err := configWriteMap(defaultConfigPath(), m); err != nil {
		fatalf("write config: %v", err)
	}
}

func feedByName(feeds []any, name string) (map[string]any, int) {
	for i, raw := range feeds {
		if f, ok := raw.(map[string]any); ok {
			if got, _ := f["name"].(string); got == name {
				return f, i
			}
		}
	}
	return nil, -1
}

func threatIntelFeedNew(args []string) {
	if len(args) != 1 {
		fatalf("usage: threatintel feed new <id>")
	}
	if !attackPatternIDRe.MatchString(args[0]) {
		fatalf("feed id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
	}
	mustAdmin()
	m, feeds := loadFeeds()
	if f, _ := feedByName(feeds, args[0]); f != nil {
		fatalf("feed %q already exists", args[0])
	}
	feeds = append(feeds, map[string]any{
		"name":     args[0],
		"disabled": true,
	})
	saveFeeds(m, feeds)
	fmt.Printf("feed %q created (disabled). Set kind/url/intervals, then `feed enable %s`.\n", args[0], args[0])
}

func threatIntelFeedSet(args []string) {
	if len(args) < 3 {
		fatalf("usage: threatintel feed set <id> <kind|url|interval-hours|min-confidence|max-age-days> <value>")
	}
	id, field := args[0], args[1]
	value := strings.Join(args[2:], " ")
	mustAdmin()
	m, feeds := loadFeeds()
	f, _ := feedByName(feeds, id)
	if f == nil {
		fatalf("no feed named %q (run `feed new %s` first)", id, id)
	}
	switch field {
	case "kind":
		if value == "" {
			fatalf("kind cannot be empty")
		}
		f["kind"] = value
	case "url":
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			fatalf("url must be http:// or https://")
		}
		f["url"] = value
	case "interval-hours":
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 {
			fatalf("interval-hours must be a positive integer")
		}
		f["interval_hours"] = n
	case "min-confidence":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 100 {
			fatalf("min-confidence must be 0..100")
		}
		f["min_confidence"] = n
	case "max-age-days":
		n, err := strconv.Atoi(value)
		if err != nil || n <= 0 {
			fatalf("max-age-days must be a positive integer")
		}
		f["max_age_days"] = n
	case "auth-key":
		// Free credential per feed (e.g. abuse.ch's Auth-Key
		// header). Empty means "feed doesn't need one"; the
		// fetcher itself decides whether the kind requires it.
		if value == "" {
			delete(f, "auth_key")
		} else {
			f["auth_key"] = value
		}
	default:
		fatalf("unknown field %q (valid: kind url interval-hours min-confidence max-age-days auth-key)", field)
	}
	saveFeeds(m, feeds)
	fmt.Printf("set %s.%s\n", id, strings.ReplaceAll(field, "-", "_"))
}

func threatIntelFeedKinds(args []string) {
	if len(args) < 2 {
		fatalf("usage: threatintel feed kinds <id> <add|remove|set> [<value>]")
	}
	id, op := args[0], args[1]
	mustAdmin()
	m, feeds := loadFeeds()
	f, _ := feedByName(feeds, id)
	if f == nil {
		fatalf("no feed named %q", id)
	}
	cur := stringSliceFromAny(f["indicator_kinds"])
	switch op {
	case "add":
		if len(args) != 3 {
			fatalf("usage: threatintel feed kinds <id> add <kind>")
		}
		for _, k := range cur {
			if k == args[2] {
				saveFeeds(m, feeds)
				return
			}
		}
		cur = append(cur, args[2])
	case "remove":
		if len(args) != 3 {
			fatalf("usage: threatintel feed kinds <id> remove <kind>")
		}
		out := cur[:0]
		for _, k := range cur {
			if k != args[2] {
				out = append(out, k)
			}
		}
		cur = out
	case "set":
		if len(args) != 3 {
			fatalf("usage: threatintel feed kinds <id> set <k1>,<k2>,...")
		}
		cur = nil
		for _, p := range strings.Split(args[2], ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				cur = append(cur, p)
			}
		}
	default:
		fatalf("usage: threatintel feed kinds <id> <add|remove|set>")
	}
	if len(cur) == 0 {
		delete(f, "indicator_kinds")
	} else {
		out := make([]any, len(cur))
		for i, k := range cur {
			out[i] = k
		}
		f["indicator_kinds"] = out
	}
	saveFeeds(m, feeds)
	fmt.Printf("updated %s.indicator_kinds\n", id)
}

func auditFeed(f map[string]any) []string {
	var out []string
	if name, _ := f["name"].(string); name == "" {
		out = append(out, "name: missing")
	}
	if kind, _ := f["kind"].(string); kind == "" {
		out = append(out, "kind: not set (run `feed set <id> kind <X>`)")
	}
	if u, _ := f["url"].(string); u == "" {
		out = append(out, "url: not set (run `feed set <id> url <https://...>`)")
	} else if pu, err := url.Parse(u); err != nil || (pu.Scheme != "http" && pu.Scheme != "https") {
		out = append(out, "url: must be http:// or https://")
	}
	if iv := numFromAny(f["interval_hours"]); iv <= 0 {
		out = append(out, "interval_hours: not set or non-positive (run `feed set <id> interval-hours <N>`)")
	}
	kinds := stringSliceFromAny(f["indicator_kinds"])
	if len(kinds) == 0 {
		out = append(out, "indicator_kinds: empty (run `feed kinds <id> set ip:port,domain,sha256`)")
	}
	return out
}

func numFromAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func threatIntelFeedValidate(args []string) {
	if len(args) != 1 {
		fatalf("usage: threatintel feed validate <id>")
	}
	_, feeds := loadFeeds()
	f, _ := feedByName(feeds, args[0])
	if f == nil {
		fatalf("no feed named %q", args[0])
	}
	problems := auditFeed(f)
	if len(problems) == 0 {
		fmt.Printf("feed %q is complete and would enable cleanly.\n", args[0])
		return
	}
	fmt.Printf("feed %q has %d problem(s):\n", args[0], len(problems))
	for _, p := range problems {
		fmt.Println("  -", p)
	}
	os.Exit(1)
}

func threatIntelFeedEnable(args []string) {
	if len(args) != 1 {
		fatalf("usage: threatintel feed enable <id>")
	}
	mustAdmin()
	m, feeds := loadFeeds()
	f, _ := feedByName(feeds, args[0])
	if f == nil {
		fatalf("no feed named %q", args[0])
	}
	if problems := auditFeed(f); len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "cannot enable: feed %q is not yet complete:\n", args[0])
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "  -", p)
		}
		os.Exit(1)
	}
	delete(f, "disabled")
	saveFeeds(m, feeds)
	fmt.Printf("feed %q ENABLED — daemon hot-reloads within ~1s\n", args[0])
}

func threatIntelFeedSetDisabled(args []string, disabled bool) {
	if len(args) != 1 {
		fatalf("usage: threatintel feed disable <id>")
	}
	mustAdmin()
	m, feeds := loadFeeds()
	f, _ := feedByName(feeds, args[0])
	if f == nil {
		fatalf("no feed named %q", args[0])
	}
	if disabled {
		f["disabled"] = true
	} else {
		delete(f, "disabled")
	}
	saveFeeds(m, feeds)
	if disabled {
		fmt.Printf("feed %q disabled (kept in file)\n", args[0])
	} else {
		fmt.Printf("feed %q enabled\n", args[0])
	}
}

func threatIntelFeedDelete(args []string) {
	if len(args) != 1 {
		fatalf("usage: threatintel feed delete <id>")
	}
	mustAdmin()
	m, feeds := loadFeeds()
	out := feeds[:0]
	removed := 0
	for _, raw := range feeds {
		if f, ok := raw.(map[string]any); ok {
			if name, _ := f["name"].(string); name == args[0] {
				removed++
				continue
			}
		}
		out = append(out, raw)
	}
	if removed == 0 {
		fatalf("no feed named %q", args[0])
	}
	saveFeeds(m, out)
	fmt.Printf("deleted %d feed(s) named %q\n", removed, args[0])
}

func threatIntelFeedList() {
	_, feeds := loadFeeds()
	if len(feeds) == 0 {
		fmt.Println("(no feeds configured)")
		return
	}
	type row struct{ name, kind, state string }
	rows := make([]row, 0, len(feeds))
	for _, raw := range feeds {
		f, _ := raw.(map[string]any)
		state := "enabled"
		if d, _ := f["disabled"].(bool); d {
			state = "disabled"
		}
		name, _ := f["name"].(string)
		kind, _ := f["kind"].(string)
		rows = append(rows, row{name, kind, state})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	for _, r := range rows {
		fmt.Printf("  %-20s  %-30s  %s\n", r.name, r.kind, r.state)
	}
}

func threatIntelFeedShow(args []string) {
	if len(args) != 1 {
		fatalf("usage: threatintel feed show <id>")
	}
	_, feeds := loadFeeds()
	f, _ := feedByName(feeds, args[0])
	if f == nil {
		fatalf("no feed named %q", args[0])
	}
	out, _ := json.MarshalIndent(f, "", "  ")
	fmt.Println(string(out))
}

// ----- firstseen tuple ---------------------------------------------------

func runFirstSeenCmd(args []string) {
	if len(args) == 0 {
		firstSeenUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "status":
		runFirstSeenStatus(args[1:])
	case "tuple":
		runFirstSeenTuple(args[1:])
	case "help", "-h", "--help":
		firstSeenUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown firstseen subcommand: %s\n", args[0])
		firstSeenUsage()
		os.Exit(2)
	}
}

func firstSeenUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem firstseen <subcommand> [args]

  status                                 print first-seen detector state
  tuple <subcommand>                     manage tuple definitions

tuple subcommands:
  tuple list                             one line per tuple
  tuple show <id>                        print the full tuple JSON
  tuple add <id> <field1>,<field2>,...   define a new tuple by ordered field names
  tuple remove <id>                      delete a tuple
  tuple fields <id> <field1>,<field2>... rewrite the field list in place

example session:
  sudo simplesiem firstseen tuple add user_country user,geoip.country
  sudo simplesiem firstseen tuple add proc_dir process,path_dir
  sudo simplesiem firstseen tuple list
  sudo simplesiem firstseen tuple remove user_country`)
}

func runFirstSeenTuple(args []string) {
	if len(args) == 0 {
		firstSeenUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		firstSeenTupleList()
	case "show":
		firstSeenTupleShow(args[1:])
	case "add":
		firstSeenTupleAdd(args[1:])
	case "remove", "delete":
		firstSeenTupleRemove(args[1:])
	case "fields":
		firstSeenTupleFields(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown firstseen tuple subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

var fieldChunkRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func parseTupleFields(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func loadTuples() (map[string]any, []any) {
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	fs := getOrCreateMap(m, "firstseen")
	rawTuples, _ := fs["tuples"].([]any)
	return m, rawTuples
}

func saveTuples(m map[string]any, tuples []any) {
	fs := getOrCreateMap(m, "firstseen")
	if len(tuples) == 0 {
		delete(fs, "tuples")
	} else {
		fs["tuples"] = tuples
	}
	if err := configWriteMap(defaultConfigPath(), m); err != nil {
		fatalf("write config: %v", err)
	}
}

func tupleByName(tuples []any, name string) (map[string]any, int) {
	for i, raw := range tuples {
		if t, ok := raw.(map[string]any); ok {
			if got, _ := t["name"].(string); got == name {
				return t, i
			}
		}
	}
	return nil, -1
}

func firstSeenTupleAdd(args []string) {
	if len(args) != 2 {
		fatalf("usage: firstseen tuple add <id> <field1>,<field2>,...")
	}
	if !attackPatternIDRe.MatchString(args[0]) {
		fatalf("tuple id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
	}
	fields := parseTupleFields(args[1])
	if len(fields) < 1 {
		fatalf("at least one field is required")
	}
	for _, f := range fields {
		if !fieldChunkRe.MatchString(f) {
			fatalf("field %q has illegal characters; allowed: alphanumerics, dot, underscore, hyphen", f)
		}
	}
	mustAdmin()
	m, tuples := loadTuples()
	if t, _ := tupleByName(tuples, args[0]); t != nil {
		fatalf("tuple %q already exists", args[0])
	}
	flds := make([]any, len(fields))
	for i, f := range fields {
		flds[i] = f
	}
	tuples = append(tuples, map[string]any{
		"name":   args[0],
		"fields": flds,
	})
	saveTuples(m, tuples)
	fmt.Printf("tuple %q added with %d field(s)\n", args[0], len(fields))
}

func firstSeenTupleFields(args []string) {
	if len(args) != 2 {
		fatalf("usage: firstseen tuple fields <id> <field1>,<field2>,...")
	}
	fields := parseTupleFields(args[1])
	if len(fields) < 1 {
		fatalf("at least one field is required")
	}
	for _, f := range fields {
		if !fieldChunkRe.MatchString(f) {
			fatalf("field %q has illegal characters", f)
		}
	}
	mustAdmin()
	m, tuples := loadTuples()
	t, _ := tupleByName(tuples, args[0])
	if t == nil {
		fatalf("no tuple named %q", args[0])
	}
	flds := make([]any, len(fields))
	for i, f := range fields {
		flds[i] = f
	}
	t["fields"] = flds
	saveTuples(m, tuples)
	fmt.Printf("tuple %q fields rewritten (%d field(s))\n", args[0], len(fields))
}

func firstSeenTupleRemove(args []string) {
	if len(args) != 1 {
		fatalf("usage: firstseen tuple remove <id>")
	}
	mustAdmin()
	m, tuples := loadTuples()
	out := tuples[:0]
	removed := 0
	for _, raw := range tuples {
		if t, ok := raw.(map[string]any); ok {
			if name, _ := t["name"].(string); name == args[0] {
				removed++
				continue
			}
		}
		out = append(out, raw)
	}
	if removed == 0 {
		fatalf("no tuple named %q", args[0])
	}
	saveTuples(m, out)
	fmt.Printf("removed tuple %q\n", args[0])
}

func firstSeenTupleList() {
	_, tuples := loadTuples()
	if len(tuples) == 0 {
		fmt.Println("(no tuples configured)")
		return
	}
	type row struct {
		name   string
		fields string
	}
	rows := make([]row, 0, len(tuples))
	for _, raw := range tuples {
		t, _ := raw.(map[string]any)
		name, _ := t["name"].(string)
		flds := stringSliceFromAny(t["fields"])
		rows = append(rows, row{name, strings.Join(flds, ",")})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	for _, r := range rows {
		fmt.Printf("  %-30s  %s\n", r.name, r.fields)
	}
}

func firstSeenTupleShow(args []string) {
	if len(args) != 1 {
		fatalf("usage: firstseen tuple show <id>")
	}
	_, tuples := loadTuples()
	t, _ := tupleByName(tuples, args[0])
	if t == nil {
		fatalf("no tuple named %q", args[0])
	}
	out, _ := json.MarshalIndent(t, "", "  ")
	fmt.Println(string(out))
}

