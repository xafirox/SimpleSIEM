package sieg

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// runHuntCmd dispatches `simplesiem hunt <subcommand>`. Hunt is a set
// of read-only investigation primitives: long-tail rare-value
// detection, entity-centred pivots, first-seen entity discovery,
// and saved-query reuse. Each is a thin wrapper around the existing
// event walker — no daemon-side state.
func runHuntCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem hunt <rare|pivot|firstseen|save|list|run|delete> [flags]

  rare       Events whose --field value occurs <N times in --since window.
             Catches long-tail anomalies without needing to write a rule.
  pivot      Single-entity timeline (--entity user:alice or remote:1.2.3.4).
             Walks every log type filtering for events that mention the entity.
  firstseen  Field values that first appeared inside the --since window.
             "What's new on the network?" check.
  save       Save a hunt invocation by name for later replay.
  list       List saved hunts.
  run        Re-run a saved hunt.
  delete     Remove a saved hunt.`)
		os.Exit(2)
	}
	switch args[0] {
	case "rare":
		runHuntRare(args[1:])
	case "pivot":
		runHuntPivot(args[1:])
	case "firstseen":
		runHuntFirstSeen(args[1:])
	case "save":
		runHuntSave(args[1:])
	case "list":
		runHuntList(args[1:])
	case "run":
		runHuntRun(args[1:])
	case "delete":
		runHuntDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown hunt subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

// runHuntRare reports events whose --field value occurs at most
// --max-count times in the window. Default 2 (i.e., values seen
// only once or twice). Useful for finding outlier source IPs,
// rare process names, etc.
func runHuntRare(args []string) {
	args = permuteArgs(args, map[string]bool{
		"config": true, "since": true, "type": true, "host": true,
		"field": true, "max-count": true,
	})
	fs := flag.NewFlagSet("hunt rare", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	since := fs.String("since", "24h", "time window")
	typeFilter := fs.String("type", "", "log type (default: all)")
	hostFilter := fs.String("host", "", "in server / master mode, restrict to one agent ID")
	field := fs.String("field", "", "field to bucket on (e.g. source_ip, process, remote)")
	maxCount := fs.Int("max-count", 2, "show events whose field value occurs at most N times")
	_ = fs.Parse(args)
	if strings.TrimSpace(*field) == "" {
		fatalf("--field <name> is required (e.g. --field source_ip)")
	}
	cfg := loadConfig(*cfgPath)
	start, err := parseSince(*since)
	if err != nil {
		fatalf("--since: %v", err)
	}
	end := time.Now().UTC()
	events := loadEventsInRangeMulti(searchRoots(cfg, *hostFilter), start, end, *typeFilter)
	counts := map[string]int{}
	for _, e := range events {
		v := strField(e.Data, *field)
		if v == "" {
			continue
		}
		counts[v]++
	}
	hits := 0
	fmt.Printf("Rare values for field %q (≤%d occurrences) — %s -> %s   (%s)\n",
		*field, *maxCount,
		displayTS(start).Format("2006-01-02 15:04:05"),
		displayTS(end).Format("2006-01-02 15:04:05"),
		displayTZ())
	for _, e := range events {
		v := strField(e.Data, *field)
		if v == "" || counts[v] > *maxCount {
			continue
		}
		hits++
		ts := displayTS(e.TS).Format("2006-01-02 15:04:05")
		ev, _ := e.Data["event"].(string)
		fmt.Printf("  %s  %-9s %s=%s  event=%s\n", ts, e.Type, *field, v, ev)
	}
	if hits == 0 {
		fmt.Println("(no rare values in the window)")
	}
}

// runHuntPivot prints a single-entity narrative across every log
// type. --entity accepts "field:value" (e.g. "user:alice",
// "source_ip:1.2.3.4"); the helper greps every event in the
// window for that field/value combination and prints a coalesced
// timeline.
func runHuntPivot(args []string) {
	args = permuteArgs(args, map[string]bool{
		"config": true, "since": true, "host": true, "entity": true, "type": true,
	})
	fs := flag.NewFlagSet("hunt pivot", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	since := fs.String("since", "1h", "time window")
	hostFilter := fs.String("host", "", "in server / master mode, restrict to one agent ID")
	entity := fs.String("entity", "", "field:value (e.g. user:alice, source_ip:1.2.3.4)")
	typeFilter := fs.String("type", "", "log type (default: all)")
	_ = fs.Parse(args)
	if strings.TrimSpace(*entity) == "" {
		fatalf("--entity field:value is required (e.g. --entity user:alice)")
	}
	parts := strings.SplitN(*entity, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		fatalf("--entity must be field:value (e.g. user:alice)")
	}
	field, value := parts[0], parts[1]
	cfg := loadConfig(*cfgPath)
	start, err := parseSince(*since)
	if err != nil {
		fatalf("--since: %v", err)
	}
	end := time.Now().UTC()
	events := loadEventsInRangeMulti(searchRoots(cfg, *hostFilter), start, end, *typeFilter)
	hits := 0
	fmt.Printf("Pivot: %s=%s  %s -> %s   (%s)\n",
		field, value,
		displayTS(start).Format("2006-01-02 15:04:05"),
		displayTS(end).Format("2006-01-02 15:04:05"),
		displayTZ())
	for _, e := range events {
		if !strings.EqualFold(strField(e.Data, field), value) {
			continue
		}
		hits++
		ts := displayTS(e.TS).Format("2006-01-02 15:04:05")
		ev, _ := e.Data["event"].(string)
		summary := eventSummary(e)
		fmt.Printf("  %s  %-9s %s\n", ts, e.Type, ev)
		if summary != "" {
			fmt.Printf("                              %s\n", summary)
		}
	}
	if hits == 0 {
		fmt.Println("(no events mention this entity in the window)")
	}
}

// runHuntFirstSeen reports field values that first appear inside
// the --since window — i.e., the value isn't present in events
// older than --since (subject to baseline being readable). Quick
// "what's new?" check for a field.
func runHuntFirstSeen(args []string) {
	args = permuteArgs(args, map[string]bool{
		"config": true, "since": true, "type": true, "host": true,
		"field": true, "baseline": true,
	})
	fs := flag.NewFlagSet("hunt firstseen", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	since := fs.String("since", "24h", "time window for first-occurrence detection")
	baseline := fs.String("baseline", "30d", "how far back to look for prior occurrences (must be > --since)")
	typeFilter := fs.String("type", "", "log type (default: all)")
	hostFilter := fs.String("host", "", "in server / master mode, restrict to one agent ID")
	field := fs.String("field", "", "field whose new values to flag (e.g. source_ip, sha256, remote_host, user)")
	_ = fs.Parse(args)
	if strings.TrimSpace(*field) == "" {
		fatalf("--field <name> is required (e.g. --field source_ip)")
	}
	cfg := loadConfig(*cfgPath)
	winStart, err := parseSince(*since)
	if err != nil {
		fatalf("--since: %v", err)
	}
	baseStart, err := parseSince(*baseline)
	if err != nil {
		fatalf("--baseline: %v", err)
	}
	if !baseStart.Before(winStart) {
		fatalf("--baseline must be wider than --since (got baseline=%s, since=%s)", *baseline, *since)
	}
	end := time.Now().UTC()
	roots := searchRoots(cfg, *hostFilter)
	// Two-pass scan: collect every value seen in the baseline-but-
	// outside-window slice, then walk the window slice and flag
	// values not in that set.
	priorEvents := loadEventsInRangeMulti(roots, baseStart, winStart, *typeFilter)
	prior := map[string]bool{}
	for _, e := range priorEvents {
		v := strField(e.Data, *field)
		if v != "" {
			prior[v] = true
		}
	}
	windowEvents := loadEventsInRangeMulti(roots, winStart, end, *typeFilter)
	firstSeen := map[string]time.Time{}
	for _, e := range windowEvents {
		v := strField(e.Data, *field)
		if v == "" || prior[v] {
			continue
		}
		if old, ok := firstSeen[v]; !ok || e.TS.Before(old) {
			firstSeen[v] = e.TS
		}
	}
	type row struct {
		value string
		first time.Time
	}
	rows := make([]row, 0, len(firstSeen))
	for v, t := range firstSeen {
		rows = append(rows, row{v, t})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].first.Before(rows[j].first) })
	fmt.Printf("First-seen %s values — window %s, baseline %s   (%s; %d new values)\n",
		*field, *since, *baseline, displayTZ(), len(rows))
	if len(rows) == 0 {
		return
	}
	for _, r := range rows {
		fmt.Printf("  %s  %s\n", displayTS(r.first).Format("2006-01-02 15:04:05"), r.value)
	}
}

// savedHunt is one row in <state>/saved_hunts.json. Persisted by
// `hunt save`, replayed by `hunt run`.
type savedHunt struct {
	Name        string    `json:"name"`
	Subcommand  string    `json:"subcommand"`
	Args        []string  `json:"args"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
}

func savedHuntsPath(cfg Config) string {
	dir := cfg.StateDir
	if dir == "" {
		dir = defaultStateDir()
	}
	return filepath.Join(dir, "saved_hunts.json")
}

func loadSavedHunts(cfg Config) ([]savedHunt, error) {
	data, err := os.ReadFile(savedHuntsPath(cfg))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var hunts []savedHunt
	if err := json.Unmarshal(data, &hunts); err != nil {
		return nil, err
	}
	return hunts, nil
}

func writeSavedHunts(cfg Config, hunts []savedHunt) error {
	dir := cfg.StateDir
	if dir == "" {
		dir = defaultStateDir()
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(hunts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(savedHuntsPath(cfg), data, 0o640)
}

// runHuntSave persists a hunt invocation by name. Operators reach
// for this when a particular pivot/rare/firstseen invocation is
// part of their regular triage workflow and they don't want to
// re-type the flags.
//
// Usage:
//
//	simplesiem hunt save <name> "<description>" -- hunt rare --field source_ip --since 7d
//
// The double-dash separates the save metadata from the hunt
// invocation that gets stored.
func runHuntSave(args []string) {
	if len(args) < 2 {
		fatalf("usage: simplesiem hunt save <name> \"<description>\" -- <hunt subcommand and flags>")
	}
	name := args[0]
	desc := args[1]
	rest := args[2:]
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 || rest[0] == "save" || rest[0] == "list" || rest[0] == "delete" || rest[0] == "run" {
		fatalf("hunt save: trailing arguments must be a hunt subcommand (rare/pivot/firstseen) and its flags")
	}
	cfg := loadConfig(defaultConfigPath())
	hunts, _ := loadSavedHunts(cfg)
	for i, h := range hunts {
		if h.Name == name {
			// Overwrite by name; keep CreatedAt/CreatedBy.
			hunts[i].Subcommand = rest[0]
			hunts[i].Args = append([]string{}, rest[1:]...)
			hunts[i].Description = desc
			if err := writeSavedHunts(cfg, hunts); err != nil {
				fatalf("write saved hunts: %v", err)
			}
			fmt.Printf("Updated saved hunt %q\n", name)
			return
		}
	}
	hunts = append(hunts, savedHunt{
		Name:        name,
		Subcommand:  rest[0],
		Args:        append([]string{}, rest[1:]...),
		Description: desc,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   currentOperatorName(),
	})
	if err := writeSavedHunts(cfg, hunts); err != nil {
		fatalf("write saved hunts: %v", err)
	}
	fmt.Printf("Saved hunt %q\n", name)
}

func runHuntList(args []string) {
	_ = args
	cfg := loadConfig(defaultConfigPath())
	hunts, err := loadSavedHunts(cfg)
	if err != nil {
		fatalf("read saved hunts: %v", err)
	}
	if len(hunts) == 0 {
		fmt.Println("No saved hunts.")
		return
	}
	sort.Slice(hunts, func(i, j int) bool { return hunts[i].Name < hunts[j].Name })
	for _, h := range hunts {
		fmt.Printf("%-20s by %-12s  %s  %s %s\n",
			h.Name, h.CreatedBy,
			h.CreatedAt.Format("2006-01-02"),
			h.Subcommand, strings.Join(h.Args, " "))
		if h.Description != "" {
			fmt.Printf("%22s%s\n", "", h.Description)
		}
	}
}

func runHuntRun(args []string) {
	if len(args) == 0 {
		fatalf("usage: simplesiem hunt run <name>")
	}
	name := args[0]
	cfg := loadConfig(defaultConfigPath())
	hunts, _ := loadSavedHunts(cfg)
	for _, h := range hunts {
		if h.Name == name {
			runHuntCmd(append([]string{h.Subcommand}, h.Args...))
			return
		}
	}
	fatalf("no saved hunt named %q", name)
}

func runHuntDelete(args []string) {
	if len(args) == 0 {
		fatalf("usage: simplesiem hunt delete <name>")
	}
	name := args[0]
	cfg := loadConfig(defaultConfigPath())
	hunts, err := loadSavedHunts(cfg)
	if err != nil {
		fatalf("read saved hunts: %v", err)
	}
	out := hunts[:0]
	removed := false
	for _, h := range hunts {
		if h.Name == name {
			removed = true
			continue
		}
		out = append(out, h)
	}
	if !removed {
		fatalf("no saved hunt named %q", name)
	}
	if err := writeSavedHunts(cfg, out); err != nil {
		fatalf("write saved hunts: %v", err)
	}
	fmt.Printf("Deleted saved hunt %q\n", name)
}

// currentOperatorName returns $USER (or equivalent) so saved hunts
// carry attribution. Falls back to "unknown" rather than failing —
// hunt save shouldn't error just because os/user is unhappy.
func currentOperatorName() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}

// _ ensures io is used somewhere in this file's imports if a future
// edit needs to consume reader streams; harmless no-op today.
var _ = io.Discard
