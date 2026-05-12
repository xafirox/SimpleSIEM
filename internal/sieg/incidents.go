package sieg

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// #6 — Alerts → incidents grouping. Groups alerts by
// (host, time-window) into incidents. Default window 60s,
// configurable. Authority chain: master if enrolled → server if no
// master → collector receives state during master outage → standalone
// always groups own alerts.

type IncidentsConfig struct {
	Enabled       bool `json:"enabled"`
	WindowSeconds int  `json:"window_seconds"`
	// MaxLifetimeSeconds caps a single incident's duration; alerts
	// past this start a new incident even if activity continues.
	MaxLifetimeSeconds int `json:"max_lifetime_seconds"`
	// IsAuthoritative is set on the tier currently doing the grouping.
	// Master sets true; servers default true and turn false when the
	// master signals it's authoritative.
	IsAuthoritative bool `json:"is_authoritative"`
}

func defaultIncidentsConfig() IncidentsConfig {
	return IncidentsConfig{
		Enabled:            true,
		WindowSeconds:      60,
		MaxLifetimeSeconds: 24 * 60 * 60,
		IsAuthoritative:    true,
	}
}

// incident is the wire shape stored in <log_dir>/_incidents/<date>.jsonl.
type incident struct {
	IncidentID    string    `json:"incident_id"`
	Host          string    `json:"host"`
	AssetClass    string    `json:"asset_class,omitempty"`
	FirstAlertTS  time.Time `json:"first_alert_ts"`
	LastAlertTS   time.Time `json:"last_alert_ts"`
	RuleIDs       []string  `json:"rule_ids"`
	MaxSeverity   string    `json:"max_severity"`
	Alerts        []string  `json:"alerts"`
}

type incidentGrouper struct {
	mu       sync.Mutex
	cfg      IncidentsConfig
	open     map[string]*incident // key: host -> active incident
	logDir   string
	logger   *Storage
}

func newIncidentGrouper(cfg IncidentsConfig, logDir string, logger *Storage) *incidentGrouper {
	if cfg.WindowSeconds <= 0 {
		cfg.WindowSeconds = 60
	}
	if cfg.MaxLifetimeSeconds <= 0 {
		cfg.MaxLifetimeSeconds = 24 * 60 * 60
	}
	return &incidentGrouper{
		cfg:    cfg,
		open:   map[string]*incident{},
		logDir: logDir,
		logger: logger,
	}
}

// SetAuthoritative toggles whether THIS grouper is doing the work.
// Used by the master signal handler to disable lower tiers.
func (g *incidentGrouper) SetAuthoritative(v bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cfg.IsAuthoritative = v
}

// IngestAlert is the alert hook entry point. Returns the incident_id
// the alert is associated with so callers (webhooks, syslog) can
// include it in their payloads.
func (g *incidentGrouper) IngestAlert(alert map[string]any) string {
	if g == nil || !g.cfg.Enabled || !g.cfg.IsAuthoritative {
		return ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	host := strFieldFromAny(alert["host"])
	if host == "" {
		host = strFieldFromAny(alert["matched_host"])
	}
	if host == "" {
		host = "unknown"
	}
	now := time.Now().UTC()
	if tsRaw, ok := alert["@timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, tsRaw); err == nil {
			now = t.UTC()
		}
	}
	ruleID := strFieldFromAny(alert["rule"])
	severity := strFieldFromAny(alert["severity"])
	alertID := strFieldFromAny(alert["alert_id"])
	if alertID == "" {
		alertID = strFieldFromAny(alert["@id"])
	}

	curr := g.open[host]
	closeOldDueToWindow := curr != nil && now.Sub(curr.LastAlertTS) > time.Duration(g.cfg.WindowSeconds)*time.Second
	closeOldDueToMaxLife := curr != nil && now.Sub(curr.FirstAlertTS) > time.Duration(g.cfg.MaxLifetimeSeconds)*time.Second
	if curr == nil || closeOldDueToWindow || closeOldDueToMaxLife {
		if curr != nil {
			g.flushUnsafe(curr)
		}
		curr = &incident{
			IncidentID:   newIncidentID(host, now),
			Host:         host,
			FirstAlertTS: now,
			LastAlertTS:  now,
			RuleIDs:      nil,
			MaxSeverity:  severity,
		}
		g.open[host] = curr
	}
	curr.LastAlertTS = now
	if !contains(curr.RuleIDs, ruleID) && ruleID != "" {
		curr.RuleIDs = append(curr.RuleIDs, ruleID)
	}
	if alertID != "" {
		curr.Alerts = append(curr.Alerts, alertID)
	}
	if incidentSeverityRank(severity) > incidentSeverityRank(curr.MaxSeverity) {
		curr.MaxSeverity = severity
	}
	g.flushUnsafe(curr)
	return curr.IncidentID
}

func (g *incidentGrouper) flushUnsafe(inc *incident) {
	if g.logDir == "" {
		return
	}
	dir := filepath.Join(g.logDir, "_incidents")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return
	}
	path := filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	data, err := json.Marshal(inc)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}

func incidentSeverityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func newIncidentID(host string, t time.Time) string {
	h := sha1.Sum([]byte(host + t.Format(time.RFC3339Nano)))
	return fmt.Sprintf("inc-%s-%s-%s", t.Format("20060102T150405Z"), host, hex.EncodeToString(h[:4]))
}

// runIncidentsCmd dispatches `simplesiem incidents <list|show|config>`.
func runIncidentsCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem incidents <list|show|config>

  list [--since 24h] [--severity high]
  show <id>
  config --window <dur>
  status`)
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		runIncidentsList(args[1:])
	case "show":
		runIncidentsShow(args[1:])
	case "config":
		runIncidentsConfig(args[1:])
	case "status":
		runIncidentsStatus()
	default:
		fatalf("unknown incidents subcommand: %s", args[0])
	}
}

func runIncidentsList(args []string) {
	args = permuteArgs(args, map[string]bool{"since": true, "severity": true})
	fs := flag.NewFlagSet("incidents list", flag.ExitOnError)
	since := fs.String("since", "24h", "filter by recency")
	sev := fs.String("severity", "", "minimum severity")
	_ = fs.Parse(args)
	cfg := loadConfig(defaultConfigPath())
	dir := filepath.Join(cfg.LogDir, "_incidents")
	sinceT, _ := parseSince(*since)
	entries, _ := os.ReadDir(dir)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() > entries[j].Name() })
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		dec := json.NewDecoder(f)
		for {
			var inc incident
			if err := dec.Decode(&inc); err != nil {
				break
			}
			if !sinceT.IsZero() && inc.LastAlertTS.Before(sinceT) {
				continue
			}
			if *sev != "" && incidentSeverityRank(inc.MaxSeverity) < incidentSeverityRank(*sev) {
				continue
			}
			fmt.Printf("%s  host=%s  severity=%s  alerts=%d  rules=%v\n",
				inc.IncidentID, inc.Host, inc.MaxSeverity, len(inc.Alerts), inc.RuleIDs)
			count++
		}
		f.Close()
	}
	if count == 0 {
		fmt.Println("(no incidents)")
	}
}

func runIncidentsShow(args []string) {
	if len(args) == 0 {
		fatalf("usage: incidents show <id>")
	}
	id := args[0]
	cfg := loadConfig(defaultConfigPath())
	dir := filepath.Join(cfg.LogDir, "_incidents")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		dec := json.NewDecoder(f)
		for {
			var inc incident
			if err := dec.Decode(&inc); err != nil {
				break
			}
			if inc.IncidentID == id {
				out, _ := json.MarshalIndent(inc, "", "  ")
				fmt.Println(string(out))
				f.Close()
				return
			}
		}
		f.Close()
	}
	fatalf("incident %q not found", id)
}

func runIncidentsConfig(args []string) {
	args = permuteArgs(args, map[string]bool{"window": true})
	fs := flag.NewFlagSet("incidents config", flag.ExitOnError)
	window := fs.String("window", "", "incident grouping window (e.g. 60s, 5m)")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	cfg := loadConfig(defaultConfigPath())
	if normaliseMode(cfg.Mode) == "server" && len(cfg.Server.MasterCNs) > 0 {
		fatalf("incidents config is refused on a server with a master enrolled. Run on the master.")
	}
	if *window == "" {
		fatalf("--window is required (e.g. 60s, 5m)")
	}
	d, err := parseDurationDays(*window)
	if err != nil {
		fatalf("--window %q: %v", *window, err)
	}
	if d <= 0 {
		fatalf("--window must be positive (got %s); use 'incidents disable' to turn off grouping", d)
	}
	cfg.Incidents.WindowSeconds = int(d.Seconds())
	cfg.Incidents.Enabled = true
	if err := saveConfig(defaultConfigPath(), cfg); err != nil {
		fatalf("save: %v", err)
	}
	fmt.Printf("incidents.window_seconds = %d\n", cfg.Incidents.WindowSeconds)
}

func runIncidentsStatus() {
	cfg := loadConfig(defaultConfigPath())
	fmt.Printf("incidents enabled:        %v\n", cfg.Incidents.Enabled)
	fmt.Printf("window_seconds:           %d\n", cfg.Incidents.WindowSeconds)
	fmt.Printf("max_lifetime_seconds:     %d\n", cfg.Incidents.MaxLifetimeSeconds)
	fmt.Printf("is_authoritative:         %v\n", cfg.Incidents.IsAuthoritative)
}
