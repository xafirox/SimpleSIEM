package sieg

import (
	"bufio"
	"compress/gzip"
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

// #10 — triage timeline + pivot. Five concrete edges, depth-1 only.

type pivotEdge string

const (
	edgeSameHost      pivotEdge = "same_host"
	edgeSamePid       pivotEdge = "same_pid_lineage"
	edgeSameUser      pivotEdge = "same_user"
	edgeSameRemote    pivotEdge = "same_remote_host"
	edgeSameFilename  pivotEdge = "same_filename"
)

var allPivotEdges = []pivotEdge{edgeSameHost, edgeSamePid, edgeSameUser, edgeSameRemote, edgeSameFilename}

// runTriagePivotCmd dispatches `simplesiem triage --pivot-from <id>`.
func runTriagePivotCmd(args []string) {
	args = permuteArgs(args, map[string]bool{
		"pivot-from": true, "window": true, "edges": true,
	})
	fs := flag.NewFlagSet("triage pivot", flag.ExitOnError)
	pivotFrom := fs.String("pivot-from", "", "alert ID to pivot from")
	windowStr := fs.String("window", "5m", "edge window (max 24h)")
	edgesStr := fs.String("edges", "", "comma-separated edges (default: all 5)")
	jsonOut := fs.Bool("json", false, "JSON output")
	maxEvents := fs.Int("max-events", 500, "hard cap on events returned (max 2000)")
	_ = fs.Parse(args)

	if *pivotFrom == "" {
		fatalf("--pivot-from <alert-id> is required")
	}
	window, err := parseDurationDays(*windowStr)
	if err != nil {
		fatalf("--window %q: %v", *windowStr, err)
	}
	if window > 24*time.Hour {
		fatalf("--window %s exceeds 24h cap", window)
	}
	if *maxEvents > 2000 {
		*maxEvents = 2000
	}
	enabledEdges := allPivotEdges
	if *edgesStr != "" {
		enabledEdges = nil
		for _, e := range strings.Split(*edgesStr, ",") {
			enabledEdges = append(enabledEdges, pivotEdge(strings.TrimSpace(e)))
		}
	}

	cfg := loadConfig(defaultConfigPath())
	alert, err := findAlert(cfg.LogDir, *pivotFrom)
	if err != nil {
		fatalf("alert %q not found: %v", *pivotFrom, err)
	}
	timeline := buildPivotTimeline(cfg.LogDir, alert, window, enabledEdges, *maxEvents)
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(timeline)
		return
	}
	fmt.Printf("=== Triage timeline for %s ===\n", *pivotFrom)
	if alert.Host != "" {
		fmt.Printf("Alert: %s host=%s rule=%s severity=%s fired_at=%s\n",
			alert.AlertID, alert.Host, alert.RuleID, alert.Severity,
			alert.Timestamp.Format(time.RFC3339))
	}
	fmt.Println()
	if len(timeline.Events) == 0 {
		fmt.Println("(no related events within window)")
		return
	}
	for _, e := range timeline.Events {
		marker := "       "
		if e.IsAlert {
			marker = "[ALERT]"
		} else if len(e.Edges) > 0 {
			marker = "       "
		}
		ts := e.Timestamp.Format("15:04:05")
		fmt.Printf("%s  %s  %s  %s\n", ts, marker, e.LogType, summarize(e.Event))
		if len(e.Edges) > 0 {
			fmt.Printf("            edges: %v\n", e.Edges)
		}
	}
	fmt.Printf("\nEdges followed: %v\n", timeline.EdgesFollowed)
}

type pivotedAlert struct {
	AlertID   string
	RuleID    string
	Host      string
	Severity  string
	User      string
	Pid       string
	Remote    string
	Filename  string
	Timestamp time.Time
	Event     map[string]any
}

type triageTimelineEvent struct {
	Timestamp time.Time      `json:"@timestamp"`
	LogType   string         `json:"type"`
	Edges     []pivotEdge    `json:"edges,omitempty"`
	IsAlert   bool           `json:"is_alert,omitempty"`
	Event     map[string]any `json:"event"`
}

type triageTimeline struct {
	AlertID       string                `json:"alert_id"`
	EdgesFollowed []pivotEdge           `json:"edges_followed"`
	Events        []triageTimelineEvent `json:"events"`
}

func findAlert(logDir, alertID string) (*pivotedAlert, error) {
	hosts, _ := os.ReadDir(logDir)
	for _, h := range hosts {
		if !h.IsDir() {
			continue
		}
		alertsDir := filepath.Join(logDir, h.Name(), "alerts")
		files, _ := os.ReadDir(alertsDir)
		sort.Slice(files, func(i, j int) bool { return files[i].Name() > files[j].Name() })
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			path := filepath.Join(alertsDir, f.Name())
			if a := findAlertInFile(path, alertID, h.Name()); a != nil {
				return a, nil
			}
		}
	}
	return nil, fmt.Errorf("not in any alerts/")
}

func findAlertInFile(path, alertID, host string) *pivotedAlert {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil
		}
		defer gz.Close()
		r = gz
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		got := strFieldFromAny(ev["alert_id"])
		if got == "" {
			got = strFieldFromAny(ev["@id"])
		}
		if got != alertID {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, strFieldFromAny(ev["@timestamp"]))
		return &pivotedAlert{
			AlertID:   alertID,
			RuleID:    strFieldFromAny(ev["rule"]),
			Host:      host,
			Severity:  strFieldFromAny(ev["severity"]),
			User:      strFieldFromAny(ev["user"]),
			Timestamp: t,
			Event:     ev,
		}
	}
	return nil
}

func buildPivotTimeline(logDir string, alert *pivotedAlert, window time.Duration, edges []pivotEdge, maxEvents int) triageTimeline {
	tl := triageTimeline{AlertID: alert.AlertID, EdgesFollowed: edges}
	startT := alert.Timestamp.Add(-window)
	endT := alert.Timestamp.Add(window)

	enabledEdge := map[pivotEdge]bool{}
	for _, e := range edges {
		enabledEdge[e] = true
	}

	addAlertEvent := triageTimelineEvent{
		Timestamp: alert.Timestamp, LogType: "alerts",
		IsAlert: true, Event: alert.Event,
	}
	tl.Events = append(tl.Events, addAlertEvent)

	hosts, _ := os.ReadDir(logDir)
	for _, h := range hosts {
		if !h.IsDir() || strings.HasPrefix(h.Name(), "_") {
			continue
		}
		isHomeHost := h.Name() == alert.Host
		hostPath := filepath.Join(logDir, h.Name())
		types, _ := os.ReadDir(hostPath)
		for _, t := range types {
			if !t.IsDir() {
				continue
			}
			files, _ := os.ReadDir(filepath.Join(hostPath, t.Name()))
			for _, f := range files {
				if f.IsDir() {
					continue
				}
				if len(tl.Events) >= maxEvents {
					return tl
				}
				gatherPivotEdges(filepath.Join(hostPath, t.Name(), f.Name()), t.Name(), alert, &tl, startT, endT, enabledEdge, isHomeHost, maxEvents)
			}
		}
	}
	sort.Slice(tl.Events, func(i, j int) bool { return tl.Events[i].Timestamp.Before(tl.Events[j].Timestamp) })
	return tl
}

func gatherPivotEdges(path, logType string, alert *pivotedAlert, tl *triageTimeline, startT, endT time.Time, enabled map[pivotEdge]bool, isHomeHost bool, maxEvents int) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return
		}
		defer gz.Close()
		r = gz
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(tl.Events) >= maxEvents {
			return
		}
		var ev map[string]any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, strFieldFromAny(ev["@timestamp"]))
		if t.IsZero() || t.Before(startT) || t.After(endT) {
			continue
		}
		hits := []pivotEdge{}
		if isHomeHost && enabled[edgeSameHost] {
			hits = append(hits, edgeSameHost)
		}
		if isHomeHost && enabled[edgeSamePid] && alert.Pid != "" {
			pid := strFieldFromAny(ev["pid"])
			ppid := strFieldFromAny(ev["parent_pid"])
			if pid == alert.Pid || ppid == alert.Pid {
				hits = append(hits, edgeSamePid)
			}
		}
		if enabled[edgeSameUser] && alert.User != "" {
			if strFieldFromAny(ev["user"]) == alert.User {
				hits = append(hits, edgeSameUser)
			}
		}
		if enabled[edgeSameRemote] && alert.Remote != "" {
			if strFieldFromAny(ev["remote_host"]) == alert.Remote {
				hits = append(hits, edgeSameRemote)
			}
		}
		if enabled[edgeSameFilename] && alert.Filename != "" {
			if strFieldFromAny(ev["path"]) == alert.Filename {
				hits = append(hits, edgeSameFilename)
			}
		}
		if len(hits) > 0 {
			tl.Events = append(tl.Events, triageTimelineEvent{
				Timestamp: t, LogType: logType,
				Edges: hits, Event: ev,
			})
		}
	}
}

func summarize(ev map[string]any) string {
	parts := []string{}
	for _, k := range []string{"event", "user", "remote_host", "path", "process", "rule"} {
		if v := strFieldFromAny(ev[k]); v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, " ")
}
