package sieg

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// runTreeCmd reconstructs a process tree from on-disk process events
// (process_start carries pid + ppid + parent_name + cmdline) and
// renders it as an indented ASCII tree. Operators use this for
// "what spawned what?" investigations during triage.
//
// Two anchor modes:
//   - --pid <N>:    show ancestors AND descendants of one specific PID.
//   - --since <w>:  show every root-level process_start in the window
//                   with its descendants. Default 1h.
//
// Stateless: walks log_dir directly, no daemon round-trip.
func runTreeCmd(args []string) {
	args = permuteArgs(args, map[string]bool{
		"config": true, "since": true, "host": true, "pid": true, "format": true,
	})
	fs := flag.NewFlagSet("tree", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	since := fs.String("since", "1h", "time window (1h, 30m, 7d, RFC3339)")
	hostFilter := fs.String("host", "", "in server / master mode, restrict to one agent ID")
	pidFlag := fs.Int("pid", 0, "anchor on this PID; show ancestors + descendants. 0 = show all roots in window")
	format := fs.String("format", "table", "output format: table (indented ASCII tree, default) or json")
	_ = fs.Parse(args)
	switch *format {
	case "table", "json":
	default:
		fatalf("--format must be one of: table, json")
	}

	start, err := parseSince(*since)
	if err != nil {
		fatalf("--since: %v", err)
	}
	cfg := loadConfig(*cfgPath)
	if _, err := os.Stat(cfg.LogDir); err != nil {
		fmt.Fprintln(os.Stderr, "no logs at", cfg.LogDir)
		return
	}
	end := time.Now().UTC()
	roots := searchRoots(cfg, *hostFilter)
	events := loadEventsInRangeMulti(roots, start, end, "processes")

	procs := map[int]*processNode{}
	for _, e := range events {
		ev, _ := e.Data["event"].(string)
		if ev != "process_start" {
			continue
		}
		pid := intField(e.Data, "pid")
		if pid == 0 {
			continue
		}
		ppid := intField(e.Data, "ppid")
		p := &processNode{
			Pid:        pid,
			Ppid:       ppid,
			Name:       strField(e.Data, "name"),
			Cmdline:    strField(e.Data, "cmdline"),
			Host:       strField(e.Data, "host"),
			TS:         e.TS,
			ParentName: strField(e.Data, "parent_name"),
			User:       strField(e.Data, "user"),
		}
		// Same PID may legitimately reappear if PIDs were reused
		// inside the window; keep the latest observation.
		if existing, ok := procs[pid]; !ok || existing.TS.Before(p.TS) {
			procs[pid] = p
		}
	}
	// Build child links.
	for pid, p := range procs {
		if parent, ok := procs[p.Ppid]; ok {
			parent.Children = append(parent.Children, pid)
		}
	}
	for _, p := range procs {
		sort.Ints(p.Children)
	}

	if *format == "json" {
		emitTreeJSON(procs, *pidFlag)
		return
	}

	if *pidFlag > 0 {
		anchor := *pidFlag
		if _, ok := procs[anchor]; !ok {
			fatalf("pid %d has no process_start event in the %s window", anchor, *since)
		}
		// Walk to the highest visible ancestor of the anchor.
		root := anchor
		for {
			p, ok := procs[root]
			if !ok {
				break
			}
			if _, parentExists := procs[p.Ppid]; !parentExists {
				break
			}
			root = p.Ppid
		}
		fmt.Printf("Process tree anchored on pid %d (rendered from highest ancestor pid %d):\n", anchor, root)
		renderProcessTree(procs, root, "", anchor)
		return
	}

	// Show every root — process whose parent isn't in the captured set.
	rootPids := []int{}
	for pid, p := range procs {
		if _, ok := procs[p.Ppid]; !ok {
			rootPids = append(rootPids, pid)
		}
	}
	sort.Ints(rootPids)
	fmt.Printf("Process tree — %s -> %s   (%s; %d processes captured, %d roots)\n",
		displayTS(start).Format("2006-01-02 15:04:05"),
		displayTS(end).Format("2006-01-02 15:04:05"),
		displayTZ(), len(procs), len(rootPids))
	for _, pid := range rootPids {
		renderProcessTree(procs, pid, "", 0)
	}
}

type processNode struct {
	Pid        int
	Ppid       int
	Name       string
	Cmdline    string
	Host       string
	TS         time.Time
	ParentName string
	User       string
	Children   []int
}

func renderProcessTree(procs map[int]*processNode, pid int, indent string, highlightPid int) {
	p, ok := procs[pid]
	if !ok {
		return
	}
	marker := "  "
	if pid == highlightPid {
		marker = "→ "
	}
	cmd := p.Cmdline
	if cmd == "" {
		cmd = p.Name
	}
	if len(cmd) > 90 {
		cmd = cmd[:89] + "…"
	}
	hostPart := ""
	if p.Host != "" {
		hostPart = "  host=" + p.Host
	}
	userPart := ""
	if p.User != "" {
		userPart = "  user=" + p.User
	}
	fmt.Printf("%s%s[%d] %s%s%s\n", indent, marker, pid, cmd, hostPart, userPart)
	for _, c := range p.Children {
		renderProcessTree(procs, c, indent+"  ", highlightPid)
	}
}

func emitTreeJSON(procs map[int]*processNode, pid int) {
	type out struct {
		Pid      int       `json:"pid"`
		Ppid     int       `json:"ppid"`
		Name     string    `json:"name"`
		Cmdline  string    `json:"cmdline"`
		User     string    `json:"user"`
		Host     string    `json:"host"`
		TS       time.Time `json:"ts"`
		Children []int     `json:"children"`
	}
	all := []out{}
	for _, p := range procs {
		all = append(all, out{
			Pid: p.Pid, Ppid: p.Ppid, Name: p.Name, Cmdline: p.Cmdline,
			User: p.User, Host: p.Host, TS: p.TS, Children: p.Children,
		})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Pid < all[j].Pid })
	jsonOut := map[string]any{"processes": all}
	if pid > 0 {
		jsonOut["anchor"] = pid
	}
	if data, err := json.MarshalIndent(jsonOut, "", "  "); err == nil {
		fmt.Println(string(data))
	}
}

// intField returns m[key] interpreted as int (covers float64 from
// JSON unmarshal, plus native numeric types).
func intField(m map[string]any, key string) int {
	switch x := m[key].(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int32:
		return int(x)
	case int64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	}
	return 0
}
