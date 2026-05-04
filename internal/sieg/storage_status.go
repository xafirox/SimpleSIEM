package sieg

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// printStorageStatus renders the storage-quota block for `simplesiem
// status`. Three sections:
//
//  1. Local volume(s): one line per configured location showing
//     OK/WARN/HALTED, used%, free, and which one is currently active
//     for writes. The local probe reads disk usage live (cached for 5s
//     by cachedProbeVolume) so an operator running status after
//     freeing space sees the recovery within one heartbeat.
//
//  2. Halted-now banner: when the daemon's storage controller has
//     entered HALT — that is, the active volume is past the halt
//     threshold AND no failover slot was usable — surface that
//     prominently in red so it can't be missed.
//
//  3. Remote warnings (server + master modes only): scan today's meta
//     log for every host the local daemon knows about and surface
//     storage_warning / storage_halt events newer than 24h. For server
//     mode this includes realm peers (replicated through `.from-<peer>`
//     files); for master mode it includes every server/agent the
//     master pulls events from, plus the paired collector.
func printStorageStatus(cfg Config) {
	q := resolveQuotas(cfg)
	locs := allStorageLocations(cfg)
	fmt.Println()
	fmt.Printf("storage         warn=%s  halt=%s\n", q.Warn.Original, q.Halt.Original)

	worstLocal := storageOK
	for i, loc := range locs {
		v, err := cachedProbeVolume(loc)
		if err != nil {
			fmt.Printf("  %s  %s\n", loc, colorize("PROBE FAILED: "+err.Error(), colYellow))
			continue
		}
		state := classifyVolume(v, q.Warn, q.Halt)
		if state > worstLocal {
			worstLocal = state
		}
		role := "primary"
		if i > 0 {
			role = fmt.Sprintf("failover #%d", i)
		}
		stateLabel := stateLabelColored(state)
		fmt.Printf("  %s  [%s] %s  used %s of %s (%.1f%%, %s free)\n",
			stateLabel, role, loc,
			formatBytesDecimal(v.Used),
			formatBytesDecimal(v.Total),
			v.UsedPercent,
			formatBytesDecimal(v.Free))
	}

	// Halt banner — read from the most recent storage-state event in
	// the local meta log. Live probe alone can't tell us the daemon is
	// actively rejecting writes (an operator could free space between
	// our probe and theirs), so this is the authoritative signal.
	if event, ts, ok := readLatestStorageStateEvent(cfg); ok {
		switch event {
		case "storage_halt":
			fmt.Printf("  %s  %s — daemon is rejecting new event writes (since %s, %s ago)\n",
				colorize("HALTED", colRed),
				"SimpleSIEM has stopped collecting events",
				displayTS(ts).Format("2006-01-02 15:04:05"),
				humanAgo(time.Since(ts)))
			fmt.Println("                free disk space or set storage.failover_locations in config.json to recover.")
		case "storage_failover":
			fmt.Printf("  %s — primary volume halted; daemon is now writing to a failover location (%s ago)\n",
				colorize("FAILOVER ACTIVE", colYellow), humanAgo(time.Since(ts)))
		}
	}

	// Remote-host warnings — server / master / collector mode only.
	mode := normaliseMode(cfg.Mode)
	if mode == "server" || mode == "master" || mode == "collector" {
		printRemoteStorageWarnings(cfg)
	}
}

func stateLabelColored(s storageState) string {
	switch s {
	case storageWarn:
		return colorize("WARN", colYellow)
	case storageHalt:
		return colorize("HALT", colRed)
	default:
		return colorize(" OK ", colGreen)
	}
}

// readLatestStorageStateEvent finds the most recent storage_warning /
// storage_halt / storage_recovered / storage_failover event in any of
// the local meta logs (today + yesterday for safety in the
// just-after-midnight case). Returns the event name and its timestamp
// so the caller can display it. Returns ok=false when nothing is
// found.
func readLatestStorageStateEvent(cfg Config) (event string, ts time.Time, ok bool) {
	candidates := []string{}
	for _, loc := range allStorageLocations(cfg) {
		// Local meta paths vary by mode. Cover all of them; missing
		// directories are skipped silently.
		switch normaliseMode(cfg.Mode) {
		case "agent":
			candidates = append(candidates,
				filepath.Join(loc, "_agent", "meta"))
		case "server":
			candidates = append(candidates,
				filepath.Join(loc, "_server", "meta"))
			localID := pickServerLocalID(cfg.Server.LocalID)
			candidates = append(candidates, filepath.Join(loc, localID, "meta"))
		case "master":
			candidates = append(candidates,
				filepath.Join(loc, "_master", "meta"))
			localID := pickServerLocalID(cfg.Server.LocalID)
			candidates = append(candidates, filepath.Join(loc, localID, "meta"))
		case "collector":
			candidates = append(candidates,
				filepath.Join(loc, "_collector", "meta"))
			localID := pickServerLocalID(cfg.Server.LocalID)
			candidates = append(candidates, filepath.Join(loc, localID, "meta"))
		default:
			candidates = append(candidates, filepath.Join(loc, "meta"))
		}
	}

	storageEvents := map[string]bool{
		"storage_warning":   true,
		"storage_halt":      true,
		"storage_recovered": true,
		"storage_failover":  true,
		"storage_failback":  true,
	}
	today := time.Now().UTC().Format("2006-01-02")
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	for _, dir := range candidates {
		for _, day := range []string{today, yesterday} {
			path := filepath.Join(dir, day+".jsonl")
			if e, t, found := scanLastMatching(path, storageEvents); found && t.After(ts) {
				event, ts, ok = e, t, true
			}
		}
	}
	return
}

// scanLastMatching reads a JSONL file and returns the most recent
// (highest ts) event whose `event` field appears in the wanted set.
// Files don't fit in memory in the worst case, but storage events are
// rare; a forward-only line scan is fine.
func scanLastMatching(path string, wanted map[string]bool) (string, time.Time, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", time.Time{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var lastEvent string
	var lastTS time.Time
	for sc.Scan() {
		var obj map[string]any
		if err := json.Unmarshal(sc.Bytes(), &obj); err != nil {
			continue
		}
		ev, _ := obj["event"].(string)
		if !wanted[ev] {
			continue
		}
		tsStr, _ := obj["ts"].(string)
		t, err := time.Parse(time.RFC3339Nano, tsStr)
		if err != nil {
			continue
		}
		if t.After(lastTS) {
			lastTS = t
			lastEvent = ev
		}
	}
	if lastEvent == "" {
		return "", time.Time{}, false
	}
	return lastEvent, lastTS, true
}

// printRemoteStorageWarnings scans the meta directory of every
// remote host known to this server / master / collector and surfaces
// any storage_warning or storage_halt events newer than 24h. The
// remote events arrive through the existing event-replication
// pipeline:
//   - server mode: realm peers replicate via .from-<peer>.jsonl
//   - master mode: per-server pulls land under <log_dir>/<host>/meta/
//     as .from-<server>.jsonl; agent meta arrives the same way
//   - collector mode: pulls from a single source land under
//     <log_dir>/<host>/meta/.from-<origin>.jsonl
//
// Result: any host with an unresolved warning shows up here without
// the operator having to log into that host individually.
func printRemoteStorageWarnings(cfg Config) {
	type remoteAlert struct {
		host  string
		event string
		ts    time.Time
		path  string
	}
	now := time.Now()
	cutoff := now.Add(-24 * time.Hour)

	alerts := []remoteAlert{}
	wanted := map[string]bool{
		"storage_warning":  true,
		"storage_halt":     true,
		"storage_failover": true,
	}

	selfLocalID := pickServerLocalID(cfg.Server.LocalID)
	for _, loc := range allStorageLocations(cfg) {
		hosts := listHosts(loc)
		for _, host := range hosts {
			// Skip our own pseudo-host buckets — those are already
			// covered by the local volume probe block above.
			if host == "_server" || host == "_master" || host == "_collector" || host == "_agent" || host == selfLocalID {
				continue
			}
			metaDir := filepath.Join(loc, host, "meta")
			entries, err := os.ReadDir(metaDir)
			if err != nil {
				continue
			}
			// Per-host, find the most recent storage warning across
			// all .jsonl shards (own + replicated). Only the most
			// recent event matters — if a warning was followed by a
			// recovered, the recovered is in the local meta log
			// (not propagated, so we can't filter on it here).
			var best remoteAlert
			best.host = host
			for _, e := range entries {
				name := e.Name()
				if !strings.HasSuffix(name, ".jsonl") {
					continue
				}
				path := filepath.Join(metaDir, name)
				if ev, ts, ok := scanLastMatching(path, wanted); ok && ts.After(best.ts) && ts.After(cutoff) {
					best.event = ev
					best.ts = ts
					best.path = path
				}
			}
			if best.event != "" {
				alerts = append(alerts, best)
			}
		}
	}

	if len(alerts) == 0 {
		return
	}
	sort.Slice(alerts, func(i, j int) bool {
		// Halt > failover > warning, then most-recent first.
		sevI := remoteSeverityRank(alerts[i].event)
		sevJ := remoteSeverityRank(alerts[j].event)
		if sevI != sevJ {
			return sevI > sevJ
		}
		return alerts[i].ts.After(alerts[j].ts)
	})
	fmt.Println("  remote storage warnings (last 24h):")
	for _, a := range alerts {
		label := colorize("WARN", colYellow)
		if a.event == "storage_halt" {
			label = colorize("HALT", colRed)
		} else if a.event == "storage_failover" {
			label = colorize("FAILOVER", colYellow)
		}
		fmt.Printf("    %s  %-20s  %s ago  (%s)\n",
			label, a.host, humanAgo(now.Sub(a.ts)), a.event)
	}
}

func remoteSeverityRank(ev string) int {
	switch ev {
	case "storage_halt":
		return 3
	case "storage_failover":
		return 2
	case "storage_warning":
		return 1
	}
	return 0
}
