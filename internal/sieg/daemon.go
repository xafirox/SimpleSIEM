package sieg

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type daemonState struct {
	storage *Storage
	// extraStorages are additional Storage instances we own (e.g. the
	// forwarding storage in agent mode). Stop() closes each so writer
	// goroutines don't leak.
	extraStorages []*Storage
	cancel        context.CancelFunc
	wg            *sync.WaitGroup
	shipper       *Shipper
	server        *serverState
	mode          string
}

// startDaemon loads config, picks a mode (standalone/agent/server), and
// launches the appropriate components. Callers must Stop() to shut down
// cleanly.
func startDaemon(cfgPath string) (*daemonState, error) {
	cfg, cerr := loadConfigStrict(cfgPath)
	if cerr != nil {
		return nil, fmt.Errorf("config: %w (refusing to start with defaults — fix the file or use `simplesiem run --config <path>` after correcting it)", cerr)
	}
	// Seed config.json.bak if it's missing. Covers installs that
	// pre-date the install-time seeding so the malformed-edit
	// rollback path always has a target after the first daemon
	// start. Best-effort: a copy failure isn't fatal.
	if cfgPath != "" {
		if _, err := os.Stat(cfgPath + ".bak"); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(cfgPath); rerr == nil {
				_ = os.WriteFile(cfgPath+".bak", data, 0o640)
			}
		}
	}
	mode := normaliseMode(cfg.Mode)
	if err := os.MkdirAll(cfg.LogDir, 0o755); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	switch mode {
	case "server":
		st, err := startServerOnlyDaemon(ctx, &wg, cfg, cfgPath)
		if err != nil {
			cancel()
			return nil, err
		}
		return &daemonState{cancel: cancel, wg: &wg, server: st, mode: mode, storage: nil}, nil
	case "agent":
		ds, err := startAgentDaemon(ctx, &wg, cfg)
		if err != nil {
			cancel()
			return nil, err
		}
		ds.cancel = cancel
		ds.wg = &wg
		ds.mode = mode
		return ds, nil
	case "master":
		ds, err := startMasterDaemon(ctx, &wg, cfg)
		if err != nil {
			cancel()
			return nil, err
		}
		ds.cancel = cancel
		ds.wg = &wg
		ds.mode = mode
		return ds, nil
	case "collector":
		ds, err := startCollectorDaemon(ctx, &wg, cfg)
		if err != nil {
			cancel()
			return nil, err
		}
		ds.cancel = cancel
		ds.wg = &wg
		ds.mode = mode
		return ds, nil
	}

	// Standalone (default)
	gid := resolveGroupGID(cfg.LogOwnerGroup)
	// Pick the active write location up-front so a daemon starting on
	// an already-full primary volume opens its handles on the first
	// non-halted failover instead of writing into a halted directory.
	initialLoc := pickInitialStorageLocation(cfg)
	group := newStorageGroup(initialLoc)
	storage, err := group.Open("", gid, int64(cfg.MaxLogFileMB)*1024*1024, cfg.WriteQueueSize)
	if err != nil {
		cancel()
		return nil, err
	}
	newStorageController(group, cfg).start(ctx, &wg)

	if cfg.RulesPath != "" {
		if rules, err := loadRules(cfg.RulesPath); err == nil {
			storage.SetRules(rules)
			storage.Write("meta", map[string]any{
				"event": "rules_loaded", "path": cfg.RulesPath, "count": len(rules),
			})
		} else if !os.IsNotExist(err) {
			storage.Write("errors", map[string]any{
				"collector": "rules", "error": err.Error(), "path": cfg.RulesPath,
			})
		}
		// Hot-reload watcher: every CLI verb that mutates rules.json
		// (rules enable / disable / set / delete / new + match/threshold/
		// sequence/...) writes via atomicWriteFile. Without this watcher
		// the running daemon never picks up the change — operators see
		// the CLI's "daemon will hot-reload within ~1s" message and then
		// wonder why their rule never fires.
		startRulesWatcher(ctx, &wg, cfg.RulesPath, func(rules []*alertRule) {
			storage.SetRules(rules)
		}, storage)
	}

	// SIEM-enhancement pipeline (#1 stats, #2 suppression, #6 incidents,
	// #9 fixture capture) + background workers (suppression watcher,
	// MITRE auto-fetch, threat-intel auto-fetch). Standalone mode
	// always groups its own alerts; no master/server gating applies.
	pipeline := newAlertPipeline(cfg, cfg.LogDir, storage)
	if pipeline != nil {
		storage.AddAlertHook(pipeline.hook)
	}
	startSiemEnhancements(ctx, &wg, cfg, storage, pipeline)

	if cfg.Server.NetworkIngest.Enabled || cfg.Master.NetworkIngest.Enabled {
		storage.Write("meta", map[string]any{
			"event": "network_ingest_refused",
			"mode":  "standalone",
			"hint":  "network ingest is server/master-only; remove .network_ingest.enabled",
		})
	}
	storage.Write("meta", map[string]any{
		"event":            "start",
		"mode":             mode,
		"pid":              os.Getpid(),
		"platform":         runtime.GOOS,
		"arch":             runtime.GOARCH,
		"version":          version,
		"build":            buildNumber,
		"file_watch_paths": cfg.FileWatchPaths,
		"network_interval": cfg.NetworkInterval,
		"process_interval": cfg.ProcessInterval,
		"traffic_interval": cfg.TrafficInterval,
	})

	startLocalCollectors(ctx, &wg, cfg, storage, storage)
	startRetention(ctx, &wg, cfg.LogDir, cfg.RetentionDays)
	startChainHeadSigner(ctx, &wg, cfg, storage)
	startDaemonHeartbeat(ctx, &wg, storage, mode)

	return &daemonState{storage: storage, cancel: cancel, wg: &wg, mode: mode}, nil
}

// startDaemonHeartbeat writes a meta:daemon_alive event every 60s so
// the file mtime under the primary store's meta dir never falls behind
// the 10-minute wedge threshold during normal operation. Without this,
// a truly idle host (no auth/network/file activity) goes silent on
// disk between collector polls, and `daemonLooksWedged` flags the
// daemon as "running but SILENT" even though everything is healthy.
//
// The event is intentionally cheap: a single small JSON line per
// minute. The write goes through the regular Storage queue so a
// wedged writer won't fake liveness — if the writer is dead the
// heartbeat won't reach disk and the wedge alarm correctly fires.
//
// Hardening: a panic-recover wraps the loop body so a transient
// failure inside Storage.Write (e.g., the writer closing the queue
// during shutdown) can't kill the goroutine. The first beat fires
// immediately so the meta file's mtime is fresh from second zero —
// previously the first beat was at t=60s and the wedge check could
// false-fire on a daemon that had only just started in some race
// windows.
func startDaemonHeartbeat(ctx context.Context, wg *sync.WaitGroup, storage *Storage, mode string) {
	if storage == nil {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = recover() }()
		beat := func() {
			defer func() { _ = recover() }()
			storage.Write("meta", map[string]any{
				"event": "daemon_alive",
				"mode":  mode,
			})
		}
		// First beat is immediate so the mtime is fresh from t=0.
		beat()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			beat()
		}
	}()
}

// startChainHeadSigner is a small helper that's safe to call from
// any daemon entry point. It creates the per-host signer (key file
// at <state>/chainhead.key, generated on first call) and starts the
// hourly signing loop. If construction fails (state_dir missing,
// can't write key file, etc.) we log to errors and skip signing —
// the daemon stays alive; operators see the meta event.
func startChainHeadSigner(ctx context.Context, wg *sync.WaitGroup, cfg Config, logger *Storage) {
	if cfg.LogDir == "" {
		return
	}
	stateDir := cfg.StateDir
	if stateDir == "" {
		stateDir = defaultStateDir()
	}
	signer, err := newChainHeadSigner(cfg.LogDir, stateDir, time.Hour, logger)
	if err != nil {
		if logger != nil {
			logger.Write("errors", map[string]any{
				"collector": "chainhead",
				"error":     err.Error(),
				"hint":      "signed chain heads disabled until <state>/chainhead.key is writable",
			})
		}
		return
	}
	signer.Start(ctx, wg)
}

// startLocalCollectors launches the standard host-monitoring collector
// set (network, files, auth, processes/traffic, authlog) writing to
// `eventStore`. healthLogger is where the HealthMonitor's own
// collector_silent / collector_recovered meta events go (in standalone
// that's the same store as eventStore; in server mode it's the slim
// _server pseudo-host store so the receiver and host-monitoring are
// kept visually separate).
//
// Used by:
//   - standalone mode (eventStore = top-level Storage)
//   - server mode with collect_locally:true (eventStore = the per-host
//     Storage for the server's own hostname; agents write to their
//     own per-host Storage independently)
func startLocalCollectors(ctx context.Context, wg *sync.WaitGroup, cfg Config, eventStore, healthLogger *Storage) *HealthMonitor {
	pCache := newProcCache()
	dCache := newDNSCache(seconds(cfg.DNSCacheTTL), 4096)
	state := newStateStore(cfg.StateDir)

	trafficInterval := cfg.TrafficInterval
	if trafficInterval <= 0 {
		trafficInterval = 30
	}

	// Heartbeat liveness. timeout = 5x the slowest tick + a buffer so a
	// single missed cycle doesn't trip the silent-collector alert.
	health := newHealthMonitor(healthLogger, time.Minute, 5*time.Minute)
	health.Register("network", "files", "auth", "processes", "traffic", "authlog")

	collectors := []Collector{
		&NetworkCollector{
			storage:   eventStore,
			interval:  seconds(cfg.NetworkInterval),
			dnsCache:  dCache,
			procCache: pCache,
			health:    health,
			state:     state,
		},
		&FileCollector{
			storage:   eventStore,
			paths:     cfg.FileWatchPaths,
			recursive: cfg.FileWatchRecursive,
			health:    health,
		},
		&AuthCollector{
			storage:  eventStore,
			interval: seconds(cfg.AuthInterval),
			health:   health,
		},
		&ProcessCollector{
			storage:         eventStore,
			interval:        seconds(cfg.ProcessInterval),
			trafficInterval: seconds(trafficInterval),
			procCache:       pCache,
			dnsCache:        dCache,
			health:          health,
		},
		&AuthLogCollector{
			storage:  eventStore,
			paths:    cfg.AuthLogPaths,
			interval: seconds(authLogInterval(cfg.AuthLogInterval)),
			health:   health,
			state:    state,
		},
	}
	health.Start(ctx, wg)
	for _, c := range collectors {
		c.Start(ctx, wg)
	}
	return health
}

func normaliseMode(s string) string {
	switch s {
	case "agent", "server", "master", "collector":
		return s
	default:
		return "standalone"
	}
}

// startServerOnlyDaemon runs the HTTPS receiver, plus (when
// server.collect_locally is true, the default) the same host-monitoring
// collector set used in standalone mode — writing into the per-host
// directory keyed by the server's own hostname. Operators get a single
// pane that includes the SIEM server itself alongside the agents
// shipping to it. Per-host Storage instances for incoming agents are
// still created lazily as those agents connect.
func startServerOnlyDaemon(ctx context.Context, wg *sync.WaitGroup, cfg Config, cfgPath string) (*serverState, error) {
	st, err := runServer(ctx, wg, cfg, cfgPath)
	if err != nil {
		return nil, err
	}
	// Storage quota controller — server mode keeps a per-host Storage
	// for every connecting agent (plus _server pseudo-host), all
	// registered with st.group. The controller probes the active root
	// volume and toggles halted / SwitchRoot across every member when
	// thresholds are crossed.
	newStorageController(st.group, cfg).start(ctx, wg)
	startRetention(ctx, wg, cfg.LogDir, cfg.RetentionDays)

	// _server pseudo-host: receiver lifecycle + collector_silent events.
	serverStore, _ := st.storageFor("_server")
	if serverStore != nil {
		serverStore.Write("meta", map[string]any{
			"event":           "start",
			"mode":            "server",
			"pid":             os.Getpid(),
			"platform":        runtime.GOOS,
			"arch":            runtime.GOARCH,
			"version":         version,
			"build":           buildNumber,
			"listen":          cfg.Server.Listen,
			"collect_locally": cfg.Server.CollectLocally,
		})
		// Heartbeat under _server so the wedge detector's mtime check
		// (which scans <log_dir>/_server/meta/) sees activity even
		// when the server has no agents shipping events yet.
		startDaemonHeartbeat(ctx, wg, serverStore, "server")
	}

	if cfg.Server.CollectLocally {
		localID := pickServerLocalID(cfg.Server.LocalID)
		localStore, lerr := st.storageFor(localID)
		if lerr != nil || localStore == nil {
			if serverStore != nil {
				serverStore.Write("errors", map[string]any{
					"collector": "server", "error": "could not open local storage: " + errString(lerr),
					"local_id": localID,
				})
			}
			return st, nil
		}
		// Stamp origin_server on every event written through localStore
		// so the server's own host activity is included when a master
		// (or realm peer) calls /v1/sync/events. Without this, the
		// sync handler's `origin_server == self` filter excludes
		// every locally-collected event and the master never sees the
		// server's own host as a forwarded origin.
		localStore.SetOriginServer(deriveSelfPeerID(cfg.Server.Listen))
		localStore.Write("meta", map[string]any{
			"event":            "start",
			"mode":             "server (local collection)",
			"local_id":         localID,
			"pid":              os.Getpid(),
			"platform":         runtime.GOOS,
			"arch":             runtime.GOARCH,
			"version":          version,
			"build":            buildNumber,
			"file_watch_paths": cfg.FileWatchPaths,
			"network_interval": cfg.NetworkInterval,
			"process_interval": cfg.ProcessInterval,
			"traffic_interval": cfg.TrafficInterval,
		})
		// Seed the per-host firstSeen + todBaseline detectors with a
		// synthetic startup observation so persistIfDirty on a quiet
		// server still produces a non-empty file. Without this, an
		// idle 18-second test window can produce zero observations
		// (no new processes, no new connections under network_interval),
		// dirty stays false, and the persistIfDirty shutdown write
		// is a no-op. Run in a goroutine so the caller returns to the
		// daemon's main loop without waiting on user.Current() — which
		// can be slow in stripped containers. Best-effort: nil-safe.
		go func() {
			defer func() { _ = recover() }()
			seedEvent := map[string]any{
				"event":   "daemon_init",
				"user":    daemonUser(),
				"process": serviceName,
				"name":    serviceName,
			}
			if st.firstSeen != nil {
				st.firstSeen.observe(localID, seedEvent)
			}
			if st.todBaseline != nil {
				st.todBaseline.observe(localID, seedEvent)
			}
		}()
		// Collector heartbeats go to _server so the receiver's
		// audit trail carries any collector_silent events. Event
		// data lands under <log_dir>/<local_id>/.
		startLocalCollectors(ctx, wg, cfg, localStore, serverStore)
	}

	return st, nil
}

// pickServerLocalID resolves the identifier under which the server's
// own monitored events are stored. Honours an explicit server.local_id
// (when it's a valid agent-style identifier), otherwise falls back to
// the OS hostname. Anything not validAgentID-compatible — strange
// hostnames, unset hostnames in stripped containers — collapses to
// "_localhost" so collection never silently fails because of a name.
func pickServerLocalID(explicit string) string {
	if explicit != "" && validAgentID(explicit) {
		return explicit
	}
	if h, err := os.Hostname(); err == nil && validAgentID(h) {
		return h
	}
	return "_localhost"
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// daemonUser returns the username the daemon is running as (e.g.
// "root" on Linux, "Administrator" on Windows). Falls back to a
// numeric uid string or "unknown" so the field is never empty —
// the observeHook + first-seen / todBaseline detectors key on it.
// Cross-platform: os/user works on every supported target.
func daemonUser() string {
	if u, err := user.Current(); err == nil {
		if u.Username != "" {
			return u.Username
		}
		if u.Uid != "" {
			return u.Uid
		}
	}
	return "unknown"
}

// startAgentDaemon runs collectors but routes their output to a Shipper
// instead of local Storage. A slim local Storage at <log_dir>/_agent/ is
// kept for meta/errors so operators can still triage shipping problems
// on the agent host.
func startAgentDaemon(ctx context.Context, wg *sync.WaitGroup, cfg Config) (*daemonState, error) {
	initialLoc := pickInitialStorageLocation(cfg)
	group := newStorageGroup(initialLoc)
	local, err := agentLocalStorage(cfg, group)
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	if cfg.Agent.ID == "" {
		cfg.Agent.ID = hostname
	}
	shipper, err := newShipper(cfg.Agent, hostname, local)
	if err != nil {
		local.Write("errors", map[string]any{"collector": "agent", "error": err.Error()})
		return nil, err
	}
	// Mirror local meta+errors to the server. The agent's _agent
	// store is a local audit trail (kept for offline triage), but
	// the server should see the same events so a centrally-monitoring
	// operator gets a full picture without SSH'ing to each agent.
	// Each mirrored event is stamped with host=<agent_id> so the
	// server files it under <log_dir>/<agent_id>/ alongside the
	// collected events. Mirrored events also get `agent_local: true`
	// so server-side rules can distinguish "agent diagnostic" from
	// "host activity" if needed.
	agentID := cfg.Agent.ID
	local.SetMirror(func(logType string, event map[string]any) {
		if event == nil {
			return
		}
		if _, has := event["host"]; !has {
			event["host"] = agentID
		}
		event["agent_local"] = true
		shipper.Enqueue(logType, event)
	})
	// Surface a meta event if the operator has misconfigured an agent
	// with cfg.server.network_ingest.enabled=true — agents NEVER bind
	// the syslog listener; only servers and masters do.
	if cfg.Server.NetworkIngest.Enabled || cfg.Master.NetworkIngest.Enabled {
		local.Write("meta", map[string]any{
			"event": "network_ingest_refused",
			"mode":  "agent",
			"hint":  "network ingest is server/master-only; remove .network_ingest.enabled",
		})
	}
	go agentTLSPing(cfg.Agent, local)
	wg.Add(1)
	go agentHeartbeatLoop(ctx, wg, cfg.Agent, local)
	startAgentGatewayReporter(ctx, wg, cfg.Agent, local)
	startCertExpiryMonitor(ctx, wg, local, "agent", collectAgentCertPaths(cfg))

	// Build a dedicated Storage that forwards to the shipper. The
	// collectors call .Write on it; rules/chain are skipped because of
	// the forward hook.
	gid := resolveGroupGID(cfg.LogOwnerGroup)
	storage, err := group.Open("_agent_forward", gid,
		int64(cfg.MaxLogFileMB)*1024*1024, cfg.WriteQueueSize)
	if err != nil {
		return nil, err
	}
	newStorageController(group, cfg).start(ctx, wg)
	storage.SetForward(func(logType string, event map[string]any) {
		shipper.Enqueue(logType, event)
	})

	local.Write("meta", map[string]any{
		"event":      "start",
		"mode":       "agent",
		"agent_id":   cfg.Agent.ID,
		"server_url": cfg.Agent.ServerURL,
		"pid":        os.Getpid(),
		"platform":   runtime.GOOS,
		"arch":       runtime.GOARCH,
		"version":    version,
		"build":      buildNumber,
	})
	// Heartbeat under _agent so the wedge detector sees fresh writes
	// even on a quiet host. Agent forwards every collector event to
	// the shipper so the local _agent meta stream is otherwise empty
	// once the start banner is written.
	startDaemonHeartbeat(ctx, wg, local, "agent")

	startLocalCollectors(ctx, wg, cfg, storage, local)
	shipper.Start(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shipper.Stop()
	}()

	// One-shot legacy backshipment: when the operator converted from
	// standalone to agent with --keep-old, the previous standalone-mode
	// logs were rehomed into <log_dir>/_legacy/. Queue every line as
	// an event tagged with this agent's ID so the server stores it
	// under the correct host directory. Marker file ensures we only
	// run once per legacy snapshot.
	wg.Add(1)
	go func() {
		defer wg.Done()
		backshipLegacyLogs(ctx, cfg, shipper, local)
	}()

	return &daemonState{
		storage:       local,
		extraStorages: []*Storage{storage},
		shipper:       shipper,
	}, nil
}

// backshipLegacyLogs walks <log_dir>/_legacy/ and queues every NEW
// event it finds into the agent's shipper, so the operator's
// pre-conversion activity is preserved on the server.
//
// Re-run-safe: a cursor file at <log_dir>/_legacy/.cursor tracks the
// per-file byte offset we've already queued. On every agent start we
// resume from each file's saved offset and queue any lines added or
// previously unread. Earlier versions used a `.shipped` boolean
// marker that flipped to true on the first run regardless of whether
// the shipper actually delivered — a server-down restart left every
// legacy event unshipped forever (the as3 manual-test failure mode).
//
// Each event gets host=<agent_id> stamped on it so the server files
// it under this agent's host directory; otherwise standalone events
// (which have no host attribution) would silently drop.
func backshipLegacyLogs(ctx context.Context, cfg Config, shipper *Shipper, local *Storage) {
	legacyDir := filepath.Join(cfg.LogDir, "_legacy")
	if _, err := os.Stat(legacyDir); err != nil {
		return
	}
	agentID := cfg.Agent.ID
	if agentID == "" {
		hostname, _ := os.Hostname()
		agentID = hostname
	}
	cursorPath := filepath.Join(legacyDir, ".cursor")
	cursors := loadLegacyCursor(cursorPath)
	// Migrate from the old .shipped marker if present: assume every
	// .jsonl was already queued in full at last run (set cursor to
	// each file's current size). Without this, an upgrade from the
	// old build would re-ship the entire legacy tree on first start.
	legacyMarker := filepath.Join(legacyDir, ".shipped")
	if _, err := os.Stat(legacyMarker); err == nil {
		_ = filepath.WalkDir(legacyDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".jsonl") {
				return nil
			}
			rel, _ := filepath.Rel(legacyDir, path)
			// os.Stat(path) bypasses Windows' MFT directory-entry
			// cache, which can be stale for legacy log files
			// that were left held open by a previous daemon run.
			// Linux/macOS lstat returns the same value as Info();
			// the swap is a Windows-only correctness fix.
			if info, ierr := os.Stat(path); ierr == nil {
				cursors[rel] = info.Size()
			}
			return nil
		})
		// Drop the legacy marker — cursors take over from here.
		_ = os.Remove(legacyMarker)
		_ = saveLegacyCursor(cursorPath, cursors)
	}
	queued := 0
	skipped := 0
	_ = filepath.WalkDir(legacyDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".jsonl") {
			return nil
		}
		rel, _ := filepath.Rel(legacyDir, path)
		// Type is the parent dir name: <legacy>/<type>/<date>.jsonl
		typ := filepath.Base(filepath.Dir(path))
		f, ferr := os.Open(path)
		if ferr != nil {
			return nil
		}
		defer f.Close()
		startOff := cursors[rel]
		if startOff > 0 {
			if _, serr := f.Seek(startOff, 0); serr != nil {
				startOff = 0
			}
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		fileQueued := 0
		bytesRead := startOff
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return filepath.SkipAll
			default:
			}
			line := scanner.Bytes()
			bytesRead += int64(len(line)) + 1 // +1 for newline
			var ev map[string]any
			if jerr := json.Unmarshal(line, &ev); jerr != nil {
				skipped++
				continue
			}
			if _, hasHost := ev["host"]; !hasHost {
				ev["host"] = agentID
			}
			ev["legacy_backship"] = true
			shipper.Enqueue(typ, ev)
			fileQueued++
		}
		if fileQueued > 0 {
			cursors[rel] = bytesRead
		}
		queued += fileQueued
		return nil
	})
	if queued > 0 || skipped > 0 {
		_ = saveLegacyCursor(cursorPath, cursors)
		local.Write("meta", map[string]any{
			"event":   "legacy_backship_queued",
			"events":  queued,
			"skipped": skipped,
			"hint":    "pre-conversion standalone logs queued to the shipper; server will receive them on the next successful flush. Cursor at " + cursorPath + " tracks the high-water mark; restart re-reads only what's new.",
		})
	}
}

func authLogInterval(n int) int {
	if n <= 0 {
		return 2
	}
	return n
}

// loadLegacyCursor reads <log_dir>/_legacy/.cursor — a JSON map of
// {relative_path -> byte_offset} tracking how far we've read each
// legacy file. Returns an empty map if the cursor doesn't exist or
// fails to parse (broken cursor degrades to "re-read from start";
// safer than dropping the events on the floor).
func loadLegacyCursor(path string) map[string]int64 {
	out := map[string]int64{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	if jerr := json.Unmarshal(data, &out); jerr != nil {
		return map[string]int64{}
	}
	return out
}

// saveLegacyCursor writes the cursor file atomically. Best-effort —
// a write failure means the next start re-ships from the prior
// cursor (worst case is duplicate events at the server, which is
// recoverable; the alternative of losing events is not).
func saveLegacyCursor(path string, cursors map[string]int64) error {
	data, err := json.MarshalIndent(cursors, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o640)
}

func (d *daemonState) Stop() {
	if d.storage != nil {
		d.storage.Write("meta", map[string]any{"event": "stop", "mode": d.mode})
	}
	d.cancel()
	d.wg.Wait()
	if d.storage != nil {
		d.storage.Close()
	}
	for _, s := range d.extraStorages {
		s.Close()
	}
	if d.server != nil {
		d.server.closeAll()
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return os.Chmod(dst, 0o755)
	}
	return nil
}
