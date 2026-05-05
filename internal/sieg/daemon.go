package sieg

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
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

	return &daemonState{storage: storage, cancel: cancel, wg: &wg, mode: mode}, nil
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

// backshipLegacyLogs walks <log_dir>/_legacy/ and queues every event
// it finds into the agent's shipper, so the operator's pre-conversion
// activity is preserved on the server. Idempotent via a marker file
// at <log_dir>/_legacy/.shipped — re-runs are a no-op.
//
// Each event gets host=<agent_id> stamped on it so the server files
// it under this agent's host directory; otherwise standalone events
// (which have no host attribution) would silently drop.
func backshipLegacyLogs(ctx context.Context, cfg Config, shipper *Shipper, local *Storage) {
	legacyDir := filepath.Join(cfg.LogDir, "_legacy")
	if _, err := os.Stat(legacyDir); err != nil {
		return
	}
	marker := filepath.Join(legacyDir, ".shipped")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	agentID := cfg.Agent.ID
	if agentID == "" {
		hostname, _ := os.Hostname()
		agentID = hostname
	}
	queued := 0
	_ = filepath.WalkDir(legacyDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".jsonl") {
			return nil
		}
		// Type is the parent dir name: <legacy>/<type>/<date>.jsonl
		typ := filepath.Base(filepath.Dir(path))
		f, ferr := os.Open(path)
		if ferr != nil {
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return filepath.SkipAll
			default:
			}
			var ev map[string]any
			if jerr := json.Unmarshal(scanner.Bytes(), &ev); jerr != nil {
				continue
			}
			if _, hasHost := ev["host"]; !hasHost {
				ev["host"] = agentID
			}
			ev["legacy_backship"] = true
			shipper.Enqueue(typ, ev)
			queued++
		}
		return nil
	})
	if queued > 0 {
		_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o640)
		local.Write("meta", map[string]any{
			"event":   "legacy_backship_queued",
			"events":  queued,
			"hint":    "pre-conversion standalone logs queued to the shipper; server will receive them on the next successful flush",
		})
	}
}

func authLogInterval(n int) int {
	if n <= 0 {
		return 2
	}
	return n
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
