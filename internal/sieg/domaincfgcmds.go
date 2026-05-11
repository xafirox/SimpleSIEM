package sieg

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// runTrustCmd manages the destructive-master opt-in gates that previously
// required hand-edits of cfg.server.master_can_rotate_ca and
// master_can_uninstall (server) / master_can_uninstall (collector). Both
// are off by default — granting either means the operator explicitly
// trusts the master with cluster-wide destructive operations.
func runTrustCmd(args []string) {
	if len(args) == 0 {
		trustUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "show":
		trustShow()
	case "grant":
		trustGrant(args[1:])
	case "revoke":
		trustRevoke(args[1:])
	case "help", "-h", "--help":
		trustUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown trust subcommand: %s\n", args[0])
		trustUsage()
		os.Exit(2)
	}
}

func trustUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem trust <subcommand> [args]

subcommands:
  show                                  print the current trust posture
  grant rotate-ca                       allow the master to trigger CA rotate-init / finalize
                                        (writes server.master_can_rotate_ca = true)
  grant uninstall                       allow the master to trigger uninstall-all on this node
                                        (writes server.master_can_uninstall = true; on
                                        collector mode, writes collector.master_can_uninstall)
  grant master-push-allowlist           allow the master to push a network-ingest allowlist
                                        (writes server.network_ingest.master_can_push_allowlist
                                        = true)
  revoke rotate-ca                      flip the rotate-ca opt-in OFF
  revoke uninstall                      flip the uninstall opt-in OFF
  revoke master-push-allowlist          flip the master-push-allowlist opt-in OFF

examples:
  simplesiem trust grant uninstall
  simplesiem trust revoke rotate-ca
  simplesiem trust show`)
}

func trustShow() {
	cfg := loadConfig(defaultConfigPath())
	mode := normaliseMode(cfg.Mode)
	fmt.Printf("mode: %s\n", mode)
	fmt.Printf("server.master_can_rotate_ca           = %v\n", cfg.Server.MasterCanRotateCA)
	fmt.Printf("server.master_can_uninstall           = %v\n", cfg.Server.MasterCanUninstall)
	fmt.Printf("server.network_ingest.master_can_push_allowlist = %v\n",
		cfg.Server.NetworkIngest.MasterCanPushAllowlist)
	fmt.Printf("collector.master_can_uninstall        = %v\n", cfg.Collector.MasterCanUninstall)
}

func trustGrant(args []string) {
	if len(args) != 1 {
		fatalf("usage: trust grant <rotate-ca|uninstall|master-push-allowlist>")
	}
	mustAdmin()
	switch args[0] {
	case "rotate-ca":
		editServerBool("master_can_rotate_ca", true)
		fmt.Println("granted: master may trigger CA rotation on this server")
	case "uninstall":
		mode := normaliseMode(loadConfig(defaultConfigPath()).Mode)
		if mode == "collector" {
			editCollectorBool("master_can_uninstall", true)
			fmt.Println("granted: master may trigger uninstall on this collector")
		} else {
			editServerBool("master_can_uninstall", true)
			fmt.Println("granted: master may trigger uninstall on this server")
		}
	case "master-push-allowlist":
		editServerNetworkIngestField("master_can_push_allowlist", true)
		fmt.Println("granted: master may push network-ingest allowlist edits to this server")
	default:
		fatalf("unknown grant target: %s (want rotate-ca | uninstall | master-push-allowlist)", args[0])
	}
}

func trustRevoke(args []string) {
	if len(args) != 1 {
		fatalf("usage: trust revoke <rotate-ca|uninstall|master-push-allowlist>")
	}
	mustAdmin()
	switch args[0] {
	case "rotate-ca":
		editServerBool("master_can_rotate_ca", false)
		fmt.Println("revoked: master may NOT trigger CA rotation on this server")
	case "uninstall":
		mode := normaliseMode(loadConfig(defaultConfigPath()).Mode)
		if mode == "collector" {
			editCollectorBool("master_can_uninstall", false)
			fmt.Println("revoked: master may NOT trigger uninstall on this collector")
		} else {
			editServerBool("master_can_uninstall", false)
			fmt.Println("revoked: master may NOT trigger uninstall on this server")
		}
	case "master-push-allowlist":
		editServerNetworkIngestField("master_can_push_allowlist", false)
		fmt.Println("revoked: master may NOT push allowlist edits to this server")
	default:
		fatalf("unknown revoke target: %s", args[0])
	}
}

// runTuneCmd is the catch-all for operator-tunable scalars: agent batch
// sizing, retention days, master sync interval, server reauth window,
// volume-anomaly thresholds, etc. The CLI surface keeps each knob behind
// a verb so an operator never has to remember the JSON path.
func runTuneCmd(args []string) {
	if len(args) == 0 {
		tuneUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "show":
		tuneShow()
	case "agent":
		tuneAgent(args[1:])
	case "server":
		tuneServer(args[1:])
	case "master":
		tuneMaster(args[1:])
	case "retention":
		tuneRetention(args[1:])
	case "volume-anomaly":
		tuneVolumeAnomaly(args[1:])
	case "max-log-file":
		tuneMaxLogFile(args[1:])
	case "write-queue":
		tuneWriteQueue(args[1:])
	case "baseline":
		tuneBaseline(args[1:])
	case "incidents":
		tuneIncidents(args[1:])
	case "firstseen":
		tuneFirstSeen(args[1:])
	case "threatintel":
		tuneThreatIntel(args[1:])
	case "help", "-h", "--help":
		tuneUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown tune subcommand: %s\n", args[0])
		tuneUsage()
		os.Exit(2)
	}
}

func tuneUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem tune <subcommand> [args]

subcommands:
  show                                                show every tunable knob with its value

  agent batch <N>                                     events per shipped batch
  agent interval <duration>                           batch flush cadence (e.g. 5s)
  agent spool-max <MB>                                spool ceiling on shipping failure
  agent no-local-storage <true|false>                 drop instead of spooling on outage
                                                      (DANGEROUS: loses events during outages)
  agent failover add <url>                            append a failover server URL
  agent failover remove <url>                         drop a failover URL
  agent failover clear                                wipe the failover list

  server reauth <duration>                            agent heartbeat window (e.g. 60s)

  master sync-interval <duration>                     pull cadence from each enrolled server
  master rules-path <path>                            file the master-side rule engine reads
                                                      (empty disables master-side firing)

  retention <days>                                    daily-file retention before pruning

  volume-anomaly <subcommand>:
    show
    set [--min-baseline N] [--drop-ratio F] [--low-mins N] [--cooldown-mins N]
    reset                                             clear all overrides; daemon uses defaults

  max-log-file <MB>                                   per-file rotation ceiling
  write-queue <N>                                     in-memory write queue size

  baseline <subcommand>:
    show
    enabled <true|false>
    window-days <N>                                   learning window for hour-of-day baseline
    stddev-trigger <float>                            sigma above which a host's hour fires
    max-hosts <N>                                     ceiling on tracked hosts (memory cap)
    reset                                             clear all overrides; daemon uses defaults

  incidents <subcommand>:
    show
    enabled <true|false>
    window-seconds <N>                                grouping window for an incident
    max-lifetime-seconds <N>                          cap a single incident's duration
    reset

  firstseen <subcommand>:
    show
    enabled <true|false>
    ttl-days <N>                                      retention for (host, field, value) tuples
    max-entries-per-tuple <N>                         memory cap per tuple
    reset

  threatintel <subcommand>:
    show
    enabled <true|false>
    max-set-size <N>                                  cap indicators per set
    stale-after-days <N>                              when to fall back to cached snapshot
    reset

examples:
  simplesiem tune agent batch 50
  simplesiem tune agent interval 5s
  simplesiem tune master sync-interval 30s
  simplesiem tune retention 90
  simplesiem tune volume-anomaly set --drop-ratio 0.10 --cooldown-mins 60`)
}

func tuneShow() {
	cfg := loadConfig(defaultConfigPath())
	out := map[string]any{
		"retention_days":   cfg.RetentionDays,
		"max_log_file_mb":  cfg.MaxLogFileMB,
		"write_queue_size": cfg.WriteQueueSize,
		"agent": map[string]any{
			"batch_size":             cfg.Agent.BatchSize,
			"batch_interval_seconds": cfg.Agent.BatchIntervalSec,
			"spool_max_mb":           cfg.Agent.SpoolMaxMB,
			"no_local_storage":       cfg.Agent.NoLocalStorage,
			"failover_servers":       cfg.Agent.FailoverServers,
		},
		"server": map[string]any{
			"agent_reauth_seconds": cfg.Server.AgentReauthSeconds,
			"volume_anomaly":       cfg.Server.VolumeAnomaly,
		},
		"master": map[string]any{
			"sync_interval_seconds": cfg.Master.SyncIntervalSeconds,
			"rules_path":            cfg.Master.RulesPath,
		},
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(body))
}

func tuneAgent(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem tune agent <batch|interval|spool-max|no-local-storage|failover>")
		os.Exit(2)
	}
	switch args[0] {
	case "batch":
		if len(args) != 2 {
			fatalf("usage: tune agent batch <N>")
		}
		n := mustPositiveInt(args[1], "batch")
		mustAdmin()
		editAgentField("batch_size", n)
		fmt.Printf("agent.batch_size = %d\n", n)
	case "interval":
		if len(args) != 2 {
			fatalf("usage: tune agent interval <duration>")
		}
		sec, err := parseDurationSeconds(args[1])
		if err != nil || sec < 1 {
			fatalf("interval must be a positive duration (e.g. 5s)")
		}
		mustAdmin()
		editAgentField("batch_interval_seconds", sec)
		fmt.Printf("agent.batch_interval_seconds = %d\n", sec)
	case "spool-max":
		if len(args) != 2 {
			fatalf("usage: tune agent spool-max <MB>")
		}
		n := mustPositiveInt(args[1], "spool-max")
		mustAdmin()
		editAgentField("spool_max_mb", n)
		fmt.Printf("agent.spool_max_mb = %d\n", n)
	case "no-local-storage":
		if len(args) != 2 {
			fatalf("usage: tune agent no-local-storage <true|false>")
		}
		v := strings.EqualFold(args[1], "true")
		mustAdmin()
		editAgentField("no_local_storage", v)
		if v {
			fmt.Println("WARNING: events failing to ship will now be DROPPED rather than spooled.")
		}
		fmt.Printf("agent.no_local_storage = %v\n", v)
	case "failover":
		if len(args) < 2 {
			fatalf("usage: tune agent failover <add|remove|clear> [url]")
		}
		switch args[1] {
		case "add":
			if len(args) != 3 {
				fatalf("usage: tune agent failover add <url>")
			}
			if _, err := url.Parse(args[2]); err != nil {
				fatalf("invalid URL: %v", err)
			}
			mustAdmin()
			editAgentStringList("failover_servers", func(list []string) []string {
				for _, u := range list {
					if u == args[2] {
						return list
					}
				}
				return append(list, args[2])
			})
			fmt.Printf("added failover %s\n", args[2])
		case "remove":
			if len(args) != 3 {
				fatalf("usage: tune agent failover remove <url>")
			}
			mustAdmin()
			editAgentStringList("failover_servers", func(list []string) []string {
				out := list[:0]
				for _, u := range list {
					if u != args[2] {
						out = append(out, u)
					}
				}
				return out
			})
			fmt.Printf("removed failover %s (if present)\n", args[2])
		case "clear":
			mustAdmin()
			editAgentStringList("failover_servers", func(_ []string) []string { return nil })
			fmt.Println("agent.failover_servers cleared")
		default:
			fatalf("usage: tune agent failover <add|remove|clear>")
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: simplesiem tune agent <batch|interval|spool-max|no-local-storage|failover>")
		os.Exit(2)
	}
}

func tuneServer(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem tune server <reauth>")
		os.Exit(2)
	}
	switch args[0] {
	case "reauth":
		if len(args) != 2 {
			fatalf("usage: tune server reauth <duration>")
		}
		sec, err := parseDurationSeconds(args[1])
		if err != nil || sec < 1 {
			fatalf("reauth must be a positive duration")
		}
		mustAdmin()
		editScalarUnder("server", "agent_reauth_seconds", sec)
		fmt.Printf("server.agent_reauth_seconds = %d\n", sec)
	default:
		fatalf("unknown tune server subcommand: %s", args[0])
	}
}

func tuneMaster(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem tune master <sync-interval|rules-path>")
		os.Exit(2)
	}
	switch args[0] {
	case "sync-interval":
		if len(args) != 2 {
			fatalf("usage: tune master sync-interval <duration>")
		}
		sec, err := parseDurationSeconds(args[1])
		if err != nil || sec < 1 {
			fatalf("sync-interval must be a positive duration")
		}
		mustAdmin()
		editScalarUnder("master", "sync_interval_seconds", sec)
		fmt.Printf("master.sync_interval_seconds = %d\n", sec)
	case "rules-path":
		if len(args) != 2 {
			fatalf("usage: tune master rules-path <path|->")
		}
		mustAdmin()
		val := args[1]
		if val == "-" {
			val = ""
		}
		editScalarUnder("master", "rules_path", val)
		if val == "" {
			fmt.Println("master.rules_path cleared (master-side rule firing disabled)")
		} else {
			fmt.Printf("master.rules_path = %s\n", val)
		}
	default:
		fatalf("unknown tune master subcommand: %s", args[0])
	}
}

func tuneRetention(args []string) {
	if len(args) != 1 {
		fatalf("usage: tune retention <days>")
	}
	n := mustPositiveInt(args[0], "retention")
	mustAdmin()
	editTopLevelField("retention_days", n)
	fmt.Printf("retention_days = %d\n", n)
}

func tuneVolumeAnomaly(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem tune volume-anomaly <show|set|reset>")
		os.Exit(2)
	}
	switch args[0] {
	case "show":
		cfg := loadConfig(defaultConfigPath())
		out, _ := json.MarshalIndent(cfg.Server.VolumeAnomaly, "", "  ")
		fmt.Println(string(out))
	case "set":
		fs := flag.NewFlagSet("tune volume-anomaly set", flag.ExitOnError)
		minBase := fs.Float64("min-baseline", 0, "events/min below which we never fire (default 5)")
		dropRatio := fs.Float64("drop-ratio", 0, "current/baseline ratio that counts as quiet (default 0.05)")
		lowMins := fs.Int("low-mins", 0, "minutes-low in a row before firing (default 2)")
		cooldownMins := fs.Int("cooldown-mins", 0, "per-agent re-fire suppression window (default 30)")
		_ = fs.Parse(args[1:])
		fresh := map[string]any{}
		if *minBase > 0 {
			fresh["min_baseline"] = *minBase
		}
		if *dropRatio > 0 {
			fresh["drop_ratio"] = *dropRatio
		}
		if *lowMins > 0 {
			fresh["consecutive_low_mins"] = *lowMins
		}
		if *cooldownMins > 0 {
			fresh["cooldown_minutes"] = *cooldownMins
		}
		mustAdmin()
		editServerObject("volume_anomaly", fresh)
		fmt.Printf("volume_anomaly overrides updated (%d field(s))\n", len(fresh))
	case "reset":
		mustAdmin()
		editServerObject("volume_anomaly", map[string]any{})
		fmt.Println("volume_anomaly cleared; daemon will use defaults")
	default:
		fatalf("unknown volume-anomaly subcommand: %s", args[0])
	}
}

func tuneMaxLogFile(args []string) {
	if len(args) != 1 {
		fatalf("usage: tune max-log-file <MB>")
	}
	n := mustPositiveInt(args[0], "max-log-file")
	mustAdmin()
	editTopLevelField("max_log_file_mb", n)
	fmt.Printf("max_log_file_mb = %d\n", n)
}

func tuneWriteQueue(args []string) {
	if len(args) != 1 {
		fatalf("usage: tune write-queue <N>")
	}
	n := mustPositiveInt(args[0], "write-queue")
	mustAdmin()
	editTopLevelField("write_queue_size", n)
	fmt.Printf("write_queue_size = %d\n", n)
}

func mustPositiveInt(s, label string) int {
	v := parseConfigValue(s)
	switch n := v.(type) {
	case int64:
		if n <= 0 {
			fatalf("%s must be a positive integer", label)
		}
		return int(n)
	case float64:
		if n <= 0 {
			fatalf("%s must be a positive integer", label)
		}
		return int(n)
	}
	fatalf("%s must be a positive integer", label)
	return 0
}

func editAgentField(key string, v any) {
	editScalarUnder("agent", key, v)
}

func editAgentStringList(key string, transform func([]string) []string) {
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	ag := getOrCreateMap(m, "agent")
	cur := stringSliceFromAny(ag[key])
	next := transform(cur)
	if len(next) == 0 {
		delete(ag, key)
	} else {
		out := make([]any, len(next))
		for i, v := range next {
			out[i] = v
		}
		ag[key] = out
	}
	if err := configWriteMap(cfgPath, m); err != nil {
		fatalf("write config: %v", err)
	}
}

// runStorageCfgCmd manages storage thresholds + failover-volume layout.
func runStorageCfgCmd(args []string) {
	if len(args) == 0 {
		storageCfgUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "show":
		cfg := loadConfig(defaultConfigPath())
		out, _ := json.MarshalIndent(cfg.Storage, "", "  ")
		fmt.Println(string(out))
	case "warn":
		if len(args) != 2 {
			fatalf("usage: storage-cfg warn <80%%|10GB|...>")
		}
		if err := parsePercentOrSize(args[1]); err != nil {
			fatalf("%v", err)
		}
		mustAdmin()
		editStorageField("warn_threshold", args[1])
		fmt.Printf("storage.warn_threshold = %s\n", args[1])
	case "halt":
		if len(args) != 2 {
			fatalf("usage: storage-cfg halt <90%%|5GB|...>")
		}
		if err := parsePercentOrSize(args[1]); err != nil {
			fatalf("%v", err)
		}
		mustAdmin()
		editStorageField("halt_threshold", args[1])
		fmt.Printf("storage.halt_threshold = %s\n", args[1])
	case "failover":
		runStorageFailover(args[1:])
	case "help", "-h", "--help":
		storageCfgUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown storage-cfg subcommand: %s\n", args[0])
		storageCfgUsage()
		os.Exit(2)
	}
}

func storageCfgUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem storage-cfg <subcommand> [args]

subcommands:
  show                                          print the current storage block
  warn <percent|size>                           set the WARN threshold (e.g. 80%, 100GB)
  halt <percent|size>                           set the HALT threshold (e.g. 90%, 10GB)
  failover list                                 list configured failover volume directories
  failover add <path>                           append a failover directory
  failover remove <path>                        drop a failover directory
  failover clear                                wipe the failover list

examples:
  simplesiem storage-cfg warn 80%
  simplesiem storage-cfg halt 95%
  simplesiem storage-cfg failover add /mnt/extra/simplesiem`)
}

func runStorageFailover(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem storage-cfg failover <list|add|remove|clear> [path]")
		os.Exit(2)
	}
	cfgPath := defaultConfigPath()
	switch args[0] {
	case "list":
		cfg := loadConfig(cfgPath)
		if len(cfg.Storage.FailoverLocations) == 0 {
			fmt.Println("(no failover_locations configured)")
			return
		}
		for _, p := range cfg.Storage.FailoverLocations {
			fmt.Println(p)
		}
	case "add":
		if len(args) != 2 {
			fatalf("usage: storage-cfg failover add <path>")
		}
		mustAdmin()
		editStorageStringList("failover_locations", func(list []string) []string {
			for _, p := range list {
				if p == args[1] {
					return list
				}
			}
			return append(list, args[1])
		})
		fmt.Printf("added failover location %s\n", args[1])
	case "remove":
		if len(args) != 2 {
			fatalf("usage: storage-cfg failover remove <path>")
		}
		mustAdmin()
		editStorageStringList("failover_locations", func(list []string) []string {
			out := list[:0]
			for _, p := range list {
				if p != args[1] {
					out = append(out, p)
				}
			}
			return out
		})
		fmt.Printf("removed failover location %s (if present)\n", args[1])
	case "clear":
		mustAdmin()
		editStorageStringList("failover_locations", func(_ []string) []string { return nil })
		fmt.Println("storage.failover_locations cleared")
	default:
		fmt.Fprintln(os.Stderr, "usage: simplesiem storage-cfg failover <list|add|remove|clear> [path]")
		os.Exit(2)
	}
}

func editStorageStringList(key string, transform func([]string) []string) {
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	st := getOrCreateMap(m, "storage")
	cur := stringSliceFromAny(st[key])
	next := transform(cur)
	if len(next) == 0 {
		delete(st, key)
	} else {
		out := make([]any, len(next))
		for i, v := range next {
			out[i] = v
		}
		st[key] = out
	}
	if err := configWriteMap(cfgPath, m); err != nil {
		fatalf("write config: %v", err)
	}
}

// runWatchCmd manages cfg.file_watch_paths — the directories the
// fsnotify-based file collector watches.
func runWatchCmd(args []string) {
	if len(args) == 0 {
		watchUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		cfg := loadConfig(defaultConfigPath())
		if len(cfg.FileWatchPaths) == 0 {
			fmt.Println("(no file_watch_paths configured; daemon uses platform defaults)")
			return
		}
		for _, p := range cfg.FileWatchPaths {
			fmt.Println(p)
		}
	case "add":
		if len(args) != 2 {
			fatalf("usage: watch add <path>")
		}
		mustAdmin()
		editTopLevelStringList("file_watch_paths", func(list []string) []string {
			for _, p := range list {
				if p == args[1] {
					return list
				}
			}
			return append(list, args[1])
		})
		fmt.Printf("added watch path %s\n", args[1])
		fmt.Println("note: file_watch_paths is not hot-reloaded; restart the daemon to start watching this path")
	case "remove":
		if len(args) != 2 {
			fatalf("usage: watch remove <path>")
		}
		mustAdmin()
		editTopLevelStringList("file_watch_paths", func(list []string) []string {
			out := list[:0]
			for _, p := range list {
				if p != args[1] {
					out = append(out, p)
				}
			}
			return out
		})
		fmt.Printf("removed watch path %s (if present)\n", args[1])
		fmt.Println("note: file_watch_paths is not hot-reloaded; restart the daemon to stop watching this path")
	case "recursive":
		if len(args) != 2 {
			fatalf("usage: watch recursive <true|false>")
		}
		mustAdmin()
		editTopLevelField("file_watch_recursive", strings.EqualFold(args[1], "true"))
		fmt.Printf("file_watch_recursive = %v\n", strings.EqualFold(args[1], "true"))
	case "poll-interval":
		if len(args) != 2 {
			fatalf("usage: watch poll-interval <seconds>")
		}
		n := mustPositiveInt(args[1], "poll-interval")
		mustAdmin()
		editTopLevelField("file_poll_interval", n)
		fmt.Printf("file_poll_interval = %d\n", n)
	case "help", "-h", "--help":
		watchUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown watch subcommand: %s\n", args[0])
		watchUsage()
		os.Exit(2)
	}
}

func watchUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem watch <subcommand> [args]

subcommands:
  list                                  show file_watch_paths
  add <path>                            append a directory
  remove <path>                         drop a directory
  recursive <true|false>                set file_watch_recursive
  poll-interval <seconds>               poll fallback interval (when fsnotify is unavailable)`)
}

// runAuthLogCmd manages cfg.auth_log_paths.
func runAuthLogCmd(args []string) {
	if len(args) == 0 {
		authLogUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		cfg := loadConfig(defaultConfigPath())
		// On macOS the daemon uses the `log stream` subprocess; on
		// Windows it uses wevtutil. auth_log_paths is consulted only
		// by the Linux file-tailer. Be honest about that here so the
		// operator doesn't think they need to maintain a path list.
		if runtime.GOOS == "darwin" {
			fmt.Println("(auth-log on macOS uses `log stream` — no path list to manage; see `simplesiem status` for the active subprocess)")
			return
		}
		if runtime.GOOS == "windows" {
			fmt.Println("(auth-log on Windows uses wevtutil polling — no path list to manage; see `simplesiem status` for the active source)")
			return
		}
		if len(cfg.AuthLogPaths) == 0 {
			fmt.Println("(no auth_log_paths configured; daemon uses defaults: /var/log/auth.log /var/log/secure /var/log/messages)")
			return
		}
		for _, p := range cfg.AuthLogPaths {
			fmt.Println(p)
		}
	case "add":
		if runtime.GOOS != "linux" {
			fatalf("auth-log add is Linux-only (macOS uses `log stream`, Windows uses wevtutil — no file path to configure)")
		}
		if len(args) != 2 {
			fatalf("usage: auth-log add <path>")
		}
		mustAdmin()
		editTopLevelStringList("auth_log_paths", func(list []string) []string {
			for _, p := range list {
				if p == args[1] {
					return list
				}
			}
			return append(list, args[1])
		})
		fmt.Printf("added auth log path %s\n", args[1])
	case "remove":
		if runtime.GOOS != "linux" {
			fatalf("auth-log remove is Linux-only (macOS uses `log stream`, Windows uses wevtutil — no file path to configure)")
		}
		if len(args) != 2 {
			fatalf("usage: auth-log remove <path>")
		}
		mustAdmin()
		editTopLevelStringList("auth_log_paths", func(list []string) []string {
			out := list[:0]
			for _, p := range list {
				if p != args[1] {
					out = append(out, p)
				}
			}
			return out
		})
		fmt.Printf("removed auth log path %s (if present)\n", args[1])
	case "interval":
		if runtime.GOOS != "linux" {
			fatalf("auth-log interval is Linux-only (macOS uses `log stream`, Windows uses wevtutil — poll cadence is fixed by the OS)")
		}
		if len(args) != 2 {
			fatalf("usage: auth-log interval <seconds>")
		}
		n := mustPositiveInt(args[1], "interval")
		mustAdmin()
		editTopLevelField("auth_log_interval", n)
		fmt.Printf("auth_log_interval = %d\n", n)
	case "help", "-h", "--help":
		authLogUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown auth-log subcommand: %s\n", args[0])
		authLogUsage()
		os.Exit(2)
	}
}

func authLogUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem auth-log <subcommand> [args]

subcommands:
  list                                  show auth_log_paths
  add <path>                            append a path (e.g. /var/log/auth.log)
  remove <path>                         drop a path
  interval <seconds>                    set auth_log_interval poll cadence`)
}

// runNetworkIngestCmd manages the listener block and per-source rate
// limit for cfg.server.network_ingest. (network-source is the per-device
// allowlist; network-ingest is the listener posture.)
func runNetworkIngestCmd(args []string) {
	if len(args) == 0 {
		networkIngestUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "show":
		cfg := loadConfig(defaultConfigPath())
		mode := normaliseMode(cfg.Mode)
		var ni NetworkIngestConfig
		if mode == "master" {
			ni = cfg.Master.NetworkIngest
		} else {
			ni = cfg.Server.NetworkIngest
		}
		out, _ := json.MarshalIndent(ni, "", "  ")
		fmt.Println(string(out))
	case "enable":
		mustAdmin()
		editServerNetworkIngestField("enabled", true)
		fmt.Println("network_ingest enabled")
	case "disable":
		mustAdmin()
		editServerNetworkIngestField("enabled", false)
		fmt.Println("network_ingest disabled")
	case "tls-listen":
		if len(args) != 2 {
			fatalf("usage: network-ingest tls-listen <addr|->")
		}
		mustAdmin()
		val := args[1]
		if val == "-" {
			val = ""
		}
		editServerNetworkIngestField("syslog_tls_listen", val)
		fmt.Printf("network_ingest.syslog_tls_listen = %q\n", val)
	case "tcp-listen":
		if len(args) != 2 {
			fatalf("usage: network-ingest tcp-listen <addr|->")
		}
		mustAdmin()
		val := args[1]
		if val == "-" {
			val = ""
		}
		editServerNetworkIngestField("syslog_tcp_listen", val)
		fmt.Printf("network_ingest.syslog_tcp_listen = %q\n", val)
	case "udp-listen":
		if len(args) != 2 {
			fatalf("usage: network-ingest udp-listen <addr|->")
		}
		mustAdmin()
		val := args[1]
		if val == "-" {
			val = ""
		}
		editServerNetworkIngestField("syslog_udp_listen", val)
		fmt.Printf("network_ingest.syslog_udp_listen = %q\n", val)
	case "tls-cert-mode":
		if len(args) != 2 {
			fatalf("usage: network-ingest tls-cert-mode <selfsigned|server|operator>")
		}
		switch args[1] {
		case "selfsigned", "server", "operator":
		default:
			fatalf("tls-cert-mode must be selfsigned | server | operator")
		}
		mustAdmin()
		editServerNetworkIngestField("tls_cert_mode", args[1])
		fmt.Printf("network_ingest.tls_cert_mode = %s\n", args[1])
	case "tls-cert":
		if len(args) != 2 {
			fatalf("usage: network-ingest tls-cert <path>")
		}
		mustAdmin()
		editServerNetworkIngestField("tls_cert", args[1])
		fmt.Printf("network_ingest.tls_cert = %s\n", args[1])
	case "tls-key":
		if len(args) != 2 {
			fatalf("usage: network-ingest tls-key <path>")
		}
		mustAdmin()
		editServerNetworkIngestField("tls_key", args[1])
		fmt.Printf("network_ingest.tls_key = %s\n", args[1])
	case "rate-limit":
		if len(args) != 2 {
			fatalf("usage: network-ingest rate-limit <frames-per-second>")
		}
		n := mustPositiveInt(args[1], "rate-limit")
		mustAdmin()
		editServerNetworkIngestField("max_frames_per_source_per_second", n)
		fmt.Printf("network_ingest.max_frames_per_source_per_second = %d\n", n)
	case "max-frame-bytes":
		if len(args) != 2 {
			fatalf("usage: network-ingest max-frame-bytes <bytes>")
		}
		n := mustPositiveInt(args[1], "max-frame-bytes")
		mustAdmin()
		editServerNetworkIngestField("max_frame_bytes", n)
		fmt.Printf("network_ingest.max_frame_bytes = %d\n", n)
	case "bind-explicit":
		if len(args) != 2 {
			fatalf("usage: network-ingest bind-explicit <true|false>")
		}
		mustAdmin()
		editServerNetworkIngestField("bind_explicit", strings.EqualFold(args[1], "true"))
		fmt.Printf("network_ingest.bind_explicit = %v\n", strings.EqualFold(args[1], "true"))
	case "rdns-cache":
		if len(args) != 2 {
			fatalf("usage: network-ingest rdns-cache <seconds>")
		}
		n := mustPositiveInt(args[1], "rdns-cache")
		mustAdmin()
		editServerNetworkIngestField("rdns_cache_ttl_seconds", n)
		fmt.Printf("network_ingest.rdns_cache_ttl_seconds = %d\n", n)
	case "help", "-h", "--help":
		networkIngestUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown network-ingest subcommand: %s\n", args[0])
		networkIngestUsage()
		os.Exit(2)
	}
}

func networkIngestUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem network-ingest <subcommand> [args]

subcommands:
  show                                          print the current network_ingest block
  enable / disable                              flip the master switch
  tls-listen   <addr|->                         e.g. :6514, "-" disables
  tcp-listen   <addr|->                         cleartext TCP (e.g. :1514)
  udp-listen   <addr|->                         cleartext UDP (e.g. :514)
  tls-cert-mode <selfsigned|server|operator>    cert provider for the TLS listener
  tls-cert     <path>                           operator-supplied TLS cert (mode=operator)
  tls-key      <path>                           operator-supplied TLS key (mode=operator)
  rate-limit   <frames-per-second>              max_frames_per_source_per_second (default 1000)
  max-frame-bytes <bytes>                       max_frame_bytes (default 65536)
  bind-explicit <true|false>                    require non-loopback bind addresses
  rdns-cache   <seconds>                        rdns_cache_ttl_seconds`)
}

// ----- tune baseline / incidents / firstseen / threatintel ------------

// tuneScalarBlock is the shared body for the four medium-leverage
// scalar groups. Every supported field name maps to its on-disk JSON
// field via fieldMap. Each invocation dispatches one of:
//
//	show                         JSON-pretty-print the block
//	<field> <value>              type-checked write; resets are
//	                             handled by passing the JSON null
//	                             literal to the value parser
//	enabled <true|false>         convenience for the universal toggle
//	reset                        clear the whole block; daemon falls
//	                             back to its hardcoded defaults
func tuneScalarBlock(parent string, args []string, fieldMap map[string]struct {
	jsonKey string
	kind    string // "int", "float", "bool"
}) {
	if len(args) == 0 {
		fatalf("usage: tune %s <show|enabled|reset|<field> <value>>", parent)
	}
	switch args[0] {
	case "show":
		cfg := loadConfig(defaultConfigPath())
		var block any
		switch parent {
		case "baseline":
			block = cfg.Baseline
		case "incidents":
			block = cfg.Incidents
		case "firstseen":
			block = cfg.FirstSeen
		case "threatintel":
			block = cfg.ThreatIntel
		}
		out, _ := json.MarshalIndent(block, "", "  ")
		fmt.Println(string(out))
		return
	case "reset":
		mustAdmin()
		editTopLevelField(parent, "")
		fmt.Printf("%s overrides cleared; daemon uses defaults\n", parent)
		return
	case "enabled":
		if len(args) != 2 {
			fatalf("usage: tune %s enabled <true|false>", parent)
		}
		mustAdmin()
		editScalarUnder(parent, "enabled", strings.EqualFold(args[1], "true"))
		fmt.Printf("%s.enabled = %v\n", parent, strings.EqualFold(args[1], "true"))
		return
	}
	if len(args) != 2 {
		fatalf("usage: tune %s <field> <value>", parent)
	}
	field := args[0]
	spec, ok := fieldMap[field]
	if !ok {
		fatalf("unknown %s field %q", parent, field)
	}
	mustAdmin()
	switch spec.kind {
	case "int":
		n := mustPositiveInt(args[1], field)
		editScalarUnder(parent, spec.jsonKey, n)
		fmt.Printf("%s.%s = %d\n", parent, spec.jsonKey, n)
	case "float":
		f, err := strconv.ParseFloat(args[1], 64)
		if err != nil || f <= 0 {
			fatalf("%s must be a positive float", field)
		}
		editScalarUnder(parent, spec.jsonKey, f)
		fmt.Printf("%s.%s = %v\n", parent, spec.jsonKey, f)
	}
}

func tuneBaseline(args []string) {
	tuneScalarBlock("baseline", args, map[string]struct {
		jsonKey string
		kind    string
	}{
		"window-days":    {"window_days", "int"},
		"stddev-trigger": {"stddev_trigger", "float"},
		"max-hosts":      {"max_hosts", "int"},
	})
}

func tuneIncidents(args []string) {
	tuneScalarBlock("incidents", args, map[string]struct {
		jsonKey string
		kind    string
	}{
		"window-seconds":       {"window_seconds", "int"},
		"max-lifetime-seconds": {"max_lifetime_seconds", "int"},
	})
}

func tuneFirstSeen(args []string) {
	tuneScalarBlock("firstseen", args, map[string]struct {
		jsonKey string
		kind    string
	}{
		"ttl-days":              {"ttl_days", "int"},
		"max-entries-per-tuple": {"max_entries_per_tuple", "int"},
	})
}

func tuneThreatIntel(args []string) {
	tuneScalarBlock("threatintel", args, map[string]struct {
		jsonKey string
		kind    string
	}{
		"max-set-size":     {"max_set_size", "int"},
		"stale-after-days": {"stale_after_days", "int"},
	})
}
