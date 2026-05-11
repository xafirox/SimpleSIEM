//go:build linux || darwin

package sieg

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Paths used when falling back to standalone mode on Linux (no systemd).
const (
	standalonePIDFile        = "/var/run/simplesiem.pid"
	standaloneInstallMarker  = "/var/lib/simplesiem/.installed"
	standaloneDaemonLog      = "/var/log/simplesiem/daemon.log"
	standaloneMarkerDir      = "/var/lib/simplesiem"
)

// hasSystemd reports whether systemctl is usable on this Linux system. Docker
// containers and minimal init-less environments will return false.
func hasSystemd() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	// /run/systemd/system is only present when systemd is the active init.
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return false
	}
	return true
}

// isContainer reports whether we're running inside a container runtime. Used
// to tailor the install message.
func isContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		for _, marker := range []string{"/docker/", "/containerd/", "/kubepods", "/lxc/", "/podman/"} {
			if strings.Contains(s, marker) {
				return true
			}
		}
	}
	return false
}

func installService(args []string) {
	args = permuteArgs(args, map[string]bool{
		"bin-dir": true, "config-dir": true, "log-dir": true,
		"mode": true, "server": true, "key": true, "id": true,
		"realm": true, "realm-key": true,
		"master": true, "master-key": true,
	})
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	binDir := fs.String("bin-dir", defaultInstallDir(), "where to copy the binary")
	cfgDir := fs.String("config-dir", defaultConfigDir(), "config directory")
	logDir := fs.String("log-dir", defaultLogDir(), "log directory")
	mode := fs.String("mode", "standalone", "daemon mode: standalone | agent | server | master | collector")
	// One-shot setup flags — when --mode is server or agent, install
	// runs the setup that would otherwise require a separate `certs
	// init` (server) or `convert agent --key` (agent) before start
	// would work.
	serverURL := fs.String("server", "", "(agent mode) server URL, e.g. https://siem.example.com:9443")
	enrollKey := fs.String("key", "", "(agent mode) enrollment PSK from `simplesiem certs psk show` on the server")
	agentID := fs.String("id", "", "(agent mode) agent ID; default = hostname")
	// Server-mode realm join in the same install command.
	realmPeer := fs.String("realm", "", "(server mode) peer URL to join an existing realm with after bootstrap")
	realmKey := fs.String("realm-key", "", "(server mode) PSK from the realm peer; required with --realm")
	// Collector-mode pairing: master URL + master collector PSK.
	// REQUIRED when --mode collector — atomic fail otherwise. A
	// collector with no source has no purpose, and the documented
	// alternative path (`convert collector` interactive) already
	// guarantees one source is configured before mode flips.
	masterURL := fs.String("master", "", "(collector mode) master collector listener URL, e.g. https://master.example.com:9445")
	masterKey := fs.String("master-key", "", "(collector mode) PSK from `simplesiem master collector show-psk` on the master")
	_ = fs.Parse(args)
	// Reject leftover positionals so a typo like `install mode server`
	// (missing the `--`) doesn't silently fall through to standalone
	// install with the operator's intended args swallowed and ignored.
	if fs.NArg() > 0 {
		extras := fs.Args()
		hint := ""
		// Common typo: `install mode server` should have been `install --mode server`.
		if len(extras) >= 2 && extras[0] == "mode" {
			hint = fmt.Sprintf("\n  did you mean: simplesiem install --mode %s ...?", extras[1])
		}
		fatalf("unexpected arguments to `install`: %v%s\n  flags must use --flag form (e.g. --mode server, --key <PSK>)", extras, hint)
	}
	if *mode != "standalone" && *mode != "agent" && *mode != "server" && *mode != "master" && *mode != "collector" {
		fatalf("--mode must be standalone, agent, server, master, or collector")
	}
	if *mode == "agent" && (*serverURL == "" || *enrollKey == "") {
		fatalf("--mode agent requires --server <url> and --key <PSK>\n  get the PSK from the server with: simplesiem certs psk show\n  (or install standalone first and run `convert agent --key ...` later)")
	}
	// Atomic collector pairing: --master + --master-key are both
	// required. A collector without a source has no purpose, and
	// allowing a half-configured collector to install would leave
	// the daemon erroring on every pull cycle. Fail early with a
	// clear pointer to the documented PSK source.
	if *mode == "collector" && (*masterURL == "" || *masterKey == "") {
		fatalf("--mode collector requires --master <url> and --master-key <PSK>\n  get the PSK on the master with: simplesiem master collector show-psk\n  (and the master must have called `master collector enable` + `master collector accept-next` first)")
	}
	if os.Geteuid() != 0 {
		fatalf("must run as root (use sudo)")
	}

	exe, err := os.Executable()
	if err != nil {
		fatalf("cannot find self: %v", err)
	}
	exe, _ = filepath.Abs(exe)
	destBin := filepath.Join(*binDir, defaultBinaryName())
	cfgFile := filepath.Join(*cfgDir, "config.json")

	// c15 — for collector mode, run the master-readiness preflight
	// BEFORE any filesystem mutation so a failed preflight leaves the
	// host completely untouched. Without this, a half-installed
	// collector would land with mode=collector in config.json (from
	// configJSONForMode) even though enrollment never ran.
	var collectorPreflight MasterPreflightInfo
	if *mode == "collector" {
		fmt.Println("Preflight: validating master readiness...")
		var perr error
		collectorPreflight, perr = validateCollectorReadyForInstall(*masterURL, *masterKey)
		if perr != nil {
			fatalf("collector preflight failed (no local changes were made): %v", perr)
		}
		fmt.Printf("  master:        %s\n", collectorPreflight.URL)
		fmt.Printf("  authority:     %s\n", collectorPreflight.AuthorityKind)
		fmt.Printf("  realm:         %s (%d peer(s))\n", collectorPreflight.RealmName, collectorPreflight.PeerCount)
		fmt.Printf("  slot state:    %s\n", collectorPreflight.SlotState)
	}

	// Including defaultStateDir() ahead of writeSystemd is critical:
	// the unit's `ReadWritePaths=` includes /var/lib/simplesiem, and
	// systemd's mount-namespace setup fails with status=226/NAMESPACE
	// when any listed path is missing. State data is normally written
	// lazily at runtime (PSK, chainhead key, first-seen state) but the
	// directory itself MUST exist before systemd starts the unit.
	for _, d := range []string{*binDir, *cfgDir, *logDir, defaultStateDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			fatalf("mkdir %s: %v", d, err)
		}
	}
	if exe != destBin {
		if err := copyFile(exe, destBin); err != nil {
			fatalf("copy: %v", err)
		}
	}
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		// Mode 0o600 — the config can hold bearer_tokens, PSK paths,
		// and webhook URLs; group/world read isn't appropriate.
		// atomicWriteFile keeps a partial write from being visible
		// if the daemon is racing the installer.
		data := []byte(configJSONForMode(*mode))
		if err := atomicWriteFile(cfgFile, data, 0o600); err != nil {
			fatalf("write config: %v", err)
		}
		// Seed config.json.bak with the same default so the
		// "fall back to .bak after a malformed manual edit"
		// recovery path always has a valid file to roll back to,
		// even on a freshly-installed system that hasn't been
		// modified yet (the s10 manual-test failure mode).
		if err := os.WriteFile(cfgFile+".bak", data, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not seed %s.bak: %v\n", cfgFile, err)
		}
		fmt.Println("wrote default config:", cfgFile, "(mode:", *mode+")")
	}
	rulesFile := filepath.Join(*cfgDir, "rules.json")
	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		// Mode 0640: rules describe the detection posture; world-readable
		// rules let an unprivileged local user plan evasions. Match the
		// log-file policy (root + log_owner_group readable).
		if err := os.WriteFile(rulesFile, []byte(defaultRulesJSON), 0o640); err != nil {
			fatalf("write rules: %v", err)
		}
		fmt.Println("wrote default rules:", rulesFile)
	}

	// One-shot setup BEFORE preflight: server mode auto-bootstraps
	// CA + server cert + PSK; agent mode auto-enrolls with the PSK.
	// Operators who chose --mode standalone (or server/agent and want
	// to defer setup) skip this and the unit gets installed without
	// starting, same as before.
	if *mode == "server" {
		// Set mode explicitly: when install runs over an existing config
		// (e.g. uninstall -y left a standalone-default cfg behind), the
		// file-exists guard skipped the configJSONForMode write, so
		// cfg.Mode stays "standalone" without this assignment.
		if cfg, err := loadConfigStrict(cfgFile); err == nil {
			cfg.Mode = "server"
			_ = saveConfig(cfgFile, cfg)
		}
		if _, lines, err := ensureServerPKI(cfgFile, 10, 5); err != nil {
			fatalf("server setup: %v", err)
		} else {
			fmt.Println("Server PKI ready:")
			for _, l := range lines {
				fmt.Println("  " + l)
			}
		}
		// Optional one-shot realm join: same flags as `convert server`,
		// surfaced on `install` so a single command can stand up a
		// server AND attach it to an existing realm.
		switch {
		case *realmPeer != "" && *realmKey != "":
			fmt.Printf("joining realm via %s ...\n", *realmPeer)
			runRealmJoin([]string{*realmPeer, "--key", *realmKey, "--yes", "--config", cfgFile})
		case *realmPeer != "" && *realmKey == "":
			fatalf("--realm given without --realm-key; both are required for one-shot realm join")
		case *realmPeer == "" && *realmKey != "":
			fatalf("--realm-key given without --realm; both are required for one-shot realm join")
		}
	}
	if *mode == "collector" {
		// Preflight already ran above (BEFORE any filesystem
		// mutation); proceed straight to the enrollment dance.
		// Bootstrap collector: enroll with the master, then flip mode
		// to "collector" in config.json. The runCollectorEnroll path
		// writes per-source certs under <config>/collector/<host>/
		// and updates collector.source_url + collector.collector_id;
		// we then atomically save the config with mode=collector so
		// preflightStart's mode check passes and the daemon starts
		// in collector mode at the end of installService.
		_ = collectorPreflight // silence unused if preflight info isn't needed downstream
		fmt.Println("Enrolling collector with master (generating keypair locally, sending CSR)...")
		runCollectorEnroll([]string{*masterURL, "--key", *masterKey, "--config", cfgFile}, false)
		cfg, _ := loadConfigStrict(cfgFile)
		cfg.Mode = "collector"
		if err := saveConfig(cfgFile, cfg); err != nil {
			fatalf("save config: %v", err)
		}
		fmt.Println("Collector mode set; daemon will start with the configured master as its source.")
	}
	if *mode == "agent" {
		// Apply --id / --server overrides and run the same enrollment
		// path `convert agent --key` uses.
		acfg := defaultConfig().Agent
		acfg.ServerURL = *serverURL
		if *agentID != "" {
			acfg.ID = *agentID
		}
		hostname, _ := os.Hostname()
		fmt.Println("Enrolling with server (generating keypair locally, sending CSR)...")
		er, err := runAgentEnrollment(acfg, hostname, *enrollKey)
		if err != nil {
			fatalf("enrollment failed: %v", err)
		}
		// Persist mode + server_url + (optionally) ID + realm peer list
		// into the freshly-written config so the daemon reads them on
		// start. Mode is set explicitly because the file-exists guard
		// above skips the configJSONForMode write when install runs
		// over an existing standalone config (e.g. after `uninstall -y`).
		cfg, _ := loadConfigStrict(cfgFile)
		cfg.Mode = "agent"
		cfg.Agent.ServerURL = *serverURL
		if *agentID != "" {
			cfg.Agent.ID = *agentID
		}
		cfg.Agent.FailoverServers = er.RealmPeers
		if err := saveConfig(cfgFile, cfg); err != nil {
			fatalf("save config: %v", err)
		}
		fmt.Println("Enrollment OK; cert + CA written, agent_id added to server allowlist.")
		if er.RealmName != "" {
			fmt.Printf("Realm: %q (%d peer(s) configured for failover)\n", er.RealmName, len(er.RealmPeers))
		}
	}

	// Decide once whether we can auto-start. server/agent without certs
	// will fail the preflight; in that case install the unit but don't
	// fire it up — the operator gets a "do this next" hint instead of
	// a failed unit / dead service.
	preflightErr := preflightStart(cfgFile)
	autoStart := preflightErr == nil

	switch runtime.GOOS {
	case "linux":
		if hasSystemd() {
			if err := writeSystemd(destBin, cfgFile, autoStart); err != nil {
				fatalf("systemd setup: %v", err)
			}
		} else {
			installStandalone(destBin, cfgFile)
		}
	case "darwin":
		if err := writeLaunchd(destBin, cfgFile, *logDir, autoStart); err != nil {
			fatalf("launchd setup: %v", err)
		}
	}
	if autoStart {
		fmt.Println(productName + " installed and started.")
	} else {
		fmt.Println(productName + " installed (NOT auto-started — needs setup):")
		fmt.Printf("  %v\n", preflightErr)
		fmt.Println("After fixing the above, run: sudo simplesiem start")
	}
	fmt.Printf("  binary: %s\n  config: %s\n  logs:   %s\n", destBin, cfgFile, *logDir)
	if runtime.GOOS == "linux" && !hasSystemd() {
		fmt.Println("  service: standalone fork (systemd not detected)")
		// Standalone-fork mode has no auto-restart on host/container
		// reboot — the forked daemon dies with PID 1 and there's
		// nothing to respawn it. Surface this BEFORE the operator
		// hits the "why isn't simplesiem running after I restarted
		// the container?" failure mode.
		fmt.Println()
		fmt.Println(strings.Repeat("=", 72))
		fmt.Println("  IMPORTANT: standalone-fork mode does NOT auto-start at boot.")
		fmt.Println(strings.Repeat("=", 72))
		fmt.Println("  This host has no systemd; the daemon was forked just now but")
		fmt.Println("  WILL NOT come back up after a reboot or container restart.")
		if isContainer() {
			fmt.Println()
			fmt.Println("  Recommended for Docker: use simplesiem as the container's")
			fmt.Println("  ENTRYPOINT/CMD with --supervise so the daemon both auto-starts")
			fmt.Println("  on container start AND respawns on crash:")
			fmt.Printf("       CMD [\"%s\", \"run\", \"--supervise\", \"--config\", \"%s\"]\n", destBin, cfgFile)
		} else {
			fmt.Println()
			fmt.Println("  Recommended for non-systemd Linux: add a respawning entry to")
			fmt.Println("  your init system pointing at:")
			fmt.Printf("       %s run --supervise --config %s\n", destBin, cfgFile)
		}
		fmt.Println()
	}
}

// installStandalone writes an install marker and starts the daemon in the
// background via fork + setsid. Used on Linux when systemd is missing.
//
// The auto-start decision (skip when cert preflight fails) is made one
// level up in installService and surfaced in its summary message.
// Here we just respect that and only fork the daemon when preflight
// would pass.
func installStandalone(bin, cfg string) {
	_ = os.MkdirAll(standaloneMarkerDir, 0o755)
	if err := os.WriteFile(standaloneInstallMarker, []byte(versionString()+"\n"), 0o644); err != nil {
		fatalf("write install marker: %v", err)
	}
	if preflightStart(cfg) != nil {
		// Caller already prints the operator-facing explanation; just
		// don't start.
		return
	}
	if err := standaloneStart(bin, cfg); err != nil {
		fatalf("start daemon: %v", err)
	}
}

// standaloneStart backgrounds the daemon via setsid and records its PID.
func standaloneStart(bin, cfg string) error {
	if pid, ok := readStandalonePID(); ok && processExists(pid) {
		return fmt.Errorf("already running (pid %d)", pid)
	}
	// Preflight: catch the most common "started but never logged" failure
	// (mode = server/agent with cert files missing) BEFORE we fork the
	// daemon, so the operator sees a clear error instead of a misleading
	// "service started" followed by silence.
	if err := preflightStart(cfg); err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(standaloneDaemonLog), 0o755)
	logF, err := os.OpenFile(standaloneDaemonLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open daemon log: %w", err)
	}
	// logF is owned by the child after Start; we close our end immediately
	// after fork via defer so the FD keeps flowing to the child.
	defer logF.Close()

	cmd := exec.Command(bin, "run", "--config", cfg)
	cmd.Stdin = nil
	cmd.Stdout = logF
	cmd.Stderr = logF
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Don't hold the child as a zombie — reap in a goroutine.
	go func() { _ = cmd.Wait() }()

	_ = os.MkdirAll(filepath.Dir(standalonePIDFile), 0o755)
	if err := os.WriteFile(standalonePIDFile, []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o644); err != nil {
		return err
	}
	// Liveness probe: a daemon that dies on bad config will be gone
	// within milliseconds, but a daemon that crashes during late init
	// (e.g., a goroutine that panics 1-2 s in) used to slip past the
	// old 500 ms one-shot check. We now poll for up to 3 s so a slower
	// crash still produces a clear failure here rather than a silent
	// "service started" + a daemon that turns out to be dead. We ALSO
	// require evidence of life: the daemon must have written a
	// meta:start event by the end of the window. A process that's
	// alive but stuck before any I/O still counts as failed.
	cfgDir := filepath.Dir(cfg)
	cfgRaw, _ := os.ReadFile(cfg)
	logDir := defaultLogDir()
	if v := os.Getenv("SIMPLESIEM_LOG_DIR"); v != "" {
		logDir = v
	}
	if i := strings.Index(string(cfgRaw), `"log_dir"`); i >= 0 {
		// Best-effort: parse log_dir without dragging json in.
		var c Config
		if json.Unmarshal(cfgRaw, &c) == nil && c.LogDir != "" {
			logDir = c.LogDir
		}
	}
	_ = cfgDir
	deadline := time.Now().Add(3 * time.Second)
	startedClean := false
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		if !processExists(cmd.Process.Pid) {
			_ = os.Remove(standalonePIDFile)
			tail := lastLines(standaloneDaemonLog, 12)
			if tail == "" {
				tail = "(daemon log was empty; check " + standaloneDaemonLog + ")"
			}
			return fmt.Errorf("daemon exited shortly after start.\n%s", tail)
		}
		// Look for evidence the daemon's writer is actually working.
		// Any of meta/start, meta/agent_tls_ping_ok, or any non-empty
		// today's meta file works. Without this, an init hang past
		// process-spawn gets reported as "started" wrongly.
		if hasRecentMetaActivity(logDir) {
			startedClean = true
			break
		}
	}
	if !startedClean {
		// Process is alive but produced no log activity in 3 s. That's
		// usually fine on a slow first-boot, but it's worth a soft
		// warning so an operator chasing "no events" sees it.
		fmt.Fprintln(os.Stderr, "warning: daemon is alive but has not written its meta:start event after 3s.")
		fmt.Fprintf(os.Stderr, "  if events don't appear within a minute, check: %s\n", standaloneDaemonLog)
	}
	return nil
}

// hasRecentMetaActivity is a heuristic for "the writer goroutine has
// successfully flushed something to disk". Looks for any non-empty
// `<log_dir>/(meta|_agent/meta|_server/meta)/<today>.jsonl`. Used by
// standaloneStart's post-fork health probe.
func hasRecentMetaActivity(logDir string) bool {
	today := time.Now().UTC().Format("2006-01-02")
	candidates := []string{
		filepath.Join(logDir, "meta", today+".jsonl"),
		filepath.Join(logDir, "_agent", "meta", today+".jsonl"),
		filepath.Join(logDir, "_server", "meta", today+".jsonl"),
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.Size() > 0 {
			// Mtime must be within the last 30s to be ours, not a
			// leftover from before the kill.
			if time.Since(info.ModTime()) < 30*time.Second {
				return true
			}
		}
	}
	return false
}

// preflightStart validates the install before the daemon is forked. It
// catches the failure mode where mode=server or mode=agent with no
// cert files — the daemon would otherwise log.Fatalf silently inside
// the forked child and the operator would see "service started" with
// no events landing. The error message names exactly what's missing
// (CA vs server cert vs agent cert) and the single command that
// fixes it, so an operator partway through setup gets actionable
// guidance rather than a generic "run all the cert commands".
func preflightStart(cfgFile string) error {
	cfg, cerr := loadConfigStrict(cfgFile)
	if cerr != nil {
		return cerr
	}
	mode := normaliseMode(cfg.Mode)
	switch mode {
	case "server":
		// Tier 1: CA missing? init hasn't been run.
		if cfg.Server.CACert == "" {
			return fmt.Errorf("server.ca_cert is unset in config.json — run:\n  sudo simplesiem certs init")
		}
		if _, err := os.Stat(cfg.Server.CACert); err != nil {
			return fmt.Errorf("CA missing at %s — run:\n  sudo simplesiem certs init\n  (this also auto-issues a server cert for THIS host so start works immediately)",
				cfg.Server.CACert)
		}
		// Tier 2: CA exists, server cert doesn't. The user ran init
		// with --ca-only, or deleted the auto-issued cert. Tell them
		// the exact `certs server` command for THIS host.
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "<your-hostname>"
		}
		for _, p := range []struct {
			name, path string
		}{
			{"server.cert", cfg.Server.Cert},
			{"server.key", cfg.Server.Key},
		} {
			if p.path == "" {
				return fmt.Errorf("%s is unset in config.json", p.name)
			}
			if _, err := os.Stat(p.path); err != nil {
				return fmt.Errorf("CA exists but %s is missing at %s — run:\n  sudo simplesiem certs server %s",
					p.name, p.path, hostname)
			}
		}
	case "agent":
		if cfg.Agent.ServerURL == "" {
			return fmt.Errorf("agent mode requires agent.server_url in config.json")
		}
		for _, p := range []struct {
			name, path string
		}{
			{"agent.client_cert", cfg.Agent.ClientCert},
			{"agent.client_key", cfg.Agent.ClientKey},
			{"agent.ca_cert", cfg.Agent.CACert},
		} {
			if p.path == "" {
				return fmt.Errorf("agent mode requires %s in config.json", p.name)
			}
			if _, err := os.Stat(p.path); err != nil {
				return fmt.Errorf("agent mode: %s missing at %s — re-enroll: simplesiem convert agent --server <url> --key <PSK> (get PSK with `simplesiem certs psk show` on the server)",
					p.name, p.path)
			}
		}
	case "master":
		// Master needs at least one server registered. Per-server cert
		// existence isn't checked here — a missing cert just means that
		// server is skipped at runtime with a clear error log.
		if len(cfg.Master.Servers) == 0 {
			return fmt.Errorf("master mode has no servers configured — run: sudo simplesiem master enroll <server-url> --key <PSK>")
		}
	}
	return nil
}

// lastLines returns the last n newline-separated lines of path as a
// single string. Used by standaloneStart to surface the tail of the
// daemon log when the daemon dies right after fork. Best-effort —
// returns "" silently on any error.
func lastLines(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// standaloneStop sends SIGTERM to the daemon recorded in the PID file, waits
// for it to exit, and removes the PID file.
func standaloneStop() error {
	pid, ok := readStandalonePID()
	if !ok {
		return fmt.Errorf("not running (no pid file at %s)", standalonePIDFile)
	}
	if !processExists(pid) {
		_ = os.Remove(standalonePIDFile)
		return fmt.Errorf("stale pid file (process %d is gone)", pid)
	}
	proc, _ := os.FindProcess(pid)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		_ = os.Remove(standalonePIDFile)
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !processExists(pid) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = os.Remove(standalonePIDFile)
	return nil
}

func readStandalonePID() (int, bool) {
	data, err := os.ReadFile(standalonePIDFile)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// processExists checks whether a process with the given PID is alive by
// sending signal 0, which is a permission/existence probe on POSIX.
func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func serviceFile() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/LaunchDaemons/com." + serviceName + ".plist"
	case "linux":
		return "/etc/systemd/system/" + serviceName + ".service"
	}
	return ""
}

// isInstalled reports whether the service is installed. On Linux it checks
// the systemd unit file if systemd is available, or the standalone marker
// otherwise.
func isInstalled() bool {
	if runtime.GOOS == "linux" && !hasSystemd() {
		_, err := os.Stat(standaloneInstallMarker)
		return err == nil
	}
	_, err := os.Stat(serviceFile())
	return err == nil
}

// isRunning reports whether the daemon is currently active.
func isRunning() bool {
	switch runtime.GOOS {
	case "linux":
		if hasSystemd() {
			return exec.Command("systemctl", "is-active", "--quiet", serviceName).Run() == nil
		}
		pid, ok := readStandalonePID()
		return ok && processExists(pid)
	case "darwin":
		out, err := exec.Command("launchctl", "list", "com."+serviceName).Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), `"PID" =`)
	}
	return false
}

func startCommand(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	_ = fs.Parse(args)
	if os.Geteuid() != 0 {
		fatalf("must run as root (use sudo)")
	}
	cfgFile := filepath.Join(defaultConfigDir(), "config.json")
	// Preflight applies to systemd and launchd paths too — there's no
	// point in handing the start command to the OS service manager
	// when we can already see the configuration is incomplete.
	if err := preflightStart(cfgFile); err != nil {
		// Malformed-config errors get the loud banner; cert/url
		// problems keep the single-line preflight message they
		// already had.
		if _, ok := err.(*configParseError); ok {
			reportStartupError(err)
			os.Exit(1)
		}
		fatalf("preflight: %v", err)
	}
	switch runtime.GOOS {
	case "linux":
		if hasSystemd() {
			mustRun("systemctl", "start", serviceName)
		} else {
			destBin := filepath.Join(defaultInstallDir(), defaultBinaryName())
			if err := standaloneStart(destBin, cfgFile); err != nil {
				fatalf("start: %v", err)
			}
		}
	case "darwin":
		plist := serviceFile()
		if exec.Command("launchctl", "kickstart", "-k", "system/com."+serviceName).Run() != nil {
			mustRun("launchctl", "load", "-w", plist)
		}
	}
	if !quietServiceOutput {
		fmt.Println("service started")
	}
}

func stopCommand(args []string) {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	// Accept -y as a no-op so callers who treat it as "yes,
	// non-interactive" don't trip flag.ExitOnError. There's no
	// confirmation prompt here, so the flag is purely for ergonomic
	// consistency with `uninstall -y`, `migrate -y`, etc.
	_ = fs.Bool("y", false, "skip confirmation (no-op; stop is non-interactive)")
	_ = fs.Parse(args)
	if os.Geteuid() != 0 {
		fatalf("must run as root (use sudo)")
	}
	switch runtime.GOOS {
	case "linux":
		if hasSystemd() {
			mustRun("systemctl", "stop", serviceName)
		} else {
			if err := standaloneStop(); err != nil {
				fatalf("stop: %v", err)
			}
		}
	case "darwin":
		mustRun("launchctl", "unload", serviceFile())
	}
	if !quietServiceOutput {
		fmt.Println("service stopped")
	}
}

func uninstallService(_ []string) {
	if os.Geteuid() != 0 {
		fatalf("must run as root (use sudo)")
	}
	switch runtime.GOOS {
	case "linux":
		if hasSystemd() {
			_ = exec.Command("systemctl", "disable", "--now", serviceName).Run()
			_ = os.Remove("/etc/systemd/system/" + serviceName + ".service")
			_ = exec.Command("systemctl", "daemon-reload").Run()
		} else {
			_ = standaloneStop()
			_ = os.Remove(standaloneInstallMarker)
		}
	case "darwin":
		path := "/Library/LaunchDaemons/com." + serviceName + ".plist"
		_ = exec.Command("launchctl", "unload", path).Run()
		_ = os.Remove(path)
	}
	fmt.Println(productName + " service removed (config and logs preserved)")
}

// systemdTpl mounts a defence-in-depth posture for the daemon. Notes on
// directives that look obvious but were specifically chosen or rejected:
//
//   - PrivateTmp is NOT enabled because FileCollector watches /tmp by
//     default; PrivateTmp would give the daemon its own namespaced /tmp
//     and silently miss real /tmp activity.
//   - ProtectHome is intentionally NOT set: operators can configure
//     log_dir to anywhere realistic (e.g. /home/<user>/tmp on lab hosts,
//     /opt/siem-logs on appliances) and the daemon must be able to write
//     there without the operator re-running `simplesiem install` or hand-
//     editing the unit file. ProtectSystem=full still locks /etc, /usr,
//     /boot, /efi; the writable carve-outs in ReadWritePaths preserve
//     /etc/simplesiem for config edits and the chainhead key. The daemon
//     runs as root regardless, so ProtectHome=read-only never bounded
//     attacker capability — it only forced an extra `install` step on
//     legitimate log_dir changes.
//   - RestrictAddressFamilies includes AF_NETLINK because gopsutil reads
//     connection state via netlink on Linux.
//   - SystemCallFilter blocks @clock @cpu-emulation @debug @module @mount
//     @obsolete @raw-io @reboot @swap by listing only the allow groups.
// systemdTpl is the systemd unit installed at
// /etc/systemd/system/simplesiem.service. The hardening profile is
// scoped for "SIEM that intentionally observes every process on the
// host" — DIFFERENT from a generic web service. Specifically:
//
//   - ProtectProc is intentionally NOT set to "invisible" — that
//     would hide every other-user process from /proc/, which kills
//     the whole point of ProcessCollector. SIEMs need broad /proc
//     visibility.
//   - MemoryDenyWriteExecute is OFF. The Go runtime occasionally
//     allocates PROT_WRITE|PROT_EXEC pages on newer kernels for
//     defer/panic trampolines, and the resulting SIGSYS kill is
//     silent — the daemon dies with "no logs" before it can write
//     anything to /var/log/simplesiem. The other process-isolation
//     flags below already bound what a compromised daemon can do.
//   - SystemCallFilter is a DENY-LIST of dangerous syscall classes,
//     not an allow-list. Allow-listing breaks too easily when Go's
//     runtime adds a syscall in a future version (e.g. clone3, the
//     io_uring family). The deny-list catches root-equivalent
//     escapes (mount, module load, kernel reboot, raw I/O) without
//     guessing every legitimate syscall a Go binary needs.
//   - ReadWritePaths carves out /var/log/simplesiem (default log_dir),
//     /var/lib/simplesiem (state), /etc/simplesiem (config), and /run.
//     extraReadWritePaths() appends the operator-configured log_dir
//     and any storage failover locations at unit-write time so the
//     happy path also works for non-default log_dir values that fall
//     under ProtectSystem=full's locked subtrees.
const systemdTpl = `[Unit]
Description=SimpleSIEM on-box SIEM
After=network.target

[Service]
Type=simple
ExecStart=%s run --config %s
Restart=on-failure
RestartSec=5
User=root
NoNewPrivileges=true
ProtectSystem=full
ProtectKernelTunables=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=~@cpu-emulation @debug @keyring @memlock @module @mount @obsolete @raw-io @reboot @swap
ReadWritePaths=-/var/log/simplesiem -/var/lib/simplesiem -/etc/simplesiem -/run %s

[Install]
WantedBy=multi-user.target
`

// extraReadWritePaths returns the configured log_dir (and any other
// operator-chosen writable directory) as additional ReadWritePaths
// entries for the systemd unit. The defaults are baked into systemdTpl;
// this function adds whatever log_dir is currently set so a non-default
// log_dir doesn't get sandbox-blocked. Each path is prefixed with `-`
// so a missing dir during unit generation doesn't break the namespace.
func extraReadWritePaths(cfgFile string) string {
	c := loadConfig(cfgFile)
	seen := map[string]bool{
		"/var/log/simplesiem":  true,
		"/var/lib/simplesiem":  true,
		"/etc/simplesiem":      true,
		"/run":                 true,
	}
	var extras []string
	add := func(p string) {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		extras = append(extras, "-"+p)
	}
	add(c.LogDir)
	// Storage failover locations also need write access if they're
	// outside the defaults.
	for _, fl := range c.Storage.FailoverLocations {
		add(fl)
	}
	return strings.Join(extras, " ")
}

func writeSystemd(bin, cfg string, autoStart bool) error {
	unit := fmt.Sprintf(systemdTpl, bin, cfg, extraReadWritePaths(cfg))
	unitPath := "/etc/systemd/system/" + serviceName + ".service"
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	enableArgs := []string{"enable"}
	if autoStart {
		enableArgs = append(enableArgs, "--now")
	}
	enableArgs = append(enableArgs, serviceName)
	if err := exec.Command("systemctl", enableArgs...).Run(); err != nil {
		return fmt.Errorf("enable: %w", err)
	}
	return nil
}

const launchdTpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>run</string>
    <string>--config</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s/stdout.log</string>
  <key>StandardErrorPath</key><string>%s/stderr.log</string>
  <key>ThrottleInterval</key><integer>10</integer>
</dict>
</plist>
`

func writeLaunchd(bin, cfg, logDir string, autoStart bool) error {
	plist := fmt.Sprintf(launchdTpl, serviceName, bin, cfg, logDir, logDir)
	plistPath := "/Library/LaunchDaemons/com." + serviceName + ".plist"
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	_ = os.Chown(plistPath, 0, 0)
	_ = exec.Command("launchctl", "unload", plistPath).Run()
	if !autoStart {
		// Plist installed but not loaded — operator triggers it later
		// once certs are in place via `simplesiem start`.
		return nil
	}
	if err := exec.Command("launchctl", "load", "-w", plistPath).Run(); err != nil {
		return fmt.Errorf("launchctl load: %w", err)
	}
	return nil
}

// platformIssues reports OS-specific install-integrity problems along with
// functions that repair each one.
func platformIssues(bin, cfgFile, logDir string) []issue {
	var out []issue

	// Linux standalone mode: check marker + PID-file sanity instead of systemd.
	if runtime.GOOS == "linux" && !hasSystemd() {
		if _, err := os.Stat(standaloneInstallMarker); err != nil {
			out = append(out, issue{
				desc: "install marker missing (standalone mode): " + standaloneInstallMarker,
				fix: func() error {
					if err := os.MkdirAll(standaloneMarkerDir, 0o755); err != nil {
						return err
					}
					return os.WriteFile(standaloneInstallMarker, []byte(versionString()+"\n"), 0o644)
				},
			})
		}
		// Stale PID file — process is gone but file remains.
		if pid, ok := readStandalonePID(); ok && !processExists(pid) {
			out = append(out, issue{
				desc: fmt.Sprintf("stale pid file at %s (process %d is gone)", standalonePIDFile, pid),
				fix:  func() error { return os.Remove(standalonePIDFile) },
			})
		}
		return out
	}

	svcFile := serviceFile()
	if data, err := os.ReadFile(svcFile); err != nil {
		out = append(out, issue{
			desc: "service file missing: " + svcFile,
			fix: func() error {
				// Repairing an existing install: only auto-start if
				// preflight already passes, same policy as fresh install.
				autoStart := preflightStart(cfgFile) == nil
				if runtime.GOOS == "linux" {
					return writeSystemd(bin, cfgFile, autoStart)
				}
				return writeLaunchd(bin, cfgFile, logDir, autoStart)
			},
		})
	} else if !strings.Contains(string(data), bin) {
		out = append(out, issue{
			desc: "service file references wrong binary path",
			fix: func() error {
				// Repairing an existing install: only auto-start if
				// preflight already passes, same policy as fresh install.
				autoStart := preflightStart(cfgFile) == nil
				if runtime.GOOS == "linux" {
					return writeSystemd(bin, cfgFile, autoStart)
				}
				return writeLaunchd(bin, cfgFile, logDir, autoStart)
			},
		})
	}

	switch runtime.GOOS {
	case "linux":
		if exec.Command("systemctl", "is-enabled", "--quiet", serviceName).Run() != nil {
			out = append(out, issue{
				desc: "service not enabled for auto-start",
				fix: func() error {
					return exec.Command("systemctl", "enable", serviceName).Run()
				},
			})
		}
	case "darwin":
		if exec.Command("launchctl", "list", "com."+serviceName).Run() != nil {
			out = append(out, issue{
				desc: "service not loaded in launchd",
				fix: func() error {
					return exec.Command("launchctl", "load", "-w", svcFile).Run()
				},
			})
		}
	}
	return out
}

func mustRun(name string, args ...string) {
	c := exec.Command(name, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		fatalf("%s %v: %v", name, args, err)
	}
}
