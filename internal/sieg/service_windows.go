//go:build windows

package sieg

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

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
	mode := fs.String("mode", "", "daemon mode: standalone | agent | server | master | collector (default: standalone, or $SIMPLESIEM_MODE)")
	serverURL := fs.String("server", "", "(agent mode) server URL")
	enrollKey := fs.String("key", "", "(agent mode) enrollment PSK from `simplesiem certs psk show` on the server")
	agentID := fs.String("id", "", "(agent mode) agent ID; default = hostname")
	realmPeer := fs.String("realm", "", "(server mode) peer URL to join an existing realm with after bootstrap")
	realmKey := fs.String("realm-key", "", "(server mode) PSK from the realm peer; required with --realm")
	masterURL := fs.String("master", "", "(collector mode) master collector listener URL")
	masterKey := fs.String("master-key", "", "(collector mode) PSK from master collector show-psk")
	_ = fs.Parse(args)
	// Reject leftover positionals so a typo like `install mode server`
	// doesn't silently install standalone.
	if fs.NArg() > 0 {
		extras := fs.Args()
		hint := ""
		if len(extras) >= 2 && extras[0] == "mode" {
			hint = fmt.Sprintf("\r\n  did you mean: simplesiem install --mode %s ...?", extras[1])
		}
		fatalf("unexpected arguments to `install`: %v%s\r\n  flags must use --flag form (e.g. --mode server, --key <PSK>)", extras, hint)
	}
	chosenMode := *mode
	if chosenMode == "" {
		if v := os.Getenv("SIMPLESIEM_MODE"); v != "" {
			chosenMode = v
		} else {
			chosenMode = "standalone"
		}
	}
	if chosenMode != "standalone" && chosenMode != "agent" && chosenMode != "server" && chosenMode != "master" && chosenMode != "collector" {
		fatalf("--mode must be standalone, agent, server, master, or collector")
	}
	if chosenMode == "agent" && (*serverURL == "" || *enrollKey == "") {
		fatalf("--mode agent requires --server <url> and --key <PSK>\n  get the PSK from the server with: simplesiem certs psk show")
	}
	if chosenMode == "collector" && (*masterURL == "" || *masterKey == "") {
		fatalf("--mode collector requires --master <url> and --master-key <PSK>\r\n  get the PSK on the master with: simplesiem master collector show-psk")
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
	// host completely untouched.
	var collectorPreflight MasterPreflightInfo
	if chosenMode == "collector" {
		fmt.Println("Preflight: validating master readiness...")
		var perr error
		collectorPreflight, perr = validateCollectorReadyForInstall(*masterURL, *masterKey)
		if perr != nil {
			fatalf("collector preflight failed (no local changes were made): %v", perr)
		}
		fmt.Printf("  master:        %s\r\n", collectorPreflight.URL)
		fmt.Printf("  authority:     %s\r\n", collectorPreflight.AuthorityKind)
		fmt.Printf("  realm:         %s (%d peer(s))\r\n", collectorPreflight.RealmName, collectorPreflight.PeerCount)
		fmt.Printf("  slot state:    %s\r\n", collectorPreflight.SlotState)
	}

	for _, d := range []string{*binDir, *cfgDir, *logDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			fatalf("mkdir %s: %v (run PowerShell as Administrator)", d, err)
		}
	}
	if !pathsEqual(exe, destBin) {
		if err := copyFile(exe, destBin); err != nil {
			fatalf("copy: %v (run PowerShell as Administrator)", err)
		}
	}
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		// Mode bits map loosely to NTFS ACLs on Windows but the
		// atomicWriteFile + tighter mode still surface intent in the
		// audit and avoid leaving a partially-written config behind on
		// installer crashes.
		if err := atomicWriteFile(cfgFile, []byte(configJSONForMode(chosenMode)), 0o600); err != nil {
			fatalf("write config: %v", err)
		}
		fmt.Println("wrote default config:", cfgFile, "(mode:", chosenMode+")")
	}
	rulesFile := filepath.Join(*cfgDir, "rules.json")
	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		// On Windows, mode bits map loosely to NTFS ACLs; the file
		// inherits ACLs from %ProgramData%\SimpleSIEM. Mode is set
		// for parity with the Unix path.
		if err := os.WriteFile(rulesFile, []byte(defaultRulesJSON), 0o640); err != nil {
			fatalf("write rules: %v", err)
		}
		fmt.Println("wrote default rules:", rulesFile)
	}

	// One-shot setup before SCM registration. server -> bootstrap CA +
	// server cert + PSK; agent -> enroll with PSK. Without this an
	// operator picking --mode server gets a service that fails to
	// start until they manually run `certs init`.
	if chosenMode == "server" {
		if _, lines, err := ensureServerPKI(cfgFile, 10, 5); err != nil {
			fatalf("server setup: %v", err)
		} else {
			fmt.Println("Server PKI ready:")
			for _, l := range lines {
				fmt.Println("  " + l)
			}
		}
		switch {
		case *realmPeer != "" && *realmKey != "":
			fmt.Printf("joining realm via %s ...\r\n", *realmPeer)
			runRealmJoin([]string{*realmPeer, "--key", *realmKey, "--yes", "--config", cfgFile})
		case *realmPeer != "" && *realmKey == "":
			fatalf("--realm given without --realm-key; both are required for one-shot realm join")
		case *realmPeer == "" && *realmKey != "":
			fatalf("--realm-key given without --realm; both are required for one-shot realm join")
		}
	}
	if chosenMode == "collector" {
		// Preflight already ran above (BEFORE any filesystem
		// mutation); proceed straight to the enrollment dance.
		_ = collectorPreflight
		fmt.Println("Enrolling collector with master (generating keypair locally, sending CSR)...")
		runCollectorEnroll([]string{*masterURL, "--key", *masterKey, "--config", cfgFile}, false)
		cfg, _ := loadConfigStrict(cfgFile)
		cfg.Mode = "collector"
		if err := saveConfig(cfgFile, cfg); err != nil {
			fatalf("save config: %v", err)
		}
		fmt.Println("Collector mode set; daemon will start with the configured master as its source.")
	}
	if chosenMode == "agent" {
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
		cfg, _ := loadConfigStrict(cfgFile)
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
			fmt.Printf("Realm: %q (%d peer(s) configured for failover)\r\n", er.RealmName, len(er.RealmPeers))
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		fatalf("cannot connect to Windows Service Manager: %v (run as Administrator)", err)
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(serviceName); err == nil {
		existing.Close()
		fatalf("service %q already exists; run 'simplesiem uninstall' first", serviceName)
	}

	s, err := m.CreateService(serviceName, destBin, mgr.Config{
		DisplayName: productName,
		Description: "On-box SIEM: consolidates connection, file, login, and process logs.",
		StartType:   mgr.StartAutomatic,
	}, "run", "--config", cfgFile)
	if err != nil {
		fatalf("create service: %v", err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		fatalf("start service: %v", err)
	}
	fmt.Println(productName + " installed and started.")
	fmt.Printf("  binary: %s\n  config: %s\n  logs:   %s\n", destBin, cfgFile, *logDir)
	fmt.Printf("control: sc.exe start %s | sc.exe stop %s\n", serviceName, serviceName)
}

// isInstalled reports whether the service is registered with SCM.
// Uses sc.exe query, which doesn't require admin privileges.
func isInstalled() bool {
	return exec.Command("sc.exe", "query", serviceName).Run() == nil
}

// isRunning reports whether the registered service is currently running.
func isRunning() bool {
	out, err := exec.Command("sc.exe", "query", serviceName).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "RUNNING") ||
		strings.Contains(string(out), "START_PENDING")
}

func startCommand(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	_ = fs.Parse(args)
	cfgFile := filepath.Join(defaultConfigDir(), "config.json")
	if err := preflightStart(cfgFile); err != nil {
		fatalf("preflight: %v", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		fatalf("connect to Windows Service Manager: %v (run as Administrator)", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		fatalf("open service: %v (is it installed?)", err)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		fatalf("start: %v", err)
	}
	if !quietServiceOutput {
		fmt.Println("service started")
	}
}

// preflightStart validates the install before SCM is asked to start
// the daemon. Catches mode=server/agent without cert files so the
// operator sees a clear error instead of "service started" followed
// by silence (the SCM forks the binary and reports success even if
// the daemon log.Fatalfs immediately on bad config).
func preflightStart(cfgFile string) error {
	cfg, cerr := loadConfigStrict(cfgFile)
	if cerr != nil {
		return cerr
	}
	mode := normaliseMode(cfg.Mode)
	switch mode {
	case "server":
		if cfg.Server.CACert == "" {
			return fmt.Errorf("server.ca_cert is unset in config.json — run:\r\n  simplesiem certs init")
		}
		if _, err := os.Stat(cfg.Server.CACert); err != nil {
			return fmt.Errorf("CA missing at %s — run:\r\n  simplesiem certs init\r\n  (this also auto-issues a server cert for THIS host so start works immediately)",
				cfg.Server.CACert)
		}
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
				return fmt.Errorf("CA exists but %s is missing at %s — run:\r\n  simplesiem certs server %s",
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
		if len(cfg.Master.Servers) == 0 {
			return fmt.Errorf("master mode has no servers configured — run: simplesiem master enroll <server-url> --key <PSK>")
		}
	}
	return nil
}

func stopCommand(args []string) {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	_ = fs.Parse(args)
	m, err := mgr.Connect()
	if err != nil {
		fatalf("connect to Windows Service Manager: %v (run as Administrator)", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		fatalf("open service: %v (is it installed?)", err)
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		fatalf("stop control: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil || st.State == svc.Stopped {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !quietServiceOutput {
		fmt.Println("service stopped")
	}
}

func uninstallService(_ []string) {
	m, err := mgr.Connect()
	if err != nil {
		fatalf("cannot connect to Windows Service Manager: %v (run as Administrator)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		fmt.Println("service not installed")
		return
	}
	defer s.Close()

	if status, err := s.Query(); err == nil && status.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			st, err := s.Query()
			if err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	if err := s.Delete(); err != nil {
		fatalf("delete service: %v", err)
	}
	fmt.Println(productName + " service removed (config and logs preserved)")
}

// platformIssues reports Windows-specific install-integrity problems and the
// functions that repair each one.
func platformIssues(bin, cfgFile, logDir string) []issue {
	_ = logDir
	var out []issue

	m, err := mgr.Connect()
	if err != nil {
		out = append(out, issue{
			desc: fmt.Sprintf("cannot connect to SCM: %v", err),
			fix:  nil,
		})
		return out
	}
	// Keep m open while we fix things; close at the end.
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		// Not registered at all.
		out = append(out, issue{
			desc: "service not registered with SCM",
			fix: func() error {
				m2, err := mgr.Connect()
				if err != nil {
					return err
				}
				defer m2.Disconnect()
				ns, err := m2.CreateService(serviceName, bin, mgr.Config{
					DisplayName: productName,
					Description: "On-box SIEM: consolidates connection, file, login, and process logs.",
					StartType:   mgr.StartAutomatic,
				}, "run", "--config", cfgFile)
				if err != nil {
					return err
				}
				return ns.Close()
			},
		})
		return out
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		out = append(out, issue{
			desc: fmt.Sprintf("cannot read service config: %v", err),
			fix:  nil,
		})
		return out
	}

	if !strings.Contains(cfg.BinaryPathName, bin) {
		out = append(out, issue{
			desc: "service binary path doesn't match installed binary",
			fix: func() error {
				cfg.BinaryPathName = fmt.Sprintf(`"%s" run --config "%s"`, bin, cfgFile)
				return s.UpdateConfig(cfg)
			},
		})
	}
	if cfg.StartType != mgr.StartAutomatic {
		out = append(out, issue{
			desc: "service start type not set to Automatic",
			fix: func() error {
				cfg.StartType = mgr.StartAutomatic
				return s.UpdateConfig(cfg)
			},
		})
	}
	return out
}

func pathsEqual(a, b string) bool {
	aa, _ := filepath.Abs(a)
	bb, _ := filepath.Abs(b)
	return filepath.Clean(aa) == filepath.Clean(bb)
}
