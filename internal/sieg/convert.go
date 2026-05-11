package sieg

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runConvertCmd switches an existing install between standalone, agent,
// and server modes. It prints a warning describing what will change,
// asks for confirmation (suppress with -y), then:
//
//   1. stops the running daemon if it's running,
//   2. optionally rehomes pre-switch standalone logs under _legacy/ so
//      they remain triageable after the switch (--keep-old),
//   3. rewrites config.json with the new mode (and any --id, --server,
//      --listen overrides supplied), backing up the previous file as
//      config.json.bak,
//   4. prints next-step instructions specific to the new mode.
//
// The daemon is NOT auto-started — agent and server modes need
// operator-supplied certs/IDs that must be in place before start
// will succeed. The conversion itself is reversible; the next call
// to `convert standalone` undoes it (modulo the rehomed _legacy/
// directories, which stay where they are).
func runConvertCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem convert <agent|server|standalone|master|collector> [flags]

  -y                 skip the confirmation prompt
  --keep-old         (default true) move existing standalone-shape log dirs
                     into _legacy/ so triage --host _legacy keeps working;
                     pass --keep-old=false to discard pre-conversion logs
  --config <path>    config file (default: standard install path)

  agent-only:
  --id <agent-id>    set agent.id (default: hostname)
  --server <url>     set agent.server_url (e.g. https://siem.example.com:9443)
  --key <psk>        enrollment PSK from the server (run 'simplesiem certs psk
                     show' on the server). When set, the agent generates its
                     keypair locally and sends a CSR to /v1/enroll — no manual
                     cert copy. The PSK never authenticates anything beyond
                     enrollment; ongoing traffic uses mTLS with the issued cert.
  --force            skip the connectivity preflight (use only when staging the
                     agent before the server is up; daemon will still refuse to
                     start until certs/server are in place)

  server-only:
  --listen <addr>    set server.listen (default: :9443)
  --realm <url>      one-shot: after bootstrap, join the realm at this peer URL
                     (e.g. https://siem-a.example.com:9443). Pair with --realm-key.
  --realm-key <psk>  PSK from the peer (run 'simplesiem certs psk show' on that
                     host); required when --realm is set

  master-only:
  (interactive — prompts for each server URL + PSK, runs master enrollment
  for each, then flips mode to master and starts the daemon)

  collector-only:
  (interactive — prompts for ONE source URL + its PSK, runs collector
  enrollment, then flips mode to collector. Source must have opened
  its slot with: simplesiem certs collector accept-next)`)
		os.Exit(2)
	}
	target := args[0]
	switch target {
	case "agent", "server", "standalone", "master", "collector":
	default:
		fatalf("convert <agent|server|standalone|master|collector> — got %q", target)
	}
	// Master + collector conversions are interactive — keep their own
	// dispatch paths so the agent/server/standalone flow stays linear.
	if target == "master" {
		runConvertMaster(args[1:])
		return
	}
	if target == "collector" {
		runConvertCollector(args[1:])
		return
	}
	args = permuteArgs(args[1:], map[string]bool{
		"config": true, "id": true, "server": true, "listen": true, "key": true,
		"realm": true, "realm-key": true,
	})

	fs := flag.NewFlagSet("convert "+target, flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	// Default true: preserving existing logs under _legacy/ is almost
	// always what the operator wants — the alternative orphans the
	// pre-conversion data on disk where read commands in the new mode
	// can't see it. Pass --keep-old=false to opt out.
	keepOld := fs.Bool("keep-old", true, "rename existing standalone log dirs to _legacy/ before switching (default true; pass --keep-old=false to skip)")
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	agentID := fs.String("id", "", "agent.id to set")
	serverURL := fs.String("server", "", "agent.server_url to set")
	listen := fs.String("listen", "", "server.listen to set")
	force := fs.Bool("force", false, "skip the agent connectivity preflight (use only when standing up the agent before the server is ready)")
	enrollKey := fs.String("key", "", "enrollment PSK from the server (`simplesiem certs psk show`); when set, agent generates a keypair locally and enrolls instead of using pre-copied cert files")
	// One-shot realm join: when both --realm and --realm-key are set
	// during `convert server`, the conversion finishes the server
	// bootstrap AND runs `realm join <url> --key <psk>` against the
	// supplied peer in a single command. Operators standing up a
	// fleet can chain `convert server --realm ... --realm-key ...`
	// instead of two separate invocations.
	realmPeer := fs.String("realm", "", "(server-only, optional) peer URL to join an existing realm with after bootstrap, e.g. https://siem-a.example.com:9443")
	realmKey := fs.String("realm-key", "", "(server-only, optional) PSK from the realm peer (`simplesiem certs psk show` on that host); required with --realm")
	_ = fs.Parse(args)

	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}

	cfg := loadConfig(*cfgPath)
	from := normaliseMode(cfg.Mode)
	if from == target {
		fmt.Printf("already in %s mode; nothing to do.\n", target)
		return
	}

	// EARLY VALIDATION (before any state mutation): every flag whose
	// shape we can verify offline must be checked here. A malformed
	// --realm URL or unparseable PSK previously crashed the convert
	// AFTER config.json had been flipped to the new mode and AFTER PKI
	// generation tried (and sometimes failed) to land — the operator
	// got a half-converted host that simplesiem couldn't recover from
	// without manual surgery on certs/config. Fail fast with config
	// untouched is the only safe behaviour.
	if target == "server" && *realmPeer != "" {
		u, err := url.Parse(*realmPeer)
		if err != nil || u.Scheme == "" || u.Host == "" {
			fatalf("--realm URL is malformed (config NOT changed): expected a full URL like https://siem.example.com:9443; got %q", *realmPeer)
		}
		if u.Scheme != "https" {
			fatalf("--realm URL must use https:// (config NOT changed); got %q", *realmPeer)
		}
	}
	if *serverURL != "" {
		u, err := url.Parse(*serverURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			fatalf("--server URL is malformed (config NOT changed): expected a full URL like https://siem.example.com:9443; got %q", *serverURL)
		}
		if u.Scheme != "https" {
			fatalf("--server URL must use https:// (config NOT changed); got %q", *serverURL)
		}
	}

	// as15 — refuse server -> standalone when the realm still has
	// active dependents AND no other server can take over. The
	// "dependents" we care about: an agent_allowlist entry whose
	// CN we've recently signed certs for. If --force is set we
	// proceed but warn loudly; if there's another server in the
	// realm the demotion is fine (the peer absorbs the agents).
	if from == "server" && target == "standalone" && !*force {
		hasPeer := len(cfg.Server.Realm.Peers) > 0
		hasAgents := len(cfg.Server.AgentAllowlist) > 0
		if !hasPeer && hasAgents {
			fatalf("convert server -> standalone is refused: this server has %d agent(s) on its allowlist and no other server in the realm to take over. Demoting now would leave every agent unable to ship.\n\nResolve before retrying:\n  - uninstall the agents:    sudo simplesiem uninstall    (on each agent host)\n  - OR add a peer server:    sudo simplesiem realm join https://<peer>:9443 --key <PSK>\n  - OR override:             sudo simplesiem convert standalone --force  (will break agent shipping)",
				len(cfg.Server.AgentAllowlist))
		}
		if !hasPeer && !hasAgents {
			// No dependents — fine to demote. No warning needed.
		}
	}

	// as14 — convert server -> agent must have a realm peer to point
	// the new agent at. Without a peer, the agents on this server's
	// allowlist (if any) get orphaned with no other server to ship
	// to, AND this very host loses its identity in the realm because
	// agent mode requires a server to enroll against. Two paths:
	//   - operator passed --server explicitly → trust the operator
	//   - no --server, but realm has peers → auto-pick first peer
	//   - no --server, no peers → refuse (with --force override for
	//     advanced operators staging a multi-step migration)
	if from == "server" && target == "agent" && !*force {
		hasPeer := len(cfg.Server.Realm.Peers) > 0
		if *serverURL == "" && !hasPeer {
			fatalf("convert server -> agent is refused: no peer server is known. agent mode needs a server to ship to.\n\nResolve before retrying:\n  - pass --server <url> explicitly: sudo simplesiem convert agent --server https://<peer>:9443 --key <PSK>\n  - OR join a realm first:           sudo simplesiem realm join https://<peer>:9443 --key <PSK>\n  - OR override:                     sudo simplesiem convert agent --force  (will land in a non-functional state)")
		}
		// Auto-pick the first realm peer when --server wasn't given.
		// Operator can still override by passing --server explicitly.
		if *serverURL == "" && hasPeer {
			*serverURL = cfg.Server.Realm.Peers[0]
			fmt.Printf("as14: no --server given; using first realm peer (%s) as the new agent's server_url\n", *serverURL)
		}
	}

	printConversionWarning(from, target, cfg, *keepOld)

	if !*yes {
		if !confirmYes() {
			fmt.Println("aborted.")
			return
		}
	}

	// 1a. For agent target, EITHER do the PSK-based enrollment (when
	//     --key is set — agent generates its own keypair, server signs
	//     it remotely) OR run the existing connectivity preflight (when
	//     the operator has manually copied the cert bundle). Both paths
	//     leave config.json untouched on failure. --force skips the
	//     preflight for the "stage agent before server is ready" case.
	enrolled := false
	if target == "agent" {
		probe := cfg.Agent
		// as14 — when converting FROM server, cfg.Agent has never been
		// populated, so the cert-path fields are blank. Without them,
		// runAgentEnrollment fails on os.MkdirAll(filepath.Dir("")).
		// Backfill from the binary defaults so the enrollment writes
		// land in the standard location.
		if from == "server" {
			defaults := defaultConfig().Agent
			if probe.ClientCert == "" {
				probe.ClientCert = defaults.ClientCert
			}
			if probe.ClientKey == "" {
				probe.ClientKey = defaults.ClientKey
			}
			if probe.CACert == "" {
				probe.CACert = defaults.CACert
			}
			if probe.SpoolDir == "" {
				probe.SpoolDir = defaults.SpoolDir
			}
			if probe.SpoolMaxMB <= 0 {
				probe.SpoolMaxMB = defaults.SpoolMaxMB
			}
			if probe.BatchSize <= 0 {
				probe.BatchSize = defaults.BatchSize
			}
			if probe.BatchIntervalSec <= 0 {
				probe.BatchIntervalSec = defaults.BatchIntervalSec
			}
		}
		if *agentID != "" {
			probe.ID = *agentID
		}
		if *serverURL != "" {
			probe.ServerURL = *serverURL
		}
		hostname, _ := os.Hostname()
		switch {
		case *enrollKey != "":
			fmt.Println("enrolling with server (generating keypair locally, sending CSR)...")
			er, err := runAgentEnrollment(probe, hostname, *enrollKey)
			if err != nil {
				fatalf("enrollment failed (config NOT changed): %v", err)
			}
			// Carry the realm peer list through to the post-saveConfig
			// step so failover_servers gets persisted alongside the cert.
			cfg.Agent.FailoverServers = er.RealmPeers
			fmt.Printf("enrollment OK: cert + CA written under %s\n", filepath.Dir(probe.ClientCert))
			if er.RealmName != "" {
				fmt.Printf("realm: %q (%d peer(s))\n", er.RealmName, len(er.RealmPeers))
			}
			// Now do the same connectivity preflight against the cert we
			// just received, so any allowlist/CN edge case is caught
			// before we flip the mode. Retry with backoff so the server's
			// SNI-driven SAN auto-extension (re-issued cert, hot-reloader
			// poll cycle ~1s) has time to take effect — without this, an
			// operator dialing by a hostname the server's cert hadn't yet
			// covered would race the reload and see a SAN mismatch.
			var preflightErr error
			for _, delay := range []time.Duration{0, 1500 * time.Millisecond, 3 * time.Second} {
				if delay > 0 {
					time.Sleep(delay)
				}
				preflightErr = validateAgentReadyForConvert(probe, hostname)
				if preflightErr == nil {
					break
				}
				if !strings.Contains(preflightErr.Error(), "SAN does not cover") {
					break
				}
			}
			if preflightErr != nil {
				fatalf("post-enrollment preflight failed (config NOT changed): %v", preflightErr)
			}
			fmt.Println("post-enrollment preflight OK.")
			enrolled = true
		case !*force:
			fmt.Println("checking server connectivity...")
			if err := validateAgentReadyForConvert(probe, hostname); err != nil {
				fatalf("agent preflight failed (config NOT changed): %v\n\nOptions:\n  - re-run with --key <PSK> to enroll automatically (agent generates its own keypair)\n  - re-run with --force to stage this conversion before the server is ready", err)
			}
			fmt.Println("connectivity OK: server reachable, certs valid, agent ID accepted.")
			enrolled = true // certs already in place + verified
		}
	}

	// Remember whether we should leave the daemon running at the end.
	// Default: yes — landing in a stopped state is hostile UX. The
	// only exception is when an operator passed --force to stage an
	// agent before the server is ready; in that case starting would
	// just fail preflight.
	wantRunning := !(target == "agent" && *force && !enrolled)

	// 1. Stop the daemon if it's running. Best-effort; if stop fails the
	//    user can try again — the config edit hasn't happened yet.
	if isRunning() {
		fmt.Println("stopping daemon...")
		stopCommand(nil) // existing helper; logs its own messages
	}

	// 1b. Notify the previous role's coordinators that we're leaving
	//     it. Fired BEFORE saveConfig (we still need the live cfg
	//     fields to resolve who to tell) and BEFORE the daemon is
	//     stopped (so any TLS material the notifier reads is still
	//     hot in cache). Best-effort: failures don't block the
	//     convert. Covers every from-role: agent -> notifyAgentDeparture,
	//     server -> notifyServerDeparture (replaces the prior
	//     server->agent-only branch), master and collector for
	//     completeness even though convert.go only handles the agent /
	//     server / standalone targets — the helper no-ops when from is
	//     standalone or matches target.
	notifyConvertDeparture(cfg, from, target)

	// 2. Rehome standalone-shape log dirs if requested. Only meaningful
	//    when leaving standalone — otherwise there are no top-level
	//    log-type dirs to move.
	if *keepOld && from == "standalone" {
		if moved, err := rehomeLegacyLogs(cfg.LogDir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not rehome legacy logs: %v\n", err)
		} else if moved > 0 {
			fmt.Printf("rehomed %d log type(s) to %s/_legacy/ (still readable via 'simplesiem triage --host _legacy ...')\n",
				moved, cfg.LogDir)
		}
	}

	// 2a. For server target: bootstrap server PKI BEFORE writing
	//     config.json. The PKI step is the one most likely to fail
	//     (orphaned ca.pem from a previous agent role, filesystem
	//     permissions on certs dir, etc.) and the operator-visible
	//     consequence of a partial convert is severe — config flipped
	//     to server, certs unbootstrapped, daemon won't start, and
	//     `certs init` would itself trip on the orphan. Doing this
	//     first means a PKI failure leaves config.json unchanged so
	//     a retry (or a `certs init` invocation) starts from a
	//     coherent state. ensureServerPKI handles partial-CA cases
	//     internally — see internal/sieg/certs.go.
	var pkiLines []string
	if target == "server" {
		var err error
		if _, pkiLines, err = ensureServerPKI(*cfgPath, 10, 5); err != nil {
			fatalf("server PKI bootstrap failed (config NOT changed): %v\n  remediation: fix the cert state per the message above and re-run convert", err)
		}
	}

	// 3. Apply mode + any sticky overrides, then write config.json.
	cfg.Mode = target
	switch target {
	case "agent":
		if *agentID != "" {
			cfg.Agent.ID = *agentID
		}
		if *serverURL != "" {
			cfg.Agent.ServerURL = *serverURL
		}
		// as14 — when converting from server, the agent block has
		// never had its cert-path defaults set. Persist them now so
		// the daemon comes up able to find its own cert + spool.
		if from == "server" {
			defaults := defaultConfig().Agent
			if cfg.Agent.ClientCert == "" {
				cfg.Agent.ClientCert = defaults.ClientCert
			}
			if cfg.Agent.ClientKey == "" {
				cfg.Agent.ClientKey = defaults.ClientKey
			}
			if cfg.Agent.CACert == "" {
				cfg.Agent.CACert = defaults.CACert
			}
			if cfg.Agent.SpoolDir == "" {
				cfg.Agent.SpoolDir = defaults.SpoolDir
			}
			if cfg.Agent.SpoolMaxMB <= 0 {
				cfg.Agent.SpoolMaxMB = defaults.SpoolMaxMB
			}
			if cfg.Agent.BatchSize <= 0 {
				cfg.Agent.BatchSize = defaults.BatchSize
			}
			if cfg.Agent.BatchIntervalSec <= 0 {
				cfg.Agent.BatchIntervalSec = defaults.BatchIntervalSec
			}
		}
	case "server":
		if *listen != "" {
			cfg.Server.Listen = *listen
		}
	}
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("write config: %v", err)
	}
	fmt.Printf("config updated: %s (backup at %s.bak)\n", *cfgPath, *cfgPath)

	// Drop default rules.json if missing — same logic install uses.
	// Without this, `convert standalone/server` from a fresh container
	// would leave rules.json absent and `simplesiem rules check`
	// would error confusingly. Existing files are preserved.
	rulesPath := cfg.RulesPath
	if rulesPath == "" {
		rulesPath = filepath.Join(filepath.Dir(*cfgPath), "rules.json")
	}
	if _, err := os.Stat(rulesPath); os.IsNotExist(err) && (target == "standalone" || target == "server") {
		if err := os.WriteFile(rulesPath, []byte(defaultRulesJSON), 0o640); err == nil {
			fmt.Printf("wrote default rules: %s\n", rulesPath)
		}
	}

	// 4. Print PKI bootstrap result (the bootstrap itself ran in step 2a
	//    BEFORE we touched config.json, so a failure couldn't have
	//    landed us in a broken half-state).
	if target == "server" && len(pkiLines) > 0 {
		fmt.Println("Server PKI ready:")
		for _, l := range pkiLines {
			fmt.Println("  " + l)
		}
	}

	// 5. Restart the daemon so we end in a running state (the operator
	//    almost never wants the daemon stopped after a convert — agent
	//    mode needs it for shipping events, server mode needs it to
	//    accept them, standalone mode needs it to collect locally).
	if wantRunning {
		fmt.Println("starting daemon...")
		startCommand(nil)
	}

	// 5a. After standing up a server, join an existing realm — either
	//     via the inline --realm/--realm-key flags (one-shot, no prompt)
	//     or via the post-convert interactive prompt. Either path runs
	//     the same underlying realm-join handshake, so a leaked private
	//     key is never sent over the wire — only public CAs cross the
	//     PSK-authenticated channel.
	//
	// as13 — when converting FROM agent, the previous cfg.Agent.ServerURL
	// is a known realm-peer candidate. If the operator passed only
	// --realm-key (no --realm), use the prior server URL as the peer.
	if target == "server" && from == "agent" && *realmPeer == "" && *realmKey != "" && cfg.Agent.ServerURL != "" {
		*realmPeer = cfg.Agent.ServerURL
		fmt.Printf("as13: using prior agent.server_url (%s) as the realm-peer URL\n", *realmPeer)
	}
	if target == "server" {
		switch {
		case *realmPeer != "" && *realmKey != "":
			fmt.Println()
			fmt.Printf("joining realm via %s ...\n", *realmPeer)
			runRealmJoin([]string{*realmPeer, "--key", *realmKey, "--yes", "--config", *cfgPath})
			if isRunning() {
				fmt.Println("restarting daemon to pick up new trust bundle...")
				stopCommand(nil)
				startCommand(nil)
			}
		case *realmPeer != "" && *realmKey == "":
			fmt.Fprintln(os.Stderr, "warning: --realm given without --realm-key; skipping realm join. Re-run with both flags or use `simplesiem realm join`.")
		case *realmPeer == "" && *realmKey != "":
			fmt.Fprintln(os.Stderr, "warning: --realm-key given without --realm; ignored.")
		case !*yes:
			fmt.Println()
			if confirmYes("Join an existing realm now? [y/N] ") {
				peerURL := strings.TrimSpace(promptInput("Existing realm peer URL (e.g. https://siem-a.example.com:9443): "))
				if peerURL == "" {
					fmt.Println("skipped — run later with: sudo simplesiem realm join <peer-url> --key <PSK>")
				} else {
					psk := strings.TrimSpace(promptInput("PSK from " + peerURL + " (sudo simplesiem certs psk show on that host): "))
					if psk == "" {
						fmt.Println("skipped — run later with: sudo simplesiem realm join " + peerURL + " --key <PSK>")
					} else {
						runRealmJoin([]string{peerURL, "--key", psk, "--yes", "--config", *cfgPath})
						if isRunning() {
							fmt.Println("restarting daemon to pick up new trust bundle...")
							stopCommand(nil)
							startCommand(nil)
						}
					}
				}
			}
		}
	}

	// 6. Print mode-specific next steps. Re-load the config first so
	//    fields a sub-step mutated (realm.peers after a successful
	//    realm join) are reflected in the printout — without this,
	//    the realm-join hint would still show even though the operator
	//    just joined.
	cfg = loadConfig(*cfgPath)
	printConversionNextSteps(target, cfg, enrolled, wantRunning)
}

// printConversionWarning shows the operator exactly what's about to
// happen so the confirmation prompt is informed, not blind.
func printConversionWarning(from, to string, cfg Config, keepOld bool) {
	fmt.Printf("Converting this install: %s -> %s\n\n", from, to)
	fmt.Println("What will change:")

	// Common: mode flag + service restart needed
	fmt.Printf("  - config.json mode: %s -> %s\n", from, to)
	fmt.Println("  - the daemon will be stopped; you must run `simplesiem start` afterwards")

	switch to {
	case "agent":
		fmt.Println("  - collectors keep running locally but events ship to the configured server over mTLS")
		fmt.Println("  - the local rule engine stops; the server fires alerts on received events")
		fmt.Println("  - the daemon will REFUSE TO START until agent.id, agent.server_url, and the")
		fmt.Println("    client_cert / client_key / ca_cert files are in place")
		fmt.Println("  - convert will refuse to proceed unless the configured server is reachable,")
		fmt.Println("    accepts our cert, and has the agent ID on its allowlist (use --force to bypass)")
	case "server":
		fmt.Println("  - this host stops collecting its own events; it accepts batches from agents")
		fmt.Println("  - the rule engine fires on received traffic (you may want different rules.json)")
		fmt.Println("  - the listen port (default :9443) will be opened — check your firewall")
		fmt.Println("  - the daemon will REFUSE TO START until server.cert/key/ca_cert files are in place")
	case "standalone":
		fmt.Println("  - this host resumes collecting its own events locally")
		fmt.Println("  - the local rule engine starts firing again")
		fmt.Println("  - any agents shipping to this host will fail (server endpoint goes away)")
	}

	// Loss-of-visibility warning, scoped to the actual transition.
	switch {
	case from == "standalone" && (to == "agent" || to == "server"):
		fmt.Println()
		fmt.Println("Visibility impact:")
		if keepOld {
			fmt.Printf("  - existing %s/{network,files,...} dirs will be MOVED to %s/_legacy/\n",
				cfg.LogDir, cfg.LogDir)
			fmt.Println("    they stay readable via: simplesiem triage --host _legacy --since 30d")
		} else {
			fmt.Printf("  - existing %s/{network,files,...} dirs will become UNREACHABLE\n", cfg.LogDir)
			fmt.Println("    from triage / query / verify (the on-disk files remain, but read")
			fmt.Println("    commands in the new mode walk a different layout).")
			fmt.Println("    (default keeps them under _legacy/; you passed --keep-old=false)")
		}
	case from == "agent" && to != "agent":
		fmt.Println()
		fmt.Println("Visibility impact:")
		fmt.Println("  - your collected events live on the SERVER, not this host. The local")
		fmt.Printf("    %s/_agent/ dir keeps shipping diagnostics; collected events stay on the server.\n", cfg.LogDir)
	case from == "server" && to != "server":
		fmt.Println()
		fmt.Println("Visibility impact:")
		fmt.Printf("  - per-host directories under %s/<agent-id>/ become orphaned to read commands\n", cfg.LogDir)
		fmt.Println("    in the new mode. Files remain on disk; you can copy them out before switching")
		fmt.Println("    if the data matters.")
	}

	fmt.Println()
}

// printConversionNextSteps lists the concrete things the operator needs
// to do before `simplesiem start` will succeed in the new mode. Steps
// are numbered dynamically so a step skipped because the operator
// already supplied the value via a flag doesn't leave a gap.
//
// enrolled signals the agent path already ran PSK enrollment (certs
// in place, allowlist updated server-side); the steps then collapse to
// just "start" rather than guiding the operator through a manual file
// copy that's already done.
func printConversionNextSteps(to string, cfg Config, enrolled bool, running bool) {
	fmt.Println()
	if running {
		fmt.Println("Conversion complete. Daemon is running in " + to + " mode.")
	} else {
		fmt.Println("Conversion complete (daemon NOT auto-started — see below).")
	}
	fmt.Println()
	fmt.Println("Next steps:")
	n := 0
	step := func(line string) { n++; fmt.Printf("  %d. %s\n", n, line) }

	switch to {
	case "agent":
		if !enrolled {
			// Operator passed --force; certs aren't in place, so they
			// need to come back and run the enrollment for real.
			step("Re-run with the server's PSK to enroll: simplesiem convert agent --server <url> --key <PSK>")
			step("(get the PSK from the server: simplesiem certs psk show)")
			if !running {
				step("Then: sudo simplesiem start")
			}
		}
		step("Verify: simplesiem status   (expect mode: agent + a meta:agent_tls_ping_ok event)")
	case "server":
		if !running {
			step("sudo simplesiem start")
		}
		step("Open the listen port in your firewall (default :9443)")
		host := bestServerHostname()
		if psk, perr := readEnrollPSK(); perr == nil {
			step("On each agent host: sudo simplesiem convert agent --server https://" + host + ":9443 --key " + psk)
		} else {
			step("On each agent host: sudo simplesiem convert agent --server https://" + host + ":9443 --key <PSK from `certs psk show`>")
		}
		// Realm join hint. Skipped when this server already has peers
		// (single-line clutter when the realm is already established);
		// otherwise shown alongside the agent-enroll command so the
		// operator sees both fleet-onboarding paths in one place.
		if len(cfg.Server.Realm.Peers) == 0 {
			step("To join an existing realm in one shot: sudo simplesiem convert server -y --realm https://<peer-server>:9443 --realm-key <PSK from peer>")
			step("Or against this already-converted server: sudo simplesiem realm join https://<peer-server>:9443 --key <PSK from peer> --yes")
		}
		step("Verify: simplesiem status   (expect mode: server + hosts: 2+ as agents enroll)")
	case "standalone":
		step("(Optional) review rules.json — it now applies to local activity again")
		if !running {
			step("sudo simplesiem start")
		}
	}
}

// confirmYes prompts for a y/n answer. With no argument it uses the
// generic "Continue? [y/N] "; with an argument the caller provides
// the contextual question (e.g. "Join an existing realm now? [y/N] ").
// Anything other than y/yes (case-insensitive) is treated as a no.
// Uses the shared stdinReader so multiple prompts in one process
// don't lose each other's buffered input.
//
// The argument keeps the prompt to ONE question per yes/no: callers
// that have their own contextual question pass it here instead of
// printing it themselves and then chaining to a second "Continue?"
// prompt.
func confirmYes(prompt ...string) bool {
	p := "Continue? [y/N] "
	if len(prompt) > 0 && prompt[0] != "" {
		p = prompt[0]
	}
	fmt.Print(p)
	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// rehomeLegacyLogs moves <log_dir>/<type>/ subdirectories that are
// recognised log types into <log_dir>/_legacy/<type>/. Returns the
// count of subdirs moved. Skipping anything not in defaultLogTypes
// avoids accidentally relocating user data placed in the same dir.
func rehomeLegacyLogs(logDir string) (int, error) {
	legacy := filepath.Join(logDir, "_legacy")
	if err := os.MkdirAll(legacy, logDirMode); err != nil {
		return 0, err
	}
	moved := 0
	for _, t := range defaultLogTypes {
		src := filepath.Join(logDir, t)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(legacy, t)
		// If a previous conversion already created _legacy/<t>, don't
		// clobber it — append a numeric suffix.
		final := dst
		for n := 1; n < 1000; n++ {
			if _, err := os.Stat(final); os.IsNotExist(err) {
				break
			}
			final = fmt.Sprintf("%s.%d", dst, n)
		}
		if err := os.Rename(src, final); err != nil {
			return moved, err
		}
		moved++
	}
	return moved, nil
}

// saveConfig writes cfg back to path, preserving the previous file as
// .bak so a botched edit can be rolled back by hand. Mode is 0640 to
// match the install-time policy.
//
// .bak refresh policy: only copy the existing file to .bak when it
// parses as valid JSON. If a manual hand-edit broke the JSON and the
// operator then runs a CLI command (which calls saveConfig), we DON'T
// want to overwrite the last-known-good .bak with the broken one —
// that destroys the rollback target. So a malformed existing file
// leaves the prior .bak alone.
//
// Backfill: on installs that pre-date the install-time .bak seeding,
// the .bak might not exist at all. We backfill it from the current
// valid file before writing the new config so the rollback target is
// always present after the FIRST `saveConfig` call.
func saveConfig(path string, cfg Config) error {
	if existing, err := os.ReadFile(path); err == nil {
		var probe Config
		if jerr := json.Unmarshal(existing, &probe); jerr == nil {
			_ = os.WriteFile(path+".bak", existing, 0o640)
		}
		// else: existing is malformed; preserve whatever .bak we
		// already have so a `cp <path>.bak <path>` recovery still
		// gives the operator a valid file.
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return err
	}
	// Final safety: if the .bak STILL doesn't exist (e.g., the file
	// existed but was malformed AND no prior .bak ever got written —
	// possible on installs that pre-date the install-time seeding),
	// seed it now from the just-written valid config. The operator
	// then always has a parseable rollback target.
	if _, err := os.Stat(path + ".bak"); os.IsNotExist(err) {
		_ = os.WriteFile(path+".bak", data, 0o640)
	}
	return nil
}

// validateAgentReadyForConvert checks that the prospective AgentConfig
// can actually reach a working server BEFORE convert mutates disk state.
// It mirrors the daemon's runtime auth path so a pass here is a
// guarantee that `start` will succeed:
//
//  1. server_url, client_cert, client_key, ca_cert are set and the cert
//     files exist on disk;
//  2. agent.ca_cert is a valid CA bundle and the client keypair loads;
//  3. mTLS handshake to the server completes (proves the server cert
//     chains to our CA, the server is reachable, and our client cert
//     is presentable);
//  4. a zero-event POST to /v1/events runs through the server's CN
//     match + agent_allowlist gates and returns 2xx — so the agent ID
//     we'll be using is already approved on the server.
//
// Errors are written to be self-contained fix instructions: each one
// names exactly which command on which host needs to run.
func validateAgentReadyForConvert(acfg AgentConfig, hostname string) error {
	if acfg.ServerURL == "" {
		return fmt.Errorf("agent.server_url is empty — pass --server <https://host:port> or set agent.server_url in config.json")
	}
	id := acfg.ID
	if id == "" {
		id = hostname
	}
	if id == "" {
		return fmt.Errorf("agent.id is empty and hostname could not be resolved — pass --id <agent-id>")
	}
	for _, p := range []struct{ name, path string }{
		{"agent.client_cert", acfg.ClientCert},
		{"agent.client_key", acfg.ClientKey},
		{"agent.ca_cert", acfg.CACert},
	} {
		if p.path == "" {
			return fmt.Errorf("%s is unset in config.json — re-run with --key <PSK> to enroll (get the PSK from the server: simplesiem certs psk show)", p.name)
		}
		if _, err := os.Stat(p.path); err != nil {
			return fmt.Errorf("%s missing at %s — re-run convert with --key <PSK> to enroll (get the PSK from the server: simplesiem certs psk show)", p.name, p.path)
		}
	}
	tlsCfg, err := agentTLSConfig(acfg)
	if err != nil {
		return fmt.Errorf("load client cert/CA: %w", err)
	}
	tr := &http.Transport{
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	base := strings.TrimRight(acfg.ServerURL, "/")

	// Empty NDJSON body. Goes through the same auth gates as a real
	// upload (cert chain, CN==host, allowlist) and returns
	// {"received":0,"rejected":0} on full success.
	req, err := http.NewRequest(http.MethodPost, base+"/v1/events", bytes.NewReader(nil))
	if err != nil {
		return fmt.Errorf("build probe request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("X-SimpleSIEM-Host", id)
	if acfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+acfg.BearerToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return classifyAgentProbeErr(err, acfg, id)
	}
	defer resp.Body.Close()
	bodyBuf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	body := strings.TrimSpace(string(bodyBuf))
	switch resp.StatusCode {
	case 200, 201, 202:
		return nil
	case 401:
		return fmt.Errorf("server rejected our credentials (HTTP 401: %s) — the client cert isn't trusted by the server's CA, or bearer_token is wrong; re-enroll: simplesiem convert standalone -y && simplesiem convert agent --server %s --key <PSK from server's `certs psk show`>", body, acfg.ServerURL)
	case 403:
		// Could be CN mismatch OR allowlist rejection. Body text
		// distinguishes; pass it through verbatim.
		return fmt.Errorf("server rejected agent ID %q (HTTP 403: %s) — on the server, add %q to server.agent_allowlist in config.json and restart, OR re-enroll the agent with the current PSK", id, body, id)
	case 404:
		return fmt.Errorf("server has no /v1/events endpoint at %s (HTTP 404) — verify agent.server_url points at the SimpleSIEM server, not a different HTTP service", acfg.ServerURL)
	case 405:
		return fmt.Errorf("server rejected POST at %s/v1/events (HTTP 405) — agent.server_url probably points at a different HTTP server", base)
	case 429:
		return fmt.Errorf("server rate-limited the probe (HTTP 429) — try again in a few seconds")
	case 503:
		return fmt.Errorf("server is up but reports HTTP 503: %s — wait for it to settle and try again", body)
	default:
		return fmt.Errorf("server returned HTTP %d at %s/v1/events: %s", resp.StatusCode, base, body)
	}
}

// classifyAgentProbeErr turns a transport-level error into an
// instruction-shaped message. Substring matching is used because the
// underlying errors are unwrappable but Go's net/http and crypto/tls
// don't expose stable typed errors for these cases.
func classifyAgentProbeErr(err error, acfg AgentConfig, id string) error {
	msg := err.Error()
	// Pull out the dial target so the fix-it message can name the
	// hostname/IP that needs to be in the cert SAN.
	dialHost := acfg.ServerURL
	if u, perr := url.Parse(acfg.ServerURL); perr == nil && u.Host != "" {
		dialHost = u.Hostname()
	}
	switch {
	case strings.Contains(msg, "x509: certificate is valid for"),
		strings.Contains(msg, "certificate is not valid for any names"):
		// SAN mismatch — server cert is fine, CA is fine, but the
		// hostname/IP we dialed isn't in the cert's SAN list. Most
		// commonly hit when an operator uses an IP (e.g. a Docker
		// bridge address) instead of the hostname in agent.server_url.
		return fmt.Errorf("server cert is valid but its SAN does not cover %q — re-issue the server cert with the right name:\n  on the server, run:\n    sudo rm /etc/simplesiem/certs/server.pem /etc/simplesiem/certs/server.key\n    sudo simplesiem certs server $(hostname) %s 127.0.0.1 localhost\n    sudo simplesiem stop && sudo simplesiem start\n  OR change agent.server_url to use a hostname that's already in the SAN (got: %v)", dialHost, dialHost, err)
	case strings.Contains(msg, "certificate signed by unknown authority"),
		strings.Contains(msg, "x509: certificate"):
		return fmt.Errorf("server cert isn't trusted by agent.ca_cert (%s) — verify the server is using a cert signed by the same CA whose bundle you copied here (got: %v)", acfg.CACert, err)
	case strings.Contains(msg, "tls: bad certificate"),
		strings.Contains(msg, "tls: unknown certificate authority"),
		strings.Contains(msg, "remote error: tls"):
		return fmt.Errorf("server rejected our client cert at the TLS layer — re-enroll the agent with the current PSK (run `simplesiem certs psk show` on the server, then `simplesiem convert standalone -y && simplesiem convert agent --server %s --key <PSK>` here) (got: %v)", acfg.ServerURL, err)
	case strings.Contains(msg, "no such host"),
		strings.Contains(msg, "lookup "):
		return fmt.Errorf("DNS lookup failed for %s — fix agent.server_url or /etc/hosts (got: %v)", acfg.ServerURL, err)
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "actively refused"),
		strings.Contains(msg, "No connection could be made"):
		return fmt.Errorf("server at %s is not accepting connections — start the server (`simplesiem start` on the server host) and verify the firewall allows the listen port (got: %v)", acfg.ServerURL, err)
	case strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "deadline exceeded"),
		strings.Contains(msg, "Client.Timeout"):
		return fmt.Errorf("server at %s did not respond within 15s — likely a firewall drop or the wrong port (got: %v)", acfg.ServerURL, err)
	case strings.Contains(msg, "EOF"),
		strings.Contains(msg, "connection reset"):
		return fmt.Errorf("server at %s closed the connection during TLS — common cause: server is running but its require_client_cert + ca_cert don't match the CA we're presenting (got: %v)", acfg.ServerURL, err)
	default:
		return fmt.Errorf("could not reach server at %s: %v", acfg.ServerURL, err)
	}
}
