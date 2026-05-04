package sieg

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// runConvertMaster is the interactive operator path for `simplesiem
// convert master`. It loops through one-or-more server enrollments,
// updates config.json (mode=master + master.servers), and restarts
// the daemon — replacing the previous "edit config.json by hand,
// then run master enroll" two-step.
//
// The loop accepts any number of (url, PSK) pairs:
//
//   Server URL: https://siem-a.example.com:9443
//   PSK for https://siem-a.example.com:9443: simplesiem-psk:abc...
//   ✓ enrolled
//   Server URL (blank to finish):
//
// At least one successful enrollment is required — converting to
// master mode with master.servers empty would refuse to start.
//
// On any enrollment failure, the loop offers retry/skip/abort so an
// operator who fat-fingers a PSK doesn't have to start over. Already-
// successful enrollments stay on disk; the abort path leaves the
// install in standalone mode (config NOT flipped) so the operator
// can re-run later.
func runConvertMaster(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "id": true, "server": true, "key": true})
	fs := flag.NewFlagSet("convert master", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	masterID := fs.String("id", "", "master ID (CN) to use for all enrollments; defaults to master-<hostname>")
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	// One-shot non-interactive mode: when --server and --key are both
	// set, convert master enrolls with that single server + auto-
	// discovers realm peers + flips mode + starts the daemon, all in
	// one command. Existing interactive flow (no --server) still
	// loops through prompts so operators can register multiple
	// servers across realms in one session.
	oneShotServer := fs.String("server", "", "(non-interactive) single server URL to enroll with")
	oneShotKey := fs.String("key", "", "(non-interactive) PSK from `simplesiem certs psk show` on that server")
	_ = fs.Parse(args)

	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}

	cfg := loadConfig(*cfgPath)
	from := normaliseMode(cfg.Mode)
	if from == "master" {
		fmt.Println("already in master mode; nothing to do.")
		fmt.Println("To enroll with additional servers, run:")
		fmt.Println("  sudo simplesiem master enroll <server-url> --key <PSK>")
		return
	}
	// m2 — refuse server -> master when the realm has no other
	// server to take over the agent-allowlist + ingest authority.
	// Without the refusal, the operator's last server promotes
	// itself to master and the realm has zero ingest endpoints —
	// agents start dropping events. Hint at the resolution:
	// add a peer first.
	if from == "server" && len(cfg.Server.Realm.Peers) == 0 {
		fatalf("convert server -> master is refused: this server has no realm peers, and a master is a pure consumer (it doesn't accept agent events). Add a second server to the realm first:\n  sudo simplesiem realm join https://<peer>:9443 --key <PSK>\nthen retry the master conversion. The peer takes over agent ingest while this host runs as master.")
	}

	fmt.Println("Converting this install: " + from + " -> master")
	fmt.Println()
	fmt.Println("What will change:")
	fmt.Println("  - this host stops being a standalone collector / agent / server and becomes a master")
	fmt.Println("  - master mode pulls events from one or more registered servers via mTLS")
	fmt.Println("  - the master also collects locally so its own host stays monitored")
	fmt.Println("  - rules don't fire on the master; alerts replicate from the origin servers")
	fmt.Println()
	if *oneShotServer == "" {
		fmt.Println("You'll be prompted for each server URL + its enrollment PSK.")
		fmt.Println("Get each server's PSK with: sudo simplesiem certs psk show  (on that server)")
		fmt.Println()
	}
	if !*yes {
		if !confirmYes() {
			fmt.Println("aborted.")
			return
		}
	}

	// Non-interactive one-shot path: single server enrollment, auto-
	// discover realm peers, flip mode, restart. Mirrors the body of
	// the interactive loop but skips every prompt — useful for
	// scripted master bootstraps and one-line `install`-style ops.
	if *oneShotServer != "" && *oneShotKey != "" {
		if perr := validateMasterServerURL(*oneShotServer); perr != nil {
			fatalf("invalid --server URL: %v", perr)
		}
		fmt.Printf("enrolling with %s ...\n", *oneShotServer)
		res, err := enrollMasterWithServer(*cfgPath, *oneShotServer, *oneShotKey, *masterID)
		if err != nil {
			fatalf("enrollment failed (config NOT changed): %v", err)
		}
		fmt.Printf("  enrolled with %s (master_id=%s, realm=%s)\n", res.ServerURL, res.MasterID, res.RealmName)
		if added, _, derr := discoverAndAddRealmPeers(*cfgPath, res); derr == nil {
			for _, p := range added {
				fmt.Printf("    + auto-discovered realm peer: %s\n", p)
			}
		}
		if isRunning() {
			stopCommand(nil)
		}
		cfg = loadConfig(*cfgPath)
		cfg.Mode = "master"
		if err := saveConfig(*cfgPath, cfg); err != nil {
			fatalf("write config: %v", err)
		}
		fmt.Println("config updated:", *cfgPath, "(mode=master, master.servers="+fmt.Sprint(len(cfg.Master.Servers))+")")
		startCommand(nil)
		fmt.Println()
		fmt.Println("Conversion complete. Daemon is running in master mode.")
		return
	}
	if *oneShotServer == "" && *oneShotKey != "" {
		fatalf("--key supplied without --server; both are required for the non-interactive path")
	}
	if *oneShotServer != "" && *oneShotKey == "" {
		fatalf("--server supplied without --key; both are required for the non-interactive path")
	}

	// Loop the prompt. We prompt for each server URL, then its PSK,
	// then run the enrollment. The first round is mandatory; later
	// rounds are optional ("blank to finish").
	first := true
	enrolled := []MasterEnrollResult{}
	for {
		var url string
		if first {
			url = strings.TrimSpace(promptInput("Server URL (e.g. https://siem-a.example.com:9443): "))
		} else {
			url = strings.TrimSpace(promptInput("Server URL (blank to finish): "))
		}
		if url == "" {
			if first {
				fmt.Println("at least one server is required for master mode; aborting.")
				return
			}
			break
		}
		if perr := validateMasterServerURL(url); perr != nil {
			fmt.Fprintln(os.Stderr, "  error:", perr)
			continue
		}
		psk := strings.TrimSpace(promptInput("PSK for " + url + ": "))
		if psk == "" {
			fmt.Fprintln(os.Stderr, "  error: PSK is required (skipping this server)")
			continue
		}
		fmt.Println("  enrolling...")
		res, err := enrollMasterWithServer(*cfgPath, url, psk, *masterID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "  error:", err)
			fmt.Fprintln(os.Stderr, "  the server URL was NOT added to master.servers; try again with the right URL/PSK")
			continue
		}
		fmt.Printf("  ✓ enrolled with %s (master_id=%s, realm=%s)\n", res.ServerURL, res.MasterID, res.RealmName)
		enrolled = append(enrolled, res)
		// Auto-discover realm peers off the just-enrolled server so
		// the operator doesn't have to type each peer in the same
		// realm. New peers reuse the same client cert (it's signed
		// by a CA every realm peer trusts).
		if added, _, derr := discoverAndAddRealmPeers(*cfgPath, res); derr == nil {
			for _, p := range added {
				fmt.Printf("    + auto-discovered realm peer: %s\n", p)
			}
		}
		first = false
	}

	if len(enrolled) == 0 {
		fmt.Println("no servers enrolled; aborting (config unchanged).")
		return
	}

	// Stop the daemon (best-effort). If stop fails, the operator can
	// retry — config edit hasn't happened yet.
	if isRunning() {
		fmt.Println("stopping daemon...")
		stopCommand(nil)
	}

	// Reload config from disk (master.servers was mutated by each
	// enroll call) and flip the mode. saveConfig backs up to .bak.
	cfg = loadConfig(*cfgPath)
	cfg.Mode = "master"
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("write config: %v", err)
	}
	fmt.Println("config updated:", *cfgPath, "(mode=master, master.servers="+fmt.Sprint(len(cfg.Master.Servers))+")")

	// Start the daemon. In master mode it will pull from each server
	// and write replicated events under <log_dir>/<host>/<type>/<date>.from-<server>.jsonl
	// every master.sync_interval_seconds.
	fmt.Println("starting daemon...")
	startCommand(nil)

	fmt.Println()
	fmt.Println("Conversion complete. Daemon is running in master mode.")
	fmt.Println()
	fmt.Println("Verify:")
	fmt.Println("  simplesiem status                                  # mode: master, servers + hosts listed")
	fmt.Println("  simplesiem triage --since 1h                       # cross-realm timeline")
	fmt.Println("  simplesiem triage --host <agent-id> --window 30s   # one host across all realms")
	fmt.Println()
	fmt.Println("To enroll with additional servers later:")
	fmt.Println("  sudo simplesiem master enroll <server-url> --key <PSK>")
	fmt.Println("  sudo simplesiem stop && sudo simplesiem start      # pick up the new server")
}

// validateMasterServerURL is the same validation enrollMasterWithServer
// performs, surfaced earlier so the prompt loop can give immediate
// feedback before attempting the network round-trip.
func validateMasterServerURL(s string) error {
	s = strings.TrimRight(s, "/")
	if s == "" {
		return fmt.Errorf("URL is required")
	}
	parsed, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("must use https:// (got %q)", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("must include a host (e.g. https://siem-a.example.com:9443)")
	}
	return nil
}
