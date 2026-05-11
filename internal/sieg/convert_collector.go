package sieg

import (
	"flag"
	"fmt"
	"strings"
)

// runConvertCollector is the interactive operator path for `simplesiem
// convert collector`. The collector pairs with exactly one source —
// either a server (the common case, which the collector will later
// auto-promote to a master if one appears in the realm) or, when the
// realm already has a master, the master directly.
//
// The flow is:
//
//   1. Prompt for the source URL + the source's enrollment PSK.
//   2. Run the same code path as `simplesiem collector enroll`, which
//      generates a keypair locally, signs a CSR via /v1/enroll-collector,
//      and writes the cert bundle under <config>/collector/<host>/.
//   3. Flip mode=collector and start the daemon.
//
// Single-slot rule: the source must have its slot opened with
// `simplesiem certs collector accept-next` first. If the slot is closed,
// the enrollment fails fast with a 403 — the operator gets a clear
// fix-it message rather than silent rejection.
func runConvertCollector(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "id": true})
	fs := flag.NewFlagSet("convert collector", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	colID := fs.String("id", "", "collector ID (CN) to use; defaults to collector-<hostname>")
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	_ = fs.Parse(args)

	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}

	cfg := loadConfig(*cfgPath)
	from := normaliseMode(cfg.Mode)
	if from == "collector" {
		fmt.Println("already in collector mode; nothing to do.")
		fmt.Println("To re-pair with a different source, run:")
		fmt.Println("  sudo simplesiem collector enroll <url> --key <PSK>")
		return
	}
	// m6 — refuse master → collector. The master is the realm's
	// canonical aggregator; demoting it to a backup replicator
	// abandons every server's pull association silently. Operator
	// who really wants this can convert master → standalone first,
	// then standalone → collector — that two-step path forces them
	// to acknowledge the master is going away.
	if from == "master" {
		fatalf("convert master -> collector is refused: a master demotes to a backup-replicator role only via an explicit two-step path (convert master -> standalone, then convert standalone -> collector). The master's enrolled servers would otherwise lose their authority pull association without notice.")
	}

	fmt.Println("Converting this install: " + from + " -> collector")
	fmt.Println()
	fmt.Println("What will change:")
	fmt.Println("  - this host stops being a standalone collector / agent / server / master")
	fmt.Println("  - collector mode pulls a backup copy of every event from one source over mTLS")
	fmt.Println("  - the source keeps its data; the collector writes a SECOND copy locally")
	fmt.Println("  - only ONE collector can be associated with any given source — single-slot rule")
	fmt.Println("  - the collector also collects locally so its own host stays monitored")
	fmt.Println()
	fmt.Println("On the source server, first open the collector slot with:")
	fmt.Println("  sudo simplesiem certs collector accept-next")
	fmt.Println("then come back here and supply the source URL + PSK.")
	fmt.Println()
	if !*yes {
		if !confirmYes() {
			fmt.Println("aborted.")
			return
		}
	}

	url := strings.TrimSpace(promptInput("Source URL (e.g. https://siem-a.example.com:9443): "))
	if url == "" {
		fatalf("source URL is required")
	}
	if perr := validateMasterServerURL(url); perr != nil {
		fatalf("invalid source URL: %v", perr)
	}
	psk := strings.TrimSpace(promptInput("PSK for " + url + ": "))
	if psk == "" {
		fatalf("PSK is required")
	}

	// Notify the previous role's coordinators BEFORE enrollment so the
	// upstream allowlist / realm.peers / master.servers gets the
	// departure signal while our local cfg fields are still
	// authoritative. agent -> collector tells the old server, server ->
	// collector tells realm peers, master -> collector tells enrolled
	// servers, etc.
	notifyConvertDeparture(cfg, from, "collector")

	// Run the same enrollment path as `simplesiem collector enroll`.
	// On failure the function calls fatalf — config is left untouched.
	enrollArgs := []string{url, "--key", psk, "--config", *cfgPath}
	if *colID != "" {
		enrollArgs = append(enrollArgs, "--id", *colID)
	}
	runCollectorEnroll(enrollArgs, false)

	// Stop the daemon (best-effort). If stop fails the operator can retry.
	if isRunning() {
		fmt.Println("stopping daemon...")
		stopCommand(nil)
	}

	// Reload — collector.* was mutated by runCollectorEnroll. Flip mode.
	cfg = loadConfig(*cfgPath)
	cfg.Mode = "collector"
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("write config: %v", err)
	}
	fmt.Println("config updated:", *cfgPath, "(mode=collector)")

	fmt.Println("starting daemon...")
	startCommand(nil)

	fmt.Println()
	fmt.Println("Conversion complete. Daemon is running in collector mode.")
	fmt.Println()
	fmt.Println("Verify:")
	fmt.Println("  simplesiem status                              # mode: collector + source URL")
	fmt.Println("  simplesiem collector status                    # source, watermark, failover list")
	fmt.Println("  simplesiem triage --since 1h                   # the local backup copy")
	fmt.Println()
	fmt.Println("To change the pull interval (default daily):")
	fmt.Println("  sudo simplesiem collector interval 1h          # or 6h, 30m, etc.")
}
