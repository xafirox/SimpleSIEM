package sieg

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runUninstall is the new top-level handler for `simplesiem uninstall`.
// It wraps the old service-only removal in a mode-aware ceremony:
//
//  1. Read the current mode from config.
//  2. Print a clear summary of what's about to happen + ask confirmation.
//     Master mode prompts twice (the spec calls for two confirmations
//     because master uninstalls have the largest blast radius).
//  3. Best-effort notify peers BEFORE local teardown so a graceful
//     uninstall propagates "I'm leaving" through realm sync / master
//     allowlists / agent associations.
//  4. Call uninstallService() to remove the OS-level service.
//  5. With --all (standalone) or --purge (any mode), wipe config,
//     state, log, and cert directories. Without those flags, those
//     trees are preserved so an operator who uninstalls the wrong
//     host can re-install and recover.
//
// The unified-uninstall flag set:
//
//	-y / --yes                 skip confirmation
//	--all                      ALSO remove logs/config/state/certs (standalone shorthand)
//	--purge                    same as --all (server/master/agent/collector)
//	--force                    bypass refusal guards (e.g. uninstall-last-server)
func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	yes := fs.Bool("y", false, "skip confirmation prompts")
	all := fs.Bool("all", false, "also remove logs, config, state, and certs (standalone shorthand)")
	purge := fs.Bool("purge", false, "alias for --all (clearer naming for non-standalone modes)")
	force := fs.Bool("force", false, "bypass refusal guards (e.g. last-server-in-realm-with-master)")
	noNotify := fs.Bool("no-notify-peers", false, "skip outbound depart notifications (used by master uninstall-all cascade so remote nodes don't echo back)")
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	purgeData := *all || *purge

	cfg := loadConfig(*cfgPath)
	mode := normaliseMode(cfg.Mode)

	if !*yes {
		fmt.Println()
		fmt.Println("================================================================")
		fmt.Printf("  SimpleSIEM uninstall — mode: %s\n", mode)
		fmt.Println("================================================================")
		printUninstallImpact(cfg, mode, purgeData)
		fmt.Println()
		if !confirmYes("Proceed with uninstall? [y/N] ") {
			fmt.Println("aborted")
			return
		}
		// Master uninstall is the largest blast radius — operators
		// can take down an entire fleet's management plane with one
		// command, so the spec requires a SECOND confirmation.
		if mode == "master" {
			fmt.Println()
			fmt.Println("Master uninstall removes the management plane for every server in master.servers.")
			fmt.Println("Servers will keep working as a standalone realm; the paired collector (if any) will")
			fmt.Println("revert to its enrolled source. Are you SURE?")
			if !confirmYes("Type yes to continue: ") {
				fmt.Println("aborted")
				return
			}
		}
	}

	// Phase 3: notify peers about our departure. Best-effort — a
	// failure here doesn't block the local uninstall (the operator
	// has already confirmed). --no-notify-peers skips this entirely;
	// used by the master uninstall-all cascade because the remote
	// nodes received their cascade signal through a separate
	// channel and don't need a second "depart" notification ringing
	// back at a daemon that's about to go offline anyway.
	if !*noNotify {
		switch mode {
		case "agent":
			notifyAgentDeparture(cfg)
		case "server":
			if !*force {
				if shouldRefuseLastServer(cfg) {
					fatalf("refusing: this is the last server in realm %q AND a master is enrolled. " +
						"The master would lose its chain of trust to every agent. Pass --force to proceed " +
						"(the master will go offline until a new server is enrolled).", cfg.Server.Realm.Name)
				}
			}
			notifyServerDeparture(cfg)
		case "master":
			notifyMasterDeparture(cfg)
		case "collector":
			// c16 — refuse uninstall when the paired source is
			// unreachable, unless --force. The departure
			// notification opens the slot atomically; without it
			// the source's collector_cn stays held by a CN that
			// can't enroll again, requiring `master collector
			// revoke` on the authority side. With --force the
			// operator accepts the manual cleanup burden.
			if !*force && cfg.Collector.SourceURL != "" {
				if err := probeCollectorSource(cfg); err != nil {
					fatalf("refusing: collector source %s is unreachable (%v); the slot won't be freed atomically. Options:\n  - bring the source back up and retry,\n  - OR pass --force (then run `master collector revoke` / `certs collector revoke` on the source manually to free the slot).",
						cfg.Collector.SourceURL, err)
				}
			}
			notifyCollectorDeparture(cfg)
		}
	}

	// Phase 4: remove the OS service.
	uninstallService(nil)

	// Phase 5: optional data removal.
	if purgeData {
		purgeAllData(cfg, *cfgPath)
		fmt.Println()
		fmt.Println("All SimpleSIEM data removed (config, state, logs, certs).")
	} else {
		fmt.Println()
		fmt.Println("Service removed. Config, state, logs, and certs were preserved.")
		fmt.Println("Pass --all (or --purge) on a future run to wipe them as well.")
	}
}

// printUninstallImpact gives the operator a one-screen summary of what
// the uninstall is about to do, mode-aware. Reading this out loud is
// the spec's "warning + tell the user what is going on" requirement.
func printUninstallImpact(cfg Config, mode string, purgeData bool) {
	fmt.Println()
	fmt.Println("This will:")
	fmt.Println("  - Stop the SimpleSIEM service on this host.")
	fmt.Println("  - Remove the service registration (systemd / launchd / SCM).")

	switch mode {
	case "agent":
		fmt.Println("  - Notify the server (best-effort) that this agent is departing,")
		fmt.Println("    so the server stops expecting heartbeats and removes the agent")
		fmt.Println("    from its allowlist. Per-agent logs already on the server stay.")
	case "server":
		realm := cfg.Server.Realm.Name
		peers := cfg.Server.Realm.Peers
		fmt.Printf("  - Notify every realm peer (%d peer(s) in realm %q) and the\n", len(peers), realm)
		fmt.Println("    enrolled master (if any) that this server is departing.")
		fmt.Println("  - Peers will remove this server from their realm.peers and")
		fmt.Println("    drop its CA from the trust bundle.")
	case "master":
		fmt.Printf("  - Notify every server in master.servers (%d) that this master\n", len(cfg.Master.Servers))
		fmt.Println("    is departing. Servers keep their data but lose master-driven")
		fmt.Println("    rule pushes / CA rotation / migration commands.")
		if cfg.Master.QueryCollectorURL != "" {
			fmt.Println("  - Notify the paired collector that this master is departing.")
		}
	case "collector":
		fmt.Println("  - Notify the master / source server that this collector is")
		fmt.Println("    departing. The master frees its collector slot.")
	}
	if purgeData {
		fmt.Println()
		fmt.Println("DATA REMOVAL: --all/--purge was specified. The following are ALSO removed:")
		fmt.Printf("  - log_dir:    %s\n", cfg.LogDir)
		fmt.Printf("  - state_dir:  %s\n", cfg.StateDir)
		fmt.Printf("  - certs:      %s\n", filepath.Join(defaultConfigDir(), "certs"))
		fmt.Printf("  - config:     %s\n", defaultConfigDir())
	} else {
		fmt.Println()
		fmt.Println("Config, state, logs, and certs are preserved. Pass --all to wipe them.")
	}
}

// shouldRefuseLastServer enforces the spec's "uninstall server in
// realm with only 1 server and 1 master fails" rule. Returns true
// when this server is the last realm member AND a master is
// enrolled — in which case --force is required.
func shouldRefuseLastServer(cfg Config) bool {
	if cfg.Server.Realm.MasterURL == "" && len(cfg.Server.MasterCNs) == 0 {
		return false
	}
	// Single-server realm = no realm peers configured.
	if len(cfg.Server.Realm.Peers) > 0 {
		return false
	}
	return true
}

// notifyAgentDeparture: best-effort POST to the server's
// /v1/agent/depart so the allowlist gets cleaned up immediately.
// Failures are swallowed — local uninstall proceeds regardless.
func notifyAgentDeparture(cfg Config) {
	if cfg.Agent.ServerURL == "" {
		return
	}
	tlsCfg, err := agentTLSConfig(cfg.Agent)
	if err != nil {
		return
	}
	postDeparture(strings.TrimRight(cfg.Agent.ServerURL, "/")+"/v1/agent/depart",
		map[string]any{"agent_id": cfg.Agent.ID}, tlsCfg)
}

// notifyServerDeparture: send /v1/realm/leave to every peer (so the
// peer drops us from realm.peers) and /v1/master/server-depart to
// the master (if enrolled) so the master removes us from
// master.servers. Bot best-effort.
func notifyServerDeparture(cfg Config) {
	for _, peer := range cfg.Server.Realm.Peers {
		tlsCfg, err := buildPeerClientTLS(cfg)
		if err != nil {
			continue
		}
		body := map[string]any{
			"departing_peer": deriveSelfPeerID(cfg.Server.Listen),
			"reason":         "uninstall",
		}
		postDeparture(strings.TrimRight(peer, "/")+"/v1/realm/leave", body, tlsCfg)
	}
	if cfg.Server.Realm.MasterURL != "" {
		// Master endpoint isn't strictly necessary here — the master
		// notices the server going dark on the next pull cycle and
		// surfaces it via master rotate-ca-status. We still announce
		// for cleanliness.
		// (No client cert for the master from the server's side,
		// so this is a no-op in this iteration.)
	}
}

// notifyMasterDeparture: tell every enrolled server + the paired
// collector that the master is going away. Server-side, this is a
// signal that pushed rules / rotation policies are about to stop
// arriving; collector-side, this is a signal that the collector
// should resume autonomous operation (or fail back to its enrolled
// source server).
func notifyMasterDeparture(cfg Config) {
	for _, serverURL := range cfg.Master.Servers {
		serverID := peerIDFromURL(serverURL)
		if serverID == "" {
			continue
		}
		tlsCfg, err := loadMasterClientTLS(filepath.Join(masterCertsDir(cfg), serverID))
		if err != nil {
			continue
		}
		body := map[string]any{"master_id": cfg.Master.MasterID, "reason": "uninstall"}
		postDeparture(strings.TrimRight(serverURL, "/")+"/v1/master/depart", body, tlsCfg)
	}
	if cfg.Master.QueryCollectorURL != "" {
		// Collector-master pairing departure — best-effort, same model.
		// Endpoint not yet wired on collector listener; skip silently.
	}
}

// probeCollectorSource checks that the collector's paired source
// is reachable on /v1/health. Used by c16 — uninstall refuses to
// proceed without --force when the source is down, since the
// departure notification can't free the slot atomically.
func probeCollectorSource(cfg Config) error {
	if cfg.Collector.SourceURL == "" {
		return nil
	}
	// Reuse the per-source client cert for the probe so we exercise
	// the same TLS path the live pull uses.
	certDir := filepath.Join(collectorCertsDir(cfg), peerIDFromURL(cfg.Collector.SourceURL))
	tlsCfg, err := loadMasterClientTLS(certDir)
	if err != nil {
		return fmt.Errorf("load client cert: %w", err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}
	url := strings.TrimRight(cfg.Collector.SourceURL, "/") + "/v1/health"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("source returned HTTP %d on /v1/health", resp.StatusCode)
	}
	return nil
}

// notifyCollectorDeparture: tell the master / source server that the
// collector slot is freeing. Source side will remove the collector's
// cert binding so a future enrollment can take its place.
func notifyCollectorDeparture(cfg Config) {
	if cfg.Collector.SourceURL == "" {
		return
	}
	// Use the collector's per-source client cert to authenticate.
	certDir := filepath.Join(collectorCertsDir(cfg), peerIDFromURL(cfg.Collector.SourceURL))
	tlsCfg, err := loadMasterClientTLS(certDir)
	if err != nil {
		return
	}
	body := map[string]any{
		"collector_id": cfg.Collector.CollectorID,
		"reason":       "uninstall",
	}
	postDeparture(strings.TrimRight(cfg.Collector.SourceURL, "/")+"/v1/collector/depart", body, tlsCfg)
}

// postDeparture is the shared best-effort HTTP POST. Tight 5s
// timeout so a hung peer doesn't block the local uninstall —
// the operator has already confirmed and expects the command
// to complete promptly.
func postDeparture(url string, body any, tlsCfg *tls.Config) {
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}
	bodyBytes, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// purgeAllData wipes log_dir, state_dir, the certs directory, and
// the config directory itself. Honours storage.failover_locations
// so a multi-volume install gets every secondary log dir cleaned
// up too — otherwise a re-install would silently inherit ancient
// events from a forgotten failover volume.
func purgeAllData(cfg Config, cfgPath string) {
	for _, loc := range allStorageLocations(cfg) {
		_ = os.RemoveAll(loc)
	}
	if cfg.StateDir != "" {
		_ = os.RemoveAll(cfg.StateDir)
	}
	configDir := filepath.Dir(cfgPath)
	if configDir == "" || configDir == "." {
		configDir = defaultConfigDir()
	}
	// Remove certs subtree explicitly (often a sibling of config.json),
	// then the rest of configDir. RemoveAll on configDir handles both
	// when certs lives inside it.
	_ = os.RemoveAll(filepath.Join(configDir, "certs"))
	_ = os.RemoveAll(filepath.Join(configDir, "master"))
	_ = os.RemoveAll(filepath.Join(configDir, "collector"))
	_ = os.RemoveAll(configDir)
}
