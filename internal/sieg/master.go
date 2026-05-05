package sieg

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Master mode is the optional aggregation tier above realms. It runs
// no listener — instead it maintains a per-server client cert and
// pulls events from each registered server via the same /v1/sync/events
// endpoint realm peers use. The server-side handler accepts master
// CNs (via server.master_cns) in addition to realm peer CNs.
//
// Storage layout on the master mirrors the per-origin convention used
// by realm replication:
//
//	<log_dir>/<host>/<type>/<date>.from-<server>.jsonl
//
// Each origin keeps its own hash chain so `simplesiem verify` validates
// each file independently. Triage / query commands work transparently
// because the recursive walker (added back in R1.7) already handles
// multiple files per (host, type).

// startMasterDaemon launches the master's collectors (so the master's
// own host activity is logged too), the per-server pull goroutines,
// and the standard storage / health / retention infrastructure.
//
// Failure modes: missing per-server cert means that server is skipped
// (the operator needs to run `simplesiem master enroll` first); a
// transient pull failure logs to errors and retries on next cycle.
func startMasterDaemon(ctx context.Context, wg *sync.WaitGroup, cfg Config) (*daemonState, error) {
	gid := resolveGroupGID(cfg.LogOwnerGroup)
	maxSz := int64(cfg.MaxLogFileMB) * 1024 * 1024
	initialLoc := pickInitialStorageLocation(cfg)
	group := newStorageGroup(initialLoc)
	masterStore, err := group.Open("_master", gid, maxSz, cfg.WriteQueueSize)
	if err != nil {
		return nil, err
	}
	localID := pickServerLocalID(cfg.Server.LocalID)
	localStore, err := group.Open(localID, gid, maxSz, cfg.WriteQueueSize)
	if err != nil {
		return nil, err
	}
	newStorageController(group, cfg).start(ctx, wg)
	// Local-collection rules: same as standalone — every locally-collected
	// event passes through these. cfg.RulesPath is the root config knob.
	if rules, err := loadRules(cfg.RulesPath); err == nil {
		localStore.SetRules(rules)
	}
	// Master-side rules: applied to every event PULLED from a registered
	// server (via masterStore.EvaluateRules in masterPullOnce). The path
	// can be set per-master under cfg.master.rules_path; falls back to
	// cfg.rules_path so an operator who wants the same rule set fleet-wide
	// just sets one. When empty, master-side correlation is off.
	masterRulesPath := cfg.Master.RulesPath
	if masterRulesPath == "" {
		masterRulesPath = cfg.RulesPath
	}
	if rules, err := loadRules(masterRulesPath); err == nil {
		masterStore.SetRules(rules)
	}

	// Master alert dispatchers — same shape as the server's, fed by
	// cfg.Server.AlertWebhooks + cfg.Server.AlertSyslog (master shares
	// the server-mode dispatcher config rather than introducing a
	// parallel master.alert_* tree). Wired to masterStore so any
	// rule fire on a pulled event reaches the same downstream sinks.
	masterMetrics := newMetricsCollector()
	masterWebhooks := newAlertWebhookDispatcher(cfg.Server, masterStore, masterMetrics)
	if masterWebhooks != nil {
		masterStore.AddAlertHook(masterWebhooks.dispatch)
		go func() {
			<-ctx.Done()
			masterWebhooks.Stop()
		}()
	}
	masterSyslog := newAlertSyslogDispatcher(cfg.Server, masterStore, masterMetrics)
	if masterSyslog != nil {
		masterStore.AddAlertHook(masterSyslog.dispatch)
		go func() {
			<-ctx.Done()
			masterSyslog.Stop()
		}()
	}
	masterStore.AddAlertHook(func(alert map[string]any) {
		masterMetrics.recordAlertFire(strField(alert, "rule"), strField(alert, "severity"))
	})
	// SIEM-enhancement pipeline + background workers (#1, #2, #6,
	// #8, #9 + threat-intel). Master is the canonical authority
	// when present, so its grouper IS authoritative by default.
	masterPipeline := newAlertPipeline(cfg, cfg.LogDir, masterStore)
	if masterPipeline != nil {
		masterStore.AddAlertHook(masterPipeline.hook)
	}
	startSiemEnhancements(ctx, wg, cfg, masterStore, masterPipeline)

	masterStore.Write("meta", map[string]any{
		"event":    "start",
		"mode":     "master",
		"pid":      os.Getpid(),
		"platform": runtime.GOOS,
		"arch":     runtime.GOARCH,
		"version":  version,
		"build":    buildNumber,
		"servers":  cfg.Master.Servers,
		"local_id": localID,
	})
	localStore.Write("meta", map[string]any{
		"event":    "start",
		"mode":     "master (local collection)",
		"local_id": localID,
		"pid":      os.Getpid(),
	})

	startRetention(ctx, wg, cfg.LogDir, cfg.RetentionDays)
	startLocalCollectors(ctx, wg, cfg, localStore, masterStore)

	// Optional health listener for k8s/load-balancer probes. Plain
	// HTTP — no inbound trust relationship to leak, just "alive".
	if cfg.Master.Listen != "" {
		startMasterHealthListener(ctx, wg, cfg.Master.Listen, masterStore)
	}
	// Optional TLS listener for the paired collector. Master is the
	// authority root in cross-realm deployments; the collector pulls
	// the master's aggregated corpus over mTLS. Single-slot rule:
	// only one collector may ever associate with this master.
	startMasterCollectorListener(ctx, wg, cfg, defaultConfigPath(), masterStore)

	// Network-device sticky-IP allowlist (master-tier). Owns the
	// canonical copy in master-managed realms; pushes to every
	// consenting server.
	initNetworkSyncImpls()
	masterNetStore := newNetworkAllowlist(networkAllowlistPath(), masterStore)
	if err := masterNetStore.Load(); err != nil {
		masterNetStore.EmitReloadRejected("startup", err.Error())
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		newNetworkAllowlistWatcher(masterNetStore).run(ctx)
	}()
	startMasterNetworkIngestListener(ctx, wg, cfg, masterStore, masterNetStore)
	if niSt, err := startNetworkIngest(ctx, wg, cfg, "master", masterNetStore, masterStore,
		func(host string) (*Storage, error) {
			return openHostStorage(cfg.LogDir, host, cfg.LogOwnerGroup)
		},
		func() []*alertRule { return loadMasterRules(cfg) },
		func(alert map[string]any) {
			for _, h := range masterStore.alertHooks {
				h(alert)
			}
		}); err != nil {
		masterStore.Write("errors", map[string]any{
			"collector": "network_ingest",
			"error":     err.Error(),
		})
	} else {
		_ = niSt
	}
	go func() {
		time.Sleep(1 * time.Second)
		autoDiscoverOwnGateways(masterNetStore, "master-self", masterStore)
	}()
	go func() {
		time.Sleep(2 * time.Second)
		_ = pullAllowlistFromServers(cfg, masterNetStore)
	}()

	// Cert expiry monitor — every per-server cert + CA the master holds.
	startCertExpiryMonitor(ctx, wg, masterStore, "master", collectMasterCertPaths(cfg))
	// Hourly signing of chain heads — same purpose as on standalone
	// and server. Master signs heads for its own local-collection
	// streams (NOT for replicated peer files; those belong to the
	// origin's signer).
	startChainHeadSigner(ctx, wg, cfg, masterStore)

	interval := cfg.Master.SyncIntervalSeconds
	if interval <= 0 {
		interval = 60
	}

	// covered tracks server URLs we've already spawned pull goroutines
	// for. The dynamic server-watcher (below) re-scans cfg.Master.Servers
	// every minute so `simplesiem master enroll <url>` adds the URL
	// AND the daemon picks up the new server without an operator
	// restart. Initial fan-out happens via the same code path so the
	// startup case shares the watcher's logic.
	covered := map[string]struct{}{}
	var coveredMu sync.Mutex
	spawn := func(server, masterID string) {
		coveredMu.Lock()
		if _, ok := covered[server]; ok {
			coveredMu.Unlock()
			return
		}
		covered[server] = struct{}{}
		coveredMu.Unlock()
		serverID := peerIDFromURL(server)
		if serverID == "" {
			masterStore.Write("errors", map[string]any{
				"collector": "master_sync",
				"error":     fmt.Sprintf("master.servers entry %q has no parseable hostname; skipping", server),
			})
			return
		}
		certDir := filepath.Join(masterCertsDir(cfg), serverID)
		tlsCfg, err := loadMasterClientTLS(certDir)
		if err != nil {
			masterStore.Write("errors", map[string]any{
				"collector": "master_sync",
				"error":     fmt.Sprintf("server %q: %v", server, err),
				"hint":      fmt.Sprintf("run: sudo simplesiem master enroll %s --key <PSK from server's `simplesiem certs psk show`>", server),
			})
			// Allow a future re-enroll to retry: forget this server so
			// the next watcher tick will re-attempt the cert load.
			coveredMu.Lock()
			delete(covered, server)
			coveredMu.Unlock()
			return
		}
		wg.Add(1)
		go func(serverURL, sid, mid, cdir string, tc *tls.Config) {
			defer wg.Done()
			masterPullLoop(ctx, serverURL, sid, mid, cdir, tc, interval, masterStore, cfg.LogDir)
		}(server, serverID, cfg.Master.MasterID, certDir, tlsCfg)
		masterStore.Write("meta", map[string]any{
			"event":  "master_pull_goroutine_spawned",
			"server": server,
		})
	}
	for _, server := range cfg.Master.Servers {
		spawn(server, cfg.Master.MasterID)
	}
	// Dynamic-watch goroutine: every minute re-read cfg.Master.Servers
	// from disk and spawn pull goroutines for any new entries. This is
	// what lets `master enroll <url>` take effect without a daemon
	// restart. The spawned goroutines themselves re-read cfg per cycle
	// already, so an interval edit propagates without restart too.
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			fresh := loadConfig(defaultConfigPath())
			for _, server := range fresh.Master.Servers {
				spawn(server, fresh.Master.MasterID)
			}
		}
	}()
	return &daemonState{storage: masterStore}, nil
}

// masterCertsDir returns the on-disk root for per-server master certs.
// Default <config_dir>/master/, override via cfg.Master.CertsDir.
func masterCertsDir(cfg Config) string {
	if cfg.Master.CertsDir != "" {
		return cfg.Master.CertsDir
	}
	return filepath.Join(defaultConfigDir(), "master")
}

// loadMasterClientTLS reads cert.pem + key.pem + ca.pem from a per-server
// directory (created by `simplesiem master enroll`) and produces a
// tls.Config the master can use as a CLIENT to that server.
//
// Uses GetClientCertificate so cert auto-rotation (which atomically
// replaces cert.pem/key.pem in this directory) takes effect on the
// next handshake without recreating the master's http.Transport.
func loadMasterClientTLS(certDir string) (*tls.Config, error) {
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")
	if _, err := loadKeyPair(certPath, keyPath); err != nil {
		return nil, fmt.Errorf("client keypair (%s): %w", certDir, err)
	}
	caPool, err := loadCAPool(filepath.Join(certDir, "ca.pem"))
	if err != nil {
		return nil, fmt.Errorf("CA bundle (%s): %w", certDir, err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs(),
		RootCAs:    caPool,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	}, nil
}

// masterPullLoop is the per-server goroutine that periodically calls
// /v1/sync/events on the configured server, writing replicated events
// under <log_dir>/<host>/<type>/<date>.from-<server>.jsonl. Watermark
// per server is persisted at <state>/master/<server>.watermark.
func masterPullLoop(ctx context.Context, server, serverID, masterID, certDir string, tlsCfg *tls.Config, intervalSec int, storage *Storage, base string) {
	tr := &http.Transport{
		TLSClientConfig:       tlsCfg.Clone(),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 60 * time.Second}

	stateDir := filepath.Join(defaultStateDir(), "master")
	// 0o700 — the master collector PSK lives under this dir on hosts
	// where the listener is enabled, and Go's MkdirAll is a no-op when
	// the dir already exists. Creating with the looser 0o750 here
	// would lock in group-readable mode before ensureMasterCollectorPSK
	// could tighten it.
	_ = os.MkdirAll(stateDir, 0o700)
	watermarkPath := filepath.Join(stateDir, serverID+".watermark")

	t := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer t.Stop()
	first := time.NewTimer(5 * time.Second)
	defer first.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-t.C:
		}
		// Rotate the per-server cert before the pull so a successful
		// rotation lets the same cycle benefit from the fresh cert.
		// Best-effort — pull continues either way.
		if masterID != "" && certDir != "" {
			rotateMasterCertIfNeeded(server, masterID, certDir, defaultRotateThresholdDays, client, storage)
		}
		masterPullOnce(ctx, client, server, serverID, watermarkPath, storage, base)
		// CA-rotation catchup: bring stragglers in line with the
		// master's rotation policy (master.rotation_realms /
		// master.finalize_realms). No-op when no policy is set.
		// Reload cfg each cycle so policy edits land without restart.
		fresh := loadConfig(defaultConfigPath())
		caCatchupCheck(server, masterID, certDir, fresh, client, storage)
	}
}

// masterPullOnce does one pull cycle. Best-effort: any failure (network,
// TLS, malformed JSON) leaves the watermark unchanged so the next cycle
// retries the same point.
func masterPullOnce(ctx context.Context, client *http.Client, server, serverID, watermarkPath string, storage *Storage, base string) {
	since := readWatermark(watermarkPath)
	q := url.Values{}
	if !since.IsZero() {
		q.Set("since", since.Format(time.RFC3339Nano))
	}
	reqURL := strings.TrimRight(server, "/") + "/v1/sync/events?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		storage.Write("errors", map[string]any{
			"collector": "master_sync",
			"error":     fmt.Sprintf("pull from %s: %v", server, err),
		})
		if tr, ok := client.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		storage.Write("errors", map[string]any{
			"collector": "master_sync",
			"error":     fmt.Sprintf("pull from %s: HTTP %d: %s", server, resp.StatusCode, strings.TrimSpace(string(buf))),
			"hint":      "if 403, the server may have removed this master from server.master_cns. Re-enroll with `simplesiem master enroll`.",
		})
		return
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	maxSeen := since
	count := 0
	for scanner.Scan() {
		var ev SyncEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if !writeMasterEvent(base, serverID, ev) {
			continue
		}
		// Master-side rule evaluation runs AFTER the on-disk replicated
		// write so a tamperer can't suppress the alert by killing the
		// daemon mid-evaluation — the original event is durable first.
		// Rules are loaded once at startup; if cfg.Master.RulesPath is
		// empty this is a no-op (the rule list is empty).
		if typ, ok := ev["type"].(string); ok {
			storage.EvaluateRules(typ, ev)
		}
		if rs, _ := ev["received_at"].(string); rs != "" {
			if t, err := time.Parse(time.RFC3339Nano, rs); err == nil && t.After(maxSeen) {
				maxSeen = t
			}
		}
		count++
	}
	if maxSeen.After(since) {
		_ = writeWatermark(watermarkPath, maxSeen)
	}
	if count > 0 {
		storage.Write("meta", map[string]any{
			"event":     "master_sync_pulled",
			"server":    server,
			"events":    count,
			"watermark": maxSeen.Format(time.RFC3339Nano),
		})
	}
}

// writeMasterEvent appends a replicated event under
// <log_dir>/<host>/<type>/<date>.from-<server>.jsonl. Each origin
// server gets its own file — the chain on each file is independent
// and stays valid through `simplesiem verify`.
func writeMasterEvent(base, serverID string, ev SyncEvent) bool {
	host, _ := ev["host"].(string)
	typ, _ := ev["type"].(string)
	if host == "" || typ == "" {
		return false
	}
	if !safeHostName(base, host) {
		return false
	}
	if !agentAllowedTypes[typ] && typ != "alerts" {
		return false
	}
	origin, _ := ev["origin_server"].(string)
	if origin == "" {
		return false
	}
	date := time.Now().UTC().Format("2006-01-02")
	if rs, _ := ev["received_at"].(string); rs != "" {
		if t, err := time.Parse(time.RFC3339Nano, rs); err == nil {
			date = t.UTC().Format("2006-01-02")
		}
	}
	dir := filepath.Join(base, host, typ)
	if err := os.MkdirAll(dir, logDirMode); err != nil {
		return false
	}
	path := filepath.Join(dir, date+".from-"+origin+".jsonl")
	line, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	line = append(line, '\n')
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, logFileMode)
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = f.Write(line)
	return err == nil
}

// runMasterCmd dispatches `simplesiem master <enroll|...>`.
func runMasterCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem master <subcommand> [args]

  enroll <server-url> --key <PSK>          Enroll this master with a server.
                                           Generates a keypair locally, sends a CSR,
                                           receives a signed cert, and adds the
                                           server to master.servers.

  rotate-ca-all [--years N]                Trigger CA rotation on every server in
                                           master.servers. Each server runs its
                                           own init-rotate; clients auto-rotate
                                           over time; service is uninterrupted.
                                           Records a per-realm catchup policy so
                                           servers that were down at trigger time
                                           get rotated automatically when they
                                           come back online (next pull cycle).

  rotate-ca-realm <realm-name>             Rotate only the servers in one realm.
       [--years N]

  finalize-rotate-all                      After all clients have rotated to the
                                           new CA, remove the legacy CA from every
                                           server in master.servers. Same catchup
                                           semantics — late-joining servers get
                                           finalized automatically.

  finalize-rotate-realm <realm-name>       Finalize within one realm only.

  rotate-ca-status                         Show every server's current CA timestamp,
                                           legacy-CA count, and whether it's behind
                                           the master's rotation/finalize policy.

  rotate-ca-policy clear-all               Clear the catchup policy across all
                                           realms (auto-catchup stops).
  rotate-ca-policy clear-realm <name>      Clear the catchup policy for one realm.

  collector enable --listen <addr>         Enable the master's collector-pull TLS
                                           listener (e.g. :9445). Auto-bootstraps
                                           the master's PKI + creates an isolated
                                           PSK for collector enrollment.
  collector disable                        Disable the listener (clears the slot).
  collector accept-next                    Open the single-collector slot for the
                                           next /v1/enroll-collector request.
  collector revoke                         Clear the currently-associated collector.
  collector status                         Show slot state + listen address.
  collector show-psk                       Print the master collector PSK (paste
                                           into `+"`simplesiem collector enroll <master-url> --key`"+`
                                           on the collector host).
  collector rotate-psk                     Generate a new master collector PSK.
  collector push-interval <duration>       Set the master's pushed pull interval.

CA rotation requires `+"`server.master_can_rotate_ca: true`"+` on each target
server (default false). The master uses its existing per-server client cert
to authenticate; no PSK needed.`)
		os.Exit(2)
	}
	switch args[0] {
	case "enroll":
		runMasterEnroll(args[1:])
	case "rotate-ca-all":
		runMasterRotateCAAll(args[1:])
	case "rotate-ca-realm":
		runMasterRotateCARealm(args[1:])
	case "finalize-rotate-all":
		runMasterFinalizeRotateAll(args[1:])
	case "finalize-rotate-realm":
		runMasterFinalizeRotateRealm(args[1:])
	case "rotate-ca-status":
		runMasterRotateCAStatus(args[1:])
	case "rotate-ca-policy":
		runMasterRotatePolicy(args[1:])
	case "push-rules":
		runMasterPushRules(args[1:])
	case "collector":
		runMasterCollectorCmd(args[1:])
	case "query-collector":
		runMasterQueryCollectorCmd(args[1:])
	case "migrate-server":
		runMasterMigrateServer(args[1:])
	case "realm":
		runMasterRealmCmd(args[1:])
	case "backup":
		runBackupRemoteMasterRealm(args[1:])
	case "uninstall-all":
		runMasterUninstallAll(args[1:])
	default:
		fatalf("unknown master subcommand: %s", args[0])
	}
}

// runMasterRealmCmd dispatches `simplesiem master realm <subcommand>`.
// Today the only operation is `rename` — kept under the master.realm
// namespace so future realm-scoped master operations can land here
// without polluting the top-level master command list.
func runMasterRealmCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem master realm <rename> [args]

  rename <realm-name> <new-name> [-y]
        Rename a realm across every server in master.servers that
        currently reports realm=<realm-name>. Each server applies via
        /v1/master/push/realm-rename and propagates to its peers via
        the existing realm-sync (last-write-wins on config_version).

        Requires server.master_can_rotate_ca: true on every target
        server (the same opt-in that gates push-rules and rotate-ca).`)
		os.Exit(2)
	}
	switch args[0] {
	case "rename":
		runMasterRealmRename(args[1:])
	default:
		fatalf("unknown master realm subcommand: %s", args[0])
	}
}

// runMasterEnroll is the CLI entry point for `simplesiem master enroll`.
// Thin wrapper around enrollMasterWithServer so the same logic powers
// `convert master`'s interactive loop.
func runMasterEnroll(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "key": true, "id": true})
	fs := flag.NewFlagSet("master enroll", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	psk := fs.String("key", "", "enrollment PSK from `simplesiem certs psk show` on the server")
	masterID := fs.String("id", "", "master ID (CN) to use; defaults to master-<hostname>")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: simplesiem master enroll <server-url> --key <PSK>")
	}
	if *psk == "" {
		fatalf("--key is required (get the PSK with `simplesiem certs psk show` on the server)")
	}
	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}
	res, err := enrollMasterWithServer(*cfgPath, fs.Arg(0), *psk, *masterID)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Println("Master enrolled with", res.ServerURL)
	fmt.Println("  master_id:    ", res.MasterID)
	fmt.Println("  realm:        ", res.RealmName)
	fmt.Println("  cert dir:     ", res.CertDir)
	if res.NewlyAdded {
		fmt.Println("  config:       ", *cfgPath, "(server added to master.servers)")
	} else {
		fmt.Println("  config:       ", *cfgPath, "(server already in master.servers)")
	}

	// Auto-discover the rest of the realm. This is what saves the
	// operator from running `master enroll` once per peer in a 2-or-
	// more-server realm: query the just-enrolled server's
	// /v1/sync/config, learn its peers + their CAs, and stage cert
	// dirs for each peer using the same client cert (signed by the
	// just-enrolled CA, trusted by every realm peer because that CA
	// is in their realm peer_cas trust bundle).
	added, skipped, err := discoverAndAddRealmPeers(*cfgPath, res)
	if err != nil {
		fmt.Println()
		fmt.Println("note: realm peer auto-discovery failed:", err)
		fmt.Println("you can enroll with each peer manually via `simplesiem master enroll`.")
	} else if len(added) > 0 || len(skipped) > 0 {
		fmt.Println()
		fmt.Println("Realm peer auto-discovery:")
		for _, p := range added {
			fmt.Printf("  + %s  (added; cert dir set up using same client cert)\n", p)
		}
		for _, p := range skipped {
			fmt.Printf("  · %s  (skipped — already enrolled or peer CA not yet propagated)\n", p)
		}
		if len(added) > 0 {
			fmt.Println()
			fmt.Println("Note: master_cns propagation across realm peers happens via the")
			fmt.Println("next /v1/sync/config cycle (≤ realm.sync_interval_seconds).")
			fmt.Println("Until that completes, pulls from newly-discovered peers will fail")
			fmt.Println("with HTTP 403; the master pull loop retries each cycle and starts")
			fmt.Println("succeeding once propagation is done.")
		}
	}

	fmt.Println()
	fmt.Println("Next: sudo simplesiem start  (or restart the master daemon)")
}

// discoverAndAddRealmPeers queries the just-enrolled server's
// /v1/sync/config endpoint, walks the peer list, and stages a cert
// dir + CA for each peer the master doesn't yet know about. Returns
// (newly-added URLs, skipped URLs, error). A skipped URL means the
// master was already enrolled with that peer OR the peer's CA isn't
// yet in the responding peer's realm trust bundle (fresh realm —
// the operator can re-run later).
func discoverAndAddRealmPeers(cfgPath string, primary MasterEnrollResult) (added, skipped []string, err error) {
	// Use the just-written per-server cert to talk to the primary
	// — same TLS config the master daemon's pull loop builds.
	tlsCfg, err := loadMasterClientTLS(primary.CertDir)
	if err != nil {
		return nil, nil, fmt.Errorf("load primary cert: %w", err)
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 10 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(primary.ServerURL, "/")+"/v1/sync/config", nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("query primary's /v1/sync/config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, nil, fmt.Errorf("primary returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	var pc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&pc); err != nil {
		return nil, nil, fmt.Errorf("decode primary's config: %w", err)
	}
	peerURLs, _ := pc["peers"].([]any)
	if len(peerURLs) == 0 {
		return nil, nil, nil // single-server realm; nothing to discover
	}
	peerCAs, _ := pc["peer_cas"].([]any)
	caByID := map[string]string{}
	for _, item := range peerCAs {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		ca, _ := m["ca_pem"].(string)
		if id != "" && ca != "" {
			caByID[id] = ca
		}
	}

	cfg := loadConfig(cfgPath)
	dirRoot := masterCertsDir(cfg)
	primaryCert, perr := os.ReadFile(filepath.Join(primary.CertDir, "cert.pem"))
	if perr != nil {
		return nil, nil, fmt.Errorf("read primary cert: %w", perr)
	}
	primaryKey, perr := os.ReadFile(filepath.Join(primary.CertDir, "key.pem"))
	if perr != nil {
		return nil, nil, fmt.Errorf("read primary key: %w", perr)
	}

	for _, item := range peerURLs {
		peerURL, _ := item.(string)
		peerURL = strings.TrimRight(peerURL, "/")
		if peerURL == "" || peerURL == strings.TrimRight(primary.ServerURL, "/") {
			continue
		}
		peerID := peerIDFromURL(peerURL)
		if peerID == "" || !validHostName.MatchString(peerID) {
			skipped = append(skipped, peerURL)
			continue
		}
		// If we already have a cert dir for this peer, treat as a
		// no-op. Don't overwrite — operator may have enrolled with
		// it directly and we don't want to clobber their CA file.
		peerDir := filepath.Join(dirRoot, peerID)
		if _, err := os.Stat(peerDir); err == nil {
			skipped = append(skipped, peerURL)
			continue
		}
		caPem, ok := caByID[peerID]
		if !ok || caPem == "" {
			// Peer's CA not in primary's trust bundle yet (realm
			// sync hasn't propagated). Skip — operator can re-run
			// after the next sync cycle, or enroll directly.
			skipped = append(skipped, peerURL)
			continue
		}
		// Validate the CA before committing.
		blk, _ := pem.Decode([]byte(caPem))
		if blk == nil || blk.Type != "CERTIFICATE" {
			skipped = append(skipped, peerURL)
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil || !cert.IsCA {
			skipped = append(skipped, peerURL)
			continue
		}
		// Commit: cert dir + cert/key/ca files.
		if err := os.MkdirAll(peerDir, 0o750); err != nil {
			skipped = append(skipped, peerURL)
			continue
		}
		if err := os.WriteFile(filepath.Join(peerDir, "cert.pem"), primaryCert, 0o644); err != nil {
			skipped = append(skipped, peerURL)
			continue
		}
		if err := os.WriteFile(filepath.Join(peerDir, "key.pem"), primaryKey, 0o600); err != nil {
			skipped = append(skipped, peerURL)
			continue
		}
		if err := os.WriteFile(filepath.Join(peerDir, "ca.pem"), []byte(caPem), 0o644); err != nil {
			skipped = append(skipped, peerURL)
			continue
		}
		if err := appendMasterServer(cfgPath, peerURL); err == nil {
			added = append(added, peerURL)
		} else {
			skipped = append(skipped, peerURL)
		}
	}
	return added, skipped, nil
}

// appendMasterServer adds peerURL to master.servers if not already
// present. Serialised through allowlistEditMu (the shared config
// edit mutex) so concurrent edits don't race.
func appendMasterServer(cfgPath, peerURL string) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	for _, s := range cfg.Master.Servers {
		if s == peerURL {
			return nil
		}
	}
	cfg.Master.Servers = append(cfg.Master.Servers, peerURL)
	return saveConfig(cfgPath, cfg)
}

// MasterEnrollResult is the return value of enrollMasterWithServer,
// surfacing what the CLI / convert flow needs to print on success.
type MasterEnrollResult struct {
	ServerURL  string
	MasterID   string
	RealmName  string
	CertDir    string
	NewlyAdded bool
}

// enrollMasterWithServer is the reusable core of master enrollment.
// Generates a keypair, sends a CSR, validates the HMAC, writes
// cert+key+CA per server, and appends the server URL to
// master.servers. Returns enough metadata for callers to print a
// useful confirmation. Any failure leaves on-disk state untouched.
func enrollMasterWithServer(cfgPath, serverURL, psk, masterID string) (MasterEnrollResult, error) {
	var zero MasterEnrollResult
	serverURL = strings.TrimRight(serverURL, "/")
	if serverURL == "" {
		return zero, fmt.Errorf("server URL is required")
	}
	parsed, perr := url.Parse(serverURL)
	if perr != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return zero, fmt.Errorf("server URL must be an https URL with a host (got %q)", serverURL)
	}
	if psk == "" {
		return zero, fmt.Errorf("PSK is required")
	}
	hostname, _ := os.Hostname()
	id := masterID
	if id == "" {
		id = "master-" + hostname
	}
	if !validMasterID(id) {
		return zero, fmt.Errorf("master ID %q is invalid (must be `master-` followed by alphanumeric/.-_; no '..'; not a reserved name)", id)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return zero, fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: id, Organization: []string{"SimpleSIEM"}}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		return zero, fmt.Errorf("build CSR: %w", err)
	}
	csrPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	body, _ := json.Marshal(MasterEnrollRequest{PSK: psk, MasterID: id, CSRPem: csrPem})
	// #nosec G402 -- bootstrap-only: master has no CA for this server yet.
	// The response HMAC keyed by the PSK provides authenticity; future
	// pulls use the per-server CA at <config>/master/<server>/ca.pem.
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs()}, TLSHandshakeTimeout: 10 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodPost, serverURL+"/v1/enroll-master", bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return zero, fmt.Errorf("contact server: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("server rejected enrollment (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var er MasterEnrollResponse
	if err := json.Unmarshal(rb, &er); err != nil {
		return zero, fmt.Errorf("parse server response: %w", err)
	}
	if er.CertPem == "" || er.CAPem == "" || er.Hmac == "" {
		return zero, fmt.Errorf("server response missing required fields")
	}
	pskRaw, perr := pskRawBytes(psk)
	if perr != nil {
		return zero, fmt.Errorf("--key: %w", perr)
	}
	expected := computeEnrollHMAC(pskRaw, er.CertPem, er.CAPem, er.ReauthSeconds, er.RealmName, []string{er.ServerHost})
	if subtle.ConstantTimeCompare([]byte(er.Hmac), []byte(expected)) != 1 {
		return zero, fmt.Errorf("response HMAC mismatch — possible MITM, or PSK on server differs from supplied PSK")
	}
	cfg := loadConfig(cfgPath)
	// Cert dir name MUST match peerIDFromURL(serverURL) — that's what
	// startMasterDaemon's pull-spawn loop uses to look up the per-server
	// cert. Using er.ServerHost (the server's selfPeerID, derived from
	// its hostname) breaks for any operator who enrolled the master by
	// IP (URL host="172.30.0.7", server reports hostname="r1-server-a"
	// → cert at <root>/r1-server-a but lookup at <root>/172.30.0.7 →
	// "no such file or directory").
	urlID := peerIDFromURL(serverURL)
	if urlID == "" {
		return zero, fmt.Errorf("could not parse hostname from server URL %q", serverURL)
	}
	dir := filepath.Join(masterCertsDir(cfg), urlID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return zero, fmt.Errorf("create cert dir: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return zero, fmt.Errorf("marshal key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return zero, fmt.Errorf("write key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte(er.CertPem), 0o644); err != nil {
		return zero, fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte(er.CAPem), 0o644); err != nil {
		return zero, fmt.Errorf("write CA: %w", err)
	}
	added := false
	already := false
	for _, s := range cfg.Master.Servers {
		if s == serverURL {
			already = true
			break
		}
	}
	if !already {
		cfg.Master.Servers = append(cfg.Master.Servers, serverURL)
		if cfg.Master.MasterID == "" {
			cfg.Master.MasterID = id
		}
		added = true
	}
	if added {
		if err := saveConfig(cfgPath, cfg); err != nil {
			return zero, fmt.Errorf("save config: %w", err)
		}
	}
	return MasterEnrollResult{
		ServerURL:  serverURL,
		MasterID:   id,
		RealmName:  er.RealmName,
		CertDir:    dir,
		NewlyAdded: added,
	}, nil
}

// We import "flag" only when this file is built; keep the alias here
// so go-import re-ordering doesn't trip on it.
var _ = flag.NewFlagSet

// startMasterHealthListener exposes a tiny GET /health endpoint
// for liveness probes. Plain HTTP — see MasterConfig.Listen for the
// rationale. Best-effort: bind failure is logged and the daemon
// continues without the listener.
func startMasterHealthListener(ctx context.Context, wg *sync.WaitGroup, addr string, storage *Storage) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if storage != nil {
			storage.Write("meta", map[string]any{
				"event":  "master_health_listener_start",
				"listen": addr,
			})
		}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			if storage != nil {
				storage.Write("errors", map[string]any{
					"collector": "master_health",
					"error":     err.Error(),
				})
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
}
