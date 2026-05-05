package sieg

import (
	"compress/gzip"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// runServer launches the HTTPS receiver that accepts batched events from
// agents and writes them to per-host directories under <log_dir>/<host>/.
// Each host gets its own Storage instance with its own hash chain — chain
// breaks across hosts are expected and don't represent tampering.
func runServer(ctx context.Context, wg *sync.WaitGroup, cfg Config, cfgPath string) (*serverState, error) {
	bundle, err := newTrustBundle(cfg.Server.CACert, realmPeerCAsDir())
	if err != nil {
		return nil, fmt.Errorf("trust bundle: %w", err)
	}
	tlsCfg, reloader, err := serverTLSConfig(cfg.Server, bundle)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	skew := time.Duration(cfg.Server.MaxClockSkew) * time.Second
	if skew <= 0 {
		skew = 5 * time.Minute
	}
	maxConcurrent := cfg.Server.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 256
	}
	maxDecomp := int64(cfg.Server.MaxDecompressedBytes)
	if maxDecomp <= 0 {
		// Default to 8× the compressed cap, with a hard ceiling of 1 GiB
		// so an enormous MaxBatchBytes can't open a back door.
		maxDecomp = int64(cfg.Server.MaxBatchBytes) * 8
		if maxDecomp <= 0 || maxDecomp > 1024*1024*1024 {
			maxDecomp = 256 * 1024 * 1024
		}
	}
	allow := map[string]struct{}{}
	for _, id := range cfg.Server.AgentAllowlist {
		if id == "" {
			continue
		}
		allow[id] = struct{}{}
	}
	reauth := cfg.Server.AgentReauthSeconds
	if reauth <= 0 {
		reauth = 60
	}
	// Best-effort PSK load. Failure here doesn't break the server (the
	// PSK only matters when /v1/enroll is hit); but log it so the
	// operator sees the misconfig in status.
	psk, _ := readEnrollPSK()
	// certs dir is wherever ca.pem lives. Falls back to <config_dir>/certs.
	cdir := filepath.Dir(cfg.Server.CACert)
	if cdir == "" || cdir == "." {
		cdir = filepath.Join(filepath.Dir(cfgPath), "certs")
	}
	initialLoc := pickInitialStorageLocation(cfg)
	storeGroup := newStorageGroup(initialLoc)
	st := &serverState{
		base:              cfg.LogDir,
		group:             storeGroup,
		groupGID:          resolveGroupGID(cfg.LogOwnerGroup),
		maxBytes:          int64(cfg.Server.MaxBatchBytes),
		maxDecompBytes:    maxDecomp,
		queueSize:         cfg.WriteQueueSize,
		maxFileSz:         int64(cfg.MaxLogFileMB) * 1024 * 1024,
		tokens:            cfg.Server.BearerTokens,
		allowBearerOnly:   !cfg.Server.RequireClientCert && len(cfg.Server.BearerTokens) > 0,
		allowlist:         allow,
		maxClockSkew:      skew,
		limiter:           newRateLimiter(cfg.Server.RatePerSecond, cfg.Server.RateBurst),
		semaphore:         make(chan struct{}, maxConcurrent),
		storages:          map[string]*Storage{},
		fails:             map[string]*authFailRate{},
		enrollPSK:         psk,
		certsDir:          cdir,
		configPath:        cfgPath,
		enrollClientYears: 5,
		// Tight per-IP bucket for /v1/enroll: one token/sec, burst 3.
		// Real enrollment is a human action; this still allows three
		// fast retries in a row but throttles a brute-force flood.
		enrollLimiter:     newRateLimiter(1, 3),
		reauthSeconds:     reauth,
		realmName:         realmName(cfg.Server.Realm.Name),
		realmPeers:        append([]string{}, cfg.Server.Realm.Peers...),
		realmConfigVer:    cfg.Server.Realm.ConfigVersion,
		selfPeerID:        deriveSelfPeerID(cfg.Server.Listen),
		masterCNs:         append([]string{}, cfg.Server.MasterCNs...),
		trust:             bundle,
		agentRevoked:      copyStringMap(cfg.Server.AgentRevoked),
		masterRevoked:     copyStringMap(cfg.Server.MasterRevoked),
		masterCanRotate:   cfg.Server.MasterCanRotateCA,
		masterCanUninstall: cfg.Server.MasterCanUninstall,
	}
	if rules, err := loadRules(cfg.RulesPath); err == nil {
		st.rules = rules
	}
	st.metrics = newMetricsCollector()
	// First-seen entity detector — default-on, persistent. Logger is
	// set after _server storage opens (below).
	st.firstSeen = newFirstSeenDetector(cfg.StateDir, 30, nil)
	st.todBaseline = newTodBaselineDetector(cfg.StateDir, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events", st.handleEvents)
	mux.HandleFunc("/v1/health", st.handleHealth)
	mux.HandleFunc("/metrics", st.handleMetrics)
	mux.HandleFunc("/v1/enroll", st.handleEnroll)
	mux.HandleFunc("/v1/heartbeat", st.handleHeartbeat)
	// Realm sync endpoints — peers in the same realm pull events from
	// each other to maintain a consistent view. Authentication is mTLS
	// with the same CA the agents use; the handler additionally checks
	// that the caller's CN matches a peer in our realm.peers list.
	mux.HandleFunc("/v1/sync/events", st.handleSyncEvents)
	mux.HandleFunc("/v1/sync/config", st.handleSyncConfig)
	// Master enrollment: same PSK as agent enrollment, but the
	// returned cert is recorded in master_cns so the master can
	// pull /v1/sync/events as a privileged peer.
	mux.HandleFunc("/v1/enroll-master", st.handleEnrollMaster)
	// Collector enrollment: same PSK as agent/master enrollment, with a
	// strict single-slot rule — only one collector per server, gated on
	// `simplesiem certs collector accept-next` to free the slot.
	mux.HandleFunc("/v1/enroll-collector", st.handleEnrollCollector)
	// c15 — Non-mutating collector preflight. Mirrors the master-side
	// endpoint so a server-paired collector install can do the same
	// "gather all info up front" check.
	mux.HandleFunc("/v1/collector-preflight", st.handleCollectorPreflightOnServer)
	// Realm join: PSK-authenticated handshake that exchanges CAs
	// between two servers without copying CA private keys. Establishes
	// a trust relationship so agents enrolled with one peer are
	// accepted by every peer on failover.
	mux.HandleFunc("/v1/realm/join", st.handleRealmJoin)
	// Cert auto-rotation: mTLS-authenticated, no PSK. Lets agents
	// and masters renew their client cert before expiry without
	// operator intervention. Existing cert is the proof of identity.
	mux.HandleFunc("/v1/rotate", st.handleRotate)
	// Master-driven CA rotation: only honoured when
	// server.master_can_rotate_ca is explicitly true. Lets a master
	// trigger this server's `init-rotate` / `finalize-rotate` flow
	// remotely so a single command rotates an entire fleet.
	mux.HandleFunc("/v1/master/rotate-ca", st.handleMasterRotateCA)
	mux.HandleFunc("/v1/master/finalize-rotate", st.handleMasterFinalizeCA)
	mux.HandleFunc("/v1/master/ca-status", st.handleMasterCAStatus)
	mux.HandleFunc("/v1/master/push/rules", st.handleMasterPushRules)
	mux.HandleFunc("/v1/master/push/realm-rename", st.handleMasterPushRealmRename)
	mux.HandleFunc("/v1/master/migrate-server", st.handleMasterMigrateServer)
	mux.HandleFunc("/v1/realm/leave", st.handleRealmLeave)
	// Remote backup endpoint: invoked by a higher authority (master or
	// peer server) over mTLS to produce a backup of this server (and
	// optionally every agent it has events for) and stream the bytes
	// straight back into the response body. See backup_remote_pull.go.
	mux.HandleFunc("/v1/backup/create", st.handleBackupCreate)
	// Graceful-departure endpoints invoked by `simplesiem uninstall`
	// on a peer host. Each handler authenticates via mTLS (CN must
	// match a recognised peer of the appropriate kind) and updates
	// the server's allowlist / master_cns / collector_cn so a future
	// re-enrollment goes through the standard PSK handshake instead
	// of inheriting the prior identity.
	mux.HandleFunc("/v1/agent/depart", st.handleAgentDepart)
	mux.HandleFunc("/v1/agent/gateway", st.handleAgentGatewayReport)
	mux.HandleFunc("/v1/collector/gateway", st.handleCollectorGatewayReport)
	mux.HandleFunc("/v1/master/depart", st.handleMasterDepart)
	mux.HandleFunc("/v1/collector/depart", st.handleCollectorDepart)
	// Master cascade uninstall — gated by server.master_can_uninstall.
	// The master invokes this to trigger this server's full local
	// uninstall (and optionally a --purge data wipe).
	mux.HandleFunc("/v1/master/uninstall-self", st.handleMasterUninstallSelf)

	maxHeader := cfg.Server.MaxHeaderBytes
	if maxHeader <= 0 {
		maxHeader = 32 * 1024
	}
	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           mux,
		TLSConfig:         tlsCfg,
		MaxHeaderBytes:    maxHeader,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	st.http = srv

	ln := listenerErr(srv.Addr)
	if ln != nil {
		return nil, ln
	}

	// SAN-drift check: warn the operator at startup when the cert
	// in use doesn't cover one of this host's current IPs. Operators
	// hit this when the server's IP changed (DHCP, container restart,
	// cloud move) without a corresponding `certs server --force`.
	// Agents dialing by hostname still work; agents dialing by an IP
	// added since the cert was issued silently fail TLS until the
	// cert is refreshed. Surfacing this as a single _server/meta
	// warning at startup turns "events stop arriving" into "I see
	// the warning and know what to fix."
	if drifted := certSANDrift(cfg.Server.Cert); len(drifted) > 0 {
		if mst, err := st.storageFor("_server"); err == nil {
			mst.Write("meta", map[string]any{
				"event":            "cert_san_drift",
				"missing_from_san": drifted,
				"hint":             "agents dialing by these IPs will fail TLS; refresh with: sudo simplesiem certs server $(hostname) --force && sudo simplesiem stop && sudo simplesiem start",
			})
		}
	}

	// Hot-reload server-side config edits (allowlist, master_cns,
	// revoked maps, master_can_rotate_ca). Polls config.json mtime.
	wg.Add(1)
	go func() {
		defer wg.Done()
		newConfigWatcher(cfgPath, st).run(ctx)
	}()

	// Volume-anomaly detector — fires meta:agent_silent_anomaly when
	// a previously-chatty agent goes quiet. Wired now (default
	// thresholds, then operator-tunable from cfg.server.volume_anomaly)
	// so the per-minute rotation goroutine starts.
	st.volumeAnomaly = newVolumeAnomalyDetector(st)
	st.volumeAnomaly.tune(cfg.Server.VolumeAnomaly)
	st.volumeAnomaly.onAlert = st.writeAnomaly
	st.volumeAnomaly.onRecovered = st.writeRecovered
	st.volumeAnomaly.start(ctx, wg)

	// Alert webhooks — operator-configured POST targets that
	// receive every fired alert as JSON. Returns nil when no
	// webhooks are configured; subsequent SetAlertHook calls
	// no-op via the nil-receiver guard. The dispatcher's queue
	// goroutine is parented by the server context so it stops
	// cleanly on shutdown.
	if loggerStore, err := st.storageFor("_server"); err == nil {
		st.firstSeen.logger = loggerStore
		st.firstSeen.onWrite = func(host string, fields map[string]any) {
			// Per-host meta write so `triage --host <agent>` surfaces
			// the first-seen event under the agent's stream too.
			if hostStore, err := st.storageFor(host); err == nil {
				hostStore.Write("meta", fields)
			}
		}
		st.firstSeen.Start(ctx, wg)
		st.todBaseline.logger = loggerStore
		st.todBaseline.Start(ctx, wg)
		// Alert escalation watcher — re-fires unacked criticals
		// after configurable window. Dispatch routes through the
		// same fanout as regular alerts.
		if esc := newAlertEscalator(cfg.Server, cfg.LogDir, cfg.Mode, loggerStore, func(alert map[string]any) {
			for _, h := range loggerStore.alertHooks {
				h(alert)
			}
		}); esc != nil {
			esc.Start(ctx, wg)
		}
		st.alertWebhooks = newAlertWebhookDispatcher(cfg.Server, loggerStore, st.metrics)
		if st.alertWebhooks != nil {
			// Stop the dispatcher when the server's context is done
			// so its sender goroutine drains and exits.
			go func() {
				<-ctx.Done()
				st.alertWebhooks.Stop()
			}()
		}
		// Alert syslog — optional RFC 5424 forwarder. Mirrors the
		// webhook dispatcher's lifecycle.
		st.alertSyslog = newAlertSyslogDispatcher(cfg.Server, loggerStore, st.metrics)
		if st.alertSyslog != nil {
			go func() {
				<-ctx.Done()
				st.alertSyslog.Stop()
			}()
		}
		// SIEM-enhancement alert pipeline: rule-fire stats (#1),
		// suppression check (#2), incident grouping (#6), auto-
		// fixture capture (#9). Background workers (suppression
		// pruner, MITRE auto-fetch, threat-intel) start alongside.
		st.alertPipeline = newAlertPipeline(cfg, cfg.LogDir, loggerStore)
		st.tupleMgr = startSiemEnhancements(ctx, wg, cfg, loggerStore, st.alertPipeline)

		// Network-device sticky-IP allowlist + syslog ingest listener.
		// Server is one of the two modes that may bind a listener
		// (master is the other). The allowlist sidecar lives next to
		// config.json; mutations are atomic and hot-reloadable.
		initNetworkSyncImpls()
		netStore := newNetworkAllowlist(networkAllowlistPath(), loggerStore)
		if err := netStore.Load(); err != nil {
			netStore.EmitReloadRejected("startup", err.Error())
		}
		st.networkAllowlist = netStore
		installNetworkIngestServerEndpoints(mux, st, netStore)
		// Hot-reload watcher for the allowlist sidecar.
		wg.Add(1)
		go func() {
			defer wg.Done()
			newNetworkAllowlistWatcher(netStore).run(ctx)
		}()
		// The syslog listener (if enabled).
		if niSt, err := startNetworkIngest(ctx, wg, cfg, "server", netStore, loggerStore,
			st.storageFor, func() []*alertRule { return st.rules },
			func(alert map[string]any) {
				for _, h := range loggerStore.alertHooks {
					h(alert)
				}
			}); err != nil {
			loggerStore.Write("errors", map[string]any{
				"collector": "network_ingest",
				"error":     err.Error(),
			})
		} else if niSt != nil {
			st.networkIngest = niSt
		}
		// Pending-push dispatcher (server → master). No-op on a
		// realm without a master.
		newPendingPushDispatcher(cfg, netStore).start(ctx, wg)
		// One-shot resync at startup.
		go func() {
			time.Sleep(2 * time.Second)
			_ = pullAllowlistFromMaster(cfg, netStore)
		}()
		// Auto-discover own gateway and add it to the allowlist.
		go func() {
			time.Sleep(1 * time.Second)
			autoDiscoverOwnGateways(netStore, "server-self", loggerStore)
		}()
	}

	// Pending-join watcher: completes a master-driven realm migration
	// by running the realm-join handshake when realm.pending_join_peer
	// is set in config. Polls every 5s; clears the pending fields on
	// success so it never re-runs against the same target.
	if mst, err := st.storageFor("_server"); err == nil {
		startPendingJoinWatcher(ctx, cfgPath, mst)
	} else {
		startPendingJoinWatcher(ctx, cfgPath, nil)
	}

	// Cert expiry monitor — daily check of server.pem, ca.pem, and
	// any legacy CAs. Emits meta:cert_expiry_warning at 30d/14d/7d/1d/1h.
	if mst, err := st.storageFor("_server"); err == nil {
		startCertExpiryMonitor(ctx, wg, mst, "server", collectServerCertPaths(cfg))
		// Hourly signing of chain heads so a future audit can
		// verify the on-disk events match what the daemon attested
		// to at signing time. Uses the same per-host ECDSA P-384
		// key family as the rest of SimpleSIEM's PKI.
		startChainHeadSigner(ctx, wg, cfg, mst)
	}

	// Hot-reload the server cert when the file changes (e.g., operator
	// runs `certs server --force` to extend the SAN). The reloader
	// poll loop swaps the cert atomically; the listener picks it up
	// on the next handshake without dropping existing connections.
	wg.Add(1)
	go func() {
		defer wg.Done()
		reloader.watch(ctx, func(rerr error) {
			mst, _ := st.storageFor("_server")
			if mst == nil {
				return
			}
			if rerr != nil {
				mst.Write("errors", map[string]any{
					"collector": "tls_reloader",
					"error":     rerr.Error(),
					"hint":      "server cert file changed but couldn't be parsed; check that the new cert is signed by the existing CA",
				})
				return
			}
			mst.Write("meta", map[string]any{
				"event": "tls_cert_reloaded",
				"cert":  cfg.Server.Cert,
			})
		})
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		// ListenAndServeTLS blocks until shutdown; cert/key paths come
		// from TLSConfig.Certificates so the empty-string args are fine.
		err := srv.ListenAndServeTLS("", "")
		if !errors.Is(err, http.ErrServerClosed) {
			st.broadcastErr("server", err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		st.closeAll()
	}()

	// Realm sync: always run. The loop re-reads s.realmPeers each
	// iteration and is a no-op while the set is empty, so a single-
	// server install pays nothing and a peer added later (via
	// /v1/realm/join) starts replicating on the next cycle without
	// a daemon restart. Server-cert verification on dial uses the
	// live trust bundle, so peer CAs added at runtime are trusted
	// on the next handshake.
	if clientCert, err := loadKeyPair(cfg.Server.Cert, cfg.Server.Key); err == nil {
		peerTLS := outboundClientTLS(clientCert, bundle)
		wg.Add(1)
		go func() {
			defer wg.Done()
			st.realmSyncLoop(ctx, nil, cfg.Server.Realm.SyncIntervalSeconds, peerTLS)
		}()
	} else {
		st.broadcastErr("realm_sync", fmt.Errorf("server cert won't load as client cert: %v — re-run `simplesiem certs server $(hostname) --force` to re-issue with ClientAuth", err))
	}

	return st, nil
}

// listenerErr is a tiny pre-flight check so the operator gets a clear
// "address in use / permission denied" error before the goroutine fires
// up. Returning nil means we'd succeed; the actual listen happens inside
// http.Server.ListenAndServeTLS.
func listenerErr(addr string) error {
	// Just check the address parses; the real bind is in ListenAndServeTLS
	// where errors propagate via the goroutine. Operators see them in the
	// errors log.
	_, _, err := splitHostPort(addr)
	return err
}

func splitHostPort(addr string) (host, port string, err error) {
	if !strings.Contains(addr, ":") {
		return "", "", fmt.Errorf("listen address %q must include a port (e.g. :9443)", addr)
	}
	return "", "", nil
}

type serverState struct {
	base            string
	group           *storageGroup
	groupGID        int
	maxBytes        int64
	maxDecompBytes  int64
	maxFileSz       int64
	queueSize       int
	tokens          []string
	allowBearerOnly bool
	rules           []*alertRule
	maxClockSkew    time.Duration
	limiter         *rateLimiter
	semaphore       chan struct{}

	// allowlist is mutated at runtime by /v1/enroll, so reads from
	// /v1/events need a guard. The empty-map case (legacy "any valid
	// cert+CN pair accepted") is preserved.
	allowlistMu sync.RWMutex
	allowlist   map[string]struct{}

	mu       sync.Mutex
	storages map[string]*Storage
	http     *http.Server

	failMu sync.Mutex
	fails  map[string]*authFailRate

	// Enrollment-only state. enrollPSK is the displayable string the
	// operator shows to operators of new agent hosts; certsDir is where
	// ca.pem/ca.key live; configPath is the file we rewrite when adding
	// a freshly-enrolled agent_id to the allowlist; enrollLimiter is a
	// tighter per-IP token bucket for /v1/enroll than the events one.
	enrollPSK         string
	certsDir          string
	configPath        string
	enrollClientYears int
	enrollLimiter     *rateLimiter
	reauthSeconds     int

	// Realm fields are echoed back to agents in the enroll response so
	// they can populate their failover_servers list. RealmMu protects
	// reads/writes since peers sync the name at runtime.
	realmMu        sync.RWMutex
	realmName      string
	realmPeers     []string
	realmConfigVer int64 // unix nano of the most recent local realm-config edit; used as a tiebreaker when a peer reports a different name

	// selfPeerID is the canonical "who am I" string this server stamps
	// on events as origin_server. Used for realm replication: peers
	// only fetch events with origin_server == the peer they're
	// querying, which prevents infinite replication loops. Format is
	// the configured listen URL hostname-or-IP, falling back to
	// os.Hostname() when listen is just ":port".
	selfPeerID string

	// masterCNs is the list of cert CNs allowed to call the
	// /v1/sync/* endpoints as masters. Populated from
	// cfg.Server.MasterCNs at startup, mutated at runtime by
	// /v1/enroll-master. Distinct from realmPeers — masters are
	// identified by exact CN match instead of by URL hostname.
	masterMu  sync.RWMutex
	masterCNs []string

	// trust is the runtime CA pool used to verify TLS client certs.
	// Built from cfg.Server.CACert + every <state>/realm/peer_cas/*.pem.
	// /v1/realm/join writes a new peer CA to disk and calls
	// trust.rebuild(); the next handshake uses the new pool because
	// the listener's tls.Config.GetConfigForClient resolves ClientCAs
	// from the bundle on every connection.
	trust *trustBundle

	// revokedMu protects the two tombstone maps. Both maps are CN/ID
	// → RFC3339 timestamp of revocation. Effective allowlist check
	// is `in_allowlist AND not_in_revoked`. Tombstones propagate via
	// /v1/sync/config so revocation reaches every peer within a sync
	// interval (default 60s) without operator action on each peer.
	revokedMu     sync.RWMutex
	agentRevoked  map[string]string
	masterRevoked map[string]string

	// masterCanRotate mirrors cfg.Server.MasterCanRotateCA — gates
	// /v1/master/rotate-ca and /v1/master/finalize-rotate. Default
	// false so a compromised master can't destroy CA keys without
	// explicit operator opt-in.
	masterCanRotate bool

	// masterCanUninstall mirrors cfg.Server.MasterCanUninstall —
	// gates /v1/master/uninstall-self. Default false. Required for
	// a `master uninstall-all` cascade to reach this server. Same
	// rationale as masterCanRotate: the operator must explicitly
	// trust the master with destructive cluster-wide operations.
	masterCanUninstall bool

	// Network-device ingest state. Owned by serverState so the
	// hot-reload watcher and the master-push endpoints can both
	// reach the same store.
	networkAllowlist *networkAllowlist
	networkIngest    *networkIngestState

	// identityGuard state (see identity_guard.go). Tracks per-CN
	// last-seen (ip, ts) so a second daemon presenting the same
	// client cert from a different IP within the guard window is
	// rejected — the canonical "restored agent while the original
	// is still up" scenario.
	identityMu    sync.Mutex
	identityState map[string]identityRec

	// volumeAnomaly watches per-agent event rates and fires
	// `meta:agent_silent_anomaly` when an agent that was previously
	// chatty goes quiet. See volume_anomaly.go.
	volumeAnomaly *volumeAnomalyDetector

	// alertPipeline runs the SIEM-enhancement sinks (#1 stats,
	// #2 suppression check, #6 incidents, #9 fixture capture).
	alertPipeline *alertPipeline
	// tupleMgr is the first-seen tuple detector (#7). Per-host
	// Observe hooks call into it from the storage write path.
	tupleMgr *tupleManager

	// alertWebhooks dispatches every fired rule_match alert to the
	// operator-configured URLs in cfg.Server.AlertWebhooks. Nil when
	// no webhooks are configured. See alert_webhook.go.
	alertWebhooks *alertWebhookDispatcher

	// alertSyslog forwards every fired alert to the operator-configured
	// RFC 5424 collector in cfg.Server.AlertSyslog. Nil when address is
	// empty. See alert_syslog.go.
	alertSyslog *alertSyslogDispatcher

	// metrics is the Prometheus exposition collector exposed at
	// /metrics. Populated on every ingest + alert fire so external
	// scrapers see live counters. See metrics.go.
	metrics *metricsCollector

	// firstSeen tracks per-host entity sets and emits first-seen
	// meta events. Default-on for standard fields; persistence in
	// state_dir. See firstseen.go.
	firstSeen *firstSeenDetector

	// todBaseline keeps per-entity hour-of-day histograms and
	// emits unusual_time_anomaly events. See todbaseline.go.
	todBaseline *todBaselineDetector
}

// agentAllowedTypes is the set of log types an agent can write to.
// "alerts" is deliberately absent — only the server's rule engine
// produces alert events. An agent posting type=alerts is a direct
// attempt to forge alerts; we reject and log it.
var agentAllowedTypes = map[string]bool{
	"network":   true,
	"files":     true,
	"auth":      true,
	"processes": true,
	"traffic":   true,
	"meta":      true,
	"errors":    true,
	"dns":       true, // synthesized by NetworkCollector from observed remote_host
}

// authFailRate tracks per-IP failed auth attempts within a sliding window
// so we can log+throttle without flooding the errors log when someone is
// actively brute-forcing.
type authFailRate struct {
	count    int
	first    time.Time
	lastLog  time.Time
}

// validHostName restricts agent IDs to characters safe for a directory
// component. The regex enforces an alphanumeric leading character and a
// limited charset; safeHostName layers two additional checks (no ".."
// substring, and a path-stays-within-base verification) so a future
// regex weakening can't reintroduce path traversal.
var validHostName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// validInternalHostName matches SimpleSIEM's reserved underscore-
// prefixed pseudo-hosts (`_server`, `_master`, `_collector`,
// `_agent`, `_legacy`, `_agent_forward`, `_pre_restore_loose`,
// `_master_collector_query`, ...). Used by listHosts so triage/query
// without an explicit --host filter still walks the lifecycle event
// streams these dirs hold (e.g. master_departed, cert_san_drift,
// storage_warning). The same path-traversal guarantees as
// validHostName: no slashes, no `..`, no funny chars.
var validInternalHostName = regexp.MustCompile(`^_[A-Za-z0-9._-]{1,127}$`)

// safeHostName is the only function that should be used to validate an
// agent ID before using it as a path component on the server. It
// defends against:
//   - leading-dot names (".bashrc"-style)
//   - any embedded ".." sequence
//   - reserved Windows names
//   - host strings whose joined path escapes the configured log dir
//
// Returns true only when ALL checks pass.
func safeHostName(base, host string) bool {
	if !validAgentID(host) {
		return false
	}
	// Final belt-and-braces: confirm the joined path stays under base.
	abs, err := filepath.Abs(filepath.Join(base, host))
	if err != nil {
		return false
	}
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(abs, baseAbs+sep) || abs == baseAbs
}

// validAgentID is the path-independent half of safeHostName: the regex,
// the no-".." guard, and the Windows-reserved-name check. Used by the
// agent at startup so a misconfigured agent.id is caught locally before
// it ever creates a spool file or attempts a connection.
func validAgentID(id string) bool {
	if !validHostName.MatchString(id) {
		return false
	}
	if strings.Contains(id, "..") {
		return false
	}
	switch strings.ToUpper(id) {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return false
	}
	return true
}

func (s *serverState) storageFor(host string) (*Storage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.storages[host]; ok {
		return st, nil
	}
	st, err := s.group.Open(host, s.groupGID, s.maxFileSz, s.queueSize)
	if err != nil {
		return nil, err
	}
	if len(s.rules) > 0 {
		st.SetRules(s.rules)
	}
	if s.alertWebhooks != nil {
		// Wire the alert dispatcher into this fresh Storage so
		// rule fires fan out to operator webhooks alongside the
		// on-disk alerts/* write. Same hook on every per-host
		// store (one dispatcher, many sources).
		st.AddAlertHook(s.alertWebhooks.dispatch)
	}
	if s.alertSyslog != nil {
		st.AddAlertHook(s.alertSyslog.dispatch)
	}
	if s.metrics != nil {
		// Always-on counter so /metrics has rule-fire visibility
		// regardless of whether webhooks/syslog are configured.
		st.AddAlertHook(func(alert map[string]any) {
			s.metrics.recordAlertFire(strField(alert, "rule"), strField(alert, "severity"))
		})
	}
	if s.alertPipeline != nil {
		st.AddAlertHook(s.alertPipeline.hook)
	}
	s.storages[host] = st
	return st, nil
}

func (s *serverState) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.storages {
		st.Close()
	}
}

func (s *serverState) broadcastErr(component string, err error) {
	// Best-effort: write into every active host's errors log so the failure
	// shows up somewhere visible. If no hosts are connected yet, write to
	// a "_server" pseudo-host.
	host := "_server"
	st, gerr := s.storageFor(host)
	if gerr != nil {
		return
	}
	st.Write("errors", map[string]any{
		"collector": component, "error": err.Error(),
	})
}

// handleHealth is a cheap liveness probe. Intentionally unauthenticated
// so k8s/container/load-balancer probes that don't carry a client cert
// can still verify the daemon is alive. The response is a fixed
// {"ok":true} with no observable information about the cluster — the
// only fact a probe learns is "something is listening on this port",
// which is already revealed by TCP-level reachability.
func (s *serverState) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	addSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// handleMetrics exposes counters in Prometheus exposition format.
// Auth: requires either a valid client cert (mTLS, same as ingest) OR
// a bearer token in cfg.Server.BearerTokens. We don't expose any
// per-event payload data — only counts — but agent identifiers in
// labels are still considered fleet topology, so the endpoint is gated.
func (s *serverState) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	addSecurityHeaders(w)
	if !s.requestAuthenticated(r) {
		s.metrics.recordAuthFailure()
		w.Header().Set("WWW-Authenticate", `Bearer realm="simplesiem"`)
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		return
	}
	s.metrics.renderPrometheus(w)
}

// requestAuthenticated returns true if the request presents EITHER a
// verified client cert (TLS chain validated against the server's CA
// in the listener config) OR a bearer token in the operator-configured
// allowlist. Either is sufficient for read-only metrics — write
// endpoints stack the two together via mTLS + handler-side checks.
func (s *serverState) requestAuthenticated(r *http.Request) bool {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return true
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	for _, allowed := range s.tokens {
		if tok == allowed {
			return true
		}
	}
	return false
}

// addSecurityHeaders sets a small set of conservative response headers.
// The receiver isn't a browser-served API (clients are agents, not
// browsers) but these headers cost nothing and protect against
// misconfigured intermediaries.
func addSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
}

// handleEvents receives a batch upload. Body is gzip-compressed NDJSON;
// each line is one event. The X-SimpleSIEM-Host header identifies the
// source agent and MUST equal the client cert CN — otherwise an agent
// with a valid cert could write events under another agent's name.
func (s *serverState) handleEvents(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Per-IP token-bucket rate limit. A flooding agent gets 429s without
	// blocking other agents. Limit is checked before auth so a brute-force
	// attempt against bearer tokens is also throttled.
	ip := remoteIP(r)
	if !s.limiter.allow(ip) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Concurrent-request semaphore: bound the number of in-flight uploads
	// to defend against slow-loris-style file-descriptor exhaustion. The
	// non-blocking acquire returns 503 immediately under saturation rather
	// than queueing requests indefinitely.
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	default:
		http.Error(w, "server busy", http.StatusServiceUnavailable)
		return
	}

	if !s.authorize(r) {
		s.logAuthFailure(r, "events")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	host := r.Header.Get("X-SimpleSIEM-Host")
	if !safeHostName(s.base, host) {
		s.broadcastErr("server", fmt.Errorf("rejected agent ID %q from %s", host, r.RemoteAddr))
		http.Error(w, "invalid X-SimpleSIEM-Host", http.StatusBadRequest)
		return
	}
	cn := clientCN(r)
	if cn != "" {
		if cn != host {
			s.broadcastErr("server", fmt.Errorf("CN %q does not match X-SimpleSIEM-Host %q from %s", cn, host, r.RemoteAddr))
			http.Error(w, "agent ID does not match client cert CN", http.StatusForbidden)
			return
		}
		// Identity-guard: reject duplicate-identity events the same
		// way heartbeats do. See identity_guard.go.
		if !s.identityCheck(r, cn) {
			http.Error(w, "duplicate identity: another daemon is currently active with this cert", http.StatusConflict)
			return
		}
	} else if !s.allowBearerOnly {
		// No client cert AND we're not running in explicit bearer-only
		// mode — reject. This prevents an attacker who somehow gets a
		// valid bearer token from also impersonating any agent ID when
		// the operator intended mTLS to be required.
		s.broadcastErr("server", fmt.Errorf("rejected unauthenticated request from %s claiming host=%q", r.RemoteAddr, host))
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}

	// Allowlist gate. When non-empty, the agent ID MUST be on the list,
	// independent of how the cert chain checked out. This contains a
	// CA-key compromise: an attacker who can mint signed certs still
	// can't stand up a new agent the server hasn't been told to expect.
	// Empty list preserves legacy behaviour (any CA-signed cert + CN
	// match is sufficient). Read under RLock because /v1/enroll mutates
	// the map at runtime when a new agent joins.
	s.allowlistMu.RLock()
	allowSize := len(s.allowlist)
	_, allowed := s.allowlist[host]
	s.allowlistMu.RUnlock()
	if allowSize > 0 && !allowed {
		s.broadcastErr("server", fmt.Errorf(
			"unauthorized agent %q from %s — not in agent_allowlist (cert valid, ID not approved)",
			host, r.RemoteAddr))
		http.Error(w, "agent not authorized", http.StatusForbidden)
		return
	}
	// Revocation tombstone overrides the allowlist. The cert is still
	// cryptographically valid until NotAfter, but operator policy says
	// this identity is no longer welcome.
	if ts := s.agentRevokedAt(host); ts != "" {
		s.broadcastErr("server", fmt.Errorf(
			"revoked agent %q from %s — agent_revoked tombstone set at %s",
			host, r.RemoteAddr, ts))
		http.Error(w, "agent revoked", http.StatusForbidden)
		return
	}

	// Bound the body. A 32 MiB cap on the gzip-compressed payload lets a
	// well-behaved agent send ~10× that much NDJSON before being asked to
	// chunk; a misbehaving one can't OOM us.
	max := s.maxBytes
	if max <= 0 {
		max = 32 * 1024 * 1024
	}
	body := http.MaxBytesReader(w, r.Body, max)
	defer body.Close()

	var reader io.Reader = body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			s.broadcastErr("server", fmt.Errorf("bad gzip from %s: %v", r.RemoteAddr, err))
			http.Error(w, "bad gzip body", http.StatusBadRequest)
			return
		}
		defer gz.Close()
		// Defend against gzip bombs: bound the DECOMPRESSED stream as well.
		// LimitReader returns EOF at the cap, which makes the JSON decoder
		// fail mid-token; we record the truncation and return 413 to the
		// client so a misbehaving agent sees the rejection.
		reader = &countingLimitReader{r: gz, limit: s.maxDecompBytes}
	}

	st, err := s.storageFor(host)
	if err != nil {
		http.Error(w, "storage init failed", http.StatusInternalServerError)
		return
	}

	dec := json.NewDecoder(reader)
	dec.UseNumber() // preserve int vs float distinction in numeric fields
	received := 0
	rejected := 0
	decodeErrors := 0
	const maxDecodeErrors = 100 // abort the batch if a stream is mostly garbage
	now := time.Now().UTC()
	for dec.More() {
		var event map[string]any
		if err := dec.Decode(&event); err != nil {
			// One bad line shouldn't lose the batch. Record only the
			// first error per batch (subsequent errors are usually
			// the same root cause); abort entirely if the count
			// climbs — that's how a non-JSON stream of garbage looks
			// and we'd rather 400 than spin on the decoder for tens
			// of thousands of zero bytes.
			decodeErrors++
			if decodeErrors == 1 {
				st.Write("errors", map[string]any{
					"collector": "server", "error": "decode: " + err.Error(),
					"agent": host, "remote": r.RemoteAddr,
				})
			}
			if decodeErrors >= maxDecodeErrors {
				s.broadcastErr("server", fmt.Errorf(
					"aborting batch from %q: %d decode errors", host, decodeErrors))
				http.Error(w, "too many decode errors", http.StatusBadRequest)
				return
			}
			continue
		}
		if len(event) == 0 {
			continue
		}
		logType, _ := event["type"].(string)
		// Type allow-list: agents must NOT be able to write to "alerts"
		// (the rule engine owns that type) or to any unknown type that
		// could be mistaken for a privileged stream. Reject and record.
		if !agentAllowedTypes[logType] {
			rejected++
			s.metrics.recordReject()
			s.broadcastErr("server", fmt.Errorf("rejected disallowed type=%q from agent %q", logType, host))
			continue
		}
		// Clamp the agent's timestamp to within ±maxClockSkew of now.
		// This prevents an attacker from planting "old" events to forge
		// history or "future" events to confuse triage windows. The
		// original raw ts is preserved as agent_ts for forensics.
		if rawTS, ok := event["ts"].(string); ok && rawTS != "" {
			if t := parseAnyTS(rawTS); !t.IsZero() {
				if t.Before(now.Add(-s.maxClockSkew)) || t.After(now.Add(s.maxClockSkew)) {
					event["agent_ts"] = rawTS
					event["ts"] = now.Format(time.RFC3339Nano)
					event["clock_skewed"] = true
				}
			}
		}
		// Tag with the source host so triage can filter by it without
		// needing to walk the directory layout.
		event["host"] = host
		// Stamp received_at for forensic timing. Storage keeps event["ts"]
		// as the canonical timestamp for ordering.
		event["received_at"] = now.Format(time.RFC3339Nano)
		// Origin marker for realm replication: this is the server that
		// directly received the event from the agent. Peers in the
		// realm pull events with origin_server == self only, so we
		// can't replicate-and-then-replicate (no loops).
		event["origin_server"] = s.selfPeerID
		// Strip any chain fields the agent might have set; the server
		// owns the chain and re-adds them in writeNow.
		delete(event, "_seq")
		delete(event, "_prev")
		delete(event, "_hash")
		st.Write(logType, event)
		s.metrics.recordIngest(host, logType)
		s.firstSeen.observe(host, event)
		s.todBaseline.observe(host, event)
		received++
	}
	if cr, ok := reader.(*countingLimitReader); ok && cr.truncated {
		s.broadcastErr("server", fmt.Errorf(
			"decompressed body exceeded cap (%d bytes) from agent %q at %s — possible zip bomb",
			s.maxDecompBytes, host, r.RemoteAddr))
		// 413 is the right semantic — payload too large. Note: the agent's
		// drainSpool moves 4xx-rejected batches aside as .rejected, so an
		// operator can investigate. The events we DID decode before
		// truncation are still persisted; on retry the agent will resend
		// the whole batch and produce duplicates (the agent's local
		// timestamps make those identifiable).
		http.Error(w, "decompressed body too large", http.StatusRequestEntityTooLarge)
		return
	}
	// Volume-anomaly detector: feed the per-batch count so the
	// per-minute rotate loop can spot agents that go quiet relative
	// to their own rolling baseline. Cheap (one mutex + map lookup +
	// addition); doesn't block the response.
	if s.volumeAnomaly != nil && received > 0 {
		s.volumeAnomaly.recordIngress(host, received)
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"received":%d,"rejected":%d}`, received, rejected)
}

// parseAnyTS accepts either RFC3339 or RFC3339Nano, returning zero-time
// on failure. Used to validate agent-supplied event timestamps before we
// store them.
func parseAnyTS(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

// countingLimitReader is io.LimitReader plus a "did we hit the cap?"
// signal. The standard io.LimitReader silently EOFs at the limit, which
// makes a gzip-bomb attack indistinguishable from a normal end-of-batch.
// truncated() lets the handler tell the difference and emit a 413.
type countingLimitReader struct {
	r         io.Reader
	limit     int64
	read      int64
	truncated bool
}

func (c *countingLimitReader) Read(p []byte) (int, error) {
	if c.read >= c.limit {
		c.truncated = true
		return 0, io.EOF
	}
	if int64(len(p)) > c.limit-c.read {
		p = p[:c.limit-c.read]
	}
	n, err := c.r.Read(p)
	c.read += int64(n)
	if c.read >= c.limit {
		c.truncated = true
	}
	return n, err
}

// authorize implements the layered policy:
//
//   - If a client cert was presented, it's already chain-verified by the
//     TLS layer (RequireAndVerifyClientCert). Accept it; if bearer
//     tokens are also configured, BOTH must succeed (defence in depth).
//   - If no client cert was presented, accept only if the operator opted
//     into bearer-only mode (require_client_cert=false AND bearer_tokens
//     is non-empty). The CN-vs-host check elsewhere handles the
//     identity binding for the cert path.
//
// constant-time bearer comparison defeats timing oracles.
func (s *serverState) authorize(r *http.Request) bool {
	if r.TLS == nil {
		return false
	}
	hasCert := len(r.TLS.PeerCertificates) > 0
	if hasCert {
		if len(s.tokens) == 0 {
			return true
		}
		return s.checkBearer(r)
	}
	// No client cert. Allow only in explicit bearer-only configuration.
	if !s.allowBearerOnly {
		return false
	}
	return s.checkBearer(r)
}

func (s *serverState) checkBearer(r *http.Request) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == "" {
		return false
	}
	for _, want := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// logAuthFailure records a 401 to the server's internal errors log, with
// per-IP rate limiting so a brute-force flood doesn't drown the log.
// Per-IP counters reset every minute; the log line is emitted once per
// unique IP per 30s window plus a count summary.
func (s *serverState) logAuthFailure(r *http.Request, endpoint string) {
	ip := remoteIP(r)
	now := time.Now()
	s.failMu.Lock()
	rate, ok := s.fails[ip]
	if !ok || now.Sub(rate.first) > time.Minute {
		rate = &authFailRate{first: now}
		s.fails[ip] = rate
	}
	rate.count++
	emit := now.Sub(rate.lastLog) > 30*time.Second || rate.count == 1
	count := rate.count
	if emit {
		rate.lastLog = now
	}
	// Garbage-collect old entries opportunistically so the map can't grow
	// without bound under sustained attack.
	if len(s.fails) > 4096 {
		for k, v := range s.fails {
			if now.Sub(v.first) > 5*time.Minute {
				delete(s.fails, k)
			}
		}
	}
	s.failMu.Unlock()
	if !emit {
		return
	}
	s.broadcastErr("server", fmt.Errorf("auth failed on /%s from %s (count=%d in last minute)", endpoint, ip, count))
}

func remoteIP(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

func clientCN(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName
}

// listHosts returns the agent IDs the server has logs for. Used by read
// commands so `triage` etc. can iterate per-host directories.
func listHosts(base string) []string {
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Skip directories that look like log-type dirs (network/, files/...
		// — present in standalone mode at the top level).
		name := e.Name()
		if isLogTypeDir(name) {
			continue
		}
		// Allow leading-underscore SimpleSIEM internal pseudo-hosts
		// (`_server`, `_master`, `_collector`, `_agent`, `_legacy`,
		// `_agent_forward`, `_pre_restore`). Without this branch the
		// validHostName regex below rejects them and triage/query
		// without --host silently skips dirs that hold critical
		// receiver/master/collector lifecycle events
		// (`master_departed`, `cert_san_drift`, `storage_warning`,
		// etc.). Any underscore-prefixed name that's otherwise a
		// safe filename component is included.
		if strings.HasPrefix(name, "_") {
			if validInternalHostName.MatchString(name) {
				out = append(out, name)
			}
			continue
		}
		if !validHostName.MatchString(name) {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// realmName returns the configured realm name, defaulting to "default"
// when empty. Centralised so the same fallback applies everywhere
// (server boot, enroll response, status display).
func realmName(s string) string {
	if s == "" {
		return "default"
	}
	return s
}

// deriveSelfPeerID picks a stable identifier for this server to stamp
// on events as origin_server. Realm replication uses it to avoid
// loops: peer A pulls events from peer B by asking for "events with
// origin_server == B", so each event is only replicated by its
// originating ingress server. Falls back to hostname when listen is
// just a port (the most common case).
func deriveSelfPeerID(listen string) string {
	host, _, err := net.SplitHostPort(listen)
	if err == nil && host != "" {
		return host
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

// peerIDFromURL extracts the hostname from a peer URL (https://siem-2:9443
// → "siem-2"). Used to derive the per-peer file naming for replicated
// events and to validate that incoming sync requests came from a host
// that's in this realm's peers list. Returns "" if the URL is invalid.
func peerIDFromURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		// No port; whole Host is the hostname.
		return parsed.Host
	}
	return host
}

func isLogTypeDir(name string) bool {
	for _, t := range defaultLogTypes {
		if name == t {
			return true
		}
	}
	return false
}

// certSANDrift reads the server's TLS cert and returns the list of
// current local IPs (and the local hostname) that AREN'T in the cert
// SAN. Empty result means the cert covers everything we're currently
// reachable on. Best-effort: any read/parse error returns nil rather
// than crashing the server.
func certSANDrift(certPath string) []string {
	if certPath == "" {
		return nil
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	covered := map[string]struct{}{}
	for _, ip := range cert.IPAddresses {
		covered[ip.String()] = struct{}{}
	}
	for _, dns := range cert.DNSNames {
		covered[strings.ToLower(dns)] = struct{}{}
	}
	if cert.Subject.CommonName != "" {
		covered[strings.ToLower(cert.Subject.CommonName)] = struct{}{}
	}
	var missing []string
	// Walk current interfaces. Same filter as gatherLocalIPs in
	// certs.go (loopback / link-local / unspecified / multicast are
	// fine to ignore) so the warning only fires for "real" IPs.
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
					continue
				}
				if _, ok := covered[ip.String()]; !ok {
					missing = append(missing, ip.String())
				}
			}
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		if _, ok := covered[strings.ToLower(h)]; !ok {
			missing = append(missing, h)
		}
	}
	sort.Strings(missing)
	return missing
}
