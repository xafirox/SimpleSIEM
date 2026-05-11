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

// Collector mode is a backup-storage role. It pulls a copy of every
// event from the highest-authority peer it can reach (a master if
// one's available, otherwise a server in the realm). The source is
// not modified — events stay where they are; the collector writes a
// second copy under its own log dir using master-mode's per-origin
// chain layout.
//
// Authority hierarchy (from highest to lowest):
//
//   1. master — when the source server reports a `realm.master_url`,
//      the collector auto-promotes and re-enrolls with the master.
//      This rule covers cross-realm collection: a single collector
//      paired with a master sees every realm the master sees.
//   2. server — the default starting point. If the operator points
//      the collector at a server that's part of a realm with a
//      master, the collector promotes itself within one pull cycle.
//   3. agent — only meaningful for standalone-mode hosts (deferred;
//      standalone currently has no listener).
//
// Single-collector enforcement: every authority kind that exposes
// /v1/enroll-collector enforces a single-slot rule. Once a collector
// is associated, subsequent enrollments are refused with HTTP 403
// until the operator explicitly clears the slot.

// startCollectorDaemon launches the pull goroutine + a small local
// collector set so the collector host's own activity is visible in
// triage. Same shape as startMasterDaemon.
func startCollectorDaemon(ctx context.Context, wg *sync.WaitGroup, cfg Config) (*daemonState, error) {
	gid := resolveGroupGID(cfg.LogOwnerGroup)
	maxSz := int64(cfg.MaxLogFileMB) * 1024 * 1024

	initialLoc := pickInitialStorageLocation(cfg)
	group := newStorageGroup(initialLoc)
	collectorStore, err := group.Open("_collector", gid, maxSz, cfg.WriteQueueSize)
	if err != nil {
		return nil, err
	}
	localID := pickServerLocalID(cfg.Server.LocalID)
	localStore, err := group.Open(localID, gid, maxSz, cfg.WriteQueueSize)
	if err != nil {
		return nil, err
	}
	newStorageController(group, cfg).start(ctx, wg)
	if rules, err := loadRules(cfg.RulesPath); err == nil {
		collectorStore.SetRules(rules)
		localStore.SetRules(rules)
	}
	if cfg.RulesPath != "" {
		startRulesWatcher(ctx, wg, cfg.RulesPath, func(rules []*alertRule) {
			collectorStore.SetRules(rules)
			localStore.SetRules(rules)
		}, localStore)
	}

	// Collectors never bind the network-ingest listener — but they DO
	// report their own gateway up to their source (master or server)
	// so the realm allowlist stays in sync with this host's L2 view.
	startCollectorGatewayReporter(ctx, wg, cfg, collectorStore)
	// Surface a misconfig if the operator left network_ingest.enabled
	// on a collector — the listener is silently disabled either way,
	// but the meta event makes the misconfig visible.
	if cfg.Server.NetworkIngest.Enabled || cfg.Master.NetworkIngest.Enabled {
		collectorStore.Write("meta", map[string]any{
			"event": "network_ingest_refused",
			"mode":  "collector",
			"hint":  "network ingest is server/master-only; remove .network_ingest.enabled",
		})
	}
	collectorStore.Write("meta", map[string]any{
		"event":     "start",
		"mode":      "collector",
		"pid":       os.Getpid(),
		"platform":  runtime.GOOS,
		"arch":      runtime.GOARCH,
		"version":   version,
		"build":     buildNumber,
		"source":    cfg.Collector.SourceURL,
		"interval":  effectivePullInterval(cfg),
		"local_id":  localID,
		"authority": cfg.Collector.AuthorityHint,
	})

	startRetention(ctx, wg, cfg.LogDir, cfg.RetentionDays)
	startLocalCollectors(ctx, wg, cfg, localStore, collectorStore)
	startCertExpiryMonitor(ctx, wg, collectorStore, "collector", collectCollectorCertPaths(cfg))
	// Heartbeat under _collector so a collector that's between pull
	// cycles (default interval is once per day) doesn't trip the
	// wedge detector.
	startDaemonHeartbeat(ctx, wg, collectorStore, "collector")
	// Hourly signing of chain heads — covers the collector's local
	// collection (NOT the replicated `.from-*` mirror files; those
	// belong to the origin signer).
	startChainHeadSigner(ctx, wg, cfg, collectorStore)
	// Optional TLS listener for a paired master to query the
	// collector's archive. Off by default; opt in via
	// `simplesiem collector master enable`.
	startCollectorMasterListener(ctx, wg, cfg, defaultConfigPath(), collectorStore)

	if cfg.Collector.SourceURL == "" {
		collectorStore.Write("errors", map[string]any{
			"collector": "collector_pull",
			"error":     "collector.source_url is empty — run `simplesiem collector enroll <url> --key <PSK>` first",
		})
		return &daemonState{storage: collectorStore}, nil
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		runCollectorPullLoop(ctx, cfg, collectorStore)
	}()
	return &daemonState{storage: collectorStore}, nil
}

// effectivePullInterval picks the configured interval (defaulting
// to one day) and returns it in seconds.
func effectivePullInterval(cfg Config) int {
	if cfg.Collector.PullIntervalSeconds > 0 {
		return cfg.Collector.PullIntervalSeconds
	}
	return 86400
}

// collectorCertsDir returns the per-source cert root.
func collectorCertsDir(cfg Config) string {
	if cfg.Collector.CertsDir != "" {
		return cfg.Collector.CertsDir
	}
	return filepath.Join(defaultConfigDir(), "collector")
}

// collectCollectorCertPaths returns the cert paths the expiry monitor
// should track in collector mode.
func collectCollectorCertPaths(cfg Config) []string {
	out := []string{}
	root := collectorCertsDir(cfg)
	entries, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		for _, name := range []string{"cert.pem", "ca.pem"} {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// runCollectorPullLoop is the per-collector pull goroutine. Re-reads
// config every cycle so operator edits (interval, source URL) and
// master-pushed config (CollectorPushConfig) take effect without a
// daemon restart. The first wake fires 15s after start so the daemon
// finishes booting before the first network round-trip.
func runCollectorPullLoop(ctx context.Context, initialCfg Config, storage *Storage) {
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		cfg := loadConfig(defaultConfigPath())
		if cfg.Collector.SourceURL == "" {
			storage.Write("errors", map[string]any{
				"collector": "collector_pull",
				"error":     "source_url cleared at runtime; idle until re-enrolled",
			})
			timer.Reset(5 * time.Minute)
			continue
		}
		performCollectorPull(ctx, cfg, storage)
		timer.Reset(time.Duration(effectivePullInterval(cfg)) * time.Second)
	}
}

// performCollectorPull does one pull cycle:
//   1. Resolve which URL to dial (primary, then failover servers).
//   2. Pull /v1/sync/events since watermark.
//   3. Write events to <log_dir>/<host>/<type>/<date>.from-<source>.jsonl.
//   4. Update watermark.
//   5. Refresh failover list / authority hint via /v1/sync/config.
//   6. Refresh CA bundle if the source's CA rotated since last cycle.
//   7. Rotate own client cert if approaching expiry.
//   8. Pick up master-pushed config if the source supplied one.
func performCollectorPull(ctx context.Context, cfg Config, storage *Storage) {
	sourceURL, sourceID, certDir, ok := pickCollectorSource(cfg, storage)
	if !ok {
		return
	}
	tlsCfg, err := loadCollectorClientTLS(certDir)
	if err != nil {
		storage.Write("errors", map[string]any{
			"collector": "collector_pull",
			"source":    sourceURL,
			"error":     err.Error(),
			"hint":      "missing per-source cert; re-enroll with `simplesiem collector enroll <url> --key <PSK>`",
		})
		return
	}
	tr := &http.Transport{
		TLSClientConfig:       tlsCfg.Clone(),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Minute}

	// Cert auto-rotation: same threshold logic as agent/master.
	if cfg.Collector.CollectorID != "" {
		rotateCollectorCertIfNeeded(sourceURL, cfg.Collector.CollectorID, certDir, defaultRotateThresholdDays, client, storage)
	}

	stateDir := filepath.Join(defaultStateDir(), "collector")
	_ = os.MkdirAll(stateDir, 0o750)
	watermarkPath := filepath.Join(stateDir, sourceID+".watermark")

	doSyncEventsPull(ctx, client, sourceURL, sourceID, watermarkPath, storage, cfg.LogDir)
	checkAuthorityAndConfig(ctx, client, sourceURL, cfg, storage)

	// c5 — after each pull cycle, see whether the primary has been
	// down past the threshold and if so try a one-shot auto-repair
	// against a failover URL. The helper handles all the gating
	// (PSK file presence, cooldown, failover list, etc.).
	_, _ = tryCollectorAutoRepair(cfg, defaultConfigPath(), storage)
}

// pickCollectorSource walks (primary, ...failover) and returns the
// first reachable source via a TCP probe. Returns the chosen URL,
// peer ID, and per-source cert dir.
func pickCollectorSource(cfg Config, storage *Storage) (string, string, string, bool) {
	tryURLs := []string{cfg.Collector.SourceURL}
	tryURLs = append(tryURLs, cfg.Collector.FailoverServers...)
	root := collectorCertsDir(cfg)
	for _, u := range tryURLs {
		u = strings.TrimRight(u, "/")
		if u == "" {
			continue
		}
		id := peerIDFromURL(u)
		if id == "" {
			continue
		}
		dir := filepath.Join(root, id)
		if _, err := os.Stat(filepath.Join(dir, "cert.pem")); err != nil {
			continue
		}
		return u, id, dir, true
	}
	storage.Write("errors", map[string]any{
		"collector": "collector_pull",
		"error":     "no reachable source — neither primary nor failovers have cert dirs",
	})
	return "", "", "", false
}

// loadCollectorClientTLS mirrors loadMasterClientTLS — per-source
// cert + key + CA bundle, refreshed lazily on each handshake so
// auto-rotation takes effect without restarting the transport.
func loadCollectorClientTLS(certDir string) (*tls.Config, error) {
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

// doSyncEventsPull is the pull-side of /v1/sync/events shared between
// master and collector mode. Walks the response NDJSON, writes each
// event under <base>/<host>/<type>/<date>.from-<sourceID>.jsonl.
// collectorPullState is package-level so we can emit failsafe-on /
// failsafe-off transition meta events when the source reachability
// flips, without re-tracking state in every pull invocation.
var (
	collectorPullStateMu sync.Mutex
	collectorPullDown    = false
)

func collectorMarkSourceState(storage *Storage, source string, downNow bool) {
	collectorPullStateMu.Lock()
	prev := collectorPullDown
	collectorPullDown = downNow
	collectorPullStateMu.Unlock()
	if storage == nil || prev == downNow {
		return
	}
	if downNow {
		storage.Write("meta", map[string]any{
			"event":  "collector_query_failsafe_on",
			"source": source,
			"hint":   "source unreachable; read-only commands (query/triage/tail/alerts) are now allowed locally on the collector",
		})
	} else {
		storage.Write("meta", map[string]any{
			"event":  "collector_query_failsafe_off",
			"source": source,
			"hint":   "source reachable again; read-only commands are gated again",
		})
	}
}

func doSyncEventsPull(ctx context.Context, client *http.Client, source, sourceID, watermarkPath string, storage *Storage, base string) {
	since := readWatermark(watermarkPath)
	q := url.Values{}
	if !since.IsZero() {
		q.Set("since", since.Format(time.RFC3339Nano))
	}
	reqURL := strings.TrimRight(source, "/") + "/v1/sync/events?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		collectorMarkSourceState(storage, source, true)
		// c5 — note the down-watermark so auto-repair can apply its
		// threshold. Idempotent across repeated outages within the
		// same window.
		noteCollectorSourceDown()
		storage.Write("errors", map[string]any{
			"collector": "collector_pull",
			"source":    source,
			"error":     err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		collectorMarkSourceState(storage, source, true)
		noteCollectorSourceDown()
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		storage.Write("errors", map[string]any{
			"collector": "collector_pull",
			"source":    source,
			"error":     fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf))),
		})
		return
	}
	// Success: clear the failsafe flag + reset the down-watermark.
	collectorMarkSourceState(storage, source, false)
	noteCollectorSourceUp()
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	maxSeen := since
	count := 0
	for scanner.Scan() {
		var ev SyncEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if !writeMasterEvent(base, sourceID, ev) {
			continue
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
			"event":     "collector_pull_complete",
			"source":    source,
			"events":    count,
			"watermark": maxSeen.Format(time.RFC3339Nano),
		})
	}
}

// checkAuthorityAndConfig fetches the source's /v1/sync/config and
// (a) updates the local failover list to match the source's realm,
// (b) auto-promotes to a master when one becomes available,
// (c) adopts master-pushed config (CollectorPushConfig).
func checkAuthorityAndConfig(ctx context.Context, client *http.Client, source string, cfg Config, storage *Storage) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(source, "/")+"/v1/sync/config", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var pc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&pc); err != nil {
		return
	}
	// Refresh failover list from the realm peer set.
	if peers, ok := pc["peers"].([]any); ok {
		urls := make([]string, 0, len(peers))
		for _, p := range peers {
			if s, ok := p.(string); ok && s != strings.TrimRight(source, "/") {
				urls = append(urls, s)
			}
		}
		if len(urls) > 0 && !sameStringSet(cfg.Collector.FailoverServers, urls) {
			_ = setCollectorFailoverServers(defaultConfigPath(), urls)
			storage.Write("meta", map[string]any{
				"event": "collector_failover_list_refreshed",
				"count": len(urls),
			})
		}
	}
	// Authority promotion: if the source reports a master_url and we
	// aren't already pointed at it, emit the hint event so the operator
	// can promote on demand. Then (r21) try the auto-promote path: if
	// cfg.Collector.AutoPromoteToMaster is true AND the operator has
	// pre-staged a PSK at <state>/master_promote.psk, the collector
	// promotes itself in-process and consumes the PSK file.
	if mu, _ := pc["master_url"].(string); mu != "" && mu != source {
		storage.Write("meta", map[string]any{
			"event":      "collector_authority_promotion_available",
			"current":    source,
			"master_url": mu,
			"hint":       "a master is now reachable from this source. Re-enroll with: `simplesiem collector promote " + mu + " --key <PSK>` to switch the collector's source to the master. Or stage the PSK with `simplesiem collector queue-promote --key <PSK>` to let the daemon auto-promote.",
		})
		// r21 — auto-promote opportunistically when the operator has
		// pre-staged the PSK. Errors are logged inside the helper.
		_, _ = tryCollectorAutoPromote(cfg, defaultConfigPath(), mu, storage)
	}
	// Master-pushed config: adopt new pull interval if changed.
	if push, ok := pc["collector_push_config"].(map[string]any); ok {
		if iv, ok := push["pull_interval_seconds"].(float64); ok && int(iv) > 0 && int(iv) != cfg.Collector.PullIntervalSeconds {
			_ = setCollectorPullInterval(defaultConfigPath(), int(iv))
			storage.Write("meta", map[string]any{
				"event":          "collector_interval_pushed",
				"interval_secs":  int(iv),
				"hint":           "source pushed a new pull_interval_seconds value",
			})
		}
	}
	// CA-rotation cascade: if the source's trusted-CA bundle has
	// changed (master or server rotated), refresh the on-disk ca.pem
	// so the next handshake can verify the source's new server cert
	// without waiting for an opportunistic /v1/rotate. Derive certDir
	// directly from the source URL — calling pickCollectorSource
	// would write a misleading "no reachable source" error in the
	// rare path where the cert dir is missing.
	if bundle, ok := pc["ca_bundle"].(string); ok && bundle != "" {
		sourceID := peerIDFromURL(strings.TrimRight(source, "/"))
		if sourceID != "" {
			certDir := filepath.Join(collectorCertsDir(cfg), sourceID)
			caPath := filepath.Join(certDir, "ca.pem")
			existing, _ := os.ReadFile(caPath)
			if len(existing) > 0 && string(existing) != bundle {
				if werr := atomicWriteFile(caPath, []byte(bundle), 0o644); werr != nil {
					storage.Write("errors", map[string]any{
						"collector": "collector_pull",
						"source":    source,
						"error":     "ca bundle refresh failed: " + werr.Error(),
						"hint":      "next mTLS handshake may fail if the source's CA rotated",
					})
				} else {
					storage.Write("meta", map[string]any{
						"event":  "collector_ca_bundle_refreshed",
						"source": source,
						"src_id": sourceID,
						"hint":   "the source's CA bundle changed; updated on-disk ca.pem to keep handshakes valid",
					})
				}
			}
		}
	}
}

// rotateCollectorCertIfNeeded mirrors rotateMasterCertIfNeeded.
func rotateCollectorCertIfNeeded(serverURL, collectorID, certDir string, thresholdDays int, client *http.Client, storage *Storage) {
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")
	if !certNeedsRotation(certPath, thresholdDays) {
		return
	}
	if storage == nil {
		return
	}
	if err := rotateClientCert(client, strings.TrimRight(serverURL, "/"), certPath, keyPath, collectorID); err != nil {
		storage.Write("errors", map[string]any{
			"collector": "collector_rotate",
			"source":    serverURL,
			"error":     err.Error(),
		})
		return
	}
	storage.Write("meta", map[string]any{
		"event":  "collector_cert_rotated",
		"source": serverURL,
	})
}

// setCollectorFailoverServers persists a refreshed failover list.
func setCollectorFailoverServers(cfgPath string, urls []string) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	cfg.Collector.FailoverServers = append([]string{}, urls...)
	return saveConfig(cfgPath, cfg)
}

// setCollectorPullInterval persists an updated pull interval.
func setCollectorPullInterval(cfgPath string, secs int) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	cfg.Collector.PullIntervalSeconds = secs
	return saveConfig(cfgPath, cfg)
}

// CollectorEnrollRequest is the body of POST /v1/enroll-collector.
type CollectorEnrollRequest struct {
	PSK         string `json:"psk"`
	CollectorID string `json:"collector_id"`
	CSRPem      string `json:"csr_pem"`
}

// CollectorEnrollResponse mirrors MasterEnrollResponse with a
// collector-specific authority hint and the configured push config.
type CollectorEnrollResponse struct {
	CertPem        string              `json:"cert_pem"`
	CAPem          string              `json:"ca_pem"`
	ReauthSeconds  int                 `json:"reauth_seconds"`
	Hmac           string              `json:"hmac"`
	NewlyAdded     bool                `json:"newly_added"`
	RealmName      string              `json:"realm_name"`
	ServerHost     string              `json:"server_host"`
	AuthorityKind  string              `json:"authority_kind"` // "server" or "master"
	MasterURL      string              `json:"master_url"`     // populated when this source is a server in a realm whose master is online
	FailoverPeers  []string            `json:"failover_peers"`
	PushConfig     CollectorPushConfig `json:"push_config"`
}

// validCollectorID restricts the CN to "collector-..." prefix (same
// pattern validMasterID uses for masters). Operators browsing the
// per-host master_cns / collector_cn entries can tell at a glance
// what role each cert represents.
func validCollectorID(id string) bool {
	if !strings.HasPrefix(id, "collector-") {
		return false
	}
	return validAgentID(id)
}

// errCollectorSlotTaken / errCollectorSlotClosed are sentinel errors
// returned by claimCollectorSlot so handlers can map them to the
// right HTTP status without parsing strings.
var (
	errCollectorSlotTaken  = fmt.Errorf("collector slot already taken by a different CN")
	errCollectorSlotClosed = fmt.Errorf("collector slot closed; run `accept-next` first")
)

// handleCollectorPreflightOnServer is c15 — server-side mirror of the
// master-side handler. Lets a server-paired collector install do the
// same "gather all info up front" check as a master-paired one.
// Non-mutating, PSK-authenticated.
func (s *serverState) handleCollectorPreflightOnServer(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := remoteIP(r)
	if !s.enrollLimiter.allow(ip) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req struct {
		PSK string `json:"psk"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	currentPSK, perr := readEnrollPSK()
	if perr != nil || currentPSK == "" {
		currentPSK = s.enrollPSK
	}
	gotRaw, gerr := pskRawBytes(req.PSK)
	wantRaw, werr := pskRawBytes(currentPSK)
	if gerr != nil || werr != nil || subtle.ConstantTimeCompare(gotRaw, wantRaw) != 1 {
		s.logAuthFailure(r, "collector-preflight")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	cfg := loadConfig(s.configPath)
	slotState := "open"
	currentCN := cfg.Server.CollectorCN
	pending := cfg.Server.CollectorPendingEnroll
	switch {
	case currentCN != "" && !pending:
		slotState = "filled"
	case currentCN == "" && !pending:
		slotState = "closed"
	case pending:
		slotState = "open"
	}
	if slotState == "closed" {
		http.Error(w, "collector slot is closed; run `simplesiem certs collector accept-next` first", http.StatusServiceUnavailable)
		return
	}
	resp := MasterPreflightInfo{
		URL:           cfg.Server.Listen,
		HealthOK:      true,
		ListenerOK:    true,
		AuthorityKind: "server",
		RealmName:     cfg.Server.Realm.Name,
		PeerCount:     len(cfg.Server.Realm.Peers),
		SlotState:     slotState,
		CurrentCN:     currentCN,
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// handleEnrollCollector signs CSRs from a collector and records the
// CN in CollectorCN. Single-slot enforcement: refuses any enrollment
// unless CollectorPendingEnroll is true OR the requesting CN matches
// the existing CollectorCN (re-enroll same identity).
//
// Concurrency: the slot claim acquires allowlistEditMu BEFORE checking
// the slot state, so two concurrent valid enrollments cannot both
// succeed. The losing thread sees errCollectorSlotTaken and returns
// 403 without signing a cert.
func (s *serverState) handleEnrollCollector(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := remoteIP(r)
	if !s.enrollLimiter.allow(ip) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var er CollectorEnrollRequest
	if err := json.Unmarshal(body, &er); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	currentPSK, perr := readEnrollPSK()
	if perr != nil || currentPSK == "" {
		currentPSK = s.enrollPSK
	}
	gotRaw, gerr := pskRawBytes(er.PSK)
	wantRaw, werr := pskRawBytes(currentPSK)
	if gerr != nil || werr != nil || subtle.ConstantTimeCompare(gotRaw, wantRaw) != 1 {
		s.logAuthFailure(r, "enroll-collector")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !validCollectorID(er.CollectorID) {
		http.Error(w, "invalid collector_id (must start with `collector-`)", http.StatusBadRequest)
		return
	}

	// Validate CSR before claiming the slot — a malformed request
	// shouldn't burn the operator's `accept-next` flag.
	csrBlock, _ := pem.Decode([]byte(er.CSRPem))
	if csrBlock == nil {
		http.Error(w, "csr_pem is not PEM", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		http.Error(w, "parse CSR: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, "csr signature: "+err.Error(), http.StatusBadRequest)
		return
	}
	if csr.Subject.CommonName != er.CollectorID {
		http.Error(w, "csr CN must equal collector_id", http.StatusBadRequest)
		return
	}

	// Atomically check + claim the slot. Any concurrent enrollment that
	// raced with us is rejected here without ever reaching the signer.
	added, err := assignCollectorCNToConfig(s.configPath, er.CollectorID)
	switch err {
	case errCollectorSlotTaken:
		http.Error(w, "another collector is already associated with this server. Run `simplesiem certs collector revoke` first to free the slot.", http.StatusForbidden)
		return
	case errCollectorSlotClosed:
		http.Error(w, "this server is not currently accepting collector enrollments. Run `simplesiem certs collector accept-next` first.", http.StatusForbidden)
		return
	case nil:
		// fallthrough — slot is ours
	default:
		s.broadcastErr("enroll-collector", fmt.Errorf("update collector_cn: %v", err))
		http.Error(w, "could not persist collector_cn", http.StatusInternalServerError)
		return
	}

	caCert, caKey, err := loadCAFromDisk(s.certsDir)
	if err != nil {
		s.broadcastErr("enroll-collector", fmt.Errorf("load CA: %v", err))
		http.Error(w, "server missing CA", http.StatusServiceUnavailable)
		return
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: er.CollectorID, Organization: []string{"SimpleSIEM"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(s.enrollClientYears, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		s.broadcastErr("enroll-collector", fmt.Errorf("sign cert: %v", err))
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	clientPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))

	caPem, err := buildRealmCABundle(s.certsDir)
	if err != nil {
		http.Error(w, "build CA bundle: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cfg := loadConfig(s.configPath)
	s.realmMu.RLock()
	realm := s.realmName
	peers := append([]string{}, s.realmPeers...)
	masterURL := cfg.Server.Realm.MasterURL
	s.realmMu.RUnlock()

	resp := CollectorEnrollResponse{
		CertPem:       clientPem,
		CAPem:         caPem,
		ReauthSeconds: s.reauthSeconds,
		NewlyAdded:    added,
		RealmName:     realm,
		ServerHost:    s.selfPeerID,
		AuthorityKind: "server",
		MasterURL:     masterURL,
		FailoverPeers: peers,
	}
	resp.Hmac = computeEnrollHMAC(wantRaw, resp.CertPem, resp.CAPem, resp.ReauthSeconds, resp.RealmName, []string{resp.ServerHost})

	if mst, gerr := s.storageFor("_server"); gerr == nil {
		mst.Write("meta", map[string]any{
			"event":        "collector_enrolled",
			"collector_cn": er.CollectorID,
			"newly_added":  added,
			"remote":       r.RemoteAddr,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// assignCollectorCNToConfig atomically checks the single-collector
// slot state and claims it for cn in one critical section. Returns:
//   - (false, nil) when re-enrolling the same CN (slot was already
//     filled with this exact CN; pending flag cleared defensively).
//   - (true, nil) when claiming an open slot (newly added).
//   - (_, errCollectorSlotTaken) when another CN holds the slot.
//   - (_, errCollectorSlotClosed) when no CN holds the slot AND the
//     pending flag isn't set (operator hasn't run accept-next).
//
// Holding allowlistEditMu across the check+save eliminates the TOCTOU
// race that allowed two concurrent enrollments to both pass an
// out-of-lock check and both succeed.
func assignCollectorCNToConfig(cfgPath, cn string) (bool, error) {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	currentCN := cfg.Server.CollectorCN
	pending := cfg.Server.CollectorPendingEnroll
	if currentCN != "" && currentCN != cn {
		return false, errCollectorSlotTaken
	}
	if currentCN == "" && !pending {
		return false, errCollectorSlotClosed
	}
	if currentCN == cn {
		cfg.Server.CollectorPendingEnroll = false
		_ = saveConfig(cfgPath, cfg)
		return false, nil
	}
	cfg.Server.CollectorCN = cn
	cfg.Server.CollectorPendingEnroll = false
	if err := saveConfig(cfgPath, cfg); err != nil {
		return false, err
	}
	return true, nil
}

// runCollectorCmd dispatches `simplesiem collector <subcommand>`.
func runCollectorCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem collector <subcommand> [args]

  enroll <url> --key <PSK>     Enroll this collector with a server (or master).
                               Generates a keypair locally, sends a CSR, receives
                               a signed cert, stores it under <config>/collector/<source>/.

  promote <master-url> --key <PSK>
                               Switch this collector's source from a server to
                               the realm's master. Use after the source server
                               reports a `+"`master_url`"+` via the
                               meta:collector_authority_promotion_available event.

  queue-promote --key <PSK>    (r21) Stage the master's collector PSK so the
                               daemon auto-promotes on the next pull cycle
                               when the source surfaces a master_url. Saves
                               the PSK to <state>/master_promote.psk (mode 0600).

  queue-repair --key <PSK>     (c5) Stage a realm PSK so the daemon auto-pairs
                               with a failover server if the primary source is
                               unreachable past collector.repair_after_minutes
                               (default 30). Saves the PSK to
                               <state>/realm_repair.psk (mode 0600).

  realm-servers <subcmd>       (c4) Multi-server enrollment when no master is
                               paired. Subcommands: accept-next | list | revoke <cn>.
                               Servers run "simplesiem server query-collector enroll"
                               against this collector to land in realm_server_cns.

  interval <duration>          Set the pull interval (e.g. "1h", "24h", "5m").

  status                       Show source URL, watermark, last pull time, current
                               authority hint, failover list.`)
		os.Exit(2)
	}
	switch args[0] {
	case "enroll":
		runCollectorEnroll(args[1:], false)
	case "promote":
		runCollectorEnroll(args[1:], true)
	case "queue-promote":
		runCollectorQueuePromote(args[1:])
	case "queue-repair":
		runCollectorQueueRepair(args[1:])
	case "interval":
		runCollectorInterval(args[1:])
	case "status":
		runCollectorStatus(args[1:])
	case "master":
		runCollectorMasterCmd(args[1:])
	case "realm-servers":
		runCollectorRealmServersCmd(args[1:])
	default:
		fatalf("unknown collector subcommand: %s", args[0])
	}
}

// runCollectorEnroll generates a keypair, sends a CSR to /v1/enroll-collector,
// validates the response HMAC, writes the cert + key + CA to disk,
// updates collector.source_url + failover_servers + authority_hint
// in config.
func runCollectorEnroll(args []string, isPromote bool) {
	args = permuteArgs(args, map[string]bool{"config": true, "key": true, "id": true})
	fs := flag.NewFlagSet("collector enroll", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	psk := fs.String("key", "", "enrollment PSK from `simplesiem certs psk show` on the source")
	colID := fs.String("id", "", "collector ID (CN); defaults to collector-<hostname>")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		if isPromote {
			fatalf("usage: simplesiem collector promote <master-url> --key <PSK>")
		}
		fatalf("usage: simplesiem collector enroll <url> --key <PSK>")
	}
	if *psk == "" {
		fatalf("--key is required (PSK from the source's `simplesiem certs psk show`)")
	}
	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}
	sourceURL := strings.TrimRight(fs.Arg(0), "/")
	parsed, err := url.Parse(sourceURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		fatalf("source URL must be an https URL with a host (got %q)", sourceURL)
	}
	hostname, _ := os.Hostname()
	id := *colID
	if id == "" {
		id = "collector-" + hostname
	}
	if !validCollectorID(id) {
		fatalf("collector ID %q is invalid (must be `collector-` followed by alphanumeric/.-_)", id)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fatalf("generate key: %v", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: id, Organization: []string{"SimpleSIEM"}}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		fatalf("build CSR: %v", err)
	}
	csrPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	body, _ := json.Marshal(CollectorEnrollRequest{PSK: *psk, CollectorID: id, CSRPem: csrPem})
	// #nosec G402 -- bootstrap-only; HMAC-over-PSK authenticates the response.
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs()}, TLSHandshakeTimeout: 10 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPost, sourceURL+"/v1/enroll-collector", bytes.NewReader(body))
	if err != nil {
		fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fatalf("contact source: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		fatalf("source rejected enrollment (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var er CollectorEnrollResponse
	if err := json.Unmarshal(rb, &er); err != nil {
		fatalf("parse source response: %v", err)
	}
	if er.CertPem == "" || er.CAPem == "" || er.Hmac == "" {
		fatalf("source response missing required fields")
	}
	pskRaw, perr := pskRawBytes(*psk)
	if perr != nil {
		fatalf("--key: %v", perr)
	}
	expected := computeEnrollHMAC(pskRaw, er.CertPem, er.CAPem, er.ReauthSeconds, er.RealmName, []string{er.ServerHost})
	if subtle.ConstantTimeCompare([]byte(er.Hmac), []byte(expected)) != 1 {
		fatalf("response HMAC mismatch — possible MITM, or PSK on source differs from --key value")
	}
	// Defence-in-depth: even though the HMAC binds the response to a
	// PSK only the source knows, validate ServerHost matches a safe
	// directory-name pattern so a compromised source can't path-traverse
	// out of the collector cert root via filepath.Join + Clean.
	if !validHostName.MatchString(er.ServerHost) {
		fatalf("source returned an unsafe server_host %q (must match a hostname pattern); refusing to write cert dir", er.ServerHost)
	}
	cfg := loadConfig(*cfgPath)
	// Cert dir name MUST match peerIDFromURL(sourceURL) so the
	// daemon's pickCollectorSource lookup finds the cert. Using
	// er.ServerHost (the source's hostname) silently breaks when the
	// operator dialed by IP — same bug class as master enrollment.
	urlID := peerIDFromURL(sourceURL)
	if urlID == "" {
		fatalf("could not parse hostname from source URL %q", sourceURL)
	}
	dir := filepath.Join(collectorCertsDir(cfg), urlID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		fatalf("create cert dir: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		fatalf("write key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte(er.CertPem), 0o644); err != nil {
		fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte(er.CAPem), 0o644); err != nil {
		fatalf("write CA: %v", err)
	}
	cfg.Collector.SourceURL = sourceURL
	cfg.Collector.FailoverServers = append([]string{}, er.FailoverPeers...)
	if cfg.Collector.CollectorID == "" {
		cfg.Collector.CollectorID = id
	}
	if er.PushConfig.PullIntervalSeconds > 0 {
		cfg.Collector.PullIntervalSeconds = er.PushConfig.PullIntervalSeconds
	}
	cfg.Collector.AuthorityHint = er.AuthorityKind
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("save config: %v", err)
	}
	verb := "enrolled"
	if isPromote {
		verb = "promoted"
	}
	fmt.Println("Collector", verb, "with", sourceURL)
	fmt.Println("  collector_id:  ", id)
	fmt.Println("  authority:     ", er.AuthorityKind)
	fmt.Println("  realm:         ", er.RealmName)
	fmt.Println("  cert dir:      ", dir)
	fmt.Println("  failover peers:", len(er.FailoverPeers))
	if er.MasterURL != "" && !isPromote {
		fmt.Println()
		fmt.Println("Note: this source reports a master at", er.MasterURL+".")
		fmt.Println("Run `simplesiem collector promote", er.MasterURL, "--key <master's PSK>`")
		fmt.Println("to switch this collector's source to the master.")
	}
	fmt.Println()
	fmt.Println("Next: sudo simplesiem start  (or restart the collector daemon)")
}

// runCollectorInterval is `simplesiem collector interval <duration>`.
func runCollectorInterval(args []string) {
	if len(args) == 0 {
		fatalf("usage: simplesiem collector interval <duration> (e.g. 1h, 24h, 5m)")
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	d, err := time.ParseDuration(args[0])
	if err != nil {
		fatalf("invalid duration: %v", err)
	}
	if d < time.Minute {
		fatalf("interval must be at least 1 minute")
	}
	if err := setCollectorPullInterval(defaultConfigPath(), int(d.Seconds())); err != nil {
		fatalf("save: %v", err)
	}
	fmt.Println("collector pull interval set to", d)
}

// runCollectorStatus is `simplesiem collector status`.
func runCollectorStatus(args []string) {
	cfg := loadConfig(defaultConfigPath())
	fmt.Println("Collector configuration:")
	fmt.Println("  source_url:      ", cfg.Collector.SourceURL)
	fmt.Println("  authority:       ", cfg.Collector.AuthorityHint)
	fmt.Println("  collector_id:    ", cfg.Collector.CollectorID)
	fmt.Println("  pull_interval:   ", time.Duration(effectivePullInterval(cfg))*time.Second)
	fmt.Println("  failover servers:", len(cfg.Collector.FailoverServers))
	for _, p := range cfg.Collector.FailoverServers {
		fmt.Println("                    ", p)
	}
}

// runCertsCollectorCmd handles `simplesiem certs collector
// <accept-next|revoke|status>` — the operator-side controls for the
// single-collector slot enforced by handleEnrollCollector.
func runCertsCollectorCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem certs collector <accept-next|revoke|status>

  accept-next   Open the slot so the next /v1/enroll-collector request can succeed.
                Refused if a collector is already associated.
  revoke        Clear the currently associated collector_cn so a different host can enroll.
  status        Show the current slot state.`)
		os.Exit(2)
	}
	switch args[0] {
	case "accept-next":
		runCertsCollectorAcceptNext(args[1:])
	case "revoke":
		runCertsCollectorRevoke(args[1:])
	case "status":
		runCertsCollectorStatus(args[1:])
	default:
		fatalf("unknown certs collector subcommand: %s", args[0])
	}
}

func runCertsCollectorAcceptNext(args []string) {
	fs := flag.NewFlagSet("certs collector accept-next", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(*cfgPath)
	if cfg.Server.CollectorCN != "" {
		fatalf("collector slot is already taken by %q. Run `simplesiem certs collector revoke` to free it first.", cfg.Server.CollectorCN)
	}
	if cfg.Server.CollectorPendingEnroll {
		fmt.Println("Collector slot is already open and waiting for an enrollment.")
		return
	}
	cfg.Server.CollectorPendingEnroll = true
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("save config: %v", err)
	}
	fmt.Println("Collector slot opened. The next /v1/enroll-collector request will succeed.")
	fmt.Println("Run `simplesiem certs collector status` to confirm; cancel with `simplesiem certs collector revoke`.")
}

func runCertsCollectorRevoke(args []string) {
	fs := flag.NewFlagSet("certs collector revoke", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(*cfgPath)
	had := cfg.Server.CollectorCN
	cfg.Server.CollectorCN = ""
	cfg.Server.CollectorPendingEnroll = false
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("save config: %v", err)
	}
	if had == "" {
		fmt.Println("No collector was associated; pending flag cleared.")
		return
	}
	fmt.Println("Cleared collector association:", had)
	fmt.Println("Run `simplesiem certs collector accept-next` before the next enrollment attempt.")
}

func runCertsCollectorStatus(args []string) {
	fs := flag.NewFlagSet("certs collector status", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	cfg := loadConfig(*cfgPath)
	fmt.Println("Collector slot:")
	if cfg.Server.CollectorCN != "" {
		fmt.Println("  state:        associated")
		fmt.Println("  collector_cn:", cfg.Server.CollectorCN)
		return
	}
	if cfg.Server.CollectorPendingEnroll {
		fmt.Println("  state: open (next enrollment will succeed)")
		return
	}
	fmt.Println("  state: closed (run `simplesiem certs collector accept-next` to open)")
}

// We import "flag" only when this file is built; keep the alias here
// so go-import re-ordering doesn't trip on it.
var _ = flag.NewFlagSet
