package sieg

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Master collector listener. Phase 2 of the collector role.
//
// The master can optionally expose a TLS endpoint that a single
// collector pulls from. The listener serves the master's collected
// events (everything it's aggregated from the realm's servers)
// alongside enrollment + cert rotation for the paired collector.
//
// Single-collector rule mirrors the server-side rule. cfg.Master
// has its own CollectorCN / CollectorPendingEnroll fields; the
// master refuses any /v1/enroll-collector request unless the slot
// is open. The PSK is independent from any server's PSK so a
// compromised server PSK does not let an attacker enroll a
// collector against the master.
//
// Routes exposed:
//   - GET  /v1/health             (no client cert required)
//   - GET  /v1/sync/events        (mTLS, CN must equal CollectorCN)
//   - GET  /v1/sync/config        (mTLS, CN must equal CollectorCN)
//   - POST /v1/enroll-collector   (PSK auth, single-slot enforced)
//   - POST /v1/rotate             (mTLS, collector cert auto-rotation)

// masterListenerState is the master-side counterpart to serverState
// but specialised to the collector use case. Kept independent so the
// master's listener stays small and focused.
type masterListenerState struct {
	configPath        string
	certsDir          string
	logDir            string
	pskPath           string
	enrollClientYears int
	reauthSeconds     int
	enrollLimiter     *rateLimiter
	storage           *Storage
	failsMu           sync.Mutex
	fails             map[string]*authFailRate
}

// startMasterCollectorListener spins up the master's TLS listener for
// the paired collector when cfg.Master.CollectorListen is set. Returns
// the *http.Server so the caller can shut it down on context cancel.
//
// Best-effort: bind / TLS errors are logged to the master's storage
// and the master continues without the listener (the rest of master
// mode keeps working).
func startMasterCollectorListener(ctx context.Context, wg *sync.WaitGroup, cfg Config, cfgPath string, masterStore *Storage) {
	addr := strings.TrimSpace(cfg.Master.CollectorListen)
	if addr == "" {
		return
	}
	if cfg.Master.Cert == "" || cfg.Master.Key == "" || cfg.Master.CACert == "" {
		msg := "master.collector_listen is set but master.cert / master.key / master.ca_cert are empty"
		hint := "run: sudo simplesiem master collector enable --listen " + addr
		masterStore.Write("errors", map[string]any{
			"collector": "master_listener",
			"error":     msg,
			"hint":      hint,
		})
		// Also emit to stderr so the operator sees the warning at start
		// time rather than only when triaging logs.
		io.WriteString(os.Stderr, "warning: master collector listener disabled — "+msg+"\n  hint: "+hint+"\n")
		return
	}

	bundle, err := newTrustBundle(cfg.Master.CACert, "")
	if err != nil {
		masterStore.Write("errors", map[string]any{
			"collector": "master_listener",
			"error":     "trust bundle: " + err.Error(),
		})
		return
	}
	tlsCfg, _, err := serverTLSConfig(ServerConfig{
		Cert:              cfg.Master.Cert,
		Key:               cfg.Master.Key,
		CACert:            cfg.Master.CACert,
		RequireClientCert: true,
	}, bundle)
	if err != nil {
		masterStore.Write("errors", map[string]any{
			"collector": "master_listener",
			"error":     "tls: " + err.Error(),
		})
		return
	}

	cdir := filepath.Dir(cfg.Master.CACert)
	if cdir == "" || cdir == "." {
		cdir = filepath.Join(filepath.Dir(cfgPath), "certs")
	}
	pskPath := cfg.Master.CollectorEnrollPSKPath
	if pskPath == "" {
		pskPath = defaultMasterCollectorPSKPath()
	}

	st := &masterListenerState{
		configPath:        cfgPath,
		certsDir:          cdir,
		logDir:            cfg.LogDir,
		pskPath:           pskPath,
		enrollClientYears: 5,
		reauthSeconds:     60,
		// Match server.enrollLimiter shape: 1/sec, burst 3.
		enrollLimiter: newRateLimiter(1, 3),
		storage:       masterStore,
		fails:         map[string]*authFailRate{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", st.handleHealth)
	mux.HandleFunc("/v1/sync/events", st.handleSyncEvents)
	mux.HandleFunc("/v1/sync/config", st.handleSyncConfig)
	mux.HandleFunc("/v1/enroll-collector", st.handleEnrollCollector)
	mux.HandleFunc("/v1/collector-preflight", st.handleCollectorPreflight)
	mux.HandleFunc("/v1/rotate", st.handleRotate)
	// Graceful collector departure endpoint. Collector calls this
	// from its uninstall path so the master frees the single
	// collector slot without waiting for a heartbeat to lapse.
	mux.HandleFunc("/v1/collector/depart", st.handleCollectorDepartOnMaster)
	// Collectors paired with a master report their own default
	// gateway up so the realm allowlist stays in sync. Same body
	// shape as the server-side /v1/collector/gateway handler.
	mux.HandleFunc("/v1/collector/gateway", func(w http.ResponseWriter, r *http.Request) {
		st.handleCollectorGatewayReportMaster(w, r)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         tlsCfg,
		MaxHeaderBytes:    32 * 1024,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		masterStore.Write("meta", map[string]any{
			"event":  "master_collector_listener_start",
			"listen": addr,
		})
		// ListenAndServeTLS blocks; certs already loaded into TLSConfig.
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			masterStore.Write("errors", map[string]any{
				"collector": "master_listener",
				"error":     err.Error(),
			})
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
}

// defaultMasterCollectorPSKPath: per-master PSK file independent of
// the server's enroll.psk. Located under <state>/master/.
func defaultMasterCollectorPSKPath() string {
	return filepath.Join(defaultStateDir(), "master", "collector_enroll.psk")
}

// readMasterCollectorPSK loads the master's collector-enrollment PSK,
// returning an empty string + error when missing. Callers that want to
// auto-create on first use should call ensureMasterCollectorPSK.
func readMasterCollectorPSK(path string) (string, error) {
	if path == "" {
		path = defaultMasterCollectorPSKPath()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// ensureMasterCollectorPSK creates the PSK file if missing, with the
// same format/permissions as the server's enroll.psk. Idempotent.
func ensureMasterCollectorPSK(path string) (string, error) {
	if path == "" {
		path = defaultMasterCollectorPSKPath()
	}
	if existing, err := readMasterCollectorPSK(path); err == nil && existing != "" {
		return existing, nil
	}
	// 0o700 on the parent so a non-admin user on the same host can't
	// even enumerate the PSK file. The PSK itself is 0o600 below.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	raw := make([]byte, enrollPSKBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	psk := enrollPSKPrefix + hex.EncodeToString(raw)
	if err := os.WriteFile(path, []byte(psk+"\n"), 0o600); err != nil {
		return "", err
	}
	return psk, nil
}

// authorisedCollectorCN returns the collector CN currently associated
// with this master, if any.
func (m *masterListenerState) authorisedCollectorCN() string {
	cfg := loadConfig(m.configPath)
	return cfg.Master.CollectorCN
}

// requireCollectorMTLS gates non-enrollment routes: the caller's mTLS
// CN must equal the master's currently-associated CollectorCN. Refused
// when the slot is empty (no collector is associated yet — there is
// nothing to authorise).
func (m *masterListenerState) requireCollectorMTLS(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	if cn == "" {
		return false
	}
	want := m.authorisedCollectorCN()
	if want == "" {
		return false
	}
	return cn == want
}

func (m *masterListenerState) logAuthFailure(r *http.Request, route string) {
	ip := remoteIP(r)
	now := time.Now()
	m.failsMu.Lock()
	rate, ok := m.fails[ip]
	if !ok || now.Sub(rate.first) > time.Minute {
		rate = &authFailRate{first: now}
		m.fails[ip] = rate
	}
	rate.count++
	emit := now.Sub(rate.lastLog) > 30*time.Second || rate.count == 1
	if emit {
		rate.lastLog = now
	}
	count := rate.count
	m.failsMu.Unlock()
	if !emit {
		return
	}
	m.storage.Write("errors", map[string]any{
		"collector": "master_listener",
		"route":     route,
		"remote":    ip,
		"count":     count,
		"hint":      "repeated auth failure on master collector listener",
	})
}

func (m *masterListenerState) handleHealth(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(`{"ok":true,"role":"master"}`))
}

// handleSyncEvents serves the collector with every event the master
// has aggregated newer than `since`. The master has no native ingress
// of its own (its <log_dir>/<host>/<type>/*.from-<peer>.jsonl files are
// the only source), so unlike the server handler this one INCLUDES the
// .from-* files — that's the master's entire log corpus.
//
// Local-collection events under <log_dir>/<localID>/<type>/<date>.jsonl
// (the master's own host activity) are also included so the collector
// has visibility into the master's own state.
func (m *masterListenerState) handleSyncEvents(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !m.requireCollectorMTLS(r) {
		m.logAuthFailure(r, "sync/events")
		http.Error(w, "not the associated collector", http.StatusForbidden)
		return
	}
	since := time.Time{}
	if q := r.URL.Query().Get("since"); q != "" {
		if t, err := time.Parse(time.RFC3339Nano, q); err == nil {
			since = t
		}
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)

	hosts, _ := os.ReadDir(m.logDir)
	for _, h := range hosts {
		if !h.IsDir() {
			continue
		}
		// Skip diagnostic dirs; they're not part of the event corpus.
		if strings.HasPrefix(h.Name(), "_") {
			continue
		}
		if !validHostName.MatchString(h.Name()) {
			continue
		}
		hostDir := filepath.Join(m.logDir, h.Name())
		_ = filepath.WalkDir(hostDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(d.Name(), ".jsonl") {
				return nil
			}
			date := dateFromLogName(d.Name())
			if !date.IsZero() && !since.IsZero() && date.Before(since.Truncate(24*time.Hour)) {
				return nil
			}
			f, ferr := os.Open(path)
			if ferr != nil {
				return nil
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			for scanner.Scan() {
				var ev SyncEvent
				if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
					continue
				}
				if rs, _ := ev["received_at"].(string); rs != "" {
					if t, perr := time.Parse(time.RFC3339Nano, rs); perr == nil {
						if !since.IsZero() && !t.After(since) {
							continue
						}
					}
				}
				if eerr := enc.Encode(ev); eerr != nil {
					return eerr
				}
			}
			return nil
		})
	}
}

// handleSyncConfig identifies as a master and surfaces the
// CollectorPushConfig the operator has set.
func (m *masterListenerState) handleSyncConfig(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if !m.requireCollectorMTLS(r) {
		m.logAuthFailure(r, "sync/config")
		http.Error(w, "not the associated collector", http.StatusForbidden)
		return
	}
	cfg := loadConfig(m.configPath)
	resp := map[string]any{
		"authority_kind": "master",
		"role":           "master",
		// master_url empty: the master IS the master, no further promotion
		// path. Collectors that hit this branch stay paired here.
	}
	if cfg.Master.CollectorPushConfig.PullIntervalSeconds > 0 {
		resp["collector_push_config"] = map[string]any{
			"pull_interval_seconds": cfg.Master.CollectorPushConfig.PullIntervalSeconds,
		}
	}
	// Surface the master's full trusted-CA bundle (current + legacy)
	// so the collector can detect a CA rotation and refresh its
	// own ca.pem proactively. Without this, the collector's bundle
	// only catches up on the next cert rotation, which may be years
	// away if the cert was freshly issued.
	if bundle, err := buildRealmCABundle(m.certsDir); err == nil {
		resp["ca_bundle"] = bundle
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleCollectorDepartOnMaster is the master-listener counterpart
// to the server's /v1/collector/depart endpoint. Invoked by a
// collector's uninstall path so the master frees the single
// collector slot immediately rather than waiting for a heartbeat
// timeout. mTLS-authenticated; the caller's CN must equal the
// currently-bound CollectorCN — anyone else is a different
// collector trying to bump the legitimate one and gets refused.
func (m *masterListenerState) handleCollectorDepartOnMaster(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cn := clientCN(r)
	if cn == "" {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(m.configPath)
	if cfg.Master.CollectorCN != cn {
		http.Error(w, "collector CN does not match the bound slot", http.StatusForbidden)
		return
	}
	cfg.Master.CollectorCN = ""
	cfg.Master.CollectorPendingEnroll = false
	if err := saveConfig(m.configPath, cfg); err != nil {
		http.Error(w, "save config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if m.storage != nil {
		m.storage.Write("meta", map[string]any{
			"event":     "collector_departed",
			"collector": cn,
			"reason":    "collector invoked graceful uninstall",
		})
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// handleCollectorPreflight is c15 — gathers all the information a
// prospective collector needs to know about this master BEFORE the
// collector commits any local state change. The collector calls this
// from `validateCollectorReadyForInstall` so an operator running
// `simplesiem install --mode collector --master URL --master-key PSK`
// gets a single, actionable error if the master is missing
// prerequisites (listener up but slot closed, slot open but PSK
// rotated, slot filled by another collector, etc.) rather than
// hitting a partial install.
//
// The endpoint is PSK-authenticated (same PSK that /v1/enroll-collector
// would use) so a stranger can't probe slot state. Non-mutating: the
// preflight never claims the slot, never signs a cert, never writes
// state — it just reports what's there.
func (m *masterListenerState) handleCollectorPreflight(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := remoteIP(r)
	if !m.enrollLimiter.allow(ip) {
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
	currentPSK, perr := readMasterCollectorPSK(m.pskPath)
	if perr != nil || currentPSK == "" {
		http.Error(w, "master collector PSK not configured", http.StatusServiceUnavailable)
		return
	}
	gotRaw, gerr := pskRawBytes(req.PSK)
	wantRaw, werr := pskRawBytes(currentPSK)
	if gerr != nil || werr != nil || subtle.ConstantTimeCompare(gotRaw, wantRaw) != 1 {
		m.logAuthFailure(r, "collector-preflight")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	cfg := loadConfig(m.configPath)
	slotState := "open"
	currentCN := cfg.Master.CollectorCN
	pending := cfg.Master.CollectorPendingEnroll
	switch {
	case currentCN != "" && !pending:
		slotState = "filled"
	case currentCN == "" && !pending:
		slotState = "closed"
	case pending:
		slotState = "open"
	}

	// 503 / 409 mirror the same status codes /v1/enroll-collector
	// would emit if the operator went directly to the install. The
	// preflight surfaces them BEFORE state mutation so the operator
	// has a clear path back to fix it on the master side.
	if slotState == "closed" {
		http.Error(w, "collector slot is closed; run `simplesiem master collector accept-next` first", http.StatusServiceUnavailable)
		return
	}
	// "filled" with a different CN is a hard 409 — the operator must
	// either revoke the existing collector or re-enroll the same CN.
	// We can't tell from inside the preflight which CN the caller is
	// going to use, so we surface the current CN and let the caller
	// decide.
	if slotState == "filled" {
		// Pass through with a hint; the caller decides whether to
		// proceed (re-enrolling same CN) or abort.
	}

	resp := MasterPreflightInfo{
		URL:           cfg.Master.CollectorListen,
		HealthOK:      true,
		ListenerOK:    true,
		AuthorityKind: "master",
		RealmName:     cfg.Server.Realm.Name,
		PeerCount:     len(cfg.Server.Realm.Peers),
		SlotState:     slotState,
		CurrentCN:     currentCN,
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// handleEnrollCollector signs the collector's CSR using the master's
// CA. Single-slot enforcement mirrors the server-side rule.
func (m *masterListenerState) handleEnrollCollector(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := remoteIP(r)
	if !m.enrollLimiter.allow(ip) {
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
	currentPSK, perr := readMasterCollectorPSK(m.pskPath)
	if perr != nil || currentPSK == "" {
		http.Error(w, "master collector PSK not configured", http.StatusServiceUnavailable)
		return
	}
	gotRaw, gerr := pskRawBytes(er.PSK)
	wantRaw, werr := pskRawBytes(currentPSK)
	if gerr != nil || werr != nil || subtle.ConstantTimeCompare(gotRaw, wantRaw) != 1 {
		m.logAuthFailure(r, "enroll-collector")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !validCollectorID(er.CollectorID) {
		http.Error(w, "invalid collector_id (must start with `collector-`)", http.StatusBadRequest)
		return
	}

	// Validate CSR before claiming the slot — a malformed request must
	// not burn the operator's `accept-next` flag.
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

	// Atomic check-and-claim: any concurrent enrollment racing this
	// one is rejected here, never reaching the signer.
	added, err := assignMasterCollectorCN(m.configPath, er.CollectorID)
	switch err {
	case errCollectorSlotTaken:
		http.Error(w, "another collector is already associated with this master. Run `simplesiem master collector revoke` first to free the slot.", http.StatusForbidden)
		return
	case errCollectorSlotClosed:
		http.Error(w, "this master is not currently accepting collector enrollments. Run `simplesiem master collector accept-next` first.", http.StatusForbidden)
		return
	case nil:
		// fallthrough — slot is ours
	default:
		m.storage.Write("errors", map[string]any{
			"collector": "master_listener",
			"event":     "collector_slot_persist_failed",
			"error":     err.Error(),
			"remote":    r.RemoteAddr,
		})
		http.Error(w, "could not persist collector_cn", http.StatusInternalServerError)
		return
	}

	caCert, caKey, err := loadCAFromDisk(m.certsDir)
	if err != nil {
		http.Error(w, "master missing CA: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: er.CollectorID, Organization: []string{"SimpleSIEM"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(m.enrollClientYears, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	clientPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))

	caPem, err := buildRealmCABundle(m.certsDir)
	if err != nil {
		http.Error(w, "build CA bundle: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cfg := loadConfig(m.configPath)
	hostname, _ := os.Hostname()
	// ServerHost MUST match the peerIDFromURL that the collector
	// derives from cfg.Collector.SourceURL — the collector uses it
	// as the cert-dir name and pickCollectorSource looks up exactly
	// that name. A "master-"-prefixed ServerHost would put the cert
	// at <root>/master-<host> while the lookup would search
	// <root>/<host> and silently report "no reachable source".
	resp := CollectorEnrollResponse{
		CertPem:       clientPem,
		CAPem:         caPem,
		ReauthSeconds: m.reauthSeconds,
		NewlyAdded:    added,
		ServerHost:    hostname,
		AuthorityKind: "master",
		PushConfig:    cfg.Master.CollectorPushConfig,
	}
	resp.Hmac = computeEnrollHMAC(wantRaw, resp.CertPem, resp.CAPem, resp.ReauthSeconds, resp.RealmName, []string{resp.ServerHost})

	m.storage.Write("meta", map[string]any{
		"event":        "master_collector_enrolled",
		"collector_cn": er.CollectorID,
		"newly_added":  added,
		"remote":       r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// handleRotate signs a fresh client cert for the collector. mTLS gate:
// the caller's CN must equal the master's CollectorCN.
func (m *masterListenerState) handleRotate(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !m.requireCollectorMTLS(r) {
		m.logAuthFailure(r, "rotate")
		http.Error(w, "not the associated collector", http.StatusForbidden)
		return
	}
	caller := r.TLS.PeerCertificates[0].Subject.CommonName
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req RotateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	csrBlock, _ := pem.Decode([]byte(req.CSRPem))
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
	if csr.Subject.CommonName != caller {
		http.Error(w, "csr CN must equal the calling cert CN (no cross-identity rotation)", http.StatusBadRequest)
		return
	}
	caCert, caKey, err := loadCAFromDisk(m.certsDir)
	if err != nil {
		http.Error(w, "master missing CA", http.StatusServiceUnavailable)
		return
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: caller, Organization: []string{"SimpleSIEM"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(m.enrollClientYears, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	clientPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))
	caBundle, err := buildRealmCABundle(m.certsDir)
	if err != nil {
		http.Error(w, "build CA bundle: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := RotateResponse{
		CertPem:  clientPem,
		CABundle: caBundle,
		NotAfter: tmpl.NotAfter.UTC().Format(time.RFC3339),
	}
	m.storage.Write("meta", map[string]any{
		"event":  "master_collector_cert_rotated",
		"cn":     caller,
		"remote": r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// assignMasterCollectorCN is the master-side counterpart to
// assignCollectorCNToConfig. Same atomic check-and-claim semantics:
// returns errCollectorSlotTaken / errCollectorSlotClosed when the
// slot is occupied or closed, so the caller maps to HTTP 403 without
// signing a cert.
func assignMasterCollectorCN(cfgPath, cn string) (bool, error) {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	currentCN := cfg.Master.CollectorCN
	pending := cfg.Master.CollectorPendingEnroll
	if currentCN != "" && currentCN != cn {
		return false, errCollectorSlotTaken
	}
	if currentCN == "" && !pending {
		return false, errCollectorSlotClosed
	}
	if currentCN == cn {
		cfg.Master.CollectorPendingEnroll = false
		_ = saveConfig(cfgPath, cfg)
		return false, nil
	}
	cfg.Master.CollectorCN = cn
	cfg.Master.CollectorPendingEnroll = false
	if err := saveConfig(cfgPath, cfg); err != nil {
		return false, err
	}
	return true, nil
}

// runMasterCollectorCmd dispatches `simplesiem master collector
// <enable|disable|accept-next|revoke|status|show-psk|rotate-psk|push-interval>`.
func runMasterCollectorCmd(args []string) {
	if len(args) == 0 {
		printUsageMasterCollector()
		os.Exit(2)
	}
	switch args[0] {
	case "enable":
		runMasterCollectorEnable(args[1:])
	case "disable":
		runMasterCollectorDisable(args[1:])
	case "accept-next":
		runMasterCollectorAcceptNext(args[1:])
	case "revoke":
		runMasterCollectorRevoke(args[1:])
	case "status":
		runMasterCollectorStatus(args[1:])
	case "show-psk":
		runMasterCollectorShowPSK(args[1:])
	case "rotate-psk":
		runMasterCollectorRotatePSK(args[1:])
	case "push-interval":
		runMasterCollectorPushInterval(args[1:])
	default:
		fatalf("unknown master collector subcommand: %s", args[0])
	}
}

func printUsageMasterCollector() {
	out := "usage: simplesiem master collector <subcommand> [args]\n\n" +
		"  enable --listen <addr>     Enable the master's collector listener (TLS).\n" +
		"                             Auto-bootstraps the master's PKI when missing.\n" +
		"  disable                    Disable the listener and clear the slot.\n" +
		"  accept-next                Open the slot for the next enrollment.\n" +
		"  revoke                     Clear the currently-associated collector.\n" +
		"  status                     Show listen address + slot state.\n" +
		"  show-psk                   Print the master collector PSK.\n" +
		"  rotate-psk                 Generate a new master collector PSK.\n" +
		"  push-interval <duration>   Set the pushed collector pull interval.\n"
	io.WriteString(os.Stderr, out)
}

func runMasterCollectorEnable(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "listen": true})
	fs := flag.NewFlagSet("master collector enable", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	listen := fs.String("listen", ":9445", "TLS listen address for the collector listener")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	allowlistEditMu.Lock()
	cfg := loadConfig(*cfgPath)
	// Bootstrap PKI if missing — same shape as runCertsInit but
	// scoped to <config_dir>/certs/. Re-uses ensureServerPKI so the
	// master ends up with a CA + a server cert covering its hostname.
	if cfg.Master.CACert == "" {
		certsDir := filepath.Join(filepath.Dir(*cfgPath), "certs")
		cfg.Master.CACert = filepath.Join(certsDir, "ca.pem")
		cfg.Master.Cert = filepath.Join(certsDir, "server.pem")
		cfg.Master.Key = filepath.Join(certsDir, "server.key")
	}
	cfg.Master.CollectorListen = *listen
	if cfg.Master.CollectorEnrollPSKPath == "" {
		cfg.Master.CollectorEnrollPSKPath = defaultMasterCollectorPSKPath()
	}
	if err := saveConfig(*cfgPath, cfg); err != nil {
		allowlistEditMu.Unlock()
		fatalf("save config: %v", err)
	}
	allowlistEditMu.Unlock()

	if _, lines, err := ensureServerPKI(*cfgPath, 10, 5); err != nil {
		fatalf("PKI bootstrap failed: %v", err)
	} else {
		for _, l := range lines {
			io.WriteString(os.Stdout, "  "+l+"\n")
		}
	}
	psk, err := ensureMasterCollectorPSK(cfg.Master.CollectorEnrollPSKPath)
	if err != nil {
		fatalf("create master collector PSK: %v", err)
	}
	io.WriteString(os.Stdout, "Master collector listener enabled at "+*listen+".\n")
	io.WriteString(os.Stdout, "  PSK: "+psk+"\n")
	io.WriteString(os.Stdout, "  Run `simplesiem stop && simplesiem start` to apply.\n")
	io.WriteString(os.Stdout, "  Then on the collector host:\n")
	io.WriteString(os.Stdout, "    sudo simplesiem master collector accept-next\n")
	io.WriteString(os.Stdout, "    sudo simplesiem collector promote https://<master-host>"+*listen+" --key "+psk+"\n")
}

func runMasterCollectorDisable(args []string) {
	fs := flag.NewFlagSet("master collector disable", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(*cfgPath)
	cfg.Master.CollectorListen = ""
	cfg.Master.CollectorCN = ""
	cfg.Master.CollectorPendingEnroll = false
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("save config: %v", err)
	}
	io.WriteString(os.Stdout, "Master collector listener disabled. Restart the daemon to release the port.\n")
}

func runMasterCollectorAcceptNext(args []string) {
	fs := flag.NewFlagSet("master collector accept-next", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(*cfgPath)
	if cfg.Master.CollectorCN != "" {
		fatalf("master collector slot is already taken by %q. Run `simplesiem master collector revoke` first.", cfg.Master.CollectorCN)
	}
	if cfg.Master.CollectorPendingEnroll {
		io.WriteString(os.Stdout, "Master collector slot is already open and waiting.\n")
		return
	}
	cfg.Master.CollectorPendingEnroll = true
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("save config: %v", err)
	}
	io.WriteString(os.Stdout, "Master collector slot opened. The next /v1/enroll-collector request will succeed.\n")
}

func runMasterCollectorRevoke(args []string) {
	fs := flag.NewFlagSet("master collector revoke", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(*cfgPath)
	had := cfg.Master.CollectorCN
	cfg.Master.CollectorCN = ""
	cfg.Master.CollectorPendingEnroll = false
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("save config: %v", err)
	}
	if had == "" {
		io.WriteString(os.Stdout, "No master-side collector was associated; pending flag cleared.\n")
		return
	}
	io.WriteString(os.Stdout, "Cleared master-side collector association: "+had+"\n")
}

func runMasterCollectorStatus(args []string) {
	fs := flag.NewFlagSet("master collector status", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	cfg := loadConfig(*cfgPath)
	io.WriteString(os.Stdout, "Master collector listener:\n")
	io.WriteString(os.Stdout, "  listen:        "+cfg.Master.CollectorListen+"\n")
	io.WriteString(os.Stdout, "  cert:          "+cfg.Master.Cert+"\n")
	io.WriteString(os.Stdout, "  ca:            "+cfg.Master.CACert+"\n")
	if cfg.Master.CollectorCN != "" {
		io.WriteString(os.Stdout, "  slot state:    associated\n")
		io.WriteString(os.Stdout, "  collector_cn:  "+cfg.Master.CollectorCN+"\n")
	} else if cfg.Master.CollectorPendingEnroll {
		io.WriteString(os.Stdout, "  slot state:    open (waiting for next enrollment)\n")
	} else {
		io.WriteString(os.Stdout, "  slot state:    closed\n")
	}
	io.WriteString(os.Stdout, "  push interval: "+fmtSeconds(cfg.Master.CollectorPushConfig.PullIntervalSeconds)+"\n")
}

func runMasterCollectorShowPSK(args []string) {
	fs := flag.NewFlagSet("master collector show-psk", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	cfg := loadConfig(*cfgPath)
	path := cfg.Master.CollectorEnrollPSKPath
	if path == "" {
		path = defaultMasterCollectorPSKPath()
	}
	psk, err := readMasterCollectorPSK(path)
	if err != nil {
		fatalf("read PSK: %v\n  hint: run `simplesiem master collector enable` first", err)
	}
	io.WriteString(os.Stdout, psk+"\n")
}

func runMasterCollectorRotatePSK(args []string) {
	fs := flag.NewFlagSet("master collector rotate-psk", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	force := fs.Bool("force", false, "rotate even if a collector is already associated")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	cfg := loadConfig(*cfgPath)
	if cfg.Master.CollectorCN != "" && !*force {
		fatalf("master collector %q is already associated; pass --force to rotate the PSK anyway (associated cert is unaffected)", cfg.Master.CollectorCN)
	}
	path := cfg.Master.CollectorEnrollPSKPath
	if path == "" {
		path = defaultMasterCollectorPSKPath()
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fatalf("remove old PSK: %v", err)
	}
	psk, err := ensureMasterCollectorPSK(path)
	if err != nil {
		fatalf("rotate PSK: %v", err)
	}
	io.WriteString(os.Stdout, "Rotated master collector PSK:\n  "+psk+"\n")
}

func runMasterCollectorPushInterval(args []string) {
	if len(args) == 0 {
		fatalf("usage: simplesiem master collector push-interval <duration>")
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	d, err := time.ParseDuration(args[0])
	if err != nil {
		fatalf("invalid duration: %v", err)
	}
	if d < time.Minute {
		fatalf("interval must be >= 1m")
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(defaultConfigPath())
	cfg.Master.CollectorPushConfig.PullIntervalSeconds = int(d.Seconds())
	if err := saveConfig(defaultConfigPath(), cfg); err != nil {
		fatalf("save config: %v", err)
	}
	io.WriteString(os.Stdout, "Master will push pull_interval_seconds="+fmtSeconds(int(d.Seconds()))+" to its paired collector on each pull cycle.\n")
}

func fmtSeconds(s int) string {
	if s <= 0 {
		return "(unset)"
	}
	return (time.Duration(s) * time.Second).String()
}

