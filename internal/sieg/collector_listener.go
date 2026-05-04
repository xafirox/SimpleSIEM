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

// Collector master-query listener.
//
// The collector accumulates the entire event corpus (server-pulled +
// master-pulled + own host) and is typically the longest-retention
// component in a deployment. The paired master may have a smaller
// retention window; when it needs to look further back than its own
// store, it queries the collector via this TLS listener.
//
// Single-master rule mirrors the single-collector rule on the master
// side. The collector pairs with exactly one master; once paired, no
// other master may enroll until the operator clears the slot.
//
// Routes exposed on cfg.Collector.MasterListen:
//   - GET  /v1/health           (no client cert required)
//   - GET  /v1/sync/events      (mTLS, CN must equal MasterCN)
//   - GET  /v1/sync/config      (mTLS, CN must equal MasterCN)
//   - POST /v1/enroll-master    (PSK auth, single-slot enforced)
//   - POST /v1/rotate           (mTLS, master cert auto-rotation)

type collectorListenerState struct {
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

// startCollectorMasterListener spins up the collector's TLS listener
// for a paired master when cfg.Collector.MasterListen is set. Same
// best-effort startup pattern as startMasterCollectorListener — bind
// failures log loudly to stderr + the local errors store and the rest
// of collector mode keeps working.
func startCollectorMasterListener(ctx context.Context, wg *sync.WaitGroup, cfg Config, cfgPath string, collectorStore *Storage) {
	addr := strings.TrimSpace(cfg.Collector.MasterListen)
	if addr == "" {
		return
	}
	if cfg.Collector.Cert == "" || cfg.Collector.Key == "" || cfg.Collector.CACert == "" {
		msg := "collector.master_listen is set but collector.cert / collector.key / collector.ca_cert are empty"
		hint := "run: sudo simplesiem collector master enable --listen " + addr
		collectorStore.Write("errors", map[string]any{
			"collector": "master_listener",
			"error":     msg,
			"hint":      hint,
		})
		io.WriteString(os.Stderr, "warning: collector master listener disabled — "+msg+"\n  hint: "+hint+"\n")
		return
	}
	bundle, err := newTrustBundle(cfg.Collector.CACert, "")
	if err != nil {
		collectorStore.Write("errors", map[string]any{
			"collector": "master_listener",
			"error":     "trust bundle: " + err.Error(),
		})
		return
	}
	tlsCfg, _, err := serverTLSConfig(ServerConfig{
		Cert:              cfg.Collector.Cert,
		Key:               cfg.Collector.Key,
		CACert:            cfg.Collector.CACert,
		RequireClientCert: true,
	}, bundle)
	if err != nil {
		collectorStore.Write("errors", map[string]any{
			"collector": "master_listener",
			"error":     "tls: " + err.Error(),
		})
		return
	}
	cdir := filepath.Dir(cfg.Collector.CACert)
	if cdir == "" || cdir == "." {
		cdir = filepath.Join(filepath.Dir(cfgPath), "certs")
	}
	pskPath := cfg.Collector.MasterEnrollPSKPath
	if pskPath == "" {
		pskPath = defaultCollectorMasterPSKPath()
	}

	st := &collectorListenerState{
		configPath:        cfgPath,
		certsDir:          cdir,
		logDir:            cfg.LogDir,
		pskPath:           pskPath,
		enrollClientYears: 5,
		reauthSeconds:     60,
		enrollLimiter:     newRateLimiter(1, 3),
		storage:           collectorStore,
		fails:             map[string]*authFailRate{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", st.handleHealth)
	mux.HandleFunc("/v1/sync/events", st.handleSyncEvents)
	mux.HandleFunc("/v1/sync/config", st.handleSyncConfig)
	mux.HandleFunc("/v1/enroll-master", st.handleEnrollMaster)
	// c4 — multi-server enrollment when no master is paired. Realm
	// servers can each enroll concurrently and query the collector.
	mux.HandleFunc("/v1/enroll-realm-server", st.handleEnrollRealmServer)
	mux.HandleFunc("/v1/rotate", st.handleRotate)
	// Master cascade uninstall — gated by collector.master_can_uninstall.
	// The master invokes this when it runs `master uninstall-all` to
	// trigger the collector's own teardown.
	mux.HandleFunc("/v1/master/uninstall-collector", st.handleMasterUninstallCollector)
	// Backup endpoint: same shape as the server's /v1/backup/create.
	// Lets the paired master run `master backup --collector <out>`.
	// Auth: caller must be the paired master (requireMasterMTLS).
	mux.HandleFunc("/v1/backup/create", st.handleBackupCreateOnCollector)
	// c8 — master pushes rules.json to the collector so the rule
	// set is in place when c7's failsafe-query mode kicks in. Uses
	// the same on-disk format as the server's rules.json + the
	// same write+hot-reload pattern.
	mux.HandleFunc("/v1/master/push/rules", st.handleMasterPushRulesOnCollector)

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
		collectorStore.Write("meta", map[string]any{
			"event":  "collector_master_listener_start",
			"listen": addr,
		})
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			collectorStore.Write("errors", map[string]any{
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

func defaultCollectorMasterPSKPath() string {
	return filepath.Join(defaultStateDir(), "collector", "master_enroll.psk")
}

func readCollectorMasterPSK(path string) (string, error) {
	if path == "" {
		path = defaultCollectorMasterPSKPath()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func ensureCollectorMasterPSK(path string) (string, error) {
	if path == "" {
		path = defaultCollectorMasterPSKPath()
	}
	if existing, err := readCollectorMasterPSK(path); err == nil && existing != "" {
		return existing, nil
	}
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

func (c *collectorListenerState) authorisedMasterCN() string {
	cfg := loadConfig(c.configPath)
	return cfg.Collector.MasterCN
}

// requireMasterMTLS — the caller's mTLS CN must equal the collector's
// currently-paired MasterCN. Refused when no master is paired.
func (c *collectorListenerState) requireMasterMTLS(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	if cn == "" {
		return false
	}
	want := c.authorisedMasterCN()
	if want == "" {
		return false
	}
	return cn == want
}

// requireMasterOrRealmServerMTLS (c4) — accepts the paired master OR
// any CN in cfg.Collector.RealmServerCNs. Used to gate the read-side
// /v1/sync/events path so multiple realm servers can each query the
// collector when no master is present. /v1/rotate, master push,
// uninstall etc. stay strictly master-only via requireMasterMTLS.
func (c *collectorListenerState) requireMasterOrRealmServerMTLS(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	if cn == "" {
		return false
	}
	cfg := loadConfig(c.configPath)
	if cfg.Collector.MasterCN != "" && cn == cfg.Collector.MasterCN {
		return true
	}
	for _, allowed := range cfg.Collector.RealmServerCNs {
		if cn == allowed {
			return true
		}
	}
	return false
}

func (c *collectorListenerState) logAuthFailure(r *http.Request, route string) {
	ip := remoteIP(r)
	now := time.Now()
	c.failsMu.Lock()
	rate, ok := c.fails[ip]
	if !ok || now.Sub(rate.first) > time.Minute {
		rate = &authFailRate{first: now}
		c.fails[ip] = rate
	}
	rate.count++
	emit := now.Sub(rate.lastLog) > 30*time.Second || rate.count == 1
	if emit {
		rate.lastLog = now
	}
	count := rate.count
	c.failsMu.Unlock()
	if !emit {
		return
	}
	c.storage.Write("errors", map[string]any{
		"collector": "master_listener",
		"route":     route,
		"remote":    ip,
		"count":     count,
		"hint":      "repeated auth failure on collector master listener",
	})
}

func (c *collectorListenerState) handleHealth(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(`{"ok":true,"role":"collector"}`))
}

// handleSyncEvents streams every event in the collector's log dir
// newer than `since`. The collector's storage layout is per-origin
// (mirrors master mode), so this function INCLUDES `.from-*` files
// — the master querying back wants the full archive, not the
// collector's own ingress (the collector has no native ingress except
// its own host). Local-collection events under
// <log_dir>/<localID>/<type>/<date>.jsonl are also included.
func (c *collectorListenerState) handleSyncEvents(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// c4 — accept the paired master OR any realm server in the
	// collector's RealmServerCNs list. Other endpoints (rotate, push,
	// uninstall) stay master-only via requireMasterMTLS.
	if !c.requireMasterOrRealmServerMTLS(r) {
		c.logAuthFailure(r, "sync/events")
		http.Error(w, "not the paired master or a realm server", http.StatusForbidden)
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

	hosts, _ := os.ReadDir(c.logDir)
	for _, h := range hosts {
		if !h.IsDir() {
			continue
		}
		// Skip diagnostic dirs (_collector etc.); they're not part of
		// the queryable corpus.
		if strings.HasPrefix(h.Name(), "_") {
			continue
		}
		if !validHostName.MatchString(h.Name()) {
			continue
		}
		hostDir := filepath.Join(c.logDir, h.Name())
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
				if jerr := json.Unmarshal(scanner.Bytes(), &ev); jerr != nil {
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

func (c *collectorListenerState) handleSyncConfig(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	// c4 — same auth posture as /v1/sync/events: paired master OR any
	// realm server in RealmServerCNs.
	if !c.requireMasterOrRealmServerMTLS(r) {
		c.logAuthFailure(r, "sync/config")
		http.Error(w, "not the paired master or a realm server", http.StatusForbidden)
		return
	}
	resp := map[string]any{
		"role": "collector",
	}
	if bundle, err := buildRealmCABundle(c.certsDir); err == nil {
		resp["ca_bundle"] = bundle
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleEnrollMaster signs the master's CSR. Single-slot enforcement
// mirrors handleEnrollCollector on the server / master sides.
func (c *collectorListenerState) handleEnrollMaster(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := remoteIP(r)
	if !c.enrollLimiter.allow(ip) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var er MasterEnrollRequest
	if err := json.Unmarshal(body, &er); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	currentPSK, perr := readCollectorMasterPSK(c.pskPath)
	if perr != nil || currentPSK == "" {
		http.Error(w, "collector master PSK not configured", http.StatusServiceUnavailable)
		return
	}
	gotRaw, gerr := pskRawBytes(er.PSK)
	wantRaw, werr := pskRawBytes(currentPSK)
	if gerr != nil || werr != nil || subtle.ConstantTimeCompare(gotRaw, wantRaw) != 1 {
		c.logAuthFailure(r, "enroll-master")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !validMasterID(er.MasterID) {
		http.Error(w, "invalid master_id (must start with `master-`)", http.StatusBadRequest)
		return
	}

	// CSR validation before slot claim.
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
	if csr.Subject.CommonName != er.MasterID {
		http.Error(w, "csr CN must equal master_id", http.StatusBadRequest)
		return
	}

	// Atomic check-and-claim.
	added, err := assignCollectorMasterCN(c.configPath, er.MasterID)
	switch err {
	case errCollectorSlotTaken:
		http.Error(w, "another master is already paired with this collector. Run `simplesiem collector master revoke` first to free the slot.", http.StatusForbidden)
		return
	case errCollectorSlotClosed:
		http.Error(w, "this collector is not currently accepting master enrollments. Run `simplesiem collector master accept-next` first.", http.StatusForbidden)
		return
	case nil:
	default:
		c.storage.Write("errors", map[string]any{
			"collector": "master_listener",
			"event":     "master_slot_persist_failed",
			"error":     err.Error(),
		})
		http.Error(w, "could not persist master_cn", http.StatusInternalServerError)
		return
	}

	caCert, caKey, lerr := loadCAFromDisk(c.certsDir)
	if lerr != nil {
		http.Error(w, "collector missing CA: "+lerr.Error(), http.StatusServiceUnavailable)
		return
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: er.MasterID, Organization: []string{"SimpleSIEM"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(c.enrollClientYears, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	clientPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))
	caPem, err := buildRealmCABundle(c.certsDir)
	if err != nil {
		http.Error(w, "build CA bundle: "+err.Error(), http.StatusInternalServerError)
		return
	}
	hostname, _ := os.Hostname()
	resp := MasterEnrollResponse{
		CertPem:       clientPem,
		CAPem:         caPem,
		ReauthSeconds: c.reauthSeconds,
		NewlyAdded:    added,
		ServerHost:    hostname,
		RealmName:     "(collector)",
	}
	resp.Hmac = computeEnrollHMAC(wantRaw, resp.CertPem, resp.CAPem, resp.ReauthSeconds, resp.RealmName, []string{resp.ServerHost})
	c.storage.Write("meta", map[string]any{
		"event":     "collector_master_enrolled",
		"master_cn": er.MasterID,
		"newly_added": added,
		"remote":    r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// handleRotate signs a fresh client cert for the master. Same shape
// as the master listener's rotate path: mTLS-only, the existing
// cert is the proof of identity.
func (c *collectorListenerState) handleRotate(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.requireMasterMTLS(r) {
		c.logAuthFailure(r, "rotate")
		http.Error(w, "not the paired master", http.StatusForbidden)
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
	caCert, caKey, err := loadCAFromDisk(c.certsDir)
	if err != nil {
		http.Error(w, "collector missing CA", http.StatusServiceUnavailable)
		return
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: caller, Organization: []string{"SimpleSIEM"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(c.enrollClientYears, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	clientPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))
	caBundle, err := buildRealmCABundle(c.certsDir)
	if err != nil {
		http.Error(w, "build CA bundle: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := RotateResponse{
		CertPem:  clientPem,
		CABundle: caBundle,
		NotAfter: tmpl.NotAfter.UTC().Format(time.RFC3339),
	}
	c.storage.Write("meta", map[string]any{
		"event":  "collector_master_cert_rotated",
		"cn":     caller,
		"remote": r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// assignCollectorMasterCN — mirror of assignMasterCollectorCN.
func assignCollectorMasterCN(cfgPath, cn string) (bool, error) {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	currentCN := cfg.Collector.MasterCN
	pending := cfg.Collector.MasterPendingEnroll
	if currentCN != "" && currentCN != cn {
		return false, errCollectorSlotTaken
	}
	if currentCN == "" && !pending {
		return false, errCollectorSlotClosed
	}
	if currentCN == cn {
		cfg.Collector.MasterPendingEnroll = false
		_ = saveConfig(cfgPath, cfg)
		return false, nil
	}
	cfg.Collector.MasterCN = cn
	cfg.Collector.MasterPendingEnroll = false
	if err := saveConfig(cfgPath, cfg); err != nil {
		return false, err
	}
	return true, nil
}

// runCollectorMasterCmd dispatches `simplesiem collector master <subcommand>`.
func runCollectorMasterCmd(args []string) {
	if len(args) == 0 {
		io.WriteString(os.Stderr, `usage: simplesiem collector master <subcommand> [args]

  enable --listen <addr>    Enable the collector's master-query listener (TLS).
                            Auto-bootstraps PKI when missing.
  disable                   Disable the listener and clear the slot.
  accept-next               Open the slot for the next master enrollment.
  revoke                    Clear the currently-paired master.
  status                    Show listen address + slot state.
  show-psk                  Print the collector master PSK.
  rotate-psk                Generate a new collector master PSK.
`)
		os.Exit(2)
	}
	switch args[0] {
	case "enable":
		runCollectorMasterEnable(args[1:])
	case "disable":
		runCollectorMasterDisable(args[1:])
	case "accept-next":
		runCollectorMasterAcceptNext(args[1:])
	case "revoke":
		runCollectorMasterRevoke(args[1:])
	case "status":
		runCollectorMasterStatus(args[1:])
	case "show-psk":
		runCollectorMasterShowPSK(args[1:])
	case "rotate-psk":
		runCollectorMasterRotatePSK(args[1:])
	default:
		fatalf("unknown collector master subcommand: %s", args[0])
	}
}

func runCollectorMasterEnable(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "listen": true})
	fs := flag.NewFlagSet("collector master enable", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	listen := fs.String("listen", ":9446", "TLS listen address for the master-query listener")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	allowlistEditMu.Lock()
	cfg := loadConfig(*cfgPath)
	if cfg.Collector.CACert == "" {
		certsDir := filepath.Join(filepath.Dir(*cfgPath), "certs")
		cfg.Collector.CACert = filepath.Join(certsDir, "ca.pem")
		cfg.Collector.Cert = filepath.Join(certsDir, "server.pem")
		cfg.Collector.Key = filepath.Join(certsDir, "server.key")
	}
	cfg.Collector.MasterListen = *listen
	if cfg.Collector.MasterEnrollPSKPath == "" {
		cfg.Collector.MasterEnrollPSKPath = defaultCollectorMasterPSKPath()
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
	psk, err := ensureCollectorMasterPSK(cfg.Collector.MasterEnrollPSKPath)
	if err != nil {
		fatalf("create collector master PSK: %v", err)
	}
	io.WriteString(os.Stdout, "Collector master listener enabled at "+*listen+".\n")
	io.WriteString(os.Stdout, "  PSK: "+psk+"\n")
	io.WriteString(os.Stdout, "  Run `simplesiem restart` to apply.\n")
	io.WriteString(os.Stdout, "  Then on the master:\n")
	io.WriteString(os.Stdout, "    sudo simplesiem collector master accept-next   (here on the collector)\n")
	io.WriteString(os.Stdout, "    sudo simplesiem master query-collector enroll https://<collector-host>"+*listen+" --key "+psk+"\n")
}

func runCollectorMasterDisable(args []string) {
	fs := flag.NewFlagSet("collector master disable", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(*cfgPath)
	cfg.Collector.MasterListen = ""
	cfg.Collector.MasterCN = ""
	cfg.Collector.MasterPendingEnroll = false
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("save config: %v", err)
	}
	io.WriteString(os.Stdout, "Collector master listener disabled. Restart the daemon to release the port.\n")
}

func runCollectorMasterAcceptNext(args []string) {
	fs := flag.NewFlagSet("collector master accept-next", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(*cfgPath)
	if cfg.Collector.MasterCN != "" {
		fatalf("collector master slot is already paired with %q. Run `simplesiem collector master revoke` first.", cfg.Collector.MasterCN)
	}
	if cfg.Collector.MasterPendingEnroll {
		io.WriteString(os.Stdout, "Collector master slot is already open and waiting.\n")
		return
	}
	cfg.Collector.MasterPendingEnroll = true
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("save config: %v", err)
	}
	io.WriteString(os.Stdout, "Collector master slot opened. The next /v1/enroll-master request will succeed.\n")
}

func runCollectorMasterRevoke(args []string) {
	fs := flag.NewFlagSet("collector master revoke", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(*cfgPath)
	had := cfg.Collector.MasterCN
	cfg.Collector.MasterCN = ""
	cfg.Collector.MasterPendingEnroll = false
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("save config: %v", err)
	}
	if had == "" {
		io.WriteString(os.Stdout, "No collector-side master was paired; pending flag cleared.\n")
		return
	}
	io.WriteString(os.Stdout, "Cleared collector-side master pairing: "+had+"\n")
}

func runCollectorMasterStatus(args []string) {
	fs := flag.NewFlagSet("collector master status", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	cfg := loadConfig(*cfgPath)
	io.WriteString(os.Stdout, "Collector master listener:\n")
	io.WriteString(os.Stdout, "  listen:        "+cfg.Collector.MasterListen+"\n")
	io.WriteString(os.Stdout, "  cert:          "+cfg.Collector.Cert+"\n")
	io.WriteString(os.Stdout, "  ca:            "+cfg.Collector.CACert+"\n")
	if cfg.Collector.MasterCN != "" {
		io.WriteString(os.Stdout, "  slot state:    paired\n")
		io.WriteString(os.Stdout, "  master_cn:     "+cfg.Collector.MasterCN+"\n")
	} else if cfg.Collector.MasterPendingEnroll {
		io.WriteString(os.Stdout, "  slot state:    open (waiting for next master enrollment)\n")
	} else {
		io.WriteString(os.Stdout, "  slot state:    closed\n")
	}
}

func runCollectorMasterShowPSK(args []string) {
	fs := flag.NewFlagSet("collector master show-psk", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	cfg := loadConfig(*cfgPath)
	path := cfg.Collector.MasterEnrollPSKPath
	if path == "" {
		path = defaultCollectorMasterPSKPath()
	}
	psk, err := readCollectorMasterPSK(path)
	if err != nil {
		fatalf("read PSK: %v\n  hint: run `simplesiem collector master enable` first", err)
	}
	io.WriteString(os.Stdout, psk+"\n")
}

func runCollectorMasterRotatePSK(args []string) {
	fs := flag.NewFlagSet("collector master rotate-psk", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	force := fs.Bool("force", false, "rotate even if a master is already paired")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	cfg := loadConfig(*cfgPath)
	if cfg.Collector.MasterCN != "" && !*force {
		fatalf("collector master %q is already paired; pass --force to rotate the PSK anyway", cfg.Collector.MasterCN)
	}
	path := cfg.Collector.MasterEnrollPSKPath
	if path == "" {
		path = defaultCollectorMasterPSKPath()
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fatalf("remove old PSK: %v", err)
	}
	psk, err := ensureCollectorMasterPSK(path)
	if err != nil {
		fatalf("rotate PSK: %v", err)
	}
	io.WriteString(os.Stdout, "Rotated collector master PSK:\n  "+psk+"\n")
}

// handleBackupCreateOnCollector is the collector's side of
// /v1/backup/create. The master invokes this when running
// `simplesiem master backup --collector <out>`. Same wire shape as
// the server's handleBackupCreate: JSON body with passphrase /
// compress / include_agents flags; response body IS the .siembak.
//
// Auth: caller must be the paired master (requireMasterMTLS — the
// same gate the existing /v1/sync/events handler uses on this
// listener). include_agents is silently ignored on the collector
// side because a collector has no per-agent storage groups
// distinct from its own log_dir.
func (c *collectorListenerState) handleBackupCreateOnCollector(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.requireMasterMTLS(r) {
		c.logAuthFailure(r, "backup/create")
		http.Error(w, "not the paired master", http.StatusForbidden)
		return
	}
	var req backupRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	cfg := loadConfig(c.configPath)

	tmp, err := os.CreateTemp("", "siem-collector-backup-*.siembak")
	if err != nil {
		http.Error(w, "tmpfile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	if err := createBackup(cfg, c.configPath, tmpPath, req.Passphrase, req.Compress); err != nil {
		http.Error(w, "backup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	f, err := os.Open(tmpPath)
	if err != nil {
		http.Error(w, "open tmp: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	_, _ = io.Copy(w, f)
}

// handleMasterPushRulesOnCollector receives a rules.json from the
// paired master and writes it to the collector's rules path. The
// collector doesn't fire rules at runtime (it's a backup replicator)
// but persists them so c7's failsafe-query path can replay against
// the corpus when the master is offline. Same wire shape as the
// server's handleMasterPushRules.
func (c *collectorListenerState) handleMasterPushRulesOnCollector(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.requireMasterMTLS(r) {
		c.logAuthFailure(r, "master/push/rules")
		http.Error(w, "not the paired master", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req MasterPushRulesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON envelope", http.StatusBadRequest)
		return
	}
	if req.RulesJSON == "" {
		http.Error(w, "rules_json is empty", http.StatusBadRequest)
		return
	}
	rules, err := parseRulesBytes([]byte(req.RulesJSON))
	if err != nil {
		http.Error(w, "rules failed validation: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg := loadConfig(c.configPath)
	rulesPath := cfg.RulesPath
	if rulesPath == "" {
		rulesPath = filepath.Join(filepath.Dir(c.configPath), "rules.json")
	}
	if existing, rerr := os.ReadFile(rulesPath); rerr == nil && len(existing) > 0 {
		_ = atomicWriteFile(rulesPath+".pre-master-push", existing, 0o640)
	}
	if err := atomicWriteFile(rulesPath, []byte(req.RulesJSON), 0o640); err != nil {
		http.Error(w, "write rules: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if c.storage != nil {
		c.storage.SetRules(rules)
		c.storage.Write("meta", map[string]any{
			"event":      "rules_pushed_by_master",
			"rule_count": len(rules),
			"path":       rulesPath,
		})
	}
	resp := MasterPushRulesResponse{
		Applied:   true,
		RuleCount: len(rules),
		Path:      rulesPath,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleMasterUninstallCollector is the receiving side of `master
// uninstall-all` on a paired collector. Authentication: caller must
// be the paired master (requireMasterMTLS) AND
// collector.master_can_uninstall must be true. Returns 200
// immediately, then runs the local uninstall asynchronously so the
// master's HTTP call completes before the collector daemon
// disappears (same pattern as handleMasterUninstallSelf on the
// server side).
func (c *collectorListenerState) handleMasterUninstallCollector(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.requireMasterMTLS(r) {
		c.logAuthFailure(r, "master/uninstall-collector")
		http.Error(w, "not the paired master", http.StatusForbidden)
		return
	}
	cfg := loadConfig(c.configPath)
	if !cfg.Collector.MasterCanUninstall {
		http.Error(w, "collector.master_can_uninstall is false; remote uninstall refused", http.StatusForbidden)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	var req struct {
		Purge  bool   `json:"purge"`
		Force  bool   `json:"force"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &req)

	if c.storage != nil {
		c.storage.Write("meta", map[string]any{
			"event":  "master_uninstall_received",
			"reason": req.Reason,
			"purge":  req.Purge,
			"hint":   "master uninstall-all cascade triggered local collector uninstall",
		})
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true,"queued":true}`))

	go runDetachedSelfUninstall(req.Purge)
}
