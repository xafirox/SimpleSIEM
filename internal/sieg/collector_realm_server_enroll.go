package sieg

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// c4 — multi-server collector enrollment.
//
// In a realm with no master, EVERY server should be able to query the
// collector for forensic / audit work. The existing /v1/enroll-master
// path is single-slot (one master, with a corresponding "I'm the
// canonical querier" semantics). Servers can't share that slot.
//
// /v1/enroll-realm-server is the multi-server analogue: every realm
// server that runs `simplesiem server query-collector enroll` lands
// its CN in cfg.Collector.RealmServerCNs (a list, not a slot). Once
// in the list, a server's mTLS calls to /v1/sync/events succeed.
//
// The list is gated on the collector side by an accept-next flag —
// without that, a leaked PSK could enroll an unbounded number of
// CNs silently. accept-next opens the door for ONE new CN to enroll,
// then closes again. Re-enrollment of an already-listed CN never
// trips accept-next (idempotent).
//
// When a master is paired with the collector, this endpoint refuses:
// the master is the canonical querier and every server's collector
// queries must route through it.

// MasterEnrollResponse is reused as the wire shape — same fields,
// different meaning of NewlyAdded.

// handleEnrollRealmServer is the multi-server enrollment handler. The
// caller's CN is added to cfg.Collector.RealmServerCNs; subsequent
// /v1/sync/events calls from that CN are accepted.
func (c *collectorListenerState) handleEnrollRealmServer(w http.ResponseWriter, r *http.Request) {
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
		c.logAuthFailure(r, "enroll-realm-server")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !validRealmServerID(er.MasterID) {
		http.Error(w, "invalid server_id (must start with `server-`)", http.StatusBadRequest)
		return
	}
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
		http.Error(w, "csr CN must equal server_id", http.StatusBadRequest)
		return
	}

	// Atomic: refuse when a master is paired (master is canonical),
	// otherwise add the CN to the list. Re-enrollment of a CN
	// already in the list is idempotent.
	added, err := assignCollectorRealmServerCN(c.configPath, er.MasterID)
	switch err {
	case errCollectorMasterPaired:
		http.Error(w, "this collector has a master paired — collector queries are the master's responsibility. The master must run `simplesiem master query-collector enroll`; servers do not enroll directly when a master is present.", http.StatusForbidden)
		return
	case errCollectorRealmServerSlotClosed:
		http.Error(w, "this collector is not currently accepting realm-server enrollments. Run `simplesiem collector realm-servers accept-next` first to open the slot for this enrollment.", http.StatusForbidden)
		return
	case nil:
	default:
		c.storage.Write("errors", map[string]any{
			"collector": "master_listener",
			"event":     "realm_server_persist_failed",
			"error":     err.Error(),
		})
		http.Error(w, "could not persist realm_server_cns", http.StatusInternalServerError)
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
		NotBefore:    time.Now().Add(-24 * time.Hour),
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
		"event":       "collector_realm_server_enrolled",
		"server_cn":   er.MasterID,
		"newly_added": added,
		"remote":      r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// validRealmServerID restricts the CN to "server-..." prefix to keep
// the collector-side allowlist self-describing.
func validRealmServerID(id string) bool {
	if !strings.HasPrefix(id, "server-") {
		return false
	}
	return validAgentID(id)
}

// errCollectorMasterPaired / errCollectorRealmServerSlotClosed are
// sentinel errors mapped to specific HTTP statuses by the handler.
var (
	errCollectorMasterPaired          = fmt.Errorf("collector has a master paired; realm-server enrollment refused")
	errCollectorRealmServerSlotClosed = fmt.Errorf("collector realm-server slot closed; run `accept-next` first")
)

// assignCollectorRealmServerCN adds cn to the collector's
// RealmServerCNs list. Returns:
//   - (false, nil) when re-enrolling an already-present CN (idempotent;
//     the pending flag stays unchanged).
//   - (true, nil) when adding a new CN — consumes the pending flag.
//   - (_, errCollectorMasterPaired) when a master is currently paired.
//   - (_, errCollectorRealmServerSlotClosed) when the new-CN attempt
//     would land but accept-next hasn't been opened.
func assignCollectorRealmServerCN(cfgPath, cn string) (bool, error) {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	if cfg.Collector.MasterCN != "" {
		return false, errCollectorMasterPaired
	}
	for _, existing := range cfg.Collector.RealmServerCNs {
		if existing == cn {
			return false, nil
		}
	}
	if !cfg.Collector.RealmServerPendingEnroll {
		return false, errCollectorRealmServerSlotClosed
	}
	cfg.Collector.RealmServerCNs = append(cfg.Collector.RealmServerCNs, cn)
	cfg.Collector.RealmServerPendingEnroll = false
	if err := saveConfig(cfgPath, cfg); err != nil {
		return false, err
	}
	return true, nil
}

// runCollectorRealmServersCmd dispatches `simplesiem collector
// realm-servers <accept-next|list|revoke>`.
func runCollectorRealmServersCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem collector realm-servers <subcommand>

  accept-next        Open the slot for the next realm-server enrollment.
                     A leaked PSK alone cannot enroll a new CN — it must
                     also race the accept-next flag, which is one-shot.
  list               Show the CNs currently allowed to query this collector
                     plus whether a master is paired (which suppresses this list).
  revoke <cn>        Remove a CN from the realm-server list. The corresponding
                     server's mTLS calls will be rejected on the next handshake.`)
		os.Exit(2)
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	cfgPath := defaultConfigPath()
	switch args[0] {
	case "accept-next":
		allowlistEditMu.Lock()
		cfg := loadConfig(cfgPath)
		if cfg.Collector.MasterCN != "" {
			allowlistEditMu.Unlock()
			fatalf("a master is paired with this collector (master_cn=%q) — realm servers cannot enroll while the master holds the canonical-querier role. Run `simplesiem collector master revoke` to unpair the master first if you want to switch to multi-server mode.", cfg.Collector.MasterCN)
		}
		cfg.Collector.RealmServerPendingEnroll = true
		if err := saveConfig(cfgPath, cfg); err != nil {
			allowlistEditMu.Unlock()
			fatalf("save config: %v", err)
		}
		allowlistEditMu.Unlock()
		fmt.Println("Realm-server slot opened. The next /v1/enroll-realm-server request will succeed.")
		fmt.Println()
		fmt.Println("On the realm server, run:")
		fmt.Println("  sudo simplesiem server query-collector enroll https://<this-collector>:9446 --key $(simplesiem collector master show-psk)")
	case "list":
		cfg := loadConfig(cfgPath)
		if cfg.Collector.MasterCN != "" {
			fmt.Println("paired master:", cfg.Collector.MasterCN)
			fmt.Println("realm servers: (suppressed — a master is the canonical querier)")
			return
		}
		fmt.Println("paired master: (none)")
		fmt.Printf("realm servers (%d):\n", len(cfg.Collector.RealmServerCNs))
		for _, cn := range cfg.Collector.RealmServerCNs {
			fmt.Println("  -", cn)
		}
		if cfg.Collector.RealmServerPendingEnroll {
			fmt.Println("accept-next: OPEN (one CN may enroll)")
		} else {
			fmt.Println("accept-next: closed")
		}
	case "revoke":
		if len(args) < 2 {
			fatalf("usage: simplesiem collector realm-servers revoke <cn>")
		}
		want := args[1]
		allowlistEditMu.Lock()
		cfg := loadConfig(cfgPath)
		out := cfg.Collector.RealmServerCNs[:0]
		removed := false
		for _, cn := range cfg.Collector.RealmServerCNs {
			if cn == want {
				removed = true
				continue
			}
			out = append(out, cn)
		}
		if !removed {
			allowlistEditMu.Unlock()
			fatalf("CN %q is not in realm_server_cns", want)
		}
		cfg.Collector.RealmServerCNs = append([]string{}, out...)
		if err := saveConfig(cfgPath, cfg); err != nil {
			allowlistEditMu.Unlock()
			fatalf("save config: %v", err)
		}
		allowlistEditMu.Unlock()
		fmt.Printf("Removed %q from realm_server_cns. The corresponding server's mTLS calls will be rejected on the next handshake.\n", want)
	default:
		fatalf("unknown collector realm-servers subcommand: %s", args[0])
	}
}
