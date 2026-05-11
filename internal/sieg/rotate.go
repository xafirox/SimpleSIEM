package sieg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Auto-rotation: agents and masters renew their client cert before
// it expires by presenting the EXISTING cert (mTLS) and submitting a
// fresh CSR for the same CN. No PSK needed — the cert IS the proof
// of identity. Server signs from the same CA, returns the new cert,
// the agent atomically swaps its on-disk keypair.
//
// This decouples cert lifetime from operator workload: a 5-year cert
// renews itself in the background, the operator never sees it.
//
// Triggered by:
//   - the agent's heartbeat goroutine (agentRotateLoop): once the
//     local cert is within rotateThresholdDays of NotAfter, kick a
//     rotate. Retried on the next heartbeat if it fails.
//   - the master's per-server pull goroutine (masterRotateIfNeeded):
//     same threshold, same retry behaviour, but per-server (each
//     server signed its own master cert).
//
// rotateThresholdDays defaults to 30. Configurable via
// agent.cert_rotation_days (or master.cert_rotation_days for masters)
// in config.json. Setting it to 0 disables auto-rotation.

const defaultRotateThresholdDays = 30

// RotateRequest is the body of POST /v1/rotate. The CSR's CN must
// match the cert CN that authenticated this connection — the server
// refuses requests where the caller is asking to be issued a cert
// for a different identity.
type RotateRequest struct {
	CSRPem string `json:"csr_pem"`
}

// RotateResponse mirrors EnrollResponse without the PSK-derived HMAC
// (the caller's existing cert is the auth, not a PSK). The CA bundle
// is included so an agent that loses its trust set during a partial
// install can pick it back up.
type RotateResponse struct {
	CertPem  string `json:"cert_pem"`
	CABundle string `json:"ca_bundle"`
	NotAfter string `json:"not_after"`
}

// handleRotate signs a fresh client cert for the CN that authenticated
// this connection. mTLS-only: the existing cert is the proof of identity,
// so a stale cert can be rotated as long as it's still cryptographically
// valid AND the CN is still on the allowlist (or master_cns).
//
// We deliberately do NOT charge against enrollLimiter here — rotation
// happens silently in the background once per cert lifecycle, never
// in a brute-force pattern. The mTLS layer already gates by valid cert.
func (s *serverState) handleRotate(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client cert required", http.StatusUnauthorized)
		return
	}
	caller := r.TLS.PeerCertificates[0].Subject.CommonName
	if caller == "" {
		http.Error(w, "client cert has no CN", http.StatusUnauthorized)
		return
	}

	// Caller must currently be authorised to use that CN. For agents:
	// in agent_allowlist (and not revoked). For masters: in master_cns
	// (and not revoked). Nobody else can rotate.
	isAgent := validAgentID(caller) && !validMasterID(caller)
	isMaster := validMasterID(caller)
	switch {
	case isAgent:
		s.allowlistMu.RLock()
		size := len(s.allowlist)
		_, ok := s.allowlist[caller]
		s.allowlistMu.RUnlock()
		if size > 0 && !ok {
			http.Error(w, "agent not on allowlist (rotation blocked)", http.StatusForbidden)
			return
		}
		if s.agentRevokedAt(caller) != "" {
			http.Error(w, "agent revoked (rotation refused)", http.StatusForbidden)
			return
		}
	case isMaster:
		s.masterMu.RLock()
		known := false
		for _, cn := range s.masterCNs {
			if cn == caller {
				known = true
				break
			}
		}
		s.masterMu.RUnlock()
		if !known {
			http.Error(w, "master not in master_cns (rotation blocked)", http.StatusForbidden)
			return
		}
		if s.masterRevokedAt(caller) != "" {
			http.Error(w, "master revoked (rotation refused)", http.StatusForbidden)
			return
		}
	default:
		http.Error(w, "client CN is not a recognised agent or master", http.StatusForbidden)
		return
	}

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

	caCert, caKey, err := loadCAFromDisk(s.certsDir)
	if err != nil {
		s.broadcastErr("rotate", fmt.Errorf("load CA: %v", err))
		http.Error(w, "server missing CA", http.StatusServiceUnavailable)
		return
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: caller, Organization: []string{"SimpleSIEM"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(s.enrollClientYears, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		s.broadcastErr("rotate", fmt.Errorf("sign cert: %v", err))
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	clientPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))
	caBundle, err := buildRealmCABundle(s.certsDir)
	if err != nil {
		http.Error(w, "build CA bundle: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if mst, gerr := s.storageFor("_server"); gerr == nil {
		role := "agent"
		if isMaster {
			role = "master"
		}
		mst.Write("meta", map[string]any{
			"event":     "cert_rotated",
			"role":      role,
			"cn":        caller,
			"not_after": tmpl.NotAfter.Format(time.RFC3339),
			"remote":    r.RemoteAddr,
		})
	}

	resp := RotateResponse{
		CertPem:  clientPem,
		CABundle: caBundle,
		NotAfter: tmpl.NotAfter.UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// certNeedsRotation returns true when the cert at certPath expires
// within thresholdDays. Returns false on any read/parse error so a
// transient fs problem doesn't mass-trigger rotation requests.
func certNeedsRotation(certPath string, thresholdDays int) bool {
	if thresholdDays <= 0 {
		return false
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	threshold := time.Now().Add(time.Duration(thresholdDays) * 24 * time.Hour)
	return cert.NotAfter.Before(threshold)
}

// rotateClientCert generates a new EC P-256 keypair, sends a CSR to
// serverURL/v1/rotate over the existing mTLS connection (described by
// tlsCfg), validates the response, and atomically replaces the on-disk
// cert/key pair. Returns nil on success.
//
// caller is informational only — used in error messages so the agent
// or master logs make it clear which identity was being rotated.
func rotateClientCert(client *http.Client, serverURL, certPath, keyPath string, caller string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: caller, Organization: []string{"SimpleSIEM"}}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		return fmt.Errorf("build CSR: %w", err)
	}
	csrPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	body, _ := json.Marshal(RotateRequest{CSRPem: csrPem})
	req, err := http.NewRequest(http.MethodPost, serverURL+"/v1/rotate", &readerOnce{data: body})
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("contact server: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server rejected rotate (HTTP %d): %s", resp.StatusCode, string(rb))
	}
	var rr RotateResponse
	if err := json.Unmarshal(rb, &rr); err != nil {
		return fmt.Errorf("parse rotate response: %w", err)
	}
	if rr.CertPem == "" {
		return fmt.Errorf("server returned empty cert")
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Atomic swap: write tmp files, fsync, rename. Order matters —
	// write the key first so a crash between writes leaves the
	// (still-valid) old cert paired with the old key, never the new
	// cert with no key.
	if err := atomicWriteFile(keyPath, keyPem, 0o600); err != nil {
		return fmt.Errorf("write new key: %w", err)
	}
	if err := atomicWriteFile(certPath, []byte(rr.CertPem), 0o644); err != nil {
		return fmt.Errorf("write new cert: %w", err)
	}
	// Refresh the on-disk CA bundle when the server returned one. This
	// closes the rotation-cascade gap: when the source's CA rotated,
	// the bundle now contains current+legacy CAs and the next mTLS
	// handshake validates the source's new server cert. Best-effort —
	// failure here doesn't roll back the cert/key write since the
	// rotation itself succeeded; the CA bundle just stays one cycle
	// stale until the next successful rotate. We surface the error so
	// the caller can record it instead of silently degrading.
	if rr.CABundle != "" {
		caPath := filepath.Join(filepath.Dir(certPath), "ca.pem")
		if _, err := os.Stat(caPath); err == nil {
			if werr := atomicWriteFile(caPath, []byte(rr.CABundle), 0o644); werr != nil {
				return fmt.Errorf("rotate succeeded but CA bundle refresh failed: %w (next handshake may fail if the source's CA also rotated)", werr)
			}
		}
	}
	return nil
}

// readerOnce is a one-shot io.Reader that satisfies http.NewRequest
// without depending on bytes.NewReader (which the rotate file would
// otherwise pull in for a single use).
type readerOnce struct {
	data []byte
	off  int
}

func (r *readerOnce) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

// rotateAgentCertIfNeeded is invoked from the agent's heartbeat loop
// (one cycle in, after a successful beat) to check whether the local
// client cert is approaching expiry and renew it if so. Best-effort:
// any failure logs and retries on the next beat.
func rotateAgentCertIfNeeded(cfg AgentConfig, log *Storage, thresholdDays int, client *http.Client) {
	if !certNeedsRotation(cfg.ClientCert, thresholdDays) {
		return
	}
	cn := cfg.ID
	if cn == "" {
		// Defence in depth: ID should always be populated post-enroll.
		return
	}
	urlBase := normaliseRotateURL(cfg.ServerURL)
	if urlBase == "" {
		return
	}
	if err := rotateClientCert(client, urlBase, cfg.ClientCert, cfg.ClientKey, cn); err != nil {
		log.Write("errors", map[string]any{
			"collector": "agent_rotate",
			"error":     err.Error(),
			"hint":      "auto-rotation failed — will retry on next heartbeat. If the cert expires, agent must be re-enrolled.",
		})
		return
	}
	log.Write("meta", map[string]any{
		"event": "agent_cert_rotated",
		"hint":  "client cert renewed; the new cert is the live one as of now",
	})
}

// rotateMasterCertIfNeeded is the master-mode counterpart, invoked by
// each master pull goroutine before its sync cycle. The masterCertDir
// holds cert.pem/key.pem/ca.pem for one server; the rotation hits THAT
// server's /v1/rotate so the new cert is signed by the same CA.
func rotateMasterCertIfNeeded(serverURL, masterID, certDir string, thresholdDays int, client *http.Client, storage *Storage) {
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")
	if !certNeedsRotation(certPath, thresholdDays) {
		return
	}
	urlBase := normaliseRotateURL(serverURL)
	if urlBase == "" {
		return
	}
	if err := rotateClientCert(client, urlBase, certPath, keyPath, masterID); err != nil {
		if storage != nil {
			storage.Write("errors", map[string]any{
				"collector": "master_rotate",
				"server":    serverURL,
				"error":     err.Error(),
				"hint":      "auto-rotation failed — will retry on next sync cycle. If cert expires, re-enroll with: simplesiem master enroll <url> --key <PSK>",
			})
		}
		return
	}
	if storage != nil {
		storage.Write("meta", map[string]any{
			"event":     "master_cert_rotated",
			"server":    serverURL,
			"master_id": masterID,
		})
	}
}

// normaliseRotateURL strips a trailing slash so url + "/v1/rotate"
// produces a clean path. Returns "" if the input is empty so callers
// can no-op cleanly.
func normaliseRotateURL(u string) string {
	if u == "" {
		return ""
	}
	for len(u) > 0 && u[len(u)-1] == '/' {
		u = u[:len(u)-1]
	}
	return u
}
