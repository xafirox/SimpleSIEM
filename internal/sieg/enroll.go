package sieg

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PSK-based enrollment. The bootstrap problem is that an agent has no
// pre-shared CA when it first contacts the server, so we can't use
// regular mTLS for the first connection. Instead:
//
//   - The server holds one long-lived PSK (random 32 bytes, hex-encoded
//     for display) at <state>/enroll.psk. Anyone with it can mint a
//     client cert via /v1/enroll, so it's mode 0600 and rotatable.
//   - The agent presents the PSK + a CSR (the agent's private key never
//     leaves the host). The server signs the CSR with its CA and adds
//     the CN to agent_allowlist atomically.
//   - The /v1/enroll RESPONSE is HMAC'd with the PSK. The agent verifies
//     the HMAC before trusting the returned cert/CA. This means the agent
//     doesn't need to pre-know the server's cert: a MITM that doesn't
//     hold the PSK can't forge a valid response.
//
// After enrollment, all traffic uses regular mTLS (the agent now has the
// CA it needs to validate the server, and a client cert chained to the
// same CA). The PSK is never used again for that agent.

// enrollPSKPrefix is the visible string the operator pastes around. The
// hex secret follows. Keeping a fixed prefix means a stray clipboard
// fragment is recognisable as "this is a SimpleSIEM PSK".
const enrollPSKPrefix = "simplesiem-psk:"

// enrollPSKBytes is the raw PSK length. 32 bytes = 256 bits, encoded as
// 64 hex chars in the displayed token.
const enrollPSKBytes = 32

// EnrollRequest is the agent->server body for /v1/enroll.
type EnrollRequest struct {
	PSK     string `json:"psk"`      // simplesiem-psk:<hex>
	AgentID string `json:"agent_id"` // CN to use; must equal CSR CN
	CSRPem  string `json:"csr_pem"`  // PEM-encoded PKCS#10 CSR
}

// EnrollResponse is the server->agent body for /v1/enroll. Hmac is over
// (CertPem || CAPem || ReauthSeconds-as-decimal-string || RealmPeers
// joined by spaces) keyed by the raw PSK bytes; the agent verifies it
// before trusting the returned material.
type EnrollResponse struct {
	CertPem       string   `json:"cert_pem"`
	CAPem         string   `json:"ca_pem"`
	ReauthSeconds int      `json:"reauth_seconds"`
	Hmac          string   `json:"hmac"` // hex
	NewlyAdded    bool     `json:"newly_added"`
	// RealmName + RealmPeers tell the agent which redundancy group it
	// just joined and where to fail over if the primary server goes
	// down. Empty Peers means single-server deployment; the agent will
	// still work, just without failover.
	RealmName  string   `json:"realm_name"`
	RealmPeers []string `json:"realm_peers"`
}

// enrollPSKPath is the on-disk location of the server's PSK.
func enrollPSKPath() string {
	return filepath.Join(defaultStateDir(), "enroll.psk")
}

// generateEnrollPSK writes a fresh PSK to disk and returns the displayable
// string. Refuses to clobber an existing file unless force=true so a
// careless re-init doesn't lock out pending agent enrollments.
func generateEnrollPSK(force bool) (string, error) {
	path := enrollPSKPath()
	if !force {
		if _, err := os.Stat(path); err == nil {
			return "", fmt.Errorf("PSK already exists at %s; pass --force to rotate (this invalidates pending enrollments)", path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create state dir: %w", err)
	}
	raw := make([]byte, enrollPSKBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate PSK: %w", err)
	}
	display := enrollPSKPrefix + hex.EncodeToString(raw)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(display+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write PSK: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("install PSK: %w", err)
	}
	return display, nil
}

// readEnrollPSK loads the displayable PSK string from disk. Returns
// ("", error) when the file doesn't exist or is unreadable.
func readEnrollPSK() (string, error) {
	data, err := os.ReadFile(enrollPSKPath())
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(data))
	if !strings.HasPrefix(s, enrollPSKPrefix) {
		return "", fmt.Errorf("PSK file at %s is malformed (missing %q prefix); rotate with `simplesiem certs psk rotate --force`", enrollPSKPath(), enrollPSKPrefix)
	}
	return s, nil
}

// pskRawBytes extracts the 32-byte secret from the displayable PSK
// string. Used for HMAC keying. Returns an error if the format is wrong
// so a typo'd PSK fails fast instead of silently mis-keying the HMAC.
func pskRawBytes(display string) ([]byte, error) {
	if !strings.HasPrefix(display, enrollPSKPrefix) {
		return nil, fmt.Errorf("PSK must start with %q", enrollPSKPrefix)
	}
	hexPart := strings.TrimPrefix(display, enrollPSKPrefix)
	raw, err := hex.DecodeString(hexPart)
	if err != nil {
		return nil, fmt.Errorf("PSK hex decode: %w", err)
	}
	if len(raw) != enrollPSKBytes {
		return nil, fmt.Errorf("PSK is %d bytes, want %d", len(raw), enrollPSKBytes)
	}
	return raw, nil
}

// computeEnrollHMAC binds the response material to the PSK so the agent
// can detect a MITM that doesn't know the secret. Domain-separator
// prefix prevents a future endpoint from accidentally matching the same
// HMAC for a different payload. Realm fields are included so a
// MITM can't strip / inject failover peers.
func computeEnrollHMAC(pskRaw []byte, certPem, caPem string, reauthSeconds int, realmName string, realmPeers []string) string {
	// HMAC-SHA384 paired with the P-384 cert family — same security
	// level (~192-bit). The domain-separator string prevents the
	// HMAC from accidentally matching a different endpoint's HMAC
	// over the same byte stream; it has no version connotation.
	mac := hmac.New(sha512.New384, pskRaw)
	_, _ = mac.Write([]byte("simplesiem-enroll-hmac\n"))
	_, _ = mac.Write([]byte(certPem))
	_, _ = mac.Write([]byte("\n"))
	_, _ = mac.Write([]byte(caPem))
	_, _ = mac.Write([]byte(fmt.Sprintf("\n%d\n", reauthSeconds)))
	_, _ = mac.Write([]byte(realmName))
	_, _ = mac.Write([]byte("\n"))
	for _, p := range realmPeers {
		_, _ = mac.Write([]byte(p))
		_, _ = mac.Write([]byte("\n"))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// runCertsPSK dispatches `certs psk <show|rotate>`. Kept as a separate
// subcommand-of-subcommand so the operator pulling up `--help` sees the
// PSK as a first-class concept, not buried inside `certs init`.
func runCertsPSK(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem certs psk <show|rotate>

  show              print the current enrollment PSK (the operator pastes this
                    into the agent's `+"`convert agent --key ...`"+` command)
  rotate [--force]  generate a new PSK; pass --force to overwrite an existing one
                    (in-flight enrollments will need the new PSK)`)
		os.Exit(2)
	}
	switch args[0] {
	case "show":
		psk, err := readEnrollPSK()
		if err != nil {
			fatalf("read PSK: %v\n  hint: run `simplesiem certs psk rotate` to create one", err)
		}
		fmt.Println(psk)
	case "rotate":
		force := false
		for _, a := range args[1:] {
			if a == "--force" || a == "-f" {
				force = true
			}
		}
		psk, err := generateEnrollPSK(force)
		if err != nil {
			fatalf("rotate PSK: %v", err)
		}
		fmt.Printf("Enrollment PSK written to %s (mode 0600).\n\n", enrollPSKPath())
		fmt.Println("On each agent host, run:")
		fmt.Printf("  sudo simplesiem convert agent --server https://%s:9443 --key %s\n\n", bestServerHostname(), psk)
		fmt.Println("Treat this string like a password: anyone with it can enroll an agent.")
	default:
		fatalf("unknown certs psk subcommand: %s", args[0])
	}
}

// ----- agent side ------------------------------------------------------

// runAgentEnrollment is called by `convert agent` when --key is set. It
// generates the keypair locally, sends the CSR, validates the response
// HMAC, and writes the cert/CA/key to disk. On success the file paths
// match cfg.Agent.{ClientCert,ClientKey,CACert} so caller can save the
// config without further changes. acfg is the *target* AgentConfig
// (after --id / --server overrides are applied).
//
// All failure paths leave config.json untouched (the caller is
// responsible for saveConfig only after this returns nil).
// runAgentEnrollment performs the PSK-authenticated enrollment.
// Returns the (validated) EnrollResponse so the caller can persist
// realm-related fields (failover_servers) into the agent config.
func runAgentEnrollment(acfg AgentConfig, hostname, psk string) (EnrollResponse, error) {
	var zero EnrollResponse
	if acfg.ServerURL == "" {
		return zero, fmt.Errorf("--server is required when using --key")
	}
	id := acfg.ID
	if id == "" {
		id = hostname
	}
	if !validAgentID(id) {
		return zero, fmt.Errorf("agent.id %q is unsafe (must start alphanumeric, [A-Za-z0-9._-], no '..', not a reserved name)", id)
	}
	pskRaw, err := pskRawBytes(psk)
	if err != nil {
		return zero, fmt.Errorf("--key: %w", err)
	}

	// Generate the agent's keypair LOCALLY. The private key never leaves
	// this host; only the public key (in the CSR) is sent to the server.
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return zero, fmt.Errorf("generate client key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: id, Organization: []string{"SimpleSIEM"}},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		return zero, fmt.Errorf("build CSR: %w", err)
	}
	csrPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	body, _ := json.Marshal(EnrollRequest{
		PSK:     psk,
		AgentID: id,
		CSRPem:  csrPem,
	})

	// First connection: we don't have the CA yet, so we can't validate
	// the server's TLS cert via the chain. We connect with InsecureSkipVerify
	// and rely on the response HMAC (keyed by the PSK that only the real
	// server knows) to detect a MITM. Once we have the CA from a verified
	// response, all future connections use full mTLS.
	tr := &http.Transport{
		// #nosec G402 -- bootstrap-only: agent has no CA at first contact.
		// Authenticity is provided by the response HMAC keyed by the PSK
		// (computeEnrollHMAC); a MITM that doesn't know the PSK can't
		// produce a valid HMAC. After enrollment, all traffic uses full
		// mTLS via agentTLSConfig with the issued CA.
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs()},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	url := strings.TrimRight(acfg.ServerURL, "/") + "/v1/enroll"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return zero, classifyAgentProbeErr(err, acfg, id)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		body := strings.TrimSpace(string(respBody))
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return zero, fmt.Errorf("enrollment PSK rejected by server (HTTP 401)\n  - on the server, run: simplesiem certs psk show\n    and confirm the value matches what was passed to --key\n  - if the server's PSK was rotated, the old value is dead; copy the new one")
		case http.StatusBadRequest:
			return zero, fmt.Errorf("server refused enrollment request (HTTP 400): %s\n  - usually a malformed CSR or invalid agent_id; re-run without --id to default to hostname", body)
		case http.StatusTooManyRequests:
			return zero, fmt.Errorf("server is rate-limiting enrollment attempts (HTTP 429) — wait a few seconds and retry")
		case http.StatusServiceUnavailable:
			return zero, fmt.Errorf("server can't sign right now (HTTP 503): %s\n  - on the server, verify `simplesiem certs init` has been run", body)
		default:
			return zero, fmt.Errorf("server rejected enrollment (HTTP %d): %s", resp.StatusCode, body)
		}
	}
	var er EnrollResponse
	if err := json.Unmarshal(respBody, &er); err != nil {
		return zero, fmt.Errorf("parse server response: %w", err)
	}
	if er.CertPem == "" || er.CAPem == "" || er.Hmac == "" {
		return zero, fmt.Errorf("server response missing required fields (server may be too old; rotate the PSK on the server and retry)")
	}
	expectedHmac := computeEnrollHMAC(pskRaw, er.CertPem, er.CAPem, er.ReauthSeconds, er.RealmName, er.RealmPeers)
	if subtle.ConstantTimeCompare([]byte(er.Hmac), []byte(expectedHmac)) != 1 {
		return zero, fmt.Errorf("response HMAC mismatch — possible MITM, or PSK on server differs from --key value")
	}

	// Sanity-check the cert before writing: parse it, confirm CN, confirm
	// it matches the keypair we generated, confirm it chains to the
	// returned CA. If any of this fails the server is broken or hostile
	// and we want to know before we overwrite anything.
	if err := verifyEnrolledCert(er.CertPem, er.CAPem, id, &priv.PublicKey); err != nil {
		return zero, fmt.Errorf("server returned an invalid bundle: %w", err)
	}

	// Write the bundle to the configured paths. Refuses to silently
	// clobber existing files: if there's already a cert there we move it
	// aside first so a fat-fingered re-enrollment doesn't lose the prior
	// material.
	for _, p := range []string{acfg.ClientCert, acfg.ClientKey, acfg.CACert} {
		if _, err := os.Stat(p); err == nil {
			ts := time.Now().UTC().Format("20060102T150405Z")
			_ = os.Rename(p, p+".backup-"+ts)
		}
	}
	if err := os.MkdirAll(filepath.Dir(acfg.ClientCert), 0o750); err != nil {
		return zero, fmt.Errorf("create cert dir: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return zero, fmt.Errorf("marshal client key: %w", err)
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(acfg.ClientKey, keyPem, 0o600); err != nil {
		return zero, fmt.Errorf("write client key: %w", err)
	}
	if err := os.WriteFile(acfg.ClientCert, []byte(er.CertPem), 0o644); err != nil {
		return zero, fmt.Errorf("write client cert: %w", err)
	}
	if err := os.WriteFile(acfg.CACert, []byte(er.CAPem), 0o644); err != nil {
		return zero, fmt.Errorf("write CA: %w", err)
	}
	// as11 — persist the PSK so the agent can re-enroll itself if its
	// cert is later revoked. Best-effort: a write failure here just
	// means a future revocation needs manual operator intervention.
	if err := saveAgentEnrollPSK(psk); err != nil {
		// Log via stderr (no Storage available in this code path) so
		// the operator sees it during install.
		fmt.Fprintf(os.Stderr, "warning: could not save PSK for as11 auto-re-enroll: %v\n", err)
	}
	return er, nil
}

// verifyEnrolledCert is the agent's defence against a server that returns
// a malformed or wrong bundle: the cert must parse, its CN must match
// the agent ID we asked for, the public key must equal the one we just
// generated, and the chain must verify against the CA.
func verifyEnrolledCert(certPem, caPem, expectID string, expectPub *ecdsa.PublicKey) error {
	cb, _ := pem.Decode([]byte(certPem))
	if cb == nil {
		return fmt.Errorf("cert is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}
	if cert.Subject.CommonName != expectID {
		return fmt.Errorf("CN %q != expected %q", cert.Subject.CommonName, expectID)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.X.Cmp(expectPub.X) != 0 || pub.Y.Cmp(expectPub.Y) != 0 {
		return fmt.Errorf("cert public key does not match locally-generated keypair (server may have substituted its own key)")
	}
	caBlock, _ := pem.Decode([]byte(caPem))
	if caBlock == nil {
		return fmt.Errorf("CA is not PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("chain verify: %w", err)
	}
	return nil
}

// agentHeartbeatLoop periodically calls /v1/heartbeat on the configured
// server. Two purposes:
//
//  1. Explicit re-authentication that the server can configure centrally:
//     the response carries reauth_seconds, so an operator changing the
//     interval on the server (e.g. to 30s under heightened concern, or
//     to 5m for low-traffic networks) propagates to all agents on the
//     next beat without restarting them.
//  2. Liveness signal: a heartbeat failure surfaces in the agent's
//     local errors log within reauth_seconds, even when the agent has
//     no events to ship. Without it, an agent could sit idle and
//     silently lose connectivity for hours.
//
// Failures are logged and don't kill the loop — events still flow over
// mTLS as long as the cert chain is valid.
func agentHeartbeatLoop(ctx context.Context, wg *sync.WaitGroup, cfg AgentConfig, log *Storage) {
	defer wg.Done()
	if cfg.ServerURL == "" {
		return
	}
	tlsCfg, err := agentTLSConfig(cfg)
	if err != nil {
		log.Write("errors", map[string]any{"collector": "agent_heartbeat", "error": err.Error()})
		return
	}
	tr := &http.Transport{
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	// Heartbeat tries the same URL pool as the shipper: primary +
	// failover_servers. The first to answer is the agent's "current"
	// peer for the next cycle. Without this list, an outage that flips
	// the shipper to a backup peer would still leave the heartbeat
	// pinned at the dead primary and lock status into DEGRADED.
	urls := []string{strings.TrimRight(cfg.ServerURL, "/") + "/v1/heartbeat"}
	for _, p := range cfg.FailoverServers {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		urls = append(urls, p+"/v1/heartbeat")
	}
	id := cfg.ID

	// Start with a quick first beat (5s after launch). Then adopt
	// whatever cadence the server returns. Default 60s if the server
	// doesn't supply one (older server, or network failure on first
	// beat).
	//
	// On failure, retry every retryEvery (5s by default) until success
	// instead of waiting the full healthy-state interval. Without this
	// fast-retry, an outage that ends mid-cycle takes up to a full
	// reauth_seconds (default 60s) to register as recovered, even though
	// the shipper saw the server come back within seconds.
	interval := 60 * time.Second
	const retryEvery = 5 * time.Second
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	healthy := true
	// rateLimitedFailure tracks "are we already logging this outage?"
	// so we don't write the same beat-failed error every 5s for an
	// hour-long outage. First failure logs; subsequent ones are silent
	// until recovery, which itself logs once.
	failureLogged := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		// Try each peer URL in turn until one answers (or all fail).
		// Network-level failures advance to the next URL; a non-2xx
		// response counts as the final answer (failing over wouldn't
		// hide the real reason and might mask config drift).
		failed := false
		var resp *http.Response
		var lastErr error
		for _, hbURL := range urls {
			req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, hbURL, nil)
			if rerr != nil {
				lastErr = rerr
				continue
			}
			req.Header.Set("X-SimpleSIEM-Host", id)
			r, derr := client.Do(req)
			if derr != nil {
				lastErr = derr
				tr.CloseIdleConnections()
				continue
			}
			resp = r
			break
		}
		if resp == nil {
			// Every peer failed at the network layer.
			if ctx.Err() == nil && !failureLogged && lastErr != nil {
				log.Write("errors", map[string]any{
					"collector": "agent_heartbeat", "error": "beat failed: " + lastErr.Error(),
					"hint": "all server URLs unreachable; events written locally + spooled until one returns. Retrying every 5s.",
				})
				failureLogged = true
			}
			failed = true
		} else {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				if !failureLogged {
					log.Write("errors", map[string]any{
						"collector": "agent_heartbeat",
						"error":     fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))),
						"hint":      "agent_id may have been removed from agent_allowlist on the server. Retrying every 5s.",
					})
					failureLogged = true
				}
				// as11 — 401/403 on heartbeat means our cert is no longer
				// trusted (revoked, allowlist removed, or CA rotated past
				// us). Try to re-enroll using the saved PSK; on success
				// the next handshake transparently uses the fresh cert.
				if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
					hostname, _ := os.Hostname()
					_, _ = tryAgentReenroll(cfg, hostname, log, tr)
				}
				failed = true
			} else {
				if !healthy {
					log.Write("meta", map[string]any{
						"event": "agent_heartbeat_recovered",
						"hint":  "/v1/heartbeat is responding again",
					})
				}
				healthy = true
				failureLogged = false
				var hb HeartbeatResponse
				if err := json.Unmarshal(body, &hb); err == nil {
					if hb.ReauthSeconds > 0 {
						newInterval := time.Duration(hb.ReauthSeconds) * time.Second
						if newInterval != interval {
							log.Write("meta", map[string]any{
								"event":     "agent_reauth_interval_changed",
								"old_secs":  int(interval.Seconds()),
								"new_secs":  hb.ReauthSeconds,
								"server_ts": hb.ServerTime,
							})
							interval = newInterval
						}
					}
					// Refresh the failover list and CA bundle on disk
					// when the realm has grown / shrunk. Compare against
					// what's currently in cfg so we don't churn writes.
					if hb.CABundle != "" && cfg.CACert != "" {
						if old, err := os.ReadFile(cfg.CACert); err != nil || string(old) != hb.CABundle {
							if werr := atomicWriteFile(cfg.CACert, []byte(hb.CABundle), 0o644); werr == nil {
								log.Write("meta", map[string]any{
									"event": "agent_ca_bundle_refreshed",
									"hint":  "server reported an updated realm CA bundle; trust set rebuilt",
									"size":  len(hb.CABundle),
								})
							} else {
								log.Write("errors", map[string]any{
									"collector": "agent_heartbeat",
									"error":     "could not write refreshed CA bundle: " + werr.Error(),
								})
							}
						}
					}
					if len(hb.FailoverServers) > 0 && !sameStringSet(cfg.FailoverServers, hb.FailoverServers) {
						// Persist the refreshed list so a daemon restart
						// has the same view. Best-effort: a write error
						// just means we'll re-detect on the next beat.
						if werr := setAgentFailoverServers(defaultConfigPath(), hb.FailoverServers); werr == nil {
							cfg.FailoverServers = append([]string{}, hb.FailoverServers...)
							log.Write("meta", map[string]any{
								"event": "agent_failover_list_refreshed",
								"count": len(hb.FailoverServers),
							})
						}
					}
					// Cert auto-rotation: piggybacks on the same mTLS
					// transport the heartbeat just used. If the local
					// cert is within the threshold of expiry, rotate now.
					// Best-effort: failures are logged and retried on
					// the next beat. The new cert takes effect on the
					// next TLS handshake (the transport caches the
					// keypair, but the next reconnect picks up the
					// fresh keypair from disk).
					rotateAgentCertIfNeeded(cfg, log, defaultRotateThresholdDays, client)
				}
			}
		}
		if failed {
			healthy = false
			timer.Reset(retryEvery)
		} else {
			timer.Reset(interval)
		}
	}
}

// atomicWriteFile writes data to path via a temp file + rename so a
// concurrent reader never sees a half-written file. Mode is applied
// to the temp file before rename. Caller is responsible for ensuring
// the parent dir exists.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// sameStringSet returns true when a and b contain the same elements
// (order-independent). Used to skip writes when the heartbeat-pushed
// failover list matches what's already on disk.
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]bool, len(a))
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}

// setAgentFailoverServers persists the refreshed failover list to
// agent.failover_servers. Serialised through the same global mutex
// agent allowlist edits use, so concurrent edits don't lose changes.
func setAgentFailoverServers(cfgPath string, list []string) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	cfg.Agent.FailoverServers = append([]string{}, list...)
	return saveConfig(cfgPath, cfg)
}

// ----- server side -----------------------------------------------------

// HeartbeatResponse is what /v1/heartbeat returns. The agent uses
// reauth_seconds to schedule its next beat; if the server has changed
// the value, the next call adopts the new cadence.
type HeartbeatResponse struct {
	OK            bool   `json:"ok"`
	ReauthSeconds int    `json:"reauth_seconds"`
	ServerTime    string `json:"server_time"`     // RFC3339Nano; lets agent detect drift
	RealmName     string `json:"realm_name,omitempty"`
	// FailoverServers is the realm peer list at heartbeat time. Agents
	// that picked up a smaller list at enrollment refresh on every beat
	// so a peer added to the realm after enrollment becomes a valid
	// failover target without re-enrolling. Populated only when this
	// server is in a non-singleton realm.
	FailoverServers []string `json:"failover_servers,omitempty"`
	// CABundle is the multi-cert PEM the agent trusts for server-cert
	// verification. Refreshed on every heartbeat so newly-joined realm
	// peers' CAs propagate to existing agents within `agent_reauth_seconds`.
	CABundle string `json:"ca_bundle,omitempty"`
}

// handleHeartbeat is the periodic re-authentication endpoint. The
// /v1/events allowlist re-check is cached for reauth_seconds; the agent
// hitting /v1/heartbeat keeps that window fresh. The response also
// pushes the current reauth_seconds value, so a server-side change
// propagates to agents without restarting them.
func (s *serverState) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorize(r) {
		s.logAuthFailure(r, "heartbeat")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Tie the heartbeat to the agent's CN so it actually re-validates
	// THIS agent against the allowlist. authorize() proves cert validity;
	// the allowlist check below proves the agent ID is still approved.
	cn := clientCN(r)
	if cn != "" {
		s.allowlistMu.RLock()
		size := len(s.allowlist)
		_, ok := s.allowlist[cn]
		s.allowlistMu.RUnlock()
		if size > 0 && !ok {
			http.Error(w, "agent not authorized", http.StatusForbidden)
			return
		}
		if s.agentRevokedAt(cn) != "" {
			http.Error(w, "agent revoked", http.StatusForbidden)
			return
		}
		// Identity-guard: reject a second daemon presenting this
		// agent's cert from a different IP inside the guard window.
		// See identity_guard.go for the rationale + emitted event.
		if !s.identityCheck(r, cn) {
			http.Error(w, "duplicate identity: another daemon is currently active with this cert", http.StatusConflict)
			return
		}
	} else if s.allowBearerOnly {
		// Bearer-only path: the X-SimpleSIEM-Host header carries the
		// agent identity. Run the same dedup so two daemons sharing a
		// leaked token can't both heartbeat from different IPs.
		if hostID := r.Header.Get("X-SimpleSIEM-Host"); hostID != "" && safeHostName(s.base, hostID) {
			if !s.identityCheck(r, "bearer:"+hostID) {
				http.Error(w, "duplicate identity: another daemon is currently active with this agent_id", http.StatusConflict)
				return
			}
		}
	}
	resp := HeartbeatResponse{
		OK:            true,
		ReauthSeconds: s.reauthSeconds,
		ServerTime:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	s.realmMu.RLock()
	if len(s.realmPeers) > 0 {
		resp.RealmName = s.realmName
		resp.FailoverServers = append([]string{}, s.realmPeers...)
	}
	s.realmMu.RUnlock()
	if resp.FailoverServers != nil {
		// Only ship the CA bundle when there's an actual realm — single
		// server installs don't need (and the agent already has) the bundle.
		if bundle, err := buildRealmCABundle(s.certsDir); err == nil {
			resp.CABundle = bundle
		}
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// handleEnroll signs CSRs presented with a valid PSK. Mounted at
// /v1/enroll. Does NOT require mTLS (the server's TLSConfig.ClientAuth
// is set to VerifyClientCertIfGiven so this endpoint is reachable
// pre-enrollment); the existing handlers re-check cert presence inline
// so security is unchanged for them.
func (s *serverState) handleEnroll(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Per-IP rate limit. Even a one-token-per-second budget is plenty for
	// real enrollment (a human types one of these per machine) and
	// drastically slows offline+online PSK guessing.
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
	var er EnrollRequest
	if err := json.Unmarshal(body, &er); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// Constant-time PSK compare to defeat timing oracles. Compare RAW
	// bytes (so a length mismatch doesn't itself leak). Re-read the PSK
	// from disk on every enroll: if an operator rotates the PSK to
	// revoke a leaked value, the running server picks up the new one
	// immediately rather than continuing to accept the old PSK until
	// next restart. On read failure (missing file mid-rotate, etc.)
	// fall back to the startup-loaded value so a transient fs blip
	// doesn't break valid enrollments.
	currentPSK, perr := readEnrollPSK()
	if perr != nil || currentPSK == "" {
		currentPSK = s.enrollPSK
	}
	gotRaw, gerr := pskRawBytes(er.PSK)
	wantRaw, werr := pskRawBytes(currentPSK)
	if gerr != nil || werr != nil || subtle.ConstantTimeCompare(gotRaw, wantRaw) != 1 {
		s.logAuthFailure(r, "enroll")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Auto-extend the server cert SAN to cover the hostname the agent
	// actually dialed. The TLS SNI value is whatever the agent put after
	// `https://` in its --server URL — exactly the name the strict-TLS
	// preflight will check moments later. Without this, an operator
	// dialing the server by an alias (DNS service name, /etc/hosts entry)
	// has to manually re-issue the cert + restart the server. PSK auth
	// already gated the call, so a leaked PSK is the only way to drift
	// the SAN — extendServerCertSAN further caps the list at 64 entries
	// so a misuse can't grow the cert without bound.
	if r.TLS != nil && r.TLS.ServerName != "" && r.TLS.ServerName != "localhost" {
		if changed, sanErr := extendServerCertSAN(s.certsDir, r.TLS.ServerName); sanErr != nil {
			s.broadcastErr("enroll", fmt.Errorf("auto-extend SAN: %v", sanErr))
		} else if changed {
			if mst, gerr := s.storageFor("_server"); gerr == nil {
				mst.Write("meta", map[string]any{
					"event":  "server_cert_san_extended",
					"added":  r.TLS.ServerName,
					"hint":   "agent dialed by a name not in the server cert SAN; cert re-issued automatically — listener hot-reloads within ~1s",
					"remote": r.RemoteAddr,
				})
			}
		}
	}
	if !validAgentID(er.AgentID) {
		http.Error(w, "invalid agent_id", http.StatusBadRequest)
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
	// Verify the CSR signature: this proves the requester holds the
	// private key whose public key we're about to certify. Without this
	// check anyone with the PSK could submit someone else's public key.
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, "csr signature: "+err.Error(), http.StatusBadRequest)
		return
	}
	// CN must match the claimed agent_id. The client cert CN is what
	// /v1/events checks against X-SimpleSIEM-Host, so a mismatch here
	// would let one agent enroll under another's identity.
	if csr.Subject.CommonName != er.AgentID {
		http.Error(w, "csr CN must equal agent_id", http.StatusBadRequest)
		return
	}

	caCert, caKey, err := loadCAFromDisk(s.certsDir)
	if err != nil {
		s.broadcastErr("enroll", fmt.Errorf("load CA: %v", err))
		http.Error(w, "server missing CA — operator must run `simplesiem certs init`", http.StatusServiceUnavailable)
		return
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: er.AgentID, Organization: []string{"SimpleSIEM"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(s.enrollClientYears, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		s.broadcastErr("enroll", fmt.Errorf("sign cert: %v", err))
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	clientPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))

	// Atomically add the agent_id to the allowlist and rebuild the
	// in-memory map so the next /v1/events from this agent isn't
	// rejected for unknown ID. Idempotent: returning newlyAdded=false
	// when the ID was already present is a normal re-enrollment flow.
	added, err := addAgentToAllowlist(s.configPath, er.AgentID)
	if err != nil {
		s.broadcastErr("enroll", fmt.Errorf("update allowlist: %v", err))
		http.Error(w, "could not persist allowlist", http.StatusInternalServerError)
		return
	}
	s.allowlistMu.Lock()
	s.allowlist[er.AgentID] = struct{}{}
	s.allowlistMu.Unlock()

	// Build the CA bundle the agent will trust. Single-server install:
	// just our own CA. Realm install: our CA + every peer CA on disk,
	// concatenated as a multi-cert PEM. The agent's loadCAPool feeds
	// the whole bundle into AppendCertsFromPEM, so the agent trusts
	// every realm peer's server cert and can fail over without
	// re-enrollment when realm.peers grows.
	caPem, err := buildRealmCABundle(s.certsDir)
	if err != nil {
		http.Error(w, "read CA: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.realmMu.RLock()
	realm := s.realmName
	peers := append([]string{}, s.realmPeers...)
	s.realmMu.RUnlock()
	resp := EnrollResponse{
		CertPem:       clientPem,
		CAPem:         caPem,
		ReauthSeconds: s.reauthSeconds,
		NewlyAdded:    added,
		RealmName:     realm,
		RealmPeers:    peers,
	}
	resp.Hmac = computeEnrollHMAC(wantRaw, resp.CertPem, resp.CAPem, resp.ReauthSeconds, resp.RealmName, resp.RealmPeers)

	// Audit log under _server/meta — this is a high-value but normal
	// event, not an error. Routing it through broadcastErr earlier
	// caused operators to see successful enrollments in their
	// errors stream and assume something was wrong.
	if st, gerr := s.storageFor("_server"); gerr == nil {
		st.Write("meta", map[string]any{
			"event":       "enroll_issued",
			"agent_id":    er.AgentID,
			"newly_added": added,
			"remote":      r.RemoteAddr,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}
