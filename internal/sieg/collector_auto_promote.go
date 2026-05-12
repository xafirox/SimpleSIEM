package sieg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// r21 — auto-promote a server-paired collector to a master when the
// realm acquires one. The bridge mechanism is a one-shot PSK file
// dropped on the collector host:
//
//   <state>/master_promote.psk   (mode 0600)
//
// The operator pre-stages this file (or runs `simplesiem collector
// queue-promote --key <PSK>`) before the master comes online; the
// daemon picks it up on the next pull cycle and runs the promote
// in-process. After a successful promote the file is consumed.
//
// Why a file instead of a config flag? PSKs shouldn't live in
// config.json (replicated, world-readable-ish). The PSK file has
// the same threat surface as the agent_enroll.psk that as11 saves —
// 0600, root-only, and used for ONE re-association cycle.

// collectorAutoPromotePSKPath is where the operator drops the master
// PSK to opt this collector into auto-promotion.
func collectorAutoPromotePSKPath() string {
	return filepath.Join(defaultStateDir(), "master_promote.psk")
}

// readCollectorAutoPromotePSK loads the staged PSK if present.
func readCollectorAutoPromotePSK() (string, error) {
	data, err := os.ReadFile(collectorAutoPromotePSKPath())
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(data))
	if !strings.HasPrefix(s, enrollPSKPrefix) {
		return "", fmt.Errorf("staged PSK at %s is malformed (missing %q prefix)", collectorAutoPromotePSKPath(), enrollPSKPrefix)
	}
	return s, nil
}

// consumeCollectorAutoPromotePSK deletes the file after a successful
// promote. Best-effort: if delete fails the file remains and the next
// cycle would attempt promote again with the same PSK (idempotent —
// the promote endpoint returns the existing CN's cert).
func consumeCollectorAutoPromotePSK() {
	_ = os.Remove(collectorAutoPromotePSKPath())
}

// tryCollectorAutoPromote runs a single promote cycle when:
//   - cfg.Collector.AutoPromoteToMaster is true
//   - the PSK file is staged on disk
//   - masterURL is reachable and not already our source
//
// All preconditions checked here so the caller (the pull loop) just
// invokes this with the source's reported master_url. Returns
// (attempted, err): attempted=false means we skipped (no PSK staged,
// or auto-promote disabled, etc.).
func tryCollectorAutoPromote(cfg Config, cfgPath, masterURL string, storage *Storage) (bool, error) {
	if !cfg.Collector.AutoPromoteToMaster {
		return false, nil
	}
	if masterURL == "" {
		return false, nil
	}
	if strings.TrimRight(masterURL, "/") == strings.TrimRight(cfg.Collector.SourceURL, "/") {
		// Already pointed at this URL — nothing to do.
		return false, nil
	}
	psk, perr := readCollectorAutoPromotePSK()
	if perr != nil {
		return false, nil // no PSK staged — silent, not an error
	}

	storage.Write("meta", map[string]any{
		"event":      "collector_auto_promote_attempt",
		"master_url": masterURL,
		"hint":       "auto_promote_to_master + staged PSK detected; promoting now",
	})

	if err := doCollectorPromote(cfgPath, masterURL, psk); err != nil {
		storage.Write("errors", map[string]any{
			"collector": "collector_auto_promote",
			"error":     err.Error(),
			"hint":      "staged PSK may have been rotated on the master; remove " + collectorAutoPromotePSKPath() + " and re-stage with the current PSK",
		})
		storage.Write("meta", map[string]any{
			"event": "collector_auto_promote_failed",
			"error": err.Error(),
		})
		return true, err
	}

	consumeCollectorAutoPromotePSK()
	storage.Write("meta", map[string]any{
		"event":      "collector_auto_promoted",
		"master_url": masterURL,
		"hint":       "collector source switched to the realm master; PSK file consumed",
	})
	return true, nil
}

// doCollectorPromote performs the same enrollment dance as
// runCollectorEnroll(...isPromote=true) but returns errors instead of
// calling fatalf, so the daemon can run it in-process from the pull
// loop. Kept as a separate function (not a refactor of runCollectorEnroll)
// so the existing CLI path's fatalf-on-each-error UX is unchanged.
func doCollectorPromote(cfgPath, sourceURL, psk string) error {
	sourceURL = strings.TrimRight(sourceURL, "/")
	parsed, err := url.Parse(sourceURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("source URL must be an https URL with a host (got %q)", sourceURL)
	}
	hostname, _ := os.Hostname()
	cfg := loadConfig(cfgPath)
	id := cfg.Collector.CollectorID
	if id == "" {
		id = "collector-" + hostname
	}
	if !validCollectorID(id) {
		return fmt.Errorf("collector ID %q is invalid", id)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: id, Organization: []string{"SimpleSIEM"}}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		return fmt.Errorf("build CSR: %w", err)
	}
	csrPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	body, _ := json.Marshal(CollectorEnrollRequest{PSK: psk, CollectorID: id, CSRPem: csrPem})
	tr := &http.Transport{
		// #nosec G402 -- bootstrap-only; HMAC-over-PSK authenticates the response.
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs()},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPost, sourceURL+"/v1/enroll-collector", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("contact source: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("source rejected enrollment (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var er CollectorEnrollResponse
	if err := json.Unmarshal(rb, &er); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	if er.CertPem == "" || er.CAPem == "" || er.Hmac == "" {
		return fmt.Errorf("response missing required fields")
	}
	pskRaw, perr := pskRawBytes(psk)
	if perr != nil {
		return fmt.Errorf("psk: %w", perr)
	}
	expected := computeEnrollHMAC(pskRaw, er.CertPem, er.CAPem, er.ReauthSeconds, er.RealmName, []string{er.ServerHost})
	if subtle.ConstantTimeCompare([]byte(er.Hmac), []byte(expected)) != 1 {
		return fmt.Errorf("response HMAC mismatch — possible MITM, or PSK on source differs")
	}
	if !validHostName.MatchString(er.ServerHost) {
		return fmt.Errorf("source returned an unsafe server_host %q", er.ServerHost)
	}
	urlID := peerIDFromURL(sourceURL)
	if urlID == "" {
		return fmt.Errorf("could not parse hostname from source URL")
	}
	dir := filepath.Join(collectorCertsDir(cfg), urlID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte(er.CertPem), 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte(er.CAPem), 0o644); err != nil {
		return fmt.Errorf("write CA: %w", err)
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
	if err := saveConfig(cfgPath, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}

// runCollectorQueuePromote is the operator-facing CLI to drop the
// PSK file in place. Equivalent to:
//
//	echo "<PSK>" > /var/lib/simplesiem/state/master_promote.psk && chmod 0600 ...
//
// but with PSK validation + correct path so the operator doesn't
// have to know the file location. Pairs with r21's auto-promote loop.
func runCollectorQueuePromote(args []string) {
	args = permuteArgs(args, map[string]bool{"key": true})
	for i := 0; i < len(args); i++ {
		if args[i] == "--key" || args[i] == "-k" {
			if i+1 >= len(args) {
				fatalf("--key requires a value (the master's collector PSK)")
			}
			psk := args[i+1]
			if _, err := pskRawBytes(psk); err != nil {
				fatalf("--key is not a valid PSK: %v", err)
			}
			if !isAdmin() {
				fatalf("must run as admin")
			}
			path := collectorAutoPromotePSKPath()
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				fatalf("create state dir: %v", err)
			}
			// atomicWriteFile applies the cross-platform mode contract:
			// 0o600 on unix and a tightened DACL (BUILTIN\Users stripped,
			// only SYSTEM + Administrators retain access) on Windows.
			// Plain os.WriteFile ignores mode on Windows and inherits the
			// parent ACL — which includes Users on C:\ProgramData.
			if err := atomicWriteFile(path, []byte(strings.TrimSpace(psk)+"\n"), 0o600); err != nil {
				fatalf("write PSK: %v", err)
			}
			fmt.Printf("Master PSK staged at %s.\n", path)
			fmt.Println("On the next pull cycle, the collector will auto-promote to pull from the master")
			fmt.Println("(when the source's /v1/sync/config reports a master_url and auto_promote_to_master is true).")
			return
		}
	}
	fatalf("usage: simplesiem collector queue-promote --key <PSK from `master collector show-psk`>")
}
