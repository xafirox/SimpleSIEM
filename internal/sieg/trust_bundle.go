package sieg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// trustBundle is the runtime CA pool the server uses to verify TLS
// client certs from agents, realm peers, and masters. It is the
// union of:
//
//   - the server's own CA (cfg.Server.CACert) — signs agents enrolled
//     here and masters that ran `master enroll` against this server,
//   - every realm-peer CA stored under <state>/realm/peer_cas/<peer>.pem
//     — signs agents and masters enrolled with peer servers, so an
//     agent failing over from peer A to this server is accepted via
//     A's CA without re-enrollment.
//
// The bundle rebuilds from disk on demand (after realm join, after
// pulling a new peer CA via /v1/sync/config). The TLS layer picks
// up the new pool through tls.Config.GetConfigForClient, so newly
// added CAs take effect on the next handshake — no listener restart.
//
// Concurrency: rebuild() takes a write lock; get() takes a read lock.
// The pool itself (*x509.CertPool) is treated as immutable after a
// rebuild — readers receive whatever was current when they called
// get(), even if a concurrent rebuild swaps in a new pool.
type trustBundle struct {
	mu        sync.RWMutex
	pool      *x509.CertPool
	ownCAPath string
	peerCAsDir string
}

// newTrustBundle builds an initial bundle from the own-CA file plus
// any *.pem files already present in peerCAsDir. The directory is
// created if missing so rebuild() can scan it on next change.
func newTrustBundle(ownCAPath, peerCAsDir string) (*trustBundle, error) {
	if peerCAsDir != "" {
		if err := os.MkdirAll(peerCAsDir, 0o750); err != nil {
			return nil, fmt.Errorf("create peer CAs dir: %w", err)
		}
	}
	b := &trustBundle{ownCAPath: ownCAPath, peerCAsDir: peerCAsDir}
	if err := b.rebuild(); err != nil {
		return nil, err
	}
	return b, nil
}

// rebuild rescans disk and replaces the in-memory pool. Safe to call
// concurrently with get() — readers continue using the old pool until
// the swap completes. Sources, in order:
//
//   - own current CA (cfg.Server.CACert) — signs new certs going forward
//   - <state>/legacy_cas/*.pem — own previous CAs, kept for trust during
//     a CA transition so client certs signed before init-rotate still
//     validate. Removed by `simplesiem certs finalize-rotate`.
//   - <state>/realm/peer_cas/*.pem — every realm peer's public CA cert.
func (b *trustBundle) rebuild() error {
	pool := x509.NewCertPool()
	if b.ownCAPath != "" {
		data, err := os.ReadFile(b.ownCAPath)
		if err != nil {
			return fmt.Errorf("read own CA %s: %w", b.ownCAPath, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return fmt.Errorf("no PEM certs in %s", b.ownCAPath)
		}
	}
	if entries, err := os.ReadDir(legacyCAsDir()); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
				continue
			}
			data, derr := os.ReadFile(filepath.Join(legacyCAsDir(), e.Name()))
			if derr != nil {
				continue
			}
			_ = pool.AppendCertsFromPEM(data)
		}
	}
	if b.peerCAsDir != "" {
		entries, err := os.ReadDir(b.peerCAsDir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
					continue
				}
				data, derr := os.ReadFile(filepath.Join(b.peerCAsDir, e.Name()))
				if derr != nil {
					continue
				}
				// Tolerate one bad file rather than failing the whole bundle.
				_ = pool.AppendCertsFromPEM(data)
			}
		}
	}
	b.mu.Lock()
	b.pool = pool
	b.mu.Unlock()
	return nil
}

// legacyCAsDir is where we stash the previous CA cert during a
// rotation. The CA *key* is destroyed on rotate; only the cert
// stays so existing client certs continue to chain-validate until
// they expire or rotate to the new CA.
func legacyCAsDir() string {
	return filepath.Join(defaultStateDir(), "legacy_cas")
}

// get returns the current pool. The pointer is stable through the
// caller's use — a concurrent rebuild() swaps in a new pool but does
// not mutate the old one.
func (b *trustBundle) get() *x509.CertPool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pool
}

// realmPeerCAsDir returns the directory holding peer CAs for the
// running install, creating it if missing. Used by both the trust
// bundle and the realm-join handler.
func realmPeerCAsDir() string {
	return filepath.Join(defaultStateDir(), "realm", "peer_cas")
}

// outboundClientTLS builds the TLS config a server uses when dialing
// a realm peer (or a master uses when dialing servers). RootCA
// verification is deferred to VerifyConnection so the live trust
// bundle is consulted on every handshake — peers added after startup
// are accepted without restarting the dialing process.
//
// Hostname verification uses the SNI value from the connection
// (set by http.Transport from the URL host), so dial-by-IP without
// an explicit ServerName will fail closed unless the cert SAN
// includes that IP.
func outboundClientTLS(clientCert tls.Certificate, bundle *trustBundle) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs(),
		Certificates: []tls.Certificate{clientCert},
		// #nosec G402 -- InsecureSkipVerify is paired with VerifyConnection
		// below, the idiomatic Go pattern for dynamic CA pools. We perform
		// full chain + hostname verification against the live trustBundle
		// on every handshake, so this is more strict than the static
		// RootCAs path (which would freeze the trust set at config time).
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no peer certs")
			}
			roots := bundle.get()
			if roots == nil {
				return fmt.Errorf("no trusted CAs in bundle")
			}
			opts := x509.VerifyOptions{
				Roots:         roots,
				Intermediates: x509.NewCertPool(),
				DNSName:       cs.ServerName,
			}
			for _, c := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}
}

// buildRealmCABundle returns a multi-cert PEM the server can hand to
// agents at /v1/enroll and /v1/heartbeat. The bundle is the union of:
//
//   - the server's own current CA (signs new certs going forward),
//   - every legacy CA in <state>/legacy_cas/ (so client certs signed
//     before init-rotate continue to validate at the agent's end too),
//   - every peer CA in <state>/realm/peer_cas/ (so the agent trusts
//     any realm peer's server cert when failing over).
func buildRealmCABundle(certsDir string) (string, error) {
	var out strings.Builder
	ownPath := filepath.Join(certsDir, "ca.pem")
	ownPem, err := os.ReadFile(ownPath)
	if err != nil {
		return "", fmt.Errorf("read own CA %s: %w", ownPath, err)
	}
	appendPEM := func(data []byte) {
		out.Write(data)
		if len(data) == 0 || data[len(data)-1] != '\n' {
			out.WriteByte('\n')
		}
	}
	appendPEM(ownPem)
	if entries, err := os.ReadDir(legacyCAsDir()); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
				continue
			}
			data, derr := os.ReadFile(filepath.Join(legacyCAsDir(), e.Name()))
			if derr != nil {
				continue
			}
			appendPEM(data)
		}
	}
	if entries, err := os.ReadDir(realmPeerCAsDir()); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
				continue
			}
			data, derr := os.ReadFile(filepath.Join(realmPeerCAsDir(), e.Name()))
			if derr != nil {
				continue
			}
			appendPEM(data)
		}
	}
	return out.String(), nil
}

// writePeerCA writes one peer's CA atomically to
// <state>/realm/peer_cas/<peer-id>.pem. Returns the path written.
// The peer ID is validated by the caller; this function refuses any
// path component (defence in depth).
func writePeerCA(peerID, caPem string) (string, error) {
	if peerID == "" || strings.ContainsAny(peerID, `/\`) || strings.Contains(peerID, "..") {
		return "", fmt.Errorf("invalid peer id %q", peerID)
	}
	dir := realmPeerCAsDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dir, peerID+".pem")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(caPem), 0o640); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return path, nil
}
