package sieg

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// certHotReloader holds a server cert that can be swapped at runtime
// without restarting the listener. The TLS layer calls GetCertificate
// once per handshake, so an atomic.Pointer swap is sufficient — every
// new connection picks up whatever was loaded most recently.
//
// We poll the cert file's mtime once a second instead of using fsnotify
// to avoid the dependency and the platform quirks (Windows file-rename
// semantics in particular). One stat() per second is a non-issue.
type certHotReloader struct {
	certPath, keyPath string
	current           atomic.Pointer[tls.Certificate]
	lastMtime         atomic.Int64
}

func newCertHotReloader(certPath, keyPath string) (*certHotReloader, error) {
	r := &certHotReloader{certPath: certPath, keyPath: keyPath}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certHotReloader) reload() error {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return err
	}
	r.current.Store(&cert)
	if info, err := os.Stat(r.certPath); err == nil {
		r.lastMtime.Store(info.ModTime().UnixNano())
	}
	return nil
}

func (r *certHotReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := r.current.Load()
	if c == nil {
		return nil, fmt.Errorf("server cert not loaded")
	}
	return c, nil
}

// watch reloads the cert when its file mtime changes. Returns when ctx
// is cancelled. Safe to call as a goroutine.
//
// We track the seen mtime even when reload() fails so a malformed cert
// file doesn't generate one error log entry per second forever — a
// single error per change is enough to alert the operator. Subsequent
// attempts only fire when the file is touched again (e.g., the
// operator rewrites it correctly).
func (r *certHotReloader) watch(ctx context.Context, onReload func(error)) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		info, err := os.Stat(r.certPath)
		if err != nil {
			continue
		}
		mt := info.ModTime().UnixNano()
		if mt == r.lastMtime.Load() {
			continue
		}
		// Record the seen mtime BEFORE attempting reload so a parse
		// failure doesn't cause us to retry the same broken file
		// every tick. The operator gets one error per change.
		r.lastMtime.Store(mt)
		err = r.reload()
		if onReload != nil {
			onReload(err)
		}
	}
}

// loadCAPool reads a PEM-encoded bundle and returns it as an x509 cert pool
// suitable for tls.Config.RootCAs / ClientCAs. Empty caPath returns nil so
// callers can decide whether nil-pool means "use system roots" or "fail".
func loadCAPool(caPath string) (*x509.CertPool, error) {
	if caPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no PEM certs found in %s", caPath)
	}
	return pool, nil
}

// loadKeyPair loads a cert+key pair from disk. Both files must exist;
// returns a descriptive error so the operator can tell which is missing.
func loadKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	if certPath == "" || keyPath == "" {
		return tls.Certificate{}, fmt.Errorf("cert (%q) and key (%q) paths required", certPath, keyPath)
	}
	if _, err := os.Stat(certPath); err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: %w", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return tls.Certificate{}, fmt.Errorf("key: %w", err)
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// agentTLSConfig builds the TLS config an agent uses to dial the server.
// Always pins TLS 1.2+ and presents a client cert. The CA pool restricts
// which server certs we'll trust — system roots are NOT used by default,
// so a public CA can't impersonate a private SIEM server.
//
// Uses GetClientCertificate to re-read the cert from disk on every
// handshake, so cert auto-rotation (which atomically replaces the
// keypair files on disk) takes effect on the next reconnection without
// the agent having to recreate its http.Transport.
func agentTLSConfig(cfg AgentConfig) (*tls.Config, error) {
	// Check the InsecureSkipTLS gate FIRST so a tampered config.json
	// can't pass the dev-only escape hatch through the env-var check
	// just because there happens to be no CA file on disk yet. The
	// gate is the sole authority for "is the dangerous setting
	// actually permitted on this host."
	if cfg.InsecureSkipTLS && os.Getenv("SIMPLESIEM_ALLOW_INSECURE_TLS") != "1" {
		return nil, fmt.Errorf("agent.insecure_skip_tls=true rejected: set SIMPLESIEM_ALLOW_INSECURE_TLS=1 in the daemon environment to opt in (dev only)")
	}
	var caPool *x509.CertPool
	if !cfg.InsecureSkipTLS {
		// Normal mTLS posture: a CA pool is required to verify the
		// server's cert. The dev-only insecure path skips this load
		// because the typical insecure_skip_tls user has not yet
		// enrolled and has no CA file on disk.
		var err error
		caPool, err = loadCAPool(cfg.CACert)
		if err != nil {
			return nil, err
		}
		if _, err := loadKeyPair(cfg.ClientCert, cfg.ClientKey); err != nil {
			return nil, fmt.Errorf("client keypair: %w", err)
		}
	}
	certPath := cfg.ClientCert
	keyPath := cfg.ClientKey
	out := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: pqHybridCurvePrefs(),
		RootCAs:          caPool,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// In insecure-skip mode the agent often has no client
			// cert yet either; return an empty cert so the handshake
			// proceeds without one.
			if cfg.InsecureSkipTLS {
				if certPath == "" || keyPath == "" {
					return &tls.Certificate{}, nil
				}
				if _, err := os.Stat(certPath); err != nil {
					return &tls.Certificate{}, nil
				}
			}
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	}
	if cfg.InsecureSkipTLS {
		out.InsecureSkipVerify = true
	}
	return out, nil
}

// serverTLSConfig builds the TLS config the server's listener uses. Pins
// TLS 1.2+, requires (and verifies) client certs when RequireClientCert is
// set, and trusts the live trustBundle (own CA + every realm-peer CA on
// disk) for client identities.
//
// Uses GetCertificate (not Certificates) so the underlying cert can be
// swapped at runtime — an operator running `certs server --force` to
// extend the SAN list doesn't need a server restart for the new cert
// to take effect. The reloader's poll loop is started by runServer.
//
// Uses GetConfigForClient to resolve ClientCAs per handshake from the
// trustBundle. Realm join writes a new peer CA to disk, calls
// bundle.rebuild(), and the next agent-failover or peer-sync connection
// trusts the new CA without restarting the listener.
// pqHybridCurvePrefs is the negotiated key-exchange order for every
// SimpleSIEM TLS handshake. SimpleSIEM only ever talks to other
// SimpleSIEM nodes — every peer is built from this same source tree
// at Go 1.24+, so we know X25519MLKEM768 is universally supported
// and there is no compatibility reason to keep classical fallbacks.
//
// X25519MLKEM768 is the NIST-approved hybrid post-quantum KEM
// (X25519 ECDH combined with ML-KEM-768 / FIPS 203). The hybrid
// construction means the session key is secure unless BOTH the
// classical and post-quantum halves are broken — closing the
// "harvest now, decrypt later" gap on captured log streams against
// a future cryptographically-relevant quantum adversary.
//
// Strict-mode rationale: a handshake with an older binary fails
// fast at the curve negotiation step rather than silently dropping
// to a weaker primitive — making downgrade attacks impossible by
// construction. SimpleSIEM has no production deployments to
// preserve compatibility with, so this is the right default.
//
// Used by every server listener via serverTLSConfig + every client
// dial site in master/collector/agent code paths.
func pqHybridCurvePrefs() []tls.CurveID {
	return []tls.CurveID{tls.X25519MLKEM768}
}

func serverTLSConfig(cfg ServerConfig, bundle *trustBundle) (*tls.Config, *certHotReloader, error) {
	reloader, err := newCertHotReloader(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("server keypair: %w", err)
	}
	out := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		GetCertificate:   reloader.getCertificate,
		CurvePreferences: pqHybridCurvePrefs(),
	}
	if cfg.RequireClientCert {
		if bundle == nil {
			return nil, nil, fmt.Errorf("require_client_cert is true but trust bundle is nil")
		}
		if bundle.get() == nil {
			return nil, nil, fmt.Errorf("require_client_cert is true but no CAs in trust bundle (own CA missing?)")
		}
		// VerifyClientCertIfGiven (rather than RequireAndVerifyClientCert)
		// lets /v1/enroll be reachable pre-enrollment — agents have no
		// client cert at that point. Existing mTLS-required endpoints
		// (/v1/events, /v1/health, /v1/heartbeat) already check cert
		// presence inline via authorize() / cert-CN-match, so security
		// for those paths is unchanged: a cert IS still required to
		// post events; the only new no-cert surface is /v1/enroll
		// itself, which is PSK-authenticated.
		out.ClientAuth = tls.VerifyClientCertIfGiven
		out.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			c := out.Clone()
			c.GetConfigForClient = nil
			c.ClientCAs = bundle.get()
			return c, nil
		}
	}
	return out, reloader, nil
}
