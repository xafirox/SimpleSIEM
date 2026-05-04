package sieg

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Cert expiry warnings: a daily check that walks every PEM cert this
// daemon owns and emits meta:cert_expiry_warning events at progressively
// shorter horizons. The check runs in every mode (server, agent,
// master) — each contributes the certs it has on disk.
//
// Default thresholds: 30d, 14d, 7d, 24h, 1h. Each is emitted at most
// once per cert per threshold per daemon lifetime; a daemon restart
// re-evaluates and may re-emit. The bookkeeping lives in memory so
// there's no on-disk state to maintain.

var certExpiryThresholds = []time.Duration{
	30 * 24 * time.Hour,
	14 * 24 * time.Hour,
	7 * 24 * time.Hour,
	24 * time.Hour,
	1 * time.Hour,
}

// startCertExpiryMonitor runs the daily check loop. The check runs
// once on startup (so an operator who restarts the daemon and immediately
// runs `simplesiem status` sees current state), then once every 24h.
//
// storage is the daemon's primary meta target. roleHint is "server",
// "agent", or "master" — purely cosmetic, attached to each event so a
// realm-wide search like `triage --type meta --grep cert_expiry` shows
// which role flagged each warning.
func startCertExpiryMonitor(ctx context.Context, wg *sync.WaitGroup, storage *Storage, roleHint string, certPaths []string) {
	if storage == nil || len(certPaths) == 0 {
		return
	}
	mon := &certExpiryMonitor{
		storage:   storage,
		role:      roleHint,
		paths:     certPaths,
		warned:    map[string]map[time.Duration]bool{},
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Initial check shortly after startup so a daemon launched
		// inside the danger window flags it immediately.
		first := time.NewTimer(30 * time.Second)
		defer first.Stop()
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-first.C:
				mon.checkAll()
			case <-t.C:
				mon.checkAll()
			}
		}
	}()
}

type certExpiryMonitor struct {
	storage *Storage
	role    string
	paths   []string

	mu     sync.Mutex
	warned map[string]map[time.Duration]bool // path → threshold → already-warned
}

func (m *certExpiryMonitor) checkAll() {
	now := time.Now()
	for _, path := range m.paths {
		m.checkOne(path, now)
	}
}

func (m *certExpiryMonitor) checkOne(path string, now time.Time) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // path optional / not yet created — silent.
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	remaining := time.Until(cert.NotAfter)
	if remaining <= 0 {
		// Already expired. Use a "fake" threshold of 0 so we warn once.
		m.warnOnce(path, 0, cert, remaining, "cert is EXPIRED — connections will fail")
		return
	}
	for _, threshold := range certExpiryThresholds {
		if remaining > threshold {
			continue
		}
		hint := fmt.Sprintf("expires in %s", humanDuration(remaining))
		m.warnOnce(path, threshold, cert, remaining, hint)
		return // only warn at the smallest threshold the cert is currently inside
	}
}

func (m *certExpiryMonitor) warnOnce(path string, threshold time.Duration, cert *x509.Certificate, remaining time.Duration, hint string) {
	m.mu.Lock()
	if m.warned[path] == nil {
		m.warned[path] = map[time.Duration]bool{}
	}
	if m.warned[path][threshold] {
		m.mu.Unlock()
		return
	}
	m.warned[path][threshold] = true
	m.mu.Unlock()
	m.storage.Write("meta", map[string]any{
		"event":          "cert_expiry_warning",
		"role":           m.role,
		"path":           path,
		"subject":        cert.Subject.CommonName,
		"not_after":      cert.NotAfter.UTC().Format(time.RFC3339),
		"days_remaining": int(remaining.Hours() / 24),
		"hint":           hint,
		"action":         "for client certs: auto-rotation handles this within 30d. For server certs: `simplesiem certs server <hostname> --force`. For CAs: `simplesiem certs init-rotate`.",
	})
}

// humanDuration formats a positive duration as a coarse human string.
// "12h", "3d 4h", "expired 2d ago".
func humanDuration(d time.Duration) string {
	if d < 0 {
		return fmt.Sprintf("expired %s ago", humanDuration(-d))
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if days > 0 {
		if hours > 0 {
			return fmt.Sprintf("%dd %dh", days, hours)
		}
		return fmt.Sprintf("%dd", days)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}

// collectServerCertPaths returns the cert paths a server-mode daemon
// should monitor: the server's TLS cert, its CA, and (when present)
// every legacy CA in <state>/legacy_cas/. Agent and master callers
// have their own helpers below.
func collectServerCertPaths(cfg Config) []string {
	out := []string{}
	if cfg.Server.Cert != "" {
		out = append(out, cfg.Server.Cert)
	}
	if cfg.Server.CACert != "" {
		out = append(out, cfg.Server.CACert)
	}
	if entries, err := os.ReadDir(legacyCAsDir()); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			out = append(out, filepath.Join(legacyCAsDir(), e.Name()))
		}
	}
	return out
}

// collectAgentCertPaths returns the cert paths an agent-mode daemon
// should monitor: its client cert and the bundled CA.
func collectAgentCertPaths(cfg Config) []string {
	out := []string{}
	if cfg.Agent.ClientCert != "" {
		out = append(out, cfg.Agent.ClientCert)
	}
	if cfg.Agent.CACert != "" {
		out = append(out, cfg.Agent.CACert)
	}
	return out
}

// collectMasterCertPaths returns the cert paths a master-mode daemon
// should monitor: every per-server cert.pem under <CertsDir>/<server>/.
// CAs in those dirs are tracked per-server too because they're the
// servers' CAs and a server CA expiring is a fleet-wide event the
// master should surface.
func collectMasterCertPaths(cfg Config) []string {
	out := []string{}
	root := masterCertsDir(cfg)
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
