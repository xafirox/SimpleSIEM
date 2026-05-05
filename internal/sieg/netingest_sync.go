package sieg

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Bidirectional master ↔ server allowlist sync.
//
// Endpoints:
//
//   on the SERVER:
//     GET  /v1/server/network-allowlist            (master → server pull)
//     GET  /v1/server/network-allowlist-snapshot   (master → server pull on resync)
//     POST /v1/master/network-allowlist            (master → server push;
//                                                    refused unless
//                                                    master_can_push_allowlist:true)
//
//   on the MASTER:
//     POST /v1/server/network-allowlist-changed    (server → master push)
//     GET  /v1/server/network-allowlist            (server → master pull)
//
// Auth on every endpoint = the existing mTLS posture (server cert
// trust pool). The endpoint handler additionally validates the caller
// CN matches a known peer of the relevant kind.

// installNetworkIngestServerEndpoints wires the server-side handlers
// onto the existing mux. Called from runServer().
func installNetworkIngestServerEndpoints(mux *http.ServeMux, st *serverState, store *networkAllowlist) {
	mux.HandleFunc("/v1/server/network-allowlist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if !st.requireMasterOrPeer(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		emitAllowlistSnapshot(w, store)
	})
	mux.HandleFunc("/v1/server/network-allowlist-snapshot", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if !st.requireMasterOrPeer(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		emitAllowlistSnapshot(w, store)
	})
	mux.HandleFunc("/v1/master/network-allowlist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if !st.requireMaster(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// Per-server consent: refuse unless master_can_push_allowlist=true.
		if !st.allowMasterPushAllowlist() {
			http.Error(w, "master_can_push_allowlist=false on this server",
				http.StatusForbidden)
			if st.metaLogger() != nil {
				st.metaLogger().Write("meta", map[string]any{
					"event":  "network_allowlist_push_refused",
					"reason": "master_can_push_allowlist_false",
				})
			}
			return
		}
		var body struct {
			ConfigVersion int64           `json:"config_version"`
			Entries       []networkSource `json:"entries"`
			FromPeer      string          `json:"from_peer"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "json", http.StatusBadRequest)
			return
		}
		store.ApplySnapshot(body.ConfigVersion, body.Entries, body.FromPeer)
		w.WriteHeader(http.StatusNoContent)
	})
}

// installNetworkIngestMasterEndpoints wires the master-side handlers.
// The master may not have an HTTP listener yet — caller must ensure
// one is running. masterStateAdapter abstracts the auth check.
func installNetworkIngestMasterEndpoints(mux *http.ServeMux, ms masterStateAdapter, store *networkAllowlist) {
	mux.HandleFunc("/v1/server/network-allowlist-changed", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if !ms.requireServerCN(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var body struct {
			ConfigVersion int64           `json:"config_version"`
			Entries       []networkSource `json:"entries"`
			FromPeer      string          `json:"from_peer"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "json", http.StatusBadRequest)
			return
		}
		store.ApplySnapshot(body.ConfigVersion, body.Entries, body.FromPeer)
		// Cascade to other servers (excluding the originator).
		go ms.fanoutAllowlist(store, body.FromPeer)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/server/network-allowlist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if !ms.requireServerCN(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		emitAllowlistSnapshot(w, store)
	})
}

func emitAllowlistSnapshot(w http.ResponseWriter, store *networkAllowlist) {
	cfgVer, entries := store.Snapshot()
	out := struct {
		ConfigVersion int64           `json:"config_version"`
		Entries       []networkSource `json:"entries"`
	}{cfgVer, entries}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// masterStateAdapter is the small interface masterState satisfies so
// the network-ingest endpoints can authenticate without importing
// master internals.
type masterStateAdapter interface {
	requireServerCN(*http.Request) bool
	fanoutAllowlist(store *networkAllowlist, excluding string)
}

// pendingPushDispatcher flushes <state>/server/network_allowlist_pending.json
// to the master on a 60-second tick. Survives master outages — every
// edit accumulates and is replayed once the master comes back.
type pendingPushDispatcher struct {
	cfg   Config
	store *networkAllowlist
	stop  chan struct{}
	wg    sync.WaitGroup
}

func newPendingPushDispatcher(cfg Config, store *networkAllowlist) *pendingPushDispatcher {
	return &pendingPushDispatcher{cfg: cfg, store: store, stop: make(chan struct{})}
}

func (p *pendingPushDispatcher) start(ctx context.Context, parentWG *sync.WaitGroup) {
	parentWG.Add(1)
	go func() {
		defer parentWG.Done()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			p.flush()
		}
	}()
}

func (p *pendingPushDispatcher) flush() {
	queuePath := pendingPushPath(p.cfg)
	data, err := os.ReadFile(queuePath)
	if err != nil {
		return // nothing queued
	}
	masterURL := firstMasterURL(p.cfg)
	if masterURL == "" {
		return
	}
	var body struct {
		ConfigVersion int64           `json:"config_version"`
		Entries       []networkSource `json:"entries"`
		FromPeer      string          `json:"from_peer"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		_ = os.Remove(queuePath)
		return
	}
	if err := postJSONToMaster(p.cfg, masterURL, "/v1/server/network-allowlist-changed", body); err != nil {
		return // try again next tick
	}
	_ = os.Remove(queuePath)
}

// realPostJSONToMaster swaps in for the package-level stub at startup.
func realPostJSONToMaster(cfg Config, base, path string, body any) error {
	c, err := newMasterPushClient(cfg)
	if err != nil {
		return err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, joinURL(base, path), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !httpStatusOK(resp.StatusCode) {
		// LimitReader caps how much error-body we'll buffer in memory.
		// A misbehaving / hostile peer could otherwise stream MBs of
		// junk that we'd quote in an error string.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func realPostJSONFromMaster(cfg Config, base, path string, body any) error {
	c, err := newServerPushClient(cfg, base)
	if err != nil {
		return err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, joinURL(base, path), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !httpStatusOK(resp.StatusCode) {
		// LimitReader caps how much error-body we'll buffer in memory.
		// A misbehaving / hostile peer could otherwise stream MBs of
		// junk that we'd quote in an error string.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func realGetFromMaster(cfg Config, base, path string) (*http.Response, error) {
	c, err := newMasterPushClient(cfg)
	if err != nil {
		return nil, err
	}
	if base == "" {
		// master is calling itself
		base = firstMasterURL(cfg)
	}
	if base == "" {
		// server-mode caller: no master URL; try to derive from first
		// enrolled master CN (stored as a hint in <state>/master_url.txt
		// at enrollment time).
		base = firstMasterURL(cfg)
	}
	if base == "" {
		return nil, fmt.Errorf("no master URL")
	}
	req, err := http.NewRequest(http.MethodGet, joinURL(base, path), nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// newMasterPushClient builds an mTLS client that uses the master's
// per-server cert (cfg.Master.CertsDir/<host>/{cert,key,ca}.pem) when
// the caller is the master, OR the server's own cert when calling out.
//
// In server mode we use cfg.Server.Cert (the server is the client to
// the master listener; the master verifies via the server's CN).
func newMasterPushClient(cfg Config) (*http.Client, error) {
	mode := normaliseMode(cfg.Mode)
	if mode == "server" {
		cert, err := tls.LoadX509KeyPair(cfg.Server.Cert, cfg.Server.Key)
		if err != nil {
			return nil, err
		}
		caBytes, err := os.ReadFile(cfg.Server.CACert)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caBytes)
		tcfg := &tls.Config{
			Certificates:     []tls.Certificate{cert},
			RootCAs:          pool,
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: pqHybridCurvePrefs(),
		}
		return &http.Client{
			Transport: &http.Transport{TLSClientConfig: tcfg},
			Timeout:   10 * time.Second,
		}, nil
	}
	// Master mode — pick first per-server cert dir.
	if len(cfg.Master.Servers) == 0 {
		return nil, fmt.Errorf("no servers enrolled")
	}
	host := serverHostFromURL(cfg.Master.Servers[0])
	dir := filepath.Join(cfg.Master.CertsDir, host)
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, err
	}
	caBytes, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caBytes)
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates:     []tls.Certificate{cert},
			RootCAs:          pool,
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: pqHybridCurvePrefs(),
		}},
		Timeout: 10 * time.Second,
	}, nil
}

func newServerPushClient(cfg Config, srvURL string) (*http.Client, error) {
	host := serverHostFromURL(srvURL)
	dir := filepath.Join(cfg.Master.CertsDir, host)
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, err
	}
	caBytes, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caBytes)
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates:     []tls.Certificate{cert},
			RootCAs:          pool,
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: pqHybridCurvePrefs(),
		}},
		Timeout: 10 * time.Second,
	}, nil
}

func serverHostFromURL(s string) string {
	u := strings.TrimPrefix(s, "https://")
	u = strings.TrimPrefix(u, "http://")
	if i := strings.Index(u, "/"); i >= 0 {
		u = u[:i]
	}
	if h, _, err := net.SplitHostPort(u); err == nil {
		return h
	}
	return u
}

func joinURL(base, path string) string {
	return strings.TrimRight(base, "/") + path
}

// initNetworkSyncImpls swaps the package-level stubs for the real
// implementations. Called once at server / master startup.
func initNetworkSyncImpls() {
	postJSONToMaster = realPostJSONToMaster
	postJSONFromMaster = realPostJSONFromMaster
	getFromMaster = realGetFromMaster
}
