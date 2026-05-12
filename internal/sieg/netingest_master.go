package sieg

import (
	"context"
	"crypto/tls"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// startMasterNetworkIngestListener stands up the master-tier HTTP
// listener used for bidirectional allowlist sync. Bound to
// cfg.Master.NetworkIngest.SyslogTLSListen — operators configure ONE
// TLS listener and the same port serves the network-allowlist sync
// endpoints. (The syslog ingest port is the same; mux routes /v1/...
// to the JSON endpoints, falls back to syslog-frame parsing for
// non-HTTP traffic.)
//
// Pass 1 implementation simplification: stand up a SECOND tiny
// listener on the configured "sync" address. We use a separate field
// — cfg.Master.NetworkIngest.TLSCert / TLSKey — to avoid colliding
// with the bare-syslog port, which streams arbitrary bytes.
//
// Address: cfg.Master.Listen + 1 (e.g. ":9444" → ":9445"-style,
// but explicitly configurable). For pass 1 we use a simple sub-path
// scheme: the master health listener already runs on cfg.Master.Listen,
// and we extend it with the allowlist endpoints by adding handlers.
func startMasterNetworkIngestListener(ctx context.Context, wg *sync.WaitGroup, cfg Config,
	masterStore *Storage, store *networkAllowlist) {
	addr := strings.TrimSpace(cfg.Master.NetworkIngest.SyslogTLSListen)
	if addr == "" {
		// No bind: the master can still RECEIVE pushes via the master
		// collector listener if it's running, but for pass 1 we keep
		// the surfaces separate. Operators wanting bidirectional sync
		// must set SyslogTLSListen.
		return
	}
	// startNetworkIngest also binds the syslog TLS listener to this
	// same address when NetworkIngest is enabled. Two listeners on one
	// port collide; the syslog listener loses (raw frames hit the HTTP
	// mux and 400 out) and unauthenticated meta events never fire.
	// Skip the master-tier sync listener when the syslog listener owns
	// the port — the /v1/server/network-allowlist endpoints are
	// unreachable until a separate sync port is configured, but the
	// primary syslog ingest works.
	if cfg.Master.NetworkIngest.Enabled {
		masterStore.Write("meta", map[string]any{
			"event":  "master_network_sync_listener_skipped",
			"reason": "syslog_listener_owns_port",
			"addr":   addr,
			"hint":   "syslog ingest takes precedence; the network-allowlist sync endpoints are not bound on this port",
		})
		return
	}
	tlsCfg, info, err := buildNetworkIngestTLS(cfg, cfg.Master.NetworkIngest)
	if err != nil {
		masterStore.Write("errors", map[string]any{
			"collector": "master_network_ingest",
			"error":     err.Error(),
		})
		return
	}
	if info != "" {
		masterStore.Write("meta", map[string]any{
			"event":  "master_network_ingest_tls_cert",
			"detail": info,
		})
	}
	mux := http.NewServeMux()
	adapter := &masterNetworkIngestAdapter{cfg: cfg, store: store, masterStore: masterStore}
	installNetworkIngestMasterEndpoints(mux, adapter, store)
	srv := &http.Server{
		Addr:              "sync-" + addr, // tagging only; Addr unused below
		Handler:           mux,
		TLSConfig:         tlsCfg,
		MaxHeaderBytes:    32 * 1024,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		masterStore.Write("errors", map[string]any{
			"collector": "master_network_ingest",
			"error":     "listen: " + err.Error(),
		})
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		masterStore.Write("meta", map[string]any{
			"event":  "master_network_ingest_listener_start",
			"listen": addr,
		})
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			masterStore.Write("errors", map[string]any{
				"collector": "master_network_ingest",
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

// masterNetworkIngestAdapter implements masterStateAdapter — auth +
// fan-out helpers that the master endpoints need.
type masterNetworkIngestAdapter struct {
	cfg         Config
	store       *networkAllowlist
	masterStore *Storage
}

func (a *masterNetworkIngestAdapter) requireServerCN(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	for _, srv := range a.cfg.Master.Servers {
		host := serverHostFromURL(srv)
		if cn == host || strings.HasSuffix(cn, "-"+host) || cn == strings.Split(host, ".")[0] {
			return true
		}
	}
	return false
}

func (a *masterNetworkIngestAdapter) fanoutAllowlist(store *networkAllowlist, excluding string) {
	cfgVer, entries := store.Snapshot()
	body := struct {
		ConfigVersion int64           `json:"config_version"`
		Entries       []networkSource `json:"entries"`
		FromPeer      string          `json:"from_peer"`
	}{cfgVer, entries, masterID(a.cfg)}
	failed := []string{}
	for _, srv := range a.cfg.Master.Servers {
		host := serverHostFromURL(srv)
		if host == excluding {
			continue
		}
		if err := postJSONFromMaster(a.cfg, srv, "/v1/master/network-allowlist", body); err != nil {
			failed = append(failed, host)
			if a.masterStore != nil {
				a.masterStore.Write("errors", map[string]any{
					"collector": "network_allowlist_fanout",
					"server":    host,
					"error":     err.Error(),
				})
			}
		}
	}
	if len(failed) > 0 && a.masterStore != nil {
		a.masterStore.Write("meta", map[string]any{
			"event":         "network_allowlist_fanout_partial",
			"failed_peers":  failed,
			"hint":          "the next master sync tick will retry; or run `simplesiem network-source resync` on the affected servers",
		})
	}
}

// loadMasterRules reads cfg.Master.RulesPath if set, else returns
// the local rules file. Best-effort.
func loadMasterRules(cfg Config) []*alertRule {
	rp := cfg.Master.RulesPath
	if rp == "" {
		rp = cfg.RulesPath
	}
	if rp == "" {
		return nil
	}
	rules, err := loadRules(rp)
	if err != nil {
		return nil
	}
	return rules
}

// openHostStorage opens (or creates) a per-host Storage rooted at
// <log_dir>/<host>/. Used by the master's network ingest path.
func openHostStorage(logDir, host, group string) (*Storage, error) {
	gid := resolveGroupGID(group)
	return NewStorage(filepath.Join(logDir, host), gid, 0, 0)
}
