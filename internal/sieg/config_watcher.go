package sieg

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"
)

// configWatcher polls config.json's mtime once a second and re-reads
// the file when it changes. State that's safe to refresh at runtime —
// agent_allowlist, master_cns, agent_revoked, master_revoked,
// master_can_rotate_ca — is diffed against the in-memory copies and
// applied immediately. Operators editing config.json see the change
// take effect within ~1s, no daemon restart required.
//
// Fields that affect listener configuration (listen address, cert
// paths, rate limits, etc.) are NOT picked up — restarting the
// daemon is required for those. The watcher silently ignores them.
type configWatcher struct {
	cfgPath  string
	state    *serverState
	lastSeen int64

	stopOnce sync.Once
	stop     chan struct{}
}

func newConfigWatcher(cfgPath string, state *serverState) *configWatcher {
	w := &configWatcher{cfgPath: cfgPath, state: state, stop: make(chan struct{})}
	if info, err := os.Stat(cfgPath); err == nil {
		w.lastSeen = info.ModTime().UnixNano()
	}
	return w
}

// run polls until ctx is cancelled. Safe to call as a goroutine.
func (w *configWatcher) run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		info, err := os.Stat(w.cfgPath)
		if err != nil {
			continue
		}
		mt := info.ModTime().UnixNano()
		if mt == w.lastSeen {
			continue
		}
		w.lastSeen = mt
		w.applyOnce()
	}
}

// applyOnce loads the current config from disk and diffs it against
// the in-memory state. On JSON parse failure we EXPLICITLY refuse to
// touch the in-memory state — `loadConfig` would silently fall back
// to defaults, which would wipe the allowlist, master_cns and revocation
// maps the daemon currently honours. Surfacing this as a meta event
// gives the operator visible feedback (`simplesiem status` notes recent
// _server errors) instead of the previous silent "your edit broke
// something and the daemon kept running with defaults" failure mode.
func (w *configWatcher) applyOnce() {
	cfg, perr := loadConfigStrict(w.cfgPath)
	if perr != nil {
		// Parse failed. Don't apply anything. Emit a meta event so the
		// operator can spot the bad edit via `simplesiem status` —
		// without it the daemon keeps running on the last-good config
		// indefinitely with no on-disk indication that hot-reload is
		// dead.
		if mst, err := w.state.storageFor("_server"); err == nil {
			mst.Write("errors", map[string]any{
				"collector": "config_watcher",
				"error":     "config.json parse failed; in-memory config unchanged",
				"detail":    perr.Error(),
				"hint":      "fix the JSON syntax (see error detail) or restore the previous version with: cp " + w.cfgPath + ".bak " + w.cfgPath,
			})
			mst.Write("meta", map[string]any{
				"event":  "config_invalid",
				"path":   w.cfgPath,
				"detail": perr.Error(),
			})
		}
		return
	}
	s := w.state

	// m9 — log_dir change refused when a collector is paired (or
	// when this host is a master with a paired query-collector).
	// log_dir is baked into Storage at daemon startup so a runtime
	// change can't actually move open file handles; the hot-reload
	// path nonetheless surfaces the rejection so the operator
	// realises their edit didn't take effect AND that even a
	// daemon restart with the new path would put the collector's
	// per-host mirror layout out of sync. The check fires only
	// when collector pairing is in play; standalone / agent /
	// master-without-collector hosts can change log_dir freely
	// (still requires a restart to actually apply).
	if cfg.LogDir != "" && cfg.LogDir != s.base {
		paired := cfg.Server.CollectorCN != "" || cfg.Master.QueryCollectorURL != ""
		if paired {
			if mst, err := s.storageFor("_server"); err == nil {
				mst.Write("errors", map[string]any{
					"collector": "config_watcher",
					"error":     "log_dir change refused: a collector is paired with this host; changing log_dir would put the collector's per-host mirror layout out of sync",
					"old":       s.base,
					"new":       cfg.LogDir,
					"hint":      "to change log_dir on a collector-paired host: (1) revoke the collector pairing (`master collector revoke` / `certs collector revoke`), (2) move the log tree manually, (3) re-pair via accept-next + enroll. Otherwise the change is ignored — the running daemon keeps using " + s.base,
				})
			}
		}
	}

	// Allowlist diff: union additions (the daemon already adds via
	// /v1/enroll), drop removals (the operator's manual edit).
	newAllow := map[string]struct{}{}
	for _, id := range cfg.Server.AgentAllowlist {
		if id != "" {
			newAllow[id] = struct{}{}
		}
	}
	allowChanged := false
	s.allowlistMu.Lock()
	if len(newAllow) != len(s.allowlist) {
		allowChanged = true
	} else {
		for id := range s.allowlist {
			if _, ok := newAllow[id]; !ok {
				allowChanged = true
				break
			}
		}
	}
	if allowChanged {
		s.allowlist = newAllow
	}
	s.allowlistMu.Unlock()

	// master_cns diff: same additive-and-remove story.
	newMasters := append([]string{}, cfg.Server.MasterCNs...)
	masterChanged := false
	s.masterMu.Lock()
	if !sameStringSlice(s.masterCNs, newMasters) {
		masterChanged = true
		s.masterCNs = newMasters
	}
	s.masterMu.Unlock()

	// Revocation maps: replace wholesale (the merge logic in
	// reconcileRealmConfig already handles propagation; an external
	// edit here is the operator's authoritative state).
	revokedChanged := false
	newAgentRev := copyStringMap(cfg.Server.AgentRevoked)
	newMasterRev := copyStringMap(cfg.Server.MasterRevoked)
	s.revokedMu.Lock()
	if !sameStringMap(s.agentRevoked, newAgentRev) || !sameStringMap(s.masterRevoked, newMasterRev) {
		revokedChanged = true
		s.agentRevoked = newAgentRev
		s.masterRevoked = newMasterRev
	}
	s.revokedMu.Unlock()

	// master_can_rotate_ca: atomic swap so HTTP handlers reading the
	// gate can never observe a torn write.
	rotateChanged := s.masterCanRotate.Swap(cfg.Server.MasterCanRotateCA) != cfg.Server.MasterCanRotateCA

	// master_can_uninstall: same shape — operator can flip without
	// daemon restart, configWatcher applies the change so a fleet-
	// wide cascade-uninstall opt-in takes effect within ~1s of
	// editing config.json.
	uninstallChanged := s.masterCanUninstall.Swap(cfg.Server.MasterCanUninstall) != cfg.Server.MasterCanUninstall

	// Realm name + version: operator's `simplesiem realm rename`
	// writes to config.json; without this branch the daemon's
	// in-memory realmName stayed stale until the next sync from a
	// peer (and single-server installs have no peer to sync from).
	// /v1/sync/config returns this value, so masters running
	// `master backup --all-realms` see the renamed realm only when
	// the daemon picks it up live.
	realmNameChanged := false
	newRealmName := strings.TrimSpace(cfg.Server.Realm.Name)
	s.realmMu.Lock()
	if newRealmName != "" && newRealmName != s.realmName {
		s.realmName = newRealmName
		realmNameChanged = true
	}
	if cfg.Server.Realm.ConfigVersion != 0 && cfg.Server.Realm.ConfigVersion != s.realmConfigVer {
		s.realmConfigVer = cfg.Server.Realm.ConfigVersion
	}
	s.realmMu.Unlock()

	// realm.peers: same story as realm.name. The operator's
	// `simplesiem realm join` writes the new peer list; the running
	// daemon needs the runtime peers list updated so cross-server
	// peerAuthorized accepts the joined peer immediately.
	realmPeersChanged := false
	newPeers := append([]string{}, cfg.Server.Realm.Peers...)
	s.realmMu.Lock()
	if !sameStringSlice(s.realmPeers, newPeers) {
		s.realmPeers = newPeers
		realmPeersChanged = true
	}
	s.realmMu.Unlock()

	// Volume-anomaly threshold tuning — pure pass-through; tune()
	// guards against zero-valued resets internally.
	if s.volumeAnomaly != nil {
		s.volumeAnomaly.tune(cfg.Server.VolumeAnomaly)
	}

	if !allowChanged && !masterChanged && !revokedChanged && !rotateChanged &&
		!uninstallChanged && !realmNameChanged && !realmPeersChanged {
		return
	}
	if mst, err := s.storageFor("_server"); err == nil {
		fields := map[string]any{
			"event": "config_hot_reloaded",
			"hint":  "config.json changed on disk; in-memory state refreshed",
		}
		if allowChanged {
			s.allowlistMu.RLock()
			fields["allowlist_size"] = len(s.allowlist)
			s.allowlistMu.RUnlock()
		}
		if masterChanged {
			s.masterMu.RLock()
			fields["master_cns_size"] = len(s.masterCNs)
			s.masterMu.RUnlock()
		}
		if revokedChanged {
			s.revokedMu.RLock()
			fields["revoked_agents"] = len(s.agentRevoked)
			fields["revoked_masters"] = len(s.masterRevoked)
			s.revokedMu.RUnlock()
		}
		if rotateChanged {
			fields["master_can_rotate_ca"] = s.masterCanRotate.Load()
		}
		if uninstallChanged {
			fields["master_can_uninstall"] = s.masterCanUninstall.Load()
		}
		if realmNameChanged {
			fields["realm_name"] = newRealmName
		}
		if realmPeersChanged {
			fields["realm_peers"] = len(newPeers)
		}
		mst.Write("meta", fields)
	}
}

// sameStringSlice reports whether two slices contain the same set of
// strings (order-independent).
func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
		if m[x] < 0 {
			return false
		}
	}
	return true
}

// sameStringMap is the map[string]string analogue of sameStringSlice.
func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
