package sieg

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Realm = the redundancy / replication group a server belongs to.
// Peers in a realm:
//   - share a CA (so each peer's server cert is mutually trusted via mTLS)
//   - run a sync goroutine that pulls events from every other peer every
//     realm.sync_interval_seconds (default 60) so each peer ends up with
//     the same view of agent traffic.
//   - reconcile the realm name itself last-write-wins by config_version
//     timestamp, so renaming the realm from any peer propagates to the
//     others.
//
// Loop avoidance: each event is stamped with origin_server at ingress
// (the server that received it from the agent). Sync requests filter
// to events with origin_server == this server's selfPeerID, so an
// event ingested by A and replicated to B is NEVER replicated by B
// back to A — B's "events I ingested locally" set doesn't include it.
//
// Storage: replicated events go into <log_dir>/<host>/<type>/<date>.from-<peer>.jsonl
// instead of the canonical <date>.jsonl, so each origin keeps an
// independent hash chain. `simplesiem verify` validates each chain
// file separately (no cross-file linkage required).

// SyncEvent is the wire format of /v1/sync/events. Each NDJSON line
// is a full event as it sits on disk on the source server, including
// its chain fields. The destination server preserves them — the chain
// stays intact across replication.
type SyncEvent map[string]any

// handleSyncEvents serves a peer asking for events newer than `since`
// that this server received directly from agents.
//
// Auth model:
//   - TLS handshake validates the caller's cert against our CA pool
//     (already enforced by the global TLS config when require_client_cert).
//   - The caller's cert CN must match the hostname of one of our
//     realm.peers entries. Without this, any agent with a valid client
//     cert could read every event in the realm — that's a real auth
//     escalation.
func (s *serverState) handleSyncEvents(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.peerAuthorized(r) {
		s.logAuthFailure(r, "sync/events")
		http.Error(w, "not a recognised realm peer", http.StatusForbidden)
		return
	}

	// Parse the watermark — empty / unparsable means "give me everything"
	// which is fine for a peer that just came online.
	since := time.Time{}
	if q := r.URL.Query().Get("since"); q != "" {
		if t, err := time.Parse(time.RFC3339Nano, q); err == nil {
			since = t
		}
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	count := 0

	// Walk every <host>/<type>/<date>.jsonl that's >= since's date.
	// Excludes .from-<peer>.jsonl files (those are replicated copies,
	// not local ingress) so we never replicate replicated events.
	base := s.base
	hosts, _ := os.ReadDir(base)
	for _, h := range hosts {
		if !h.IsDir() {
			continue
		}
		// Defence in depth: only walk directories whose name is a
		// valid host ID. The daemon never writes outside this set,
		// but a stale or unexpected directory under <log_dir> would
		// otherwise be enumerated. validHostName matches the regex
		// every other path-construction site uses.
		if !validHostName.MatchString(h.Name()) {
			continue
		}
		hostDir := filepath.Join(base, h.Name())
		_ = filepath.WalkDir(hostDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			name := d.Name()
			// Only canonical (locally-ingested) files — never replicated copies.
			if !strings.HasSuffix(name, ".jsonl") || strings.Contains(name, ".from-") {
				return nil
			}
			// Date filter: skip files older than the watermark's day.
			date := dateFromLogName(name)
			if !date.IsZero() && !since.IsZero() && date.Before(since.Truncate(24*time.Hour)) {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			for scanner.Scan() {
				var ev SyncEvent
				if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
					continue
				}
				if originStr, _ := ev["origin_server"].(string); originStr != s.selfPeerID {
					// Replicated from another peer originally; skip so
					// we only return our own ingress.
					continue
				}
				if rs, _ := ev["received_at"].(string); rs != "" {
					if t, err := time.Parse(time.RFC3339Nano, rs); err == nil {
						if !since.IsZero() && !t.After(since) {
							continue
						}
					}
				}
				if err := enc.Encode(ev); err != nil {
					return err
				}
				count++
			}
			return nil
		})
	}
	_ = count
}

// handleSyncConfig returns the realm name, a config_version (unix nano
// of the most recent local edit), the realm.peers list this server
// knows about, and the public CA of every peer this server trusts
// (including its own). Peers compare versions and adopt the latest
// realm name; they also union the peer list and write any new peer
// CAs into their trust bundle so a server that joined elsewhere
// becomes trusted across the whole realm without a separate join.
func (s *serverState) handleSyncConfig(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if !s.peerAuthorized(r) {
		s.logAuthFailure(r, "sync/config")
		http.Error(w, "not a recognised realm peer", http.StatusForbidden)
		return
	}
	s.realmMu.RLock()
	realm := s.realmName
	ver := s.realmConfigVer
	peers := append([]string{}, s.realmPeers...)
	s.realmMu.RUnlock()

	// Collect own CA + every peer CA on disk.
	peerCAs := []RealmPeerCA{}
	if ownPem, err := os.ReadFile(filepath.Join(s.certsDir, "ca.pem")); err == nil {
		peerCAs = append(peerCAs, RealmPeerCA{ID: s.selfPeerID, URL: selfPeerURL(s.selfPeerID, s.http.Addr), CAPem: string(ownPem)})
	}
	if entries, err := os.ReadDir(realmPeerCAsDir()); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
				continue
			}
			id := strings.TrimSuffix(e.Name(), ".pem")
			data, derr := os.ReadFile(filepath.Join(realmPeerCAsDir(), e.Name()))
			if derr != nil {
				continue
			}
			peerURL := ""
			for _, p := range peers {
				if peerIDFromURL(p) == id {
					peerURL = p
					break
				}
			}
			peerCAs = append(peerCAs, RealmPeerCA{ID: id, URL: peerURL, CAPem: string(data)})
		}
	}

	// Allowlist replication: peers in a realm must agree on which
	// agent IDs are authorised, otherwise an agent enrolled with peer
	// A can't fail over to peer B without re-enrollment. The merge is
	// additive (each peer unions the inbound list with its local one);
	// revocation must happen explicitly on each peer until a tombstone
	// mechanism is added.
	s.allowlistMu.RLock()
	allow := make([]string, 0, len(s.allowlist))
	for id := range s.allowlist {
		allow = append(allow, id)
	}
	s.allowlistMu.RUnlock()
	sort.Strings(allow)

	revokedAgents, revokedMasters := s.snapshotRevoked()
	cfgNow := loadConfig(s.configPath)
	unrevokeAgents := copyStringMap(cfgNow.Server.AgentUnrevokeIntent)
	unrevokeMasters := copyStringMap(cfgNow.Server.MasterUnrevokeIntent)

	// master_cns also propagates so peers in the realm know about
	// each other's masters automatically. The master-enroll
	// auto-discovery flow uses this to fan out: after enrolling
	// with one peer, the master queries this endpoint, picks up
	// the realm's peer URLs + peer CAs, and writes per-peer cert
	// dirs without the operator having to enroll separately.
	s.masterMu.RLock()
	masterCNs := append([]string{}, s.masterCNs...)
	s.masterMu.RUnlock()
	sort.Strings(masterCNs)

	resp := map[string]any{
		"realm_name":             realm,
		"config_version":         ver,
		"peer_id":                s.selfPeerID,
		"peers":                  peers,
		"peer_cas":               peerCAs,
		"agent_allowlist":        allow,
		"master_cns":             masterCNs,
		"agent_revoked":          revokedAgents,
		"master_revoked":         revokedMasters,
		"agent_unrevoke_intent":  unrevokeAgents,
		"master_unrevoke_intent": unrevokeMasters,
	}
	// master_url + collector_push_config are surfaced so collectors can
	// auto-detect a higher-authority peer and pick up master-pushed
	// pull-interval changes without an operator round-trip. Both are
	// optional — empty when no master has enrolled or no push policy
	// is configured.
	if cfgNow.Server.Realm.MasterURL != "" {
		resp["master_url"] = cfgNow.Server.Realm.MasterURL
	}
	if cfgNow.Master.CollectorPushConfig.PullIntervalSeconds > 0 {
		resp["collector_push_config"] = map[string]any{
			"pull_interval_seconds": cfgNow.Master.CollectorPushConfig.PullIntervalSeconds,
		}
	}
	// collector_cn — surface the server's currently-paired collector CN
	// so an enrolling master can detect existing collector pairings
	// during `master enroll` and decide whether to adopt the realm
	// collector (master has no slot taken) or direct it to demote
	// (master already has its own collector).
	if cfgNow.Server.CollectorCN != "" {
		resp["collector_cn"] = cfgNow.Server.CollectorCN
	}
	// Pending master→collector directives. Surface only when the caller
	// IS the paired collector (mTLS peer CN matches Server.CollectorCN)
	// — masters / peer servers seeing a directive bound for someone
	// else would be a leak. The directive is single-use: clear it after
	// inclusion so a slow-to-poll collector isn't re-told on every tick.
	if cfgNow.Server.CollectorCN != "" && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		callerCN := r.TLS.PeerCertificates[0].Subject.CommonName
		if callerCN == cfgNow.Server.CollectorCN {
			emitted := false
			if cfgNow.Server.Realm.PendingMasterCollectorPSK != "" {
				resp["master_collector_psk"] = cfgNow.Server.Realm.PendingMasterCollectorPSK
				emitted = true
			}
			if cfgNow.Server.Realm.PendingCollectorDemote {
				resp["collector_demote_to_server"] = true
				emitted = true
			}
			if emitted {
				_ = clearRealmPendingCollectorDirective(s.configPath)
			}
		}
	}
	// ca_bundle surfaces the source's full trusted-CA bundle (current
	// + legacy) so a paired collector can detect a CA rotation and
	// refresh its on-disk ca.pem proactively, closing the gap where
	// a freshly-issued collector cert wouldn't trigger /v1/rotate
	// for years and the bundle would stay stale.
	if bundle, err := buildRealmCABundle(s.certsDir); err == nil {
		resp["ca_bundle"] = bundle
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// peerAuthorized reports whether the request's TLS client cert CN
// matches a recognised realm peer or registered master. Realm peers
// are identified by hostname-of-URL (matching realm.peers); masters
// by exact CN (matching server.master_cns, populated by
// /v1/enroll-master). Both forms grant the same /v1/sync/events
// access — the master is conceptually a special peer that lives
// above the realm.
func (s *serverState) peerAuthorized(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	if cn == "" {
		return false
	}
	s.realmMu.RLock()
	for _, peer := range s.realmPeers {
		if peerIDFromURL(peer) == cn {
			s.realmMu.RUnlock()
			return true
		}
	}
	s.realmMu.RUnlock()
	// Master path: a master must be in master_cns AND not revoked.
	// The agent path's revocation check runs in handleEvents instead.
	s.masterMu.RLock()
	for _, mcn := range s.masterCNs {
		if mcn == cn {
			s.masterMu.RUnlock()
			if s.masterRevokedAt(cn) != "" {
				return false
			}
			return true
		}
	}
	s.masterMu.RUnlock()
	// Collector path: at most one CN, recorded in cfg.Server.CollectorCN.
	// Re-read from disk each call so revoke takes effect without a daemon
	// restart (consistent with masters which mutate via masterMu).
	if cfg := loadConfig(s.configPath); cfg.Server.CollectorCN != "" && cfg.Server.CollectorCN == cn {
		return true
	}
	return false
}

// realmSyncLoop is the per-server goroutine that pulls events from
// each peer every sync_interval_seconds. Always running — peers are
// re-read from the live serverState on each iteration so realm.peers
// growing after boot (via /v1/realm/join) starts replicating without
// a daemon restart. When the peer set is empty the loop is a no-op.
//
// Watermark per peer is kept under <state>/realm/<peer-id>.watermark
// holding the last received_at we've seen from that peer. On startup
// the watermark is read from disk so a restart doesn't replay every
// event since day zero.
func (s *serverState) realmSyncLoop(ctx context.Context, _ []string, intervalSec int, tlsCfg *tls.Config) {
	if intervalSec <= 0 {
		// 15s default. The sync exchanges trust+config (allowlist,
		// master_cns, revocation tombstones) — every payload is small.
		// At the previous 60s default an agent enrolled with one peer
		// could not fail over to another for up to a minute, because
		// the destination peer hadn't pulled the new allowlist entry
		// yet. The MAMS multi-agents test exposed this as flake.
		intervalSec = 15
	}
	stateDir := filepath.Join(defaultStateDir(), "realm")
	_ = os.MkdirAll(stateDir, 0o750)

	tr := &http.Transport{
		TLSClientConfig:       tlsCfg.Clone(),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 60 * time.Second}

	t := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer t.Stop()

	// Run once after a short delay so an idle restart doesn't have to
	// wait the full interval to start replicating. 500ms is enough for
	// TLS configs to settle but small enough that a fresh peer pulls
	// the realm view sub-second.
	first := time.NewTimer(500 * time.Millisecond)
	defer first.Stop()

	doSync := func() {
		s.realmMu.RLock()
		peers := append([]string{}, s.realmPeers...)
		s.realmMu.RUnlock()
		if len(peers) == 0 {
			return
		}
		for _, peer := range peers {
			s.syncFromPeer(ctx, client, stateDir, peer)
		}
		s.reconcileRealmConfig(ctx, client, peers)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			doSync()
		case <-t.C:
			doSync()
		}
	}
}

// syncFromPeer asks one peer for events newer than our watermark.
// Best-effort: any failure (network, TLS, malformed JSON) just leaves
// the watermark where it was so the next cycle retries.
func (s *serverState) syncFromPeer(ctx context.Context, client *http.Client, stateDir, peer string) {
	id := peerIDFromURL(peer)
	if id == "" {
		return
	}
	watermarkPath := filepath.Join(stateDir, id+".watermark")
	since := readWatermark(watermarkPath)

	q := url.Values{}
	if !since.IsZero() {
		q.Set("since", since.Format(time.RFC3339Nano))
	}
	reqURL := strings.TrimRight(peer, "/") + "/v1/sync/events?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		// Log once per outage rather than every cycle; agents have a
		// similar pattern. We don't have a degraded flag for peers
		// (yet); a short error per failed cycle is acceptable noise.
		s.broadcastErr("realm_sync", fmt.Errorf("pull from %s: %w", peer, err))
		if tr, ok := client.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		s.broadcastErr("realm_sync", fmt.Errorf("pull from %s: HTTP %d: %s", peer, resp.StatusCode, strings.TrimSpace(string(buf))))
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	maxSeen := since
	count := 0
	for scanner.Scan() {
		var ev SyncEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if !s.writeReplicated(ev, id) {
			continue
		}
		if rs, _ := ev["received_at"].(string); rs != "" {
			if t, err := time.Parse(time.RFC3339Nano, rs); err == nil && t.After(maxSeen) {
				maxSeen = t
			}
		}
		count++
	}
	if maxSeen.After(since) {
		_ = writeWatermark(watermarkPath, maxSeen)
	}
	if count > 0 {
		if mst, gerr := s.storageFor("_server"); gerr == nil {
			mst.Write("meta", map[string]any{
				"event":      "realm_sync_pulled",
				"peer":       peer,
				"events":     count,
				"watermark":  maxSeen.Format(time.RFC3339Nano),
			})
		}
	}
}

// writeReplicated stores an event from a peer into a per-origin file:
// <log_dir>/<host>/<type>/<date>.from-<origin>.jsonl. Returns true if
// the event was actually written (false on bad shape, missing fields,
// or self-loop guard).
func (s *serverState) writeReplicated(ev SyncEvent, peerID string) bool {
	host, _ := ev["host"].(string)
	typ, _ := ev["type"].(string)
	if host == "" || typ == "" {
		return false
	}
	if !safeHostName(s.base, host) {
		return false
	}
	if !agentAllowedTypes[typ] && typ != "alerts" {
		// We allow "alerts" via replication so the master / peers see
		// the same alert stream as the origin. Direct agent uploads
		// of "alerts" remain blocked in handleEvents.
		return false
	}
	origin, _ := ev["origin_server"].(string)
	if origin == "" {
		// Bad / fabricated event from a peer — no way to dedupe.
		return false
	}
	if origin == s.selfPeerID {
		// Loop-guard: somehow a peer sent us back our own event.
		return false
	}
	date := time.Now().UTC().Format("2006-01-02")
	if rs, _ := ev["received_at"].(string); rs != "" {
		if t, err := time.Parse(time.RFC3339Nano, rs); err == nil {
			date = t.UTC().Format("2006-01-02")
		}
	}
	dir := filepath.Join(s.base, host, typ)
	if err := os.MkdirAll(dir, logDirMode); err != nil {
		return false
	}
	path := filepath.Join(dir, date+".from-"+origin+".jsonl")
	line, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	line = append(line, '\n')
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, logFileMode)
	if err != nil {
		return false
	}
	defer f.Close()
	// Replicated events keep their original chain fields, so the
	// per-(origin, host, type) chain is preserved. simplesiem verify
	// validates each .jsonl file independently — replicated files
	// are valid as long as the origin's chain is.
	_, err = f.Write(line)
	return err == nil
}

// reconcileRealmConfig fetches each peer's realm config and:
//
//   - adopts the realm name from whichever peer reports the latest
//     config_version (last-write-wins),
//   - unions the peer URL set across every peer's response,
//   - writes any unknown peer CA (one we don't yet trust) into our
//     trust bundle, then rebuilds the live pool so the next handshake
//     accepts agents enrolled with that peer.
//
// This is what makes a 3+ node realm self-heal: B joins A, then C
// joins A, then on the next cycle A's config sync tells B about C
// (and vice-versa). No quadratic join handshake from each node.
func (s *serverState) reconcileRealmConfig(ctx context.Context, client *http.Client, peers []string) {
	type peerCfg struct {
		realm string
		ver   int64
	}
	var best peerCfg
	s.realmMu.RLock()
	best = peerCfg{realm: s.realmName, ver: s.realmConfigVer}
	s.realmMu.RUnlock()

	allURLs := map[string]bool{}
	allCAs := map[string]string{}       // id -> CA pem
	allAllow := map[string]bool{}       // agent_id -> seen on at least one peer
	allMasters := map[string]bool{}     // master CN -> seen on at least one peer
	allRevAgent := map[string]string{}  // agent_id -> earliest revocation timestamp seen
	allRevMaster := map[string]string{} // master_cn -> earliest revocation timestamp seen
	// Unrevoke intent counts: id -> count of peers (including self)
	// that voted to drop the tombstone with a timestamp newer than
	// the revocation timestamp.
	intentAgentCount := map[string]int{}
	intentMasterCount := map[string]int{}
	for _, peer := range peers {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(peer, "/")+"/v1/sync/config", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		var pc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&pc)
		resp.Body.Close()
		name, _ := pc["realm_name"].(string)
		var ver int64
		switch v := pc["config_version"].(type) {
		case float64:
			ver = int64(v)
		case json.Number:
			ver, _ = v.Int64()
		}
		if name == "" {
			continue
		}
		if ver > best.ver {
			best = peerCfg{realm: name, ver: ver}
		}
		if peerList, ok := pc["peers"].([]any); ok {
			for _, p := range peerList {
				if ps, ok := p.(string); ok && ps != "" {
					allURLs[ps] = true
				}
			}
		}
		if pcas, ok := pc["peer_cas"].([]any); ok {
			for _, item := range pcas {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				id, _ := m["id"].(string)
				caPem, _ := m["ca_pem"].(string)
				if id != "" && caPem != "" {
					allCAs[id] = caPem
				}
			}
		}
		if al, ok := pc["agent_allowlist"].([]any); ok {
			for _, item := range al {
				if id, ok := item.(string); ok && id != "" {
					allAllow[id] = true
				}
			}
		}
		if ml, ok := pc["master_cns"].([]any); ok {
			for _, item := range ml {
				if cn, ok := item.(string); ok && cn != "" {
					allMasters[cn] = true
				}
			}
		}
		if rev, ok := pc["agent_revoked"].(map[string]any); ok {
			for id, ts := range rev {
				if tss, ok := ts.(string); ok && tss != "" {
					if cur, exist := allRevAgent[id]; !exist || tss < cur {
						allRevAgent[id] = tss
					}
				}
			}
		}
		if rev, ok := pc["master_revoked"].(map[string]any); ok {
			for cn, ts := range rev {
				if tss, ok := ts.(string); ok && tss != "" {
					if cur, exist := allRevMaster[cn]; !exist || tss < cur {
						allRevMaster[cn] = tss
					}
				}
			}
		}
		if it, ok := pc["agent_unrevoke_intent"].(map[string]any); ok {
			for id, ts := range it {
				if tss, ok := ts.(string); ok && tss != "" {
					intentAgentCount[id]++
					_ = tss // timestamp also useful for the freshness check below
				}
			}
		}
		if it, ok := pc["master_unrevoke_intent"].(map[string]any); ok {
			for cn, ts := range it {
				if tss, ok := ts.(string); ok && tss != "" {
					intentMasterCount[cn]++
					_ = tss
				}
			}
		}
	}

	// Add this peer's own intent to the count (each peer's
	// /v1/sync/config response excluded itself from the loop above).
	cfgSelf := loadConfig(s.configPath)
	for id := range cfgSelf.Server.AgentUnrevokeIntent {
		intentAgentCount[id]++
	}
	for cn := range cfgSelf.Server.MasterUnrevokeIntent {
		intentMasterCount[cn]++
	}

	// Quorum check: ⌈(peers+self)/2⌉+1. Single-peer realm trivially
	// quorums with 1 vote; 2-peer realm needs 2; 3-peer realm needs 2; etc.
	totalPeers := len(peers) + 1
	quorum := (totalPeers / 2) + 1
	dropAgents := []string{}
	for id, count := range intentAgentCount {
		if count >= quorum {
			dropAgents = append(dropAgents, id)
		}
	}
	dropMasters := []string{}
	for cn, count := range intentMasterCount {
		if count >= quorum {
			dropMasters = append(dropMasters, cn)
		}
	}
	if len(dropAgents) > 0 || len(dropMasters) > 0 {
		if removed, err := dropRevocationTombstones(s.configPath, dropAgents, dropMasters); err == nil && removed > 0 {
			// Refresh in-memory state to match the persisted change.
			fresh := loadConfig(s.configPath)
			s.revokedMu.Lock()
			s.agentRevoked = copyStringMap(fresh.Server.AgentRevoked)
			s.masterRevoked = copyStringMap(fresh.Server.MasterRevoked)
			s.revokedMu.Unlock()
			if mst, gerr := s.storageFor("_server"); gerr == nil {
				mst.Write("meta", map[string]any{
					"event":   "realm_unrevoke_quorum",
					"removed": removed,
					"agents":  dropAgents,
					"masters": dropMasters,
					"hint":    "quorum reached on unrevoke intents; tombstones dropped",
				})
			}
		}
	}

	// Adopt newly-learned revocations into our tombstone maps. These
	// are additive: a revocation broadcast by any peer is enforced by
	// every peer once the sync cycle catches it.
	if added := s.mergeRevoked(allRevAgent, allRevMaster); added > 0 {
		if mst, gerr := s.storageFor("_server"); gerr == nil {
			mst.Write("meta", map[string]any{
				"event": "realm_revocations_merged",
				"added": added,
				"hint":  "agent/master revocations from peers were adopted into local tombstone map",
			})
		}
	}

	// Adopt master CNs from peers so a master enrolled with one peer
	// is automatically accepted at every peer in the realm. Drives
	// the master-enroll auto-discovery flow: after a single PSK
	// enroll with peer A, the master can pull from B/C/... too once
	// the next sync cycle propagates its CN.
	mastersAdded := []string{}
	if len(allMasters) > 0 {
		s.masterMu.RLock()
		known := map[string]bool{}
		for _, cn := range s.masterCNs {
			known[cn] = true
		}
		s.masterMu.RUnlock()
		for cn := range allMasters {
			if known[cn] {
				continue
			}
			if !validMasterID(cn) {
				continue
			}
			if added, err := addMasterCNToConfig(s.configPath, cn); err == nil && added {
				mastersAdded = append(mastersAdded, cn)
			}
		}
		if len(mastersAdded) > 0 {
			s.masterMu.Lock()
			for _, cn := range mastersAdded {
				if !contains(s.masterCNs, cn) {
					s.masterCNs = append(s.masterCNs, cn)
				}
			}
			s.masterMu.Unlock()
			if mst, gerr := s.storageFor("_server"); gerr == nil {
				mst.Write("meta", map[string]any{
					"event": "realm_master_cns_merged",
					"added": len(mastersAdded),
					"cns":   mastersAdded,
					"hint":  "master CNs from peers adopted into local master_cns; the realm now treats these masters as authorized everywhere",
				})
			}
		}
	}

	// Adopt new peer CAs into our trust bundle.
	bundleChanged := false
	for id, caPem := range allCAs {
		if id == s.selfPeerID {
			continue
		}
		if !validHostName.MatchString(id) {
			continue
		}
		// Compare against on-disk version; skip if identical.
		path := filepath.Join(realmPeerCAsDir(), id+".pem")
		old, _ := os.ReadFile(path)
		if string(old) == caPem {
			continue
		}
		// Validate the CA before writing.
		blk, _ := pem.Decode([]byte(caPem))
		if blk == nil || blk.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil || !cert.IsCA {
			continue
		}
		if _, werr := writePeerCA(id, caPem); werr == nil {
			bundleChanged = true
		}
	}
	if bundleChanged {
		if err := s.trust.rebuild(); err != nil {
			s.broadcastErr("realm_sync", fmt.Errorf("rebuild trust bundle after CA propagation: %v", err))
		} else if mst, gerr := s.storageFor("_server"); gerr == nil {
			mst.Write("meta", map[string]any{
				"event": "realm_trust_bundle_refreshed",
				"hint":  "adopted one or more peer CAs from /v1/sync/config",
			})
		}
	}

	// Adopt newly-learned agent IDs into the local allowlist (additive
	// merge — revocation must happen explicitly on each peer). Persist
	// to config and refresh the in-memory map atomically so the next
	// /v1/events from a failed-over agent is accepted.
	if len(allAllow) > 0 {
		s.allowlistMu.RLock()
		toAdd := make([]string, 0)
		for id := range allAllow {
			if _, ok := s.allowlist[id]; ok {
				continue
			}
			if !validAgentID(id) {
				continue
			}
			toAdd = append(toAdd, id)
		}
		s.allowlistMu.RUnlock()
		if len(toAdd) > 0 {
			if err := mergeAllowlistInConfig(s.configPath, toAdd); err == nil {
				s.allowlistMu.Lock()
				for _, id := range toAdd {
					s.allowlist[id] = struct{}{}
				}
				s.allowlistMu.Unlock()
				if mst, gerr := s.storageFor("_server"); gerr == nil {
					mst.Write("meta", map[string]any{
						"event": "realm_allowlist_merged",
						"added": len(toAdd),
						"hint":  "agents enrolled with peer servers were added to local allowlist for failover acceptance",
					})
				}
			}
		}
	}

	// Adopt newly-learned peer URLs into local realm.peers (idempotent).
	if len(allURLs) > 0 {
		s.realmMu.RLock()
		known := map[string]bool{}
		for _, p := range s.realmPeers {
			known[p] = true
		}
		s.realmMu.RUnlock()
		var toAdd []string
		for u := range allURLs {
			if known[u] {
				continue
			}
			if peerIDFromURL(u) == s.selfPeerID {
				continue
			}
			toAdd = append(toAdd, u)
		}
		if len(toAdd) > 0 {
			added, ver, err := addRealmPeersToConfig(s.configPath, toAdd, "")
			if err == nil && added > 0 {
				s.realmMu.Lock()
				for _, u := range toAdd {
					if !contains(s.realmPeers, u) {
						s.realmPeers = append(s.realmPeers, u)
					}
				}
				s.realmConfigVer = ver
				s.realmMu.Unlock()
				if mst, gerr := s.storageFor("_server"); gerr == nil {
					mst.Write("meta", map[string]any{
						"event": "realm_peers_grown",
						"added": added,
						"total": len(s.realmPeers),
					})
				}
			}
		}
	}

	s.realmMu.Lock()
	if best.realm != s.realmName && best.ver > s.realmConfigVer {
		old := s.realmName
		s.realmName = best.realm
		s.realmConfigVer = best.ver
		newName, newVer := best.realm, best.ver
		s.realmMu.Unlock()
		// Persist the adopted name to disk so `status` reflects the
		// change immediately AND a daemon restart doesn't revert.
		// Best-effort: a write failure leaves the in-memory state
		// updated, the next sync cycle will retry.
		if err := persistRealmName(s.configPath, newName, newVer); err != nil {
			s.broadcastErr("realm_sync", fmt.Errorf("adopted realm name %q from peer but couldn't write config: %v", newName, err))
		}
		if mst, gerr := s.storageFor("_server"); gerr == nil {
			mst.Write("meta", map[string]any{
				"event":          "realm_renamed",
				"from":           old,
				"to":             newName,
				"config_version": newVer,
				"hint":           "another peer reported a newer realm name; adopted it",
			})
		}
		return
	}
	s.realmMu.Unlock()
}

// persistRealmName atomically updates server.realm.name +
// server.realm.config_version in config.json, preserving everything
// else and backing the previous file up to .bak (same convention as
// every other config edit). Serialised through the same global mutex
// the allowlist edits use, so concurrent updates don't lose changes.
func persistRealmName(cfgPath, name string, ver int64) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	cfg.Server.Realm.Name = name
	cfg.Server.Realm.ConfigVersion = ver
	return saveConfig(cfgPath, cfg)
}

// readWatermark returns the last-seen received_at for a peer, or zero
// time if no watermark exists yet.
func readWatermark(path string) time.Time {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}
	}
	return t
}

// writeWatermark atomically updates the per-peer watermark file.
func writeWatermark(path string, t time.Time) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(t.Format(time.RFC3339Nano)), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// MasterEnrollRequest is the master->server body for /v1/enroll-master.
// Same shape as EnrollRequest but the agent_id is replaced with a
// master_id (the master's chosen CN, e.g. master-<hostname>).
//
// MasterURL is optional — when the master is configured to expose a
// collector-listener (master.collector_listen, Phase 2), it advertises
// that URL here so the server records it in cfg.Server.Realm.MasterURL.
// Collectors paired with the server then see the master in
// /v1/sync/config and can promote themselves to it.
type MasterEnrollRequest struct {
	PSK       string `json:"psk"`
	MasterID  string `json:"master_id"`
	CSRPem    string `json:"csr_pem"`
	MasterURL string `json:"master_url,omitempty"`

	// MasterCollectorPSK + DemoteCollectorToServer drive the master's
	// "join realm and re-organise the collector" logic (see master.go's
	// runMasterEnroll). Exactly zero or one of them is non-zero per
	// enrollment request — the master sets MasterCollectorPSK when its
	// own collector slot is empty AND the realm has a collector (so the
	// realm collector should adopt the master); it sets
	// DemoteCollectorToServer when its slot is already taken AND the
	// realm has a collector (so the realm collector must yield).
	MasterCollectorPSK      string `json:"master_collector_psk,omitempty"`
	DemoteCollectorToServer bool   `json:"demote_collector_to_server,omitempty"`
}

// MasterEnrollResponse mirrors EnrollResponse but adds RealmName so
// the master knows which realm this server belongs to (for organising
// its own collected data by realm at query time).
type MasterEnrollResponse struct {
	CertPem       string `json:"cert_pem"`
	CAPem         string `json:"ca_pem"`
	ReauthSeconds int    `json:"reauth_seconds"`
	Hmac          string `json:"hmac"`
	NewlyAdded    bool   `json:"newly_added"`
	RealmName     string `json:"realm_name"`
	ServerHost    string `json:"server_host"` // selfPeerID of the signing server, used as the dir name for cert storage on master
}

// handleEnrollMaster signs CSRs from a master and adds the master's
// CN to the server's master_cns list so it gains access to
// /v1/sync/events. Auth: the same enrollment PSK that agents use.
// Operators with strict role separation can rotate the PSK after
// agent fleet enrollment to scope it to master-only enrollment, but
// for the common case sharing one PSK is fine.
func (s *serverState) handleEnrollMaster(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	var er MasterEnrollRequest
	if err := json.Unmarshal(body, &er); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	currentPSK, perr := readEnrollPSK()
	if perr != nil || currentPSK == "" {
		currentPSK = s.enrollPSK
	}
	gotRaw, gerr := pskRawBytes(er.PSK)
	wantRaw, werr := pskRawBytes(currentPSK)
	if gerr != nil || werr != nil || subtle.ConstantTimeCompare(gotRaw, wantRaw) != 1 {
		s.logAuthFailure(r, "enroll-master")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !validMasterID(er.MasterID) {
		http.Error(w, "invalid master_id", http.StatusBadRequest)
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
		http.Error(w, "csr CN must equal master_id", http.StatusBadRequest)
		return
	}
	caCert, caKey, err := loadCAFromDisk(s.certsDir)
	if err != nil {
		s.broadcastErr("enroll-master", fmt.Errorf("load CA: %v", err))
		http.Error(w, "server missing CA", http.StatusServiceUnavailable)
		return
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: er.MasterID, Organization: []string{"SimpleSIEM"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(s.enrollClientYears, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		s.broadcastErr("enroll-master", fmt.Errorf("sign cert: %v", err))
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	clientPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))
	added, err := addMasterCNToConfig(s.configPath, er.MasterID)
	if err != nil {
		s.broadcastErr("enroll-master", fmt.Errorf("update master_cns: %v", err))
		http.Error(w, "could not persist master_cns", http.StatusInternalServerError)
		return
	}
	// Record the master's collector-listener URL when supplied so
	// /v1/sync/config can surface it to paired collectors. Idempotent:
	// re-enrollment with the same URL is a no-op; a different URL
	// overwrites the prior value (single-master per realm). The URL
	// must be a well-formed https URL so a compromised PSK can't
	// inject "javascript:" or relative paths into the realm config.
	if er.MasterURL != "" {
		if perr := validateMasterListenerURL(er.MasterURL); perr != nil {
			http.Error(w, "invalid master_url: "+perr.Error(), http.StatusBadRequest)
			return
		}
		_ = setRealmMasterURL(s.configPath, er.MasterURL)
	}
	// Master's "join realm and re-organise the collector" directives.
	// At most one of these is set per request; the master fills exactly
	// one based on whether its own collector slot is empty (PSK path)
	// or taken (demote path).
	if er.MasterCollectorPSK != "" || er.DemoteCollectorToServer {
		_ = setRealmPendingCollectorDirective(s.configPath, er.MasterCollectorPSK, er.DemoteCollectorToServer)
	}
	s.masterMu.Lock()
	if !contains(s.masterCNs, er.MasterID) {
		s.masterCNs = append(s.masterCNs, er.MasterID)
	}
	s.masterMu.Unlock()
	caPem, err := os.ReadFile(filepath.Join(s.certsDir, "ca.pem"))
	if err != nil {
		http.Error(w, "read CA: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.realmMu.RLock()
	realm := s.realmName
	s.realmMu.RUnlock()
	resp := MasterEnrollResponse{
		CertPem:       clientPem,
		CAPem:         string(caPem),
		ReauthSeconds: s.reauthSeconds,
		NewlyAdded:    added,
		RealmName:     realm,
		ServerHost:    s.selfPeerID,
	}
	resp.Hmac = computeEnrollHMAC(wantRaw, resp.CertPem, resp.CAPem, resp.ReauthSeconds, resp.RealmName, []string{resp.ServerHost})
	if mst, gerr := s.storageFor("_server"); gerr == nil {
		mst.Write("meta", map[string]any{
			"event":       "master_enrolled",
			"master_id":   er.MasterID,
			"newly_added": added,
			"remote":      r.RemoteAddr,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// addMasterCNToConfig atomically appends cn to server.master_cns in
// config.json, idempotent. Returns true when newly added.
func addMasterCNToConfig(cfgPath, cn string) (bool, error) {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	for _, x := range cfg.Server.MasterCNs {
		if x == cn {
			return false, nil
		}
	}
	cfg.Server.MasterCNs = append(cfg.Server.MasterCNs, cn)
	if err := saveConfig(cfgPath, cfg); err != nil {
		return false, err
	}
	return true, nil
}

// validateMasterListenerURL rejects anything that isn't a well-formed
// https URL with an explicit host. Same shape as the master-side
// validation used during `convert master` so the wire format and
// the operator-typed format stay in sync.
func validateMasterListenerURL(s string) error {
	s = strings.TrimRight(s, "/")
	if s == "" {
		return fmt.Errorf("URL is required")
	}
	parsed, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("must use https:// (got %q)", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("must include a host (e.g. https://master.example.com:9445)")
	}
	return nil
}

// CollectorDirectiveRequest is the body of POST /v1/master/collector-directive.
// Used by an already-enrolled master to forward one-shot instructions
// to the server's paired collector. Exactly one of MasterCollectorPSK
// or DemoteToServer should be set per call. MasterURL is required when
// MasterCollectorPSK is set — the auto-promote path on the collector
// dials this URL to re-enrol with the master.
type CollectorDirectiveRequest struct {
	MasterCollectorPSK string `json:"master_collector_psk,omitempty"`
	DemoteToServer     bool   `json:"demote_to_server,omitempty"`
	MasterURL          string `json:"master_url,omitempty"`
}

// handleMasterCollectorDirective records a single-use directive that
// /v1/sync/config will surface to the paired collector on its next
// poll. mTLS-authenticated: caller CN must be in server.master_cns,
// otherwise 403. Refuses if the server has no paired collector
// (nothing for the directive to target).
func (s *serverState) handleMasterCollectorDirective(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "mTLS required", http.StatusUnauthorized)
		return
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	s.masterMu.RLock()
	authed := false
	for _, m := range s.masterCNs {
		if m == cn {
			authed = true
			break
		}
	}
	s.masterMu.RUnlock()
	if !authed {
		s.logAuthFailure(r, "master/collector-directive")
		http.Error(w, "not a recognised master", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req CollectorDirectiveRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	cfgNow := loadConfig(s.configPath)
	if cfgNow.Server.CollectorCN == "" {
		http.Error(w, "this server has no paired collector — no target for the directive", http.StatusConflict)
		return
	}
	if req.MasterCollectorPSK == "" && !req.DemoteToServer {
		http.Error(w, "directive is empty (set master_collector_psk OR demote_to_server)", http.StatusBadRequest)
		return
	}
	// Persist the directive itself. The PSK adopt path additionally
	// requires the server to advertise the master_url so the collector
	// knows where to dial; record it via the same setter used by the
	// enroll-master path so a server reboot keeps the URL in sync.
	if err := setRealmPendingCollectorDirective(s.configPath, req.MasterCollectorPSK, req.DemoteToServer); err != nil {
		http.Error(w, "persist directive: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if req.MasterURL != "" && req.MasterCollectorPSK != "" {
		if perr := validateMasterListenerURL(req.MasterURL); perr != nil {
			http.Error(w, "invalid master_url: "+perr.Error(), http.StatusBadRequest)
			return
		}
		_ = setRealmMasterURL(s.configPath, req.MasterURL)
	}
	w.WriteHeader(http.StatusNoContent)
}

// setRealmMasterURL records the master's collector-listener URL so
// /v1/sync/config can advertise it to paired collectors. Idempotent.
func setRealmMasterURL(cfgPath, masterURL string) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	if cfg.Server.Realm.MasterURL == masterURL {
		return nil
	}
	cfg.Server.Realm.MasterURL = masterURL
	return saveConfig(cfgPath, cfg)
}

// setRealmPendingCollectorDirective queues a single-use directive for
// the server's paired collector to act on at its next /v1/sync/config
// poll. Exactly one of `promotePSK` / `demote` should be non-zero per
// call (the master fills one based on whether it has its own collector
// already). Both being set is tolerated — the demote takes precedence
// at delivery time because the realm's collector must yield first
// before any other change makes sense.
func setRealmPendingCollectorDirective(cfgPath, promotePSK string, demote bool) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	cfg.Server.Realm.PendingMasterCollectorPSK = strings.TrimSpace(promotePSK)
	cfg.Server.Realm.PendingCollectorDemote = demote
	return saveConfig(cfgPath, cfg)
}

// clearRealmPendingCollectorDirective wipes the single-use directive
// after the paired collector has been notified once via /v1/sync/config.
// Safe to call when nothing is pending (no-op).
func clearRealmPendingCollectorDirective(cfgPath string) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	if cfg.Server.Realm.PendingMasterCollectorPSK == "" && !cfg.Server.Realm.PendingCollectorDemote {
		return nil
	}
	cfg.Server.Realm.PendingMasterCollectorPSK = ""
	cfg.Server.Realm.PendingCollectorDemote = false
	return saveConfig(cfgPath, cfg)
}

// validMasterID matches validAgentID's policy with the additional
// constraint that the ID must start with "master-" so an operator
// browsing config.json can tell at a glance which CNs are masters.
func validMasterID(id string) bool {
	if !strings.HasPrefix(id, "master-") {
		return false
	}
	return validAgentID(id)
}

// contains reports whether haystack contains needle.
func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// (compile-time assertion the realm package wires up cleanly)
var _ = bytes.NewReader
var _ sync.RWMutex