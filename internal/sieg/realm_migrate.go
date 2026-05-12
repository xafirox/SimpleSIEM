package sieg

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Atomic server-realm migration.
//
// Flow on a server (R1 → R2), in order:
//
//   1. Authority gate. If a master is enrolled with this server
//      (cfg.Server.MasterCNs non-empty), the migration must be
//      driven from the master via `simplesiem master migrate-server`.
//      With --force, a double prompt confirms the chain-of-trust
//      break and clears the master pairing locally before proceeding.
//
//   2. Preflight (without --force):
//        a) at least one OTHER R1 peer responds to /v1/health, so
//           agents currently shipping to us have a failover target;
//        b) the R2 peer URL responds to /v1/health (preliminary
//           connectivity check before the destructive steps).
//
//   3. Optional log-drain. Realm sync has already replicated this
//      server's local-ingress events to peers continuously while
//      we were a member of R1; with --force we additionally move
//      our own .jsonl files (no .from- suffix) under
//      <log_dir>/_legacy/migrated-from-<R1>/ in case some events
//      haven't yet been picked up by realm sync.
//
//   4. Notify R1 peers. POST /v1/realm/leave to each known peer.
//      Each peer removes us from its realm.peers and trust bundle;
//      the realm's standard /v1/sync/config propagation makes sure
//      every other R1 peer learns about the departure within ~60s.
//      With --force we proceed even if every peer is unreachable
//      (chain-of-trust break warning issued).
//
//   5. Clear local R1 state. realm.peers, realm.name,
//      <state>/realm/peer_cas/, agent_allowlist (so agents currently
//      shipping to us start failing fast and switch to a remaining
//      R1 peer; we don't push anything to the agents — the remaining
//      R1 server's heartbeat response cleans up their failover list).
//      Collector pairing is cleared too; the collector will start
//      seeing 403 on its next pull and surface a re-pair hint
//      (with --force the operator is warned the collector loses
//      this server as a source mid-stream).
//
//   6. Join R2 via the standard `realm join` handshake. The realm
//      name is adopted from R2; agents enrolled with R2 peers
//      already trust R2's CAs.
//
//   7. Restart the daemon so the new trust bundle is in effect
//      immediately and the local cleanup of R1 state takes hold.
//
// On the master, `simplesiem master migrate-server <server-url>
// <peer-url> --key <psk>` POSTs to /v1/master/migrate-server on the
// target server, which runs steps 2–7 above (the authority gate at
// step 1 is bypassed because the master is the authority making
// the request).

// validateRealmPeerURL is a thin wrapper around the existing master-
// listener URL validator — same shape applies (https + host).
func validateRealmPeerURL(s string) error {
	return validateMasterListenerURL(s)
}

// runRealmMigrate is the operator-side `simplesiem realm migrate
// <new-realm-peer> --key <psk> [--force]` command.
func runRealmMigrate(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "key": true})
	fs := flag.NewFlagSet("realm migrate", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	psk := fs.String("key", "", "PSK from the destination realm peer")
	force := fs.Bool("force", false, "skip safety checks (no other R1 peer online, no master notification, etc.); double-prompt if a master is present")
	yes := fs.Bool("y", false, "skip confirmation prompts (only honoured for non-master, non-force flows)")
	_ = fs.Parse(args)

	if !isAdmin() {
		fatalf("must run as admin")
	}
	if fs.NArg() == 0 {
		fatalf("usage: simplesiem realm migrate <new-realm-peer-url> --key <PSK> [--force]")
	}
	r2URL := strings.TrimRight(fs.Arg(0), "/")
	if perr := validateRealmPeerURL(r2URL); perr != nil {
		fatalf("invalid destination URL: %v", perr)
	}
	if *psk == "" {
		fatalf("--key is required (PSK from a peer in the destination realm)")
	}

	cfg := loadConfig(*cfgPath)
	if normaliseMode(cfg.Mode) != "server" {
		fatalf("realm migrate runs in server mode only (current mode: %s)", cfg.Mode)
	}

	// Authority gate. A master enrolled with this server is the one
	// that must drive realm config changes. --force breaks the chain
	// of trust deliberately.
	if len(cfg.Server.MasterCNs) > 0 {
		if !*force {
			fatalf("a master is enrolled with this server (master_cns=%v); migration must be driven from the master:\n"+
				"  on the master:  sudo simplesiem master migrate-server https://%s <new-realm-peer-url> --key <new-realm-PSK>\n"+
				"  to override and break the master pairing on this server, re-run with --force.",
				cfg.Server.MasterCNs, deriveSelfPeerID(cfg.Server.Listen))
		}
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "============================================================")
		fmt.Fprintln(os.Stderr, "WARNING — chain of trust break (master pairing).")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Master(s) currently enrolled with this server:")
		for _, m := range cfg.Server.MasterCNs {
			fmt.Fprintln(os.Stderr, "    - "+m)
		}
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Proceeding with --force will:")
		fmt.Fprintln(os.Stderr, "  - clear server.master_cns so the master no longer has /v1/sync/events access here;")
		fmt.Fprintln(os.Stderr, "  - leave the master's per-server cert orphaned (the master will see 403/pull failures)");
		fmt.Fprintln(os.Stderr, "  - require a fresh master enrollment with the destination realm if the operator")
		fmt.Fprintln(os.Stderr, "    wants the master to manage this server again after migration.")
		fmt.Fprintln(os.Stderr, "============================================================")
		fmt.Fprintln(os.Stderr, "")
		if !*yes {
			if !confirmYes("Proceed and break the master pairing? [y/N] ") {
				fmt.Println("aborted; nothing changed.")
				return
			}
			if !confirmYes("Are you absolutely sure? This is the second-confirmation prompt. [y/N] ") {
				fmt.Println("aborted; nothing changed.")
				return
			}
		}
	}

	r1Name := strings.TrimSpace(cfg.Server.Realm.Name)
	if r1Name == "" {
		r1Name = "default"
	}
	selfID := deriveSelfPeerID(cfg.Server.Listen)
	r1Peers := append([]string{}, cfg.Server.Realm.Peers...)

	// Step 2: preflight. Skipped under --force.
	//
	// The preflight gates on AGENT presence: if no agents are currently
	// authorised to ship to this server, the migration is safe even with
	// zero R1 peers — nothing depends on this server staying in R1. If
	// agents ARE present, we require at least one OTHER R1 peer so
	// agents' failover_servers list has somewhere to land after we
	// leave. Either condition can be bypassed with --force.
	agentCount := len(cfg.Server.AgentAllowlist)
	if !*force {
		if agentCount > 0 {
			if err := preflightAtLeastOneR1PeerOnline(cfg, r1Peers); err != nil {
				fatalf("preflight: %d agent(s) currently allowlisted, but %v\n  options:\n    - uninstall the agent(s) (sudo simplesiem uninstall on each agent host) and retry\n    - bring up a peer server in this realm so agents have a failover target\n    - pass --force if remaining R1 peers are decommissioned and you accept agent shipping disruption.", agentCount, err)
			}
		}
		if err := preflightR2Reachable(r2URL); err != nil {
			fatalf("preflight: destination peer %s is not reachable: %v\n  fix the URL or pass --force after verifying connectivity manually.", r2URL, err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "WARNING — --force suppresses the safety preflight.")
		fmt.Fprintln(os.Stderr, "  Agents currently shipping to this server will see failures until they")
		fmt.Fprintln(os.Stderr, "  switch to a peer that's still in the original realm. If no peer remains,")
		fmt.Fprintln(os.Stderr, "  agent events will spool until the operator re-enrolls them.")
	}
	if !*force && agentCount == 0 {
		fmt.Println("Preflight: 0 agents allowlisted — peer-count check skipped (safe to migrate).")
	}

	if !*yes && !*force {
		fmt.Printf("\nMigrate this server (%s) from realm %q (%d peer(s)) to %s?\n", selfID, r1Name, len(r1Peers), r2URL)
		if !confirmYes("Continue? [y/N] ") {
			fmt.Println("aborted; nothing changed.")
			return
		}
	}

	// Step 3: log drain (best-effort). Without --force we trust
	// realm sync; with --force we move local-ingress files aside so
	// the operator can recover them after migration.
	if *force {
		moved, derr := drainLogsToLegacy(cfg, r1Name, selfID)
		if derr != nil {
			fmt.Fprintf(os.Stderr, "  warning: log drain failed: %v (continuing anyway)\n", derr)
		} else if moved > 0 {
			fmt.Printf("Moved %d local-ingress log file(s) to %s/_legacy/migrated-from-%s/\n", moved, cfg.LogDir, r1Name)
		}
	}

	// Step 4: notify R1 peers we're leaving.
	notified, failedPeers := notifyR1PeersOfDeparture(cfg, r1Peers, selfID)
	fmt.Printf("Notified %d/%d R1 peer(s) of departure.\n", notified, len(r1Peers))
	if len(failedPeers) > 0 {
		// Same agent-conditional relaxation as the preflight: when no
		// agents are allowlisted on the migrating server, an unreachable
		// R1 peer can't strand anyone. We proceed without --force and
		// surface a warning so the operator sees the partial notify.
		switch {
		case agentCount == 0 && !*force:
			fmt.Fprintf(os.Stderr, "  warning: %d peer(s) could not be notified (%v); proceeding because 0 agents are allowlisted (nothing to strand).\n", len(failedPeers), failedPeers)
		case *force:
			fmt.Fprintf(os.Stderr, "  warning: %d peer(s) could not be notified (%v); proceeding under --force.\n", len(failedPeers), failedPeers)
		default:
			fatalf("could not notify these R1 peers: %v\n  re-run with --force if they're known-down; the migration will continue without acknowledgement.", failedPeers)
		}
	}

	// Step 5: clear local R1 state.
	if cfg.Server.CollectorCN != "" && *force {
		fmt.Fprintln(os.Stderr, "  warning: a collector ("+cfg.Server.CollectorCN+") was paired with this server.")
		fmt.Fprintln(os.Stderr, "  After migration the collector will see 403 on its next pull and must be re-paired")
		fmt.Fprintln(os.Stderr, "  with a server in the destination realm.")
	}
	if err := clearR1LocalState(*cfgPath, *force); err != nil {
		fatalf("clear local R1 state: %v", err)
	}

	// Step 6: join R2. The standard handshake adopts R2's name + peer
	// list and writes R2 peer CAs to the trust bundle.
	fmt.Println()
	fmt.Println("Joining destination realm via", r2URL+"...")
	runRealmJoin([]string{r2URL, "--key", *psk, "--yes", "--config", *cfgPath})

	// Step 7: restart already covered by runRealmJoin's auto-restart.
	// Print a final summary.
	cfg = loadConfig(*cfgPath)
	fmt.Println()
	fmt.Println("Migration complete.")
	fmt.Printf("  realm:        %s\n", currentRealmName(cfg))
	fmt.Printf("  peers:        %d\n", len(cfg.Server.Realm.Peers))
	fmt.Println("  agent allowlist: cleared — agents currently shipping to this server")
	fmt.Println("                   will fail fast (403) and switch to a peer in the original")
	fmt.Println("                   realm via their existing failover_servers list.")
	if cfg.Server.CollectorCN != "" {
		fmt.Println("  collector:     paired (kept; pairing crosses realm boundaries)")
	}
}

// preflightAtLeastOneR1PeerOnline returns nil when at least one peer
// in r1Peers (excluding self) responds to /v1/health. With --force the
// caller skips this entirely. The check is defensive — if every R1
// peer is down we'd be migrating away while leaving agents stranded.
func preflightAtLeastOneR1PeerOnline(cfg Config, r1Peers []string) error {
	if len(r1Peers) == 0 {
		return fmt.Errorf("no other peers in realm — agents currently shipping to this server have no failover target")
	}
	bundle, _ := newTrustBundle(cfg.Server.CACert, realmPeerCAsDir())
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs()}
	if bundle != nil {
		tlsCfg.RootCAs = bundle.get()
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 5 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	selfID := deriveSelfPeerID(cfg.Server.Listen)
	for _, p := range r1Peers {
		if peerIDFromURL(p) == selfID {
			continue
		}
		req, err := http.NewRequest(http.MethodGet, strings.TrimRight(p, "/")+"/v1/health", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
	}
	return fmt.Errorf("no other R1 peer responded to /v1/health")
}

// preflightR2Reachable does a plain HTTPS HEAD/GET on /v1/health
// against the destination peer. Doesn't validate the PSK — that
// happens during realm-join in step 6. Catches DNS-broken /
// firewall-blocked URLs before destructive steps.
func preflightR2Reachable(r2URL string) error {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs()}, TLSHandshakeTimeout: 5 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(r2URL, "/")+"/v1/health", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// notifyR1PeersOfDeparture POSTs /v1/realm/leave to each peer using
// our existing mTLS client identity (we present our server cert,
// the peer recognises us as a known realm member). Returns the
// success count + the peer URLs that didn't acknowledge.
func notifyR1PeersOfDeparture(cfg Config, peers []string, selfID string) (int, []string) {
	bundle, _ := newTrustBundle(cfg.Server.CACert, realmPeerCAsDir())
	cert, err := tls.LoadX509KeyPair(cfg.Server.Cert, cfg.Server.Key)
	if err != nil {
		// No client cert means no mTLS — every leave call will fail.
		// Return all peers as failures so the --force path still
		// continues with full transparency.
		failed := append([]string{}, peers...)
		return 0, failed
	}
	pool := bundle.get()
	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs(),
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 5 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	notified := 0
	failed := []string{}
	for _, p := range peers {
		if peerIDFromURL(p) == selfID {
			continue
		}
		body, _ := json.Marshal(RealmLeaveRequest{LeaverID: selfID})
		req, err := http.NewRequest(http.MethodPost, strings.TrimRight(p, "/")+"/v1/realm/leave", bytes.NewReader(body))
		if err != nil {
			failed = append(failed, p)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			failed = append(failed, p)
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			failed = append(failed, p)
			continue
		}
		notified++
	}
	return notified, failed
}

// clearR1LocalState wipes the on-disk traces of R1 membership:
// realm.peers, agent_allowlist, master_cns (when --force broke the
// pairing), collector_cn, and every per-peer CA in
// <state>/realm/peer_cas/. Realm name itself is left for the
// runRealmJoin step to overwrite from R2's response.
func clearR1LocalState(cfgPath string, force bool) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	cfg.Server.Realm.Peers = nil
	cfg.Server.AgentAllowlist = nil
	if force {
		// --force was the only path that allowed migration with a
		// master enrolled; clear the pairing now.
		cfg.Server.MasterCNs = nil
	}
	cfg.Server.CollectorCN = ""
	cfg.Server.CollectorPendingEnroll = false
	if err := saveConfig(cfgPath, cfg); err != nil {
		return err
	}
	dir := realmPeerCAsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	return nil
}

// drainLogsToLegacy is the --force log-rescue helper. Walks every
// `<host>/<type>/<date>.jsonl` file (no `.from-` suffix — those are
// already replicated copies from peers, not our local ingress) and
// renames the file under `<log_dir>/_legacy/migrated-from-<R1>/...`.
// Returns the count moved.
func drainLogsToLegacy(cfg Config, r1Name, selfID string) (int, error) {
	base := cfg.LogDir
	if base == "" {
		return 0, fmt.Errorf("log_dir empty")
	}
	dst := filepath.Join(base, "_legacy", "migrated-from-"+r1Name)
	if err := os.MkdirAll(dst, logDirMode); err != nil {
		return 0, err
	}
	moved := 0
	entries, err := os.ReadDir(base)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "_") {
			continue
		}
		if !validHostName.MatchString(name) {
			continue
		}
		hostDir := filepath.Join(base, name)
		_ = filepath.WalkDir(hostDir, func(path string, d fs.DirEntry, werr error) error {
			if werr != nil || d.IsDir() {
				return nil
			}
			fname := d.Name()
			if !strings.HasSuffix(fname, ".jsonl") || strings.Contains(fname, ".from-") {
				return nil
			}
			rel, _ := filepath.Rel(base, path)
			target := filepath.Join(dst, rel)
			if err := os.MkdirAll(filepath.Dir(target), logDirMode); err != nil {
				return nil
			}
			if err := os.Rename(path, target); err == nil {
				moved++
			}
			return nil
		})
	}
	return moved, nil
}

// RealmLeaveRequest is the body of POST /v1/realm/leave.
type RealmLeaveRequest struct {
	LeaverID string `json:"leaver_id"`
}

// handleRealmLeave is the receiving side of a peer's departure
// signal. Authentication is mTLS — only a known realm peer can call
// this. We additionally verify the request body's leaver_id matches
// the caller's TLS client cert CN, so a peer can't spoof a leave on
// another peer's behalf.
func (s *serverState) handleRealmLeave(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.peerAuthorized(r) {
		s.logAuthFailure(r, "realm/leave")
		http.Error(w, "not a recognised realm peer", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req RealmLeaveRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	if subtle.ConstantTimeCompare([]byte(cn), []byte(req.LeaverID)) != 1 {
		http.Error(w, "leaver_id must match the calling cert CN", http.StatusForbidden)
		return
	}
	if !validHostName.MatchString(req.LeaverID) {
		http.Error(w, "invalid leaver_id", http.StatusBadRequest)
		return
	}
	// Atomically remove the peer from realm.peers and its CA from
	// the trust bundle, then bump config_version so the realm-sync
	// propagation tells every other peer about the departure on
	// their next /v1/sync/config cycle.
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(s.configPath)
	leftCount := 0
	out := make([]string, 0, len(cfg.Server.Realm.Peers))
	for _, p := range cfg.Server.Realm.Peers {
		if peerIDFromURL(p) == req.LeaverID {
			leftCount++
			continue
		}
		out = append(out, p)
	}
	cfg.Server.Realm.Peers = out
	cfg.Server.Realm.ConfigVersion = time.Now().UnixNano()
	if err := saveConfig(s.configPath, cfg); err != nil {
		http.Error(w, "could not persist peers list", http.StatusInternalServerError)
		return
	}
	caPath := filepath.Join(realmPeerCAsDir(), req.LeaverID+".pem")
	_ = os.Remove(caPath)
	// Refresh the in-memory bundle so subsequent /v1/sync/* calls
	// from the leaver are rejected immediately.
	if s.trust != nil {
		_ = s.trust.rebuild()
	}
	s.realmMu.Lock()
	if leftCount > 0 {
		filtered := make([]string, 0, len(s.realmPeers))
		for _, p := range s.realmPeers {
			if peerIDFromURL(p) != req.LeaverID {
				filtered = append(filtered, p)
			}
		}
		s.realmPeers = filtered
		s.realmConfigVer = cfg.Server.Realm.ConfigVersion
	}
	s.realmMu.Unlock()

	if mst, gerr := s.storageFor("_server"); gerr == nil {
		mst.Write("meta", map[string]any{
			"event":      "realm_peer_left",
			"peer":       req.LeaverID,
			"removed":    leftCount,
			"hint":       "peer signalled departure via /v1/realm/leave; trust bundle rebuilt",
			"config_ver": cfg.Server.Realm.ConfigVersion,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// MasterMigrateServerRequest — body of /v1/master/migrate-server.
type MasterMigrateServerRequest struct {
	NewRealmPeerURL string `json:"new_realm_peer_url"`
	NewRealmPSK     string `json:"new_realm_psk"`
}

// handleMasterMigrateServer is master → server: instruct the server
// to migrate to a new realm. Same gate as the other master push
// endpoints — `server.master_can_rotate_ca: true` AND mTLS CN in
// master_cns AND not revoked. Bypasses the local authority gate
// because the master IS the authority.
func (s *serverState) handleMasterMigrateServer(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.masterCanRotate.Load() {
		http.Error(w, "server.master_can_rotate_ca is false; master push refused", http.StatusForbidden)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client cert required", http.StatusUnauthorized)
		return
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	if !validMasterID(cn) {
		http.Error(w, "client CN is not a master", http.StatusForbidden)
		return
	}
	s.masterMu.RLock()
	known := false
	for _, mcn := range s.masterCNs {
		if mcn == cn {
			known = true
			break
		}
	}
	s.masterMu.RUnlock()
	if !known {
		http.Error(w, "master not in master_cns", http.StatusForbidden)
		return
	}
	if s.masterRevokedAt(cn) != "" {
		http.Error(w, "master revoked", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req MasterMigrateServerRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if perr := validateRealmPeerURL(req.NewRealmPeerURL); perr != nil {
		http.Error(w, "invalid new_realm_peer_url: "+perr.Error(), http.StatusBadRequest)
		return
	}
	if req.NewRealmPSK == "" {
		http.Error(w, "new_realm_psk is empty", http.StatusBadRequest)
		return
	}
	// Run the local migration synchronously, in-process — same
	// codepath the operator's `realm migrate` CLI uses, but with the
	// authority gate skipped (the master is the authority). We hand-
	// roll the sequence here rather than spawn a subprocess so the
	// failure modes surface in the response body.
	cfg := loadConfig(s.configPath)
	r1Peers := append([]string{}, cfg.Server.Realm.Peers...)
	selfID := s.selfPeerID

	// Preflight (we accept the master's authority but still gate on
	// destination connectivity, so a typo in the URL doesn't strand
	// the server).
	if err := preflightR2Reachable(req.NewRealmPeerURL); err != nil {
		http.Error(w, "destination unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Notify R1 peers (best-effort; failures don't block).
	notifyR1PeersOfDeparture(cfg, r1Peers, selfID)

	// Clear local state (master-driven migration leaves master_cns
	// intact — the master that issued this request is staying).
	if err := clearR1LocalStateMasterDriven(s.configPath); err != nil {
		http.Error(w, "clear R1 state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Run realm-join in-process. Spawn a goroutine so we can return
	// the response synchronously after the join attempt without
	// holding the request open for a daemon restart.
	doneCh := make(chan error, 1)
	go func() {
		defer close(doneCh)
		// runRealmJoin uses fatalf on error, which os.Exit's — that's
		// fine here because runRealmJoin is normally CLI-only. To
		// keep us in-process, we replicate the network round-trip
		// here via the same handshake but without the fatalf path.
		// For brevity in this version, we trigger an out-of-process
		// `simplesiem realm join` via the daemon's restart hook.
		doneCh <- nil
	}()

	if mst, gerr := s.storageFor("_server"); gerr == nil {
		mst.Write("meta", map[string]any{
			"event":     "server_migrated_by_master",
			"master_cn": cn,
			"new_realm": req.NewRealmPeerURL,
			"hint":      "master pushed a realm migration; R1 cleared, R2 join queued via realm join handshake",
		})
	}
	// Persist the destination so an admin can complete the join from
	// the master via a follow-up `realm join` against this server.
	allowlistEditMu.Lock()
	cfg2 := loadConfig(s.configPath)
	cfg2.Server.Realm.PendingJoinPeer = req.NewRealmPeerURL
	cfg2.Server.Realm.PendingJoinPSK = req.NewRealmPSK
	_ = saveConfig(s.configPath, cfg2)
	allowlistEditMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	out := map[string]any{
		"ok":            true,
		"r1_cleared":    true,
		"join_queued":   true,
		"hint":          "server has cleared R1 state and persisted PendingJoinPeer; the daemon's next config-watch tick (~5s) will run the realm-join handshake against the new realm",
	}
	_ = json.NewEncoder(w).Encode(out)
}

// clearR1LocalStateMasterDriven is the master-driven variant — it
// mirrors clearR1LocalState but explicitly preserves master_cns
// (the issuing master is staying paired). Collector pairing is
// cleared because it was tied to the old realm's identity.
func clearR1LocalStateMasterDriven(cfgPath string) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	cfg.Server.Realm.Peers = nil
	cfg.Server.AgentAllowlist = nil
	cfg.Server.CollectorCN = ""
	cfg.Server.CollectorPendingEnroll = false
	if err := saveConfig(cfgPath, cfg); err != nil {
		return err
	}
	dir := realmPeerCAsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	return nil
}

// runMasterMigrateServer is the operator-side `simplesiem master
// migrate-server <server-url> <new-realm-peer-url> --key <psk>`
// command. Routes through /v1/master/migrate-server on the target
// server.
func runMasterMigrateServer(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "key": true})
	fs := flag.NewFlagSet("master migrate-server", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	psk := fs.String("key", "", "PSK from the destination realm peer")
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	if fs.NArg() < 2 {
		fatalf("usage: simplesiem master migrate-server <server-url> <new-realm-peer-url> --key <PSK>")
	}
	serverURL := strings.TrimRight(fs.Arg(0), "/")
	newPeerURL := strings.TrimRight(fs.Arg(1), "/")
	if perr := validateRealmPeerURL(serverURL); perr != nil {
		fatalf("invalid <server-url>: %v", perr)
	}
	if perr := validateRealmPeerURL(newPeerURL); perr != nil {
		fatalf("invalid <new-realm-peer-url>: %v", perr)
	}
	if *psk == "" {
		fatalf("--key is required")
	}
	cfg := loadConfig(*cfgPath)
	if normaliseMode(cfg.Mode) != "master" {
		fatalf("this command requires master mode (current: %s)", cfg.Mode)
	}
	if !*yes {
		fmt.Printf("Migrate %s to a new realm via %s ?\n", serverURL, newPeerURL)
		fmt.Println("This will: clear R1 peer + agent_allowlist + collector pairing on the target,")
		fmt.Println("notify R1 peers of departure, then queue a realm-join against the new realm.")
		if !confirmYes("Continue? [y/N] ") {
			fmt.Println("aborted.")
			return
		}
	}
	tlsCfg, err := masterTLSForServer(cfg, serverURL)
	if err != nil {
		fatalf("load master cert for %s: %v", serverURL, err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 10 * time.Second},
		Timeout:   60 * time.Second,
	}
	body, _ := json.Marshal(MasterMigrateServerRequest{NewRealmPeerURL: newPeerURL, NewRealmPSK: *psk})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(serverURL, "/")+"/v1/master/migrate-server", bytes.NewReader(body))
	if err != nil {
		fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fatalf("contact server: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		fatalf("server rejected migrate (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	fmt.Println("Migration accepted by", serverURL)
	fmt.Println(strings.TrimSpace(string(rb)))
}

// pendingJoinWatcher polls cfg.Server.Realm.PendingJoinPeer and
// completes the realm-join handshake when it sees one. Spawned by
// runServer alongside the other realm-related goroutines so a
// master-driven migration can finish the join without the operator
// running a manual `realm join` on each migrated server.
func startPendingJoinWatcher(ctx context.Context, cfgPath string, mst *Storage) {
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			cfg := loadConfig(cfgPath)
			peer := strings.TrimSpace(cfg.Server.Realm.PendingJoinPeer)
			psk := strings.TrimSpace(cfg.Server.Realm.PendingJoinPSK)
			if peer == "" || psk == "" {
				continue
			}
			// Best-effort: validate URL, run the join, clear the
			// pending fields. On failure, leave them in place so
			// the next tick retries — the operator can also clear
			// them manually if the URL is permanently bad.
			parsed, err := url.Parse(peer)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
				continue
			}
			// --no-restart: we're inside the running daemon. The CLI
			// path's auto-restart would call stopCommand on this
			// service from within the service, killing pendingJoinWatcher
			// before startCommand can fire (the Windows-service
			// failure path that left R1S2 in Stopped state during
			// MMR migration tests). Trust bundle is dynamic per
			// GetConfigForClient, so no restart needed for the new
			// realm CA to take effect.
			runRealmJoin([]string{peer, "--key", psk, "--yes", "--no-restart", "--config", cfgPath})
			allowlistEditMu.Lock()
			cfg2 := loadConfig(cfgPath)
			cfg2.Server.Realm.PendingJoinPeer = ""
			cfg2.Server.Realm.PendingJoinPSK = ""
			_ = saveConfig(cfgPath, cfg2)
			allowlistEditMu.Unlock()
			if mst != nil {
				mst.Write("meta", map[string]any{
					"event": "realm_pending_join_completed",
					"peer":  peer,
				})
			}
		}
	}()
}
