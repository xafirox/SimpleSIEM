package sieg

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Master rules push: a privileged operation that lets a master
// distribute a rules.json across every server it manages with one
// command.
//
// The trust model is the same as CA rotation:
//   - master initiates the connection (master = client, server =
//     server) over the existing per-server mTLS channel,
//   - the server gates the operation behind two opt-ins:
//       server.master_can_rotate_ca: true  (existing high-trust flag)
//     enables ALL master push operations because they all cause
//     persistent on-disk state changes the master should not be able
//     to make without explicit operator approval per server,
//   - the master's CN must be in master_cns and not revoked,
//   - after writing rules.json, the running rule engine reloads
//     automatically (the same reload path operators use when editing
//     by hand).
//
// Validation: server runs the new rules through `rules.parse` before
// committing. Invalid rules → HTTP 400, no on-disk change.

// MasterPushRulesRequest is the body of POST /v1/master/push/rules.
type MasterPushRulesRequest struct {
	RulesJSON string `json:"rules_json"`
}

// MasterPushRulesResponse mirrors the master-rotate response shape
// for consistent fan-out reporting.
type MasterPushRulesResponse struct {
	Applied   bool   `json:"applied"`
	RuleCount int    `json:"rule_count"`
	RealmName string `json:"realm_name"`
	PeerID    string `json:"peer_id"`
	Path      string `json:"path"`
}

// handleMasterPushRules accepts a rules.json from an authorized master,
// validates it, writes it to the configured rules path, and triggers
// a hot reload of the rule engine.
func (s *serverState) handleMasterPushRules(w http.ResponseWriter, r *http.Request) {
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
	if cn == "" || !validMasterID(cn) {
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

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req MasterPushRulesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON envelope", http.StatusBadRequest)
		return
	}
	if req.RulesJSON == "" {
		http.Error(w, "rules_json is empty", http.StatusBadRequest)
		return
	}

	// Validate before committing — same parse path operators use.
	rules, err := parseRulesBytes([]byte(req.RulesJSON))
	if err != nil {
		http.Error(w, "rules failed validation: "+err.Error(), http.StatusBadRequest)
		return
	}

	cfg := loadConfig(s.configPath)
	rulesPath := cfg.RulesPath
	if rulesPath == "" {
		rulesPath = filepath.Join(filepath.Dir(s.configPath), "rules.json")
	}
	// Backup the existing file before overwrite, so an operator can
	// recover if the master pushes a posture they didn't intend.
	if existing, rerr := os.ReadFile(rulesPath); rerr == nil && len(existing) > 0 {
		_ = atomicWriteFile(rulesPath+".pre-master-push", existing, 0o640)
	}
	if err := atomicWriteFile(rulesPath, []byte(req.RulesJSON), 0o640); err != nil {
		http.Error(w, "write rules: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Hot-reload: replace the active rule set, then propagate to every
	// per-host Storage we've already opened. The setRules helper takes
	// rulesMu so the netingest listener and storageFor see a stable
	// slice through the swap.
	s.setRules(rules)
	s.mu.Lock()
	for _, st := range s.storages {
		st.SetRules(rules)
	}
	s.mu.Unlock()

	if mst, gerr := s.storageFor("_server"); gerr == nil {
		mst.Write("meta", map[string]any{
			"event":      "rules_pushed_by_master",
			"master_cn":  cn,
			"rule_count": len(rules),
			"path":       rulesPath,
		})
	}

	s.realmMu.RLock()
	realm := s.realmName
	s.realmMu.RUnlock()
	resp := MasterPushRulesResponse{
		Applied:   true,
		RuleCount: len(rules),
		RealmName: realm,
		PeerID:    s.selfPeerID,
		Path:      rulesPath,
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// parseRulesBytes is exposed so the master push handler validates
// rules using the same code path the operator's `rules check`
// command does. Pure bytes-in path — no temp file — so the file
// watcher doesn't see a flurry of /tmp/simplesiem-master-push-rules-*
// create+delete pairs every time MITRE auto-generation walks its
// curated template list at startup.
func parseRulesBytes(data []byte) ([]*alertRule, error) {
	return parseRulesData(data)
}

// runMasterPushRules is the operator-side fan-out of `simplesiem
// master push-rules <file>`. Reads the local rules.json, then POSTs
// it to /v1/master/push/rules on every server in master.servers.
// Same partial-fleet tolerance as `master rotate-ca-all`.
func runMasterPushRules(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "file": true, "realm": true})
	fs := flag.NewFlagSet("master push-rules", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	rulesPath := fs.String("file", "", "path to a rules.json to push (default: master's own rules.json)")
	realmName := fs.String("realm", "", "push to one server in this realm (auto-discovers an available peer); when omitted, falls back to fan-out across master.servers")
	yes := fs.Bool("y", false, "skip confirmation prompt")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin")
	}
	cfg := loadConfig(*cfgPath)
	if normaliseMode(cfg.Mode) != "master" {
		fatalf("not in master mode (current mode: %s)", cfg.Mode)
	}
	if len(cfg.Master.Servers) == 0 {
		fatalf("master.servers is empty")
	}
	src := *rulesPath
	if src == "" {
		src = cfg.RulesPath
		if src == "" {
			src = filepath.Join(filepath.Dir(*cfgPath), "rules.json")
		}
	}
	data, err := os.ReadFile(src)
	if err != nil {
		fatalf("read rules from %s: %v", src, err)
	}
	// Validate locally first — fail fast before any server sees it.
	if _, err := parseRulesBytes(data); err != nil {
		fatalf("local rules validation failed: %v\n  fix the file before pushing.", err)
	}

	// Per-realm push: the master probes each server in master.servers
	// for /v1/sync/config (already required for the rename + cert
	// flows), filters by realm name, and stops at the first one that
	// responds. Pushing to a single server is enough — realm sync
	// propagates the rules.json to peers via the standard last-write-
	// wins config_version path. Picking an "available" target at
	// push time means a downed peer doesn't block the operation.
	if *realmName != "" {
		fmt.Printf("Pushing rules from %s (%d bytes) to realm %q via the first available server...\n", src, len(data), *realmName)
		fmt.Println("(realm sync propagates the change to peers within ~60s of acceptance)")
		fmt.Println()
		if !*yes {
			if !confirmYes() {
				fmt.Println("aborted.")
				return
			}
		}
		target, err := pickAvailableRealmServer(cfg, *realmName)
		if err != nil {
			fatalf("no available server in realm %q: %v", *realmName, err)
		}
		fmt.Printf("  selected target: %s\n", target)
		res, err := callMasterPushRules(cfg, target, string(data))
		if err != nil {
			fatalf("push to %s failed: %v", target, err)
		}
		fmt.Printf("  ✓ %s — %d rules applied (%s)\n", target, res.RuleCount, res.Path)
		fmt.Println()
		fmt.Println("Realm sync will replicate the new rules.json to other peers in this realm")
		fmt.Println("on their next /v1/sync/config cycle (default 60s).")
		return
	}

	// Fan-out (legacy / explicit) path: push to every server in
	// master.servers, regardless of realm.
	fmt.Printf("Pushing rules from %s (%d bytes) to:\n", src, len(data))
	for _, server := range cfg.Master.Servers {
		fmt.Printf("  %s\n", server)
	}
	fmt.Println()
	fmt.Println("Each server will: validate the rules, write them to its rules.json,")
	fmt.Println("hot-reload its rule engine. Backups go to rules.json.pre-master-push.")
	fmt.Println()
	if !*yes {
		if !confirmYes() {
			fmt.Println("aborted.")
			return
		}
	}
	ok, failed := 0, 0
	for _, server := range cfg.Master.Servers {
		res, err := callMasterPushRules(cfg, server, string(data))
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", server, err)
			failed++
			continue
		}
		fmt.Printf("  ✓ %s — %d rules applied (%s)\n", server, res.RuleCount, res.Path)
		ok++
	}
	// c8 — also push to the paired query-collector when one is
	// configured. The collector stores the rules so the c7
	// failsafe-query path can replay against its corpus when the
	// master goes offline.
	if cfg.Master.QueryCollectorURL != "" {
		fmt.Printf("\nPushing to paired collector at %s...\n", cfg.Master.QueryCollectorURL)
		if res, err := callMasterPushRulesCollector(cfg, cfg.Master.QueryCollectorURL, string(data)); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ collector %s: %v\n", cfg.Master.QueryCollectorURL, err)
			failed++
		} else {
			fmt.Printf("  ✓ %s — %d rules applied (%s)\n", cfg.Master.QueryCollectorURL, res.RuleCount, res.Path)
			ok++
		}
	}
	fmt.Println()
	fmt.Printf("Push: %d ok, %d failed.\n", ok, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// callMasterPushRulesCollector dials the paired collector's
// /v1/master/push/rules endpoint via the master's per-collector
// client cert (same path the master uses to query the collector).
func callMasterPushRulesCollector(cfg Config, collectorURL, rulesJSON string) (MasterPushRulesResponse, error) {
	certDir := filepath.Join(masterQueryCollectorRoot(), peerIDFromURL(collectorURL))
	tlsCfg, err := loadMasterClientTLS(certDir)
	if err != nil {
		return MasterPushRulesResponse{}, fmt.Errorf("load query-collector cert from %s: %w", certDir, err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   30 * time.Second,
	}
	body, _ := json.Marshal(MasterPushRulesRequest{RulesJSON: rulesJSON})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(collectorURL, "/")+"/v1/master/push/rules", bytes.NewReader(body))
	if err != nil {
		return MasterPushRulesResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return MasterPushRulesResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return MasterPushRulesResponse{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	var r MasterPushRulesResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return MasterPushRulesResponse{}, fmt.Errorf("decode response: %w", err)
	}
	return r, nil
}

// pickAvailableRealmServer probes every server in master.servers and
// returns the first one that:
//   - has a usable per-server cert (loadMasterClientTLS succeeds), AND
//   - responds to /v1/sync/config (server is running), AND
//   - reports realm_name == realmName.
//
// Used by per-realm push so an operator running `master push-rules
// --realm prod-east` doesn't have to know which specific server is
// up at push time. Returns an error when no server matches.
func pickAvailableRealmServer(cfg Config, realmName string) (string, error) {
	for _, server := range cfg.Master.Servers {
		tlsCfg, err := masterTLSForServer(cfg, server)
		if err != nil {
			continue
		}
		client := &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 5 * time.Second},
			Timeout:   10 * time.Second,
		}
		got, err := fetchServerRealmName(client, server)
		if err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(realmName)) {
			return server, nil
		}
	}
	return "", fmt.Errorf("no server in master.servers reports realm=%q AND is reachable right now", realmName)
}

// callMasterPushRules dials one server's /v1/master/push/rules.
func callMasterPushRules(cfg Config, serverURL, rulesJSON string) (MasterPushRulesResponse, error) {
	var zero MasterPushRulesResponse
	tlsCfg, err := masterTLSForServer(cfg, serverURL)
	if err != nil {
		return zero, err
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 10 * time.Second},
		Timeout:   30 * time.Second,
	}
	body, _ := json.Marshal(MasterPushRulesRequest{RulesJSON: rulesJSON})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(serverURL, "/")+"/v1/master/push/rules", bytes.NewReader(body))
	if err != nil {
		return zero, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var out MasterPushRulesResponse
	if err := json.Unmarshal(rb, &out); err != nil {
		return zero, fmt.Errorf("decode: %w", err)
	}
	return out, nil
}
