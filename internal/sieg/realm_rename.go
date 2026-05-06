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
	"regexp"
	"strings"
	"time"
)

// Realm rename — hierarchy-aware operator command.
//
// Authority rules (enforced at every layer):
//   - collector / agent / standalone: rejected. These modes either
//     have no realm to rename or are pure consumers of realm config.
//   - server with cfg.Server.Realm.MasterURL set: rejected. A master
//     is present; the master is the authority. Operator must use
//     `simplesiem master realm rename <realm> <new-name>` instead.
//   - server with no master: allowed. The rename writes locally,
//     bumps config_version, and propagates to peers via the existing
//     last-write-wins realm-sync.
//   - master: rejects local `realm rename`; redirects to
//     `master realm rename`.
//
// Server-side `/v1/master/push/realm-rename` carries the master-driven
// rename across the fleet. Same opt-in gate as the other master
// push endpoints (`server.master_can_rotate_ca: true`) so a server
// that opts out of master pushes keeps full local authority over its
// realm name.

// validRealmName accepts ASCII alphanumerics + dot/dash/underscore,
// 1..64 chars. Generous enough to fit "prod-east-2", "lab.lab-1",
// etc.; tight enough that a malicious value can't sneak control
// characters or path separators into config files / log lines.
var validRealmName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// MasterRealmRenameRequest is the body of /v1/master/push/realm-rename.
type MasterRealmRenameRequest struct {
	NewName string `json:"new_name"`
}

// MasterRealmRenameResponse is the response from a server applying
// a master-driven rename. PeerID + RealmName let the master print
// per-server fan-out results consistently with `master push-rules`.
type MasterRealmRenameResponse struct {
	Applied       bool   `json:"applied"`
	OldName       string `json:"old_name"`
	NewName       string `json:"new_name"`
	ConfigVersion int64  `json:"config_version"`
	PeerID        string `json:"peer_id"`
}

// runRealmRename is the operator-side `simplesiem realm rename
// <new-name>` command. Authorization is enforced here so a non-server
// run never has a chance to mutate disk state.
func runRealmRename(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true})
	fs := flag.NewFlagSet("realm rename", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	_ = fs.Parse(args)

	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}
	if fs.NArg() == 0 {
		fatalf("usage: simplesiem realm rename <new-name>\n  use a unique, descriptive name (e.g. prod-east, lab-1) — see docs/realms.md")
	}
	newName := strings.TrimSpace(fs.Arg(0))
	if !validRealmName.MatchString(newName) {
		fatalf("invalid realm name %q: must be 1-64 chars, alphanumeric or . _ -", newName)
	}

	cfg := loadConfig(*cfgPath)
	mode := normaliseMode(cfg.Mode)
	switch mode {
	case "agent":
		fatalf("agent mode has no realm to rename. The realm name is set on the server; rename it there.")
	case "collector":
		fatalf("collector mode is a pure consumer of realm config and may not rename realms. Run this command on the highest-authority peer (a master if present, otherwise any server in the realm).")
	case "standalone":
		fatalf("standalone mode has no realm. (`server.realm.name` in config.json is unused until you `convert server`.)")
	case "master":
		fatalf("on a master, use `simplesiem master realm rename <realm-name> <new-name>` to rename a realm — the master pushes the change to every server it manages.")
	case "server":
		// fall through
	default:
		fatalf("unknown mode %q in config.json; not safe to rename a realm without a known mode", cfg.Mode)
	}

	// Authority check: any master enrollment populates server.master_cns.
	// Once a master is present on this realm, realm config is the
	// master's responsibility and the server must refuse local edits
	// — even from the operator at the keyboard. The check happens at
	// every invocation (no daemon restart needed for it to take effect)
	// because we re-load config from disk above.
	if len(cfg.Server.MasterCNs) > 0 {
		fatalf("a master is enrolled with this server (master_cns=%v); realm config changes must be made on the master.\n  Run on the master:\n    sudo simplesiem master realm rename %q <new-name>",
			cfg.Server.MasterCNs, currentRealmName(cfg))
	}

	oldName := currentRealmName(cfg)
	if oldName == newName {
		fmt.Println("Realm is already named", newName, "— nothing to do.")
		return
	}

	if !*yes {
		fmt.Printf("This will rename realm %q -> %q.\n", oldName, newName)
		if len(cfg.Server.Realm.Peers) > 0 {
			fmt.Printf("The change will propagate to %d peer(s) on the next sync cycle.\n", len(cfg.Server.Realm.Peers))
		} else {
			fmt.Println("(single-server realm; the change is local-only.)")
		}
		if !confirmYes() {
			fmt.Println("aborted; nothing changed.")
			return
		}
	}

	ver := time.Now().UnixNano()
	if err := persistRealmName(*cfgPath, newName, ver); err != nil {
		fatalf("save config: %v", err)
	}
	fmt.Printf("Renamed realm %q -> %q (config_version=%d).\n", oldName, newName, ver)
	// Auto-restart so the rename is visible in `simplesiem status`
	// immediately. Without this, `status` keeps reporting the old
	// in-memory realmName until the next config reload tick — confusing
	// UX where the operator runs a successful rename and the next
	// command they type still shows the old name.
	if isRunning() {
		restartCommand(nil)
	}
	if len(cfg.Server.Realm.Peers) > 0 {
		fmt.Println("Peers will adopt the new name on their next /v1/sync/config cycle (default 60s).")
	}
}

// currentRealmName falls back to "default" when the config field is
// empty so we never print '""' as the realm name.
func currentRealmName(cfg Config) string {
	if n := strings.TrimSpace(cfg.Server.Realm.Name); n != "" {
		return n
	}
	return "default"
}

// runMasterRealmRename is `simplesiem master realm rename <realm>
// <new-name>` — the master-driven fleet rename. Walks
// cfg.Master.Servers, queries each server's current realm name (via
// the master's per-server cert + /v1/sync/config), and POSTs the
// rename to every server whose realm name matches <realm>. Servers
// that aren't in the named realm are skipped silently; servers that
// haven't opted in to master pushes (`master_can_rotate_ca: false`)
// fail individually — the rest of the fan-out continues so a partial
// fleet doesn't block on one stubborn opt-out.
func runMasterRealmRename(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true})
	fs := flag.NewFlagSet("master realm rename", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	_ = fs.Parse(args)

	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}
	if fs.NArg() < 2 {
		fatalf("usage: simplesiem master realm rename <realm-name> <new-name>")
	}
	realmName := strings.TrimSpace(fs.Arg(0))
	newName := strings.TrimSpace(fs.Arg(1))
	if !validRealmName.MatchString(newName) {
		fatalf("invalid new realm name %q: must be 1-64 chars, alphanumeric or . _ -", newName)
	}
	if realmName == "" {
		fatalf("realm-name is required (use `simplesiem master rotate-ca-status` to list realms this master sees)")
	}

	cfg := loadConfig(*cfgPath)
	if cfg.Mode != "master" {
		fatalf("this command requires mode=master; current mode is %q", cfg.Mode)
	}
	if len(cfg.Master.Servers) == 0 {
		fatalf("master.servers is empty — enroll with at least one server first (`simplesiem master enroll <url> --key <PSK>`)")
	}

	if !*yes {
		fmt.Printf("This will rename realm %q -> %q on every server in master.servers that reports realm=%q.\n",
			realmName, newName, realmName)
		if !confirmYes() {
			fmt.Println("aborted; nothing changed.")
			return
		}
	}

	applied, skipped, failed := 0, 0, 0
	for _, server := range cfg.Master.Servers {
		serverID := peerIDFromURL(server)
		if serverID == "" {
			fmt.Fprintf(os.Stderr, "  skip %s: cannot parse hostname\n", server)
			failed++
			continue
		}
		certDir := filepath.Join(masterCertsDir(cfg), serverID)
		tlsCfg, err := loadMasterClientTLS(certDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: load cert: %v\n", server, err)
			failed++
			continue
		}
		client := &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg.Clone(), TLSHandshakeTimeout: 10 * time.Second},
			Timeout:   30 * time.Second,
		}
		// 1. Query /v1/sync/config to learn the server's current realm.
		curRealm, err := fetchServerRealmName(client, server)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: query realm: %v\n", server, err)
			failed++
			continue
		}
		if !strings.EqualFold(curRealm, realmName) {
			skipped++
			continue
		}
		// 2. Push the rename.
		if err := pushMasterRealmRename(client, server, newName); err != nil {
			fmt.Fprintf(os.Stderr, "  fail %s: %v\n", server, err)
			failed++
			continue
		}
		fmt.Printf("  applied: %s\n", server)
		applied++
	}
	fmt.Printf("\nRealm rename complete: %d applied, %d skipped (different realm), %d failed.\n", applied, skipped, failed)
	if applied > 0 {
		fmt.Println("Servers in the renamed realm will sync the new name to each other on their next /v1/sync/config cycle (default 60s).")
	}
	if failed > 0 {
		fmt.Println("Failed servers stay on the old name. Common cause: server.master_can_rotate_ca is false (operator opted that server out of master pushes). Re-run after the operator flips it.")
	}
}

func fetchServerRealmName(client *http.Client, serverURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(serverURL, "/")+"/v1/sync/config", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	var pc struct {
		RealmName string `json:"realm_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pc); err != nil {
		return "", err
	}
	return pc.RealmName, nil
}

func pushMasterRealmRename(client *http.Client, serverURL, newName string) error {
	body, _ := json.Marshal(MasterRealmRenameRequest{NewName: newName})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(serverURL, "/")+"/v1/master/push/realm-rename", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return nil
}

// handleMasterPushRealmRename receives the master-driven rename. Same
// gate as the other master push endpoints: master_can_rotate_ca must
// be true AND the caller's CN must be in master_cns AND not revoked.
func (s *serverState) handleMasterPushRealmRename(w http.ResponseWriter, r *http.Request) {
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

	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req MasterRealmRenameRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	newName := strings.TrimSpace(req.NewName)
	if !validRealmName.MatchString(newName) {
		http.Error(w, "invalid new_name; must be 1-64 chars, alphanumeric or . _ -", http.StatusBadRequest)
		return
	}

	s.realmMu.Lock()
	oldName := s.realmName
	if oldName == newName {
		s.realmMu.Unlock()
		// Idempotent: re-apply succeeds without changing version.
		w.Header().Set("Content-Type", "application/json")
		out, _ := json.Marshal(MasterRealmRenameResponse{
			Applied:       false,
			OldName:       oldName,
			NewName:       newName,
			ConfigVersion: s.realmConfigVer,
			PeerID:        s.selfPeerID,
		})
		_, _ = w.Write(out)
		return
	}
	ver := time.Now().UnixNano()
	s.realmName = newName
	s.realmConfigVer = ver
	s.realmMu.Unlock()

	if err := persistRealmName(s.configPath, newName, ver); err != nil {
		s.broadcastErr("master_push_realm_rename", fmt.Errorf("persist: %v", err))
		http.Error(w, "could not persist realm name", http.StatusInternalServerError)
		return
	}
	if mst, gerr := s.storageFor("_server"); gerr == nil {
		mst.Write("meta", map[string]any{
			"event":          "realm_renamed_by_master",
			"from":           oldName,
			"to":             newName,
			"config_version": ver,
			"master_cn":      cn,
			"hint":           "master pushed a realm rename; will propagate to peers on the next sync cycle",
		})
	}
	resp := MasterRealmRenameResponse{
		Applied:       true,
		OldName:       oldName,
		NewName:       newName,
		ConfigVersion: ver,
		PeerID:        s.selfPeerID,
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

