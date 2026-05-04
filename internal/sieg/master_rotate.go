package sieg

import (
	"bytes"
	"crypto/tls"
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

// Master-driven CA rotation across a fleet.
//
//   simplesiem master rotate-ca-all                  - every server in master.servers
//   simplesiem master rotate-ca-realm <realm-name>   - only servers in that realm
//   simplesiem master finalize-rotate-all            - cleanup everywhere
//   simplesiem master finalize-rotate-realm <name>   - cleanup in one realm
//
// The master loops over master.servers, dials each with its existing
// per-server cert (which the server's listener trusts via either the
// new CA — for already-rotated peers — or the legacy CA still in the
// trust bundle), and calls /v1/master/rotate-ca. Servers run their
// init-rotate locally; the legacy CA propagates to realm peers via
// the same /v1/sync/config sync that already carries peer CAs.
//
// "Without interrupting service" is what the existing rotation
// architecture already guarantees:
//
//   - server cert hot-reloads via certHotReloader (~1s pickup)
//   - existing client certs continue to validate via legacy CA in
//     the trust bundle on every server in the realm
//   - new connections from agents pick up the refreshed CA bundle
//     on the next heartbeat (default 60s) and trust the new CA going
//     forward; old certs continue to authenticate via legacy CA
//   - replication and master pulls keep flowing through the rotation
//
// Default-deny on the server side: the operator must set
// `server.master_can_rotate_ca: true` per server. A 403 from any one
// server doesn't fail the fan-out — the master logs it and moves on
// so partial fleets work as expected.

// runMasterRotateCAAll dispatches a rotate request to every server in
// master.servers. Per-server failures don't abort the run; they're
// reported and skipped.
func runMasterRotateCAAll(args []string) {
	fs := flag.NewFlagSet("master rotate-ca-all", flag.ExitOnError)
	years := fs.Int("years", 10, "validity of the new CA in years")
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	dispatchRotate(*cfgPath, "", *years, *yes)
}

// runMasterRotateCARealm is the realm-scoped variant. Filters servers
// by querying each one's /v1/sync/config for its realm name.
func runMasterRotateCARealm(args []string) {
	fs := flag.NewFlagSet("master rotate-ca-realm", flag.ExitOnError)
	years := fs.Int("years", 10, "validity of the new CA in years")
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: simplesiem master rotate-ca-realm <realm-name>")
	}
	dispatchRotate(*cfgPath, fs.Arg(0), *years, *yes)
}

// runMasterFinalizeRotateAll dispatches a finalize-rotate to every
// server in master.servers. Same partial-fleet tolerance as the
// rotate counterpart.
func runMasterFinalizeRotateAll(args []string) {
	fs := flag.NewFlagSet("master finalize-rotate-all", flag.ExitOnError)
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	dispatchFinalize(*cfgPath, "", *yes)
}

// runMasterFinalizeRotateRealm is the realm-scoped variant of
// runMasterFinalizeRotateAll.
func runMasterFinalizeRotateRealm(args []string) {
	fs := flag.NewFlagSet("master finalize-rotate-realm", flag.ExitOnError)
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: simplesiem master finalize-rotate-realm <realm-name>")
	}
	dispatchFinalize(*cfgPath, fs.Arg(0), *yes)
}

// dispatchRotate is the shared body of rotate-ca-all and
// rotate-ca-realm. realmFilter == "" means "all servers". The
// catchup policy is recorded in master.rotation_realms BEFORE the
// fan-out so partial success leaves the policy in place — servers
// that came up after the operator ran the command will catch up
// automatically on the next pull cycle.
func dispatchRotate(cfgPath, realmFilter string, years int, yes bool) {
	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}
	cfg := loadConfig(cfgPath)
	if normaliseMode(cfg.Mode) != "master" {
		fatalf("not in master mode (current mode: %s)", cfg.Mode)
	}
	if len(cfg.Master.Servers) == 0 {
		fatalf("master.servers is empty — enroll with at least one server first")
	}

	realmsTouched, err := determineRealmsTouched(cfg, realmFilter)
	if err != nil {
		fatalf("%v", err)
	}
	servers, err := filterServersByRealm(cfg, realmFilter)
	if err != nil {
		fatalf("%v", err)
	}
	if len(servers) == 0 {
		fmt.Println("No servers match the realm filter; nothing to do.")
		return
	}
	scope := "every registered server"
	if realmFilter != "" {
		scope = fmt.Sprintf("%d server(s) in realm %q", len(servers), realmFilter)
	}
	fmt.Println("CA rotation across", scope+":")
	for _, s := range servers {
		fmt.Printf("  %s\n", s)
	}
	fmt.Println()
	fmt.Printf("Each server will: archive its current CA, generate a new one, re-issue\n")
	fmt.Printf("its server cert. Existing client certs continue to validate via the\n")
	fmt.Printf("legacy CA. Auto-rotation will replace client certs over time. Run\n")
	fmt.Printf("`finalize-rotate-%s` after all clients have rotated.\n", filterLabel(realmFilter))
	fmt.Println()
	if !yes {
		if !confirmYes() {
			fmt.Println("aborted.")
			return
		}
	}

	// Record the rotation policy before the fan-out. Even if every
	// call fails, the policy persists so later pull cycles catch up
	// the offline machines automatically. The catchup loop compares
	// against each server's last_rotated_at file (written by
	// performCARotation with no backdating), so the policy timestamp
	// is exact "now" — no tolerance window needed.
	policyTime := time.Now().UTC().Format(time.RFC3339)
	if err := setRotationPolicy(cfgPath, realmsTouched, policyTime); err != nil {
		fatalf("write rotation policy: %v", err)
	}
	fmt.Printf("rotation policy set: %s for realm(s) %v\n", policyTime, realmsTouched)
	fmt.Println()

	ok, failed := 0, 0
	for _, server := range servers {
		res, err := callMasterRotateCA(cfg, server, years)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", server, err)
			failed++
			continue
		}
		// Persist the new server CA so the master's NEXT handshake
		// against this server (which will see the freshly hot-reloaded
		// server cert) validates instead of failing with
		// "certificate signed by unknown authority".
		if err := writeMasterPerServerCA(cfg, server, res.NewCAPem); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ %s rotated, but writing the new CA locally failed: %v\n", server, err)
			fmt.Fprintf(os.Stderr, "    re-enroll to recover: simplesiem master enroll %s --key <PSK>\n", server)
			failed++
			continue
		}
		fmt.Printf("  ✓ %s — new CA in place, server cert re-issued (legacy archived to %s)\n",
			server, res.LegacyArchivedTo)
		ok++
	}
	fmt.Println()
	fmt.Printf("Rotation: %d ok, %d failed.\n", ok, failed)
	if failed > 0 {
		fmt.Println()
		fmt.Println("Common failure modes:")
		fmt.Println("  - HTTP 403 'server.master_can_rotate_ca is false': operator must set")
		fmt.Println("    that flag on the failing server's config.json and restart its daemon.")
		fmt.Println("  - HTTP 403 'master not in master_cns': re-enroll the master with that server.")
		os.Exit(1)
	}
}

// dispatchFinalize is the shared body of finalize-rotate-all and
// finalize-rotate-realm.
func dispatchFinalize(cfgPath, realmFilter string, yes bool) {
	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}
	cfg := loadConfig(cfgPath)
	if normaliseMode(cfg.Mode) != "master" {
		fatalf("not in master mode (current mode: %s)", cfg.Mode)
	}
	if len(cfg.Master.Servers) == 0 {
		fatalf("master.servers is empty")
	}
	servers, err := filterServersByRealm(cfg, realmFilter)
	if err != nil {
		fatalf("%v", err)
	}
	if len(servers) == 0 {
		fmt.Println("No servers match the realm filter; nothing to do.")
		return
	}
	scope := "every registered server"
	if realmFilter != "" {
		scope = fmt.Sprintf("%d server(s) in realm %q", len(servers), realmFilter)
	}
	fmt.Println("Finalize CA rotation across", scope+":")
	for _, s := range servers {
		fmt.Printf("  %s\n", s)
	}
	fmt.Println()
	fmt.Println("Each server will remove its legacy CA(s) from disk. After this, any")
	fmt.Println("client cert still chaining to a legacy CA will stop validating. Verify")
	fmt.Println("that every agent and master has rotated to the new CA before continuing.")
	fmt.Println()
	if !yes {
		if !confirmYes() {
			fmt.Println("aborted.")
			return
		}
	}

	realmsTouched, err := determineRealmsTouched(cfg, realmFilter)
	if err != nil {
		fatalf("%v", err)
	}
	// Finalize policy doesn't need the 65-min backdating because the
	// catchup loop only triggers finalize when the server has already
	// caught up to the rotation policy AND has legacy CAs. So the
	// finalize timestamp can be exact "now".
	now := time.Now().UTC().Format(time.RFC3339)
	if err := setFinalizePolicy(cfgPath, realmsTouched, now); err != nil {
		fatalf("write finalize policy: %v", err)
	}
	fmt.Printf("finalize policy set: %s for realm(s) %v\n", now, realmsTouched)
	fmt.Println()

	ok, failed, totalRemoved := 0, 0, 0
	for _, server := range servers {
		res, err := callMasterFinalize(cfg, server)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", server, err)
			failed++
			continue
		}
		fmt.Printf("  ✓ %s — removed %d legacy CA(s)\n", server, res.Removed)
		ok++
		totalRemoved += res.Removed
	}
	fmt.Println()
	fmt.Printf("Finalize: %d ok, %d failed, %d legacy CAs removed total.\n", ok, failed, totalRemoved)
	if failed > 0 {
		os.Exit(1)
	}
}

// filterServersByRealm returns the subset of cfg.Master.Servers that
// match realmFilter. realmFilter == "" returns all servers. Realm
// names are queried live via /v1/sync/config — a per-server cache
// would drift on rename so we always re-query.
func filterServersByRealm(cfg Config, realmFilter string) ([]string, error) {
	if realmFilter == "" {
		return append([]string{}, cfg.Master.Servers...), nil
	}
	matched := []string{}
	for _, server := range cfg.Master.Servers {
		realm, err := queryServerRealm(cfg, server)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not query realm for %s: %v (skipping)\n", server, err)
			continue
		}
		if realm == realmFilter {
			matched = append(matched, server)
		}
	}
	return matched, nil
}

// queryServerRealm fetches a server's realm name via /v1/sync/config.
// Uses the existing per-server cert dir for mTLS auth.
func queryServerRealm(cfg Config, serverURL string) (string, error) {
	tlsCfg, err := masterTLSForServer(cfg, serverURL)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 10 * time.Second},
		Timeout:   20 * time.Second,
	}
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
	var pc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&pc); err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	realm, _ := pc["realm_name"].(string)
	return realm, nil
}

// callMasterRotateCA dials one server and triggers the rotate.
func callMasterRotateCA(cfg Config, serverURL string, years int) (MasterRotateCAResponse, error) {
	var zero MasterRotateCAResponse
	tlsCfg, err := masterTLSForServer(cfg, serverURL)
	if err != nil {
		return zero, err
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 10 * time.Second},
		Timeout:   60 * time.Second,
	}
	body, _ := json.Marshal(MasterRotateCARequest{Years: years})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(serverURL, "/")+"/v1/master/rotate-ca", bytes.NewReader(body))
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
	var out MasterRotateCAResponse
	if err := json.Unmarshal(rb, &out); err != nil {
		return zero, fmt.Errorf("decode: %w", err)
	}
	return out, nil
}

// callMasterFinalize dials one server and triggers the finalize.
func callMasterFinalize(cfg Config, serverURL string) (MasterFinalizeCAResponse, error) {
	var zero MasterFinalizeCAResponse
	tlsCfg, err := masterTLSForServer(cfg, serverURL)
	if err != nil {
		return zero, err
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 10 * time.Second},
		Timeout:   30 * time.Second,
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(serverURL, "/")+"/v1/master/finalize-rotate", bytes.NewReader([]byte("{}")))
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
	var out MasterFinalizeCAResponse
	if err := json.Unmarshal(rb, &out); err != nil {
		return zero, fmt.Errorf("decode: %w", err)
	}
	return out, nil
}

// masterTLSForServer builds the per-server mTLS config from the
// master's <config>/master/<server>/{cert,key,ca}.pem.
func masterTLSForServer(cfg Config, serverURL string) (*tls.Config, error) {
	serverID := peerIDFromURL(serverURL)
	if serverID == "" {
		return nil, fmt.Errorf("could not derive peer id from %q", serverURL)
	}
	dir := filepath.Join(masterCertsDir(cfg), serverID)
	tlsCfg, err := loadMasterClientTLS(dir)
	if err != nil {
		return nil, err
	}
	return tlsCfg, nil
}

// filterLabel turns the realm filter into the matching CLI suffix
// for the post-rotation hint message.
func filterLabel(realmFilter string) string {
	if realmFilter == "" {
		return "all"
	}
	return "realm " + realmFilter
}

// setRotationPolicy writes the rotation timestamp into
// master.rotation_realms for each realm in the slice. Atomic via the
// shared allowlistEditMu (the same mutex covers all config edits).
func setRotationPolicy(cfgPath string, realms []string, ts string) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	if cfg.Master.RotationRealms == nil {
		cfg.Master.RotationRealms = map[string]string{}
	}
	for _, r := range realms {
		if r == "" {
			continue
		}
		cfg.Master.RotationRealms[r] = ts
	}
	return saveConfig(cfgPath, cfg)
}

// setFinalizePolicy is the finalize counterpart of setRotationPolicy.
func setFinalizePolicy(cfgPath string, realms []string, ts string) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	if cfg.Master.FinalizeRealms == nil {
		cfg.Master.FinalizeRealms = map[string]string{}
	}
	for _, r := range realms {
		if r == "" {
			continue
		}
		cfg.Master.FinalizeRealms[r] = ts
	}
	return saveConfig(cfgPath, cfg)
}

// determineRealmsTouched figures out which realm names the policy
// should cover. realmFilter == "" → query every server in
// master.servers and return the union of their realm names.
// realmFilter == "<name>" → just that name.
func determineRealmsTouched(cfg Config, realmFilter string) ([]string, error) {
	if realmFilter != "" {
		return []string{realmFilter}, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, server := range cfg.Master.Servers {
		realm, err := queryServerRealm(cfg, server)
		if err != nil {
			// Skip unreachable servers; their realm will be added
			// when they come back online + reachable. This is also
			// why the per-server catchup loop reads master config
			// fresh each cycle.
			continue
		}
		if realm == "" || seen[realm] {
			continue
		}
		seen[realm] = true
		out = append(out, realm)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("could not determine any realm names from reachable servers (network down?)")
	}
	return out, nil
}

// runMasterRotateCAStatus is `simplesiem master rotate-ca-status`.
// Prints a one-line-per-server summary of the fleet's CA state plus
// the master's policy timestamps. Read-only.
func runMasterRotateCAStatus(args []string) {
	fs := flag.NewFlagSet("master rotate-ca-status", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	cfg := loadConfig(*cfgPath)
	if normaliseMode(cfg.Mode) != "master" {
		fatalf("not in master mode (current mode: %s)", cfg.Mode)
	}

	if len(cfg.Master.RotationRealms) > 0 || len(cfg.Master.FinalizeRealms) > 0 {
		fmt.Println("Master rotation policy:")
		for realm, ts := range cfg.Master.RotationRealms {
			fmt.Printf("  rotation_realms[%s] = %s\n", realm, ts)
		}
		for realm, ts := range cfg.Master.FinalizeRealms {
			fmt.Printf("  finalize_realms[%s] = %s\n", realm, ts)
		}
		fmt.Println()
	} else {
		fmt.Println("No rotation policy set.")
		fmt.Println()
	}

	fmt.Printf("%-32s  %-12s  %-22s  %-7s  %s\n", "server", "realm", "ca_not_before", "legacy", "behind?")
	fmt.Println(strings.Repeat("-", 100))
	for _, server := range cfg.Master.Servers {
		client, err := buildPerServerClient(cfg, server)
		if err != nil {
			fmt.Printf("%-32s  UNREACHABLE   (%v)\n", server, err)
			continue
		}
		st, err := fetchCAStatus(client, server)
		if err != nil {
			fmt.Printf("%-32s  UNREACHABLE   (%v)\n", server, err)
			continue
		}
		behind := ""
		if pol, ok := cfg.Master.RotationRealms[st.RealmName]; ok && pol != "" {
			polT, _ := time.Parse(time.RFC3339, pol)
			// last_rotated_at is the authoritative comparison point.
			// Empty == never rotated; otherwise compare directly.
			if st.LastRotatedAt == "" {
				behind = "ROTATE"
			} else if rotT, err := time.Parse(time.RFC3339, st.LastRotatedAt); err == nil && rotT.Before(polT) {
				behind = "ROTATE"
			}
		}
		if behind == "" && st.LegacyCount > 0 {
			if pol, ok := cfg.Master.FinalizeRealms[st.RealmName]; ok && pol != "" {
				behind = "FINALIZE"
			}
		}
		fmt.Printf("%-32s  %-12s  %-22s  %-7d  %s\n",
			server, st.RealmName, st.CANotBefore, st.LegacyCount, behind)
	}
	fmt.Println()
	fmt.Println("ROTATE   = server's CA is older than rotation_realms policy; catchup will rotate next cycle.")
	fmt.Println("FINALIZE = server has legacy CAs to clean per finalize_realms policy; catchup will finalize.")
}

// runMasterRotatePolicy clears the catchup policy. Two subforms:
//
//   simplesiem master rotate-ca-policy clear-all
//   simplesiem master rotate-ca-policy clear-realm <realm-name>
//
// Catchup stops as soon as the policy entry is gone.
func runMasterRotatePolicy(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem master rotate-ca-policy <clear-all|clear-realm <realm>>`)
		os.Exit(2)
	}
	fs := flag.NewFlagSet("master rotate-ca-policy", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args[1:])
	if !isAdmin() {
		fatalf("must run as admin")
	}
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(*cfgPath)
	switch args[0] {
	case "clear-all":
		cfg.Master.RotationRealms = nil
		cfg.Master.FinalizeRealms = nil
		fmt.Println("Cleared rotation_realms and finalize_realms across all realms.")
	case "clear-realm":
		if fs.NArg() == 0 {
			fatalf("clear-realm requires a realm name")
		}
		realm := fs.Arg(0)
		if cfg.Master.RotationRealms != nil {
			delete(cfg.Master.RotationRealms, realm)
		}
		if cfg.Master.FinalizeRealms != nil {
			delete(cfg.Master.FinalizeRealms, realm)
		}
		fmt.Printf("Cleared rotation/finalize policy for realm %q.\n", realm)
	default:
		fatalf("unknown rotate-ca-policy subcommand %q (try clear-all or clear-realm)", args[0])
	}
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("save config: %v", err)
	}
}

// buildPerServerClient is the operator-CLI counterpart of the
// internal masterTLSForServer helper. Returns an http.Client suitable
// for talking to one server using the master's per-server cert.
func buildPerServerClient(cfg Config, serverURL string) (*http.Client, error) {
	tlsCfg, err := masterTLSForServer(cfg, serverURL)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 10 * time.Second},
		Timeout:   20 * time.Second,
	}, nil
}

// writeMasterPerServerCA atomically writes the new server CA into
// the master's per-server cert dir (<CertsDir>/<server>/ca.pem).
// Called after a successful rotation so master's NEXT handshake
// validates the server's just-rotated cert.
func writeMasterPerServerCA(cfg Config, serverURL, caPem string) error {
	if caPem == "" {
		return fmt.Errorf("server returned empty new_ca_pem (cannot update master's per-server CA file)")
	}
	serverID := peerIDFromURL(serverURL)
	if serverID == "" {
		return fmt.Errorf("could not derive peer id from %q", serverURL)
	}
	dir := filepath.Join(masterCertsDir(cfg), serverID)
	caPath := filepath.Join(dir, "ca.pem")
	return atomicWriteFile(caPath, []byte(caPem), 0o644)
}
