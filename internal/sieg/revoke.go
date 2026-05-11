package sieg

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"
)

// Revocation: tombstone-based, propagated via realm sync.
//
// The X.509 layer continues to trust the cert until its NotAfter
// (we don't issue full RFC 5280 CRLs — operators don't typically
// have OCSP responders or distribution points to consume them).
// Instead, the operator-managed allowlist gate gains a tombstone
// map: an entry in agent_revoked / master_revoked overrides the
// allowlist entry for that ID. Tombstones merge additively across
// realm peers via /v1/sync/config, so revoking once on any peer
// reaches every peer within a sync interval.
//
// To "unrevoke" (e.g., accidental revocation), the operator removes
// the entry from agent_revoked on every peer manually — there's no
// "unrevoke" CLI yet because the additive merge means a single peer
// re-broadcasting the tombstone would resurrect it. A future feature
// could add a deletion-with-quorum primitive; for now, revoke is
// effectively final until manually reverted everywhere.

// agentRevokedAt returns the RFC3339 timestamp when this agent_id
// was revoked, or "" if not revoked. Read-locked so concurrent
// merges from sync don't race.
func (s *serverState) agentRevokedAt(id string) string {
	s.revokedMu.RLock()
	defer s.revokedMu.RUnlock()
	if s.agentRevoked == nil {
		return ""
	}
	return s.agentRevoked[id]
}

// masterRevokedAt is the master-CN counterpart of agentRevokedAt.
func (s *serverState) masterRevokedAt(cn string) string {
	s.revokedMu.RLock()
	defer s.revokedMu.RUnlock()
	if s.masterRevoked == nil {
		return ""
	}
	return s.masterRevoked[cn]
}

// snapshotRevoked returns shallow copies of the revocation maps for
// inclusion in /v1/sync/config responses. Caller must NOT mutate.
func (s *serverState) snapshotRevoked() (map[string]string, map[string]string) {
	s.revokedMu.RLock()
	defer s.revokedMu.RUnlock()
	return copyStringMap(s.agentRevoked), copyStringMap(s.masterRevoked)
}

// mergeRevoked is the inbound side of revocation propagation. Called
// by reconcileRealmConfig with the union of every peer's tombstones.
// Adds any new entries (additive merge) and persists to config.json
// so a daemon restart preserves the merged state.
func (s *serverState) mergeRevoked(agents, masters map[string]string) (added int) {
	if len(agents) == 0 && len(masters) == 0 {
		return 0
	}
	s.revokedMu.Lock()
	if s.agentRevoked == nil {
		s.agentRevoked = map[string]string{}
	}
	if s.masterRevoked == nil {
		s.masterRevoked = map[string]string{}
	}
	for id, ts := range agents {
		if _, ok := s.agentRevoked[id]; !ok {
			s.agentRevoked[id] = ts
			added++
		}
	}
	for cn, ts := range masters {
		if _, ok := s.masterRevoked[cn]; !ok {
			s.masterRevoked[cn] = ts
			added++
		}
	}
	a := copyStringMap(s.agentRevoked)
	m := copyStringMap(s.masterRevoked)
	s.revokedMu.Unlock()
	if added > 0 {
		_ = persistRevocationMaps(s.configPath, a, m)
	}
	return added
}

// persistRevocationMaps writes the revoked maps to config.json.
// Serialised through allowlistEditMu since it shares config with
// allowlist edits.
func persistRevocationMaps(cfgPath string, agents, masters map[string]string) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	cfg.Server.AgentRevoked = agents
	cfg.Server.MasterRevoked = masters
	return saveConfig(cfgPath, cfg)
}

// addRevocationToConfig is the operator-side write path called by
// `simplesiem certs revoke <id>`. Sets a fresh timestamp for id in
// the appropriate map (agent if validAgentID && !validMasterID,
// master if validMasterID), persists, and returns whether the id
// was newly revoked.
func addRevocationToConfig(cfgPath, id string) (newlyRevoked bool, kind string, err error) {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	now := time.Now().UTC().Format(time.RFC3339)
	switch {
	case validMasterID(id):
		if cfg.Server.MasterRevoked == nil {
			cfg.Server.MasterRevoked = map[string]string{}
		}
		if _, ok := cfg.Server.MasterRevoked[id]; ok {
			return false, "master", nil
		}
		cfg.Server.MasterRevoked[id] = now
		kind = "master"
	case validAgentID(id):
		if cfg.Server.AgentRevoked == nil {
			cfg.Server.AgentRevoked = map[string]string{}
		}
		if _, ok := cfg.Server.AgentRevoked[id]; ok {
			return false, "agent", nil
		}
		cfg.Server.AgentRevoked[id] = now
		kind = "agent"
	default:
		return false, "", fmt.Errorf("%q is not a valid agent ID or master CN", id)
	}
	if err := saveConfig(cfgPath, cfg); err != nil {
		return false, kind, err
	}
	return true, kind, nil
}

// runCertsUnrevoke is `simplesiem certs unrevoke <subcmd|id>`. Adds an
// "unrevoke intent" entry on this peer. When ⌈peers/2⌉+1 peers have
// matching intents (collected via realm sync) AND the intent
// timestamp is newer than the revocation timestamp, every peer drops
// the tombstone on the next /v1/sync/config cycle. Single-server
// realms quorum trivially with 1 vote.
//
// Subcommands:
//
//	unrevoke <agent-id|master-cn>     record this peer's intent
//	unrevoke list                     show pending intents on this peer
//	unrevoke clear <id>               withdraw this peer's intent
func runCertsUnrevoke(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem certs unrevoke <subcommand>

subcommands:
  <agent-id|master-cn>                  record this peer's unrevoke intent
                                        (quorum is ⌈peers/2⌉+1 — every realm
                                        peer must run the same command before
                                        the tombstone is dropped)
  list                                  show pending unrevoke intents on this peer
  clear <agent-id|master-cn>            withdraw this peer's intent`)
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		runCertsUnrevokeList(args[1:])
		return
	case "clear":
		runCertsUnrevokeClear(args[1:])
		return
	}
	fs := flag.NewFlagSet("certs unrevoke", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem certs unrevoke <agent-id|master-cn>|list|clear")
		os.Exit(2)
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	id := fs.Arg(0)
	added, kind, err := addUnrevokeIntentToConfig(*cfgPath, id)
	if err != nil {
		fatalf("%v", err)
	}
	if !added {
		fmt.Printf("%s %q already has an unrevoke intent on this peer; nothing to do.\n", kind, id)
		return
	}
	fmt.Printf("Recorded unrevoke intent for %s %q on this peer.\n", kind, id)
	fmt.Println()
	fmt.Println("Realm convergence: the tombstone is dropped only when")
	fmt.Println("⌈peers/2⌉+1 peers in the realm have matching intents that")
	fmt.Println("are newer than the original revocation timestamp.")
	fmt.Println()
	fmt.Println("Run the same command on each remaining peer (or wait for")
	fmt.Println("operators on those hosts to vote) to reach quorum.")
}

func runCertsUnrevokeList(_ []string) {
	cfg := loadConfig(defaultConfigPath())
	if len(cfg.Server.AgentUnrevokeIntent) == 0 && len(cfg.Server.MasterUnrevokeIntent) == 0 {
		fmt.Println("(no pending unrevoke intents)")
		return
	}
	if len(cfg.Server.AgentUnrevokeIntent) > 0 {
		fmt.Println("agents:")
		for k, v := range cfg.Server.AgentUnrevokeIntent {
			fmt.Printf("  %-30s %s\n", k, v)
		}
	}
	if len(cfg.Server.MasterUnrevokeIntent) > 0 {
		fmt.Println("masters:")
		for k, v := range cfg.Server.MasterUnrevokeIntent {
			fmt.Printf("  %-30s %s\n", k, v)
		}
	}
}

func runCertsUnrevokeClear(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem certs unrevoke clear <agent-id|master-cn>")
		os.Exit(2)
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	id := args[0]
	cfgPath := defaultConfigPath()
	cfg := loadConfig(cfgPath)
	hit := false
	if cfg.Server.AgentUnrevokeIntent != nil {
		if _, ok := cfg.Server.AgentUnrevokeIntent[id]; ok {
			delete(cfg.Server.AgentUnrevokeIntent, id)
			hit = true
		}
	}
	if cfg.Server.MasterUnrevokeIntent != nil {
		if _, ok := cfg.Server.MasterUnrevokeIntent[id]; ok {
			delete(cfg.Server.MasterUnrevokeIntent, id)
			hit = true
		}
	}
	if !hit {
		fmt.Printf("no unrevoke intent on this peer for %q; nothing to clear\n", id)
		return
	}
	if err := saveConfig(cfgPath, cfg); err != nil {
		fatalf("save config: %v", err)
	}
	fmt.Printf("withdrew unrevoke intent for %q on this peer\n", id)
}

// addUnrevokeIntentToConfig records this peer's intent to drop the
// tombstone for id. Sets a fresh timestamp; the merge logic in
// reconcileRealmConfig requires that this timestamp be newer than
// the revocation timestamp to count.
func addUnrevokeIntentToConfig(cfgPath, id string) (newlyAdded bool, kind string, err error) {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	now := time.Now().UTC().Format(time.RFC3339)
	switch {
	case validMasterID(id):
		if cfg.Server.MasterUnrevokeIntent == nil {
			cfg.Server.MasterUnrevokeIntent = map[string]string{}
		}
		if existing := cfg.Server.MasterUnrevokeIntent[id]; existing != "" {
			return false, "master", nil
		}
		cfg.Server.MasterUnrevokeIntent[id] = now
		kind = "master"
	case validAgentID(id):
		if cfg.Server.AgentUnrevokeIntent == nil {
			cfg.Server.AgentUnrevokeIntent = map[string]string{}
		}
		if existing := cfg.Server.AgentUnrevokeIntent[id]; existing != "" {
			return false, "agent", nil
		}
		cfg.Server.AgentUnrevokeIntent[id] = now
		kind = "agent"
	default:
		return false, "", fmt.Errorf("%q is not a valid agent ID or master CN", id)
	}
	if err := saveConfig(cfgPath, cfg); err != nil {
		return false, kind, err
	}
	return true, kind, nil
}

// runCertsRevoke is the CLI entry point for `simplesiem certs revoke
// <agent-id|master-cn>`. Adds a tombstone locally; realm peers learn
// about it on the next /v1/sync/config cycle (default 60s).
func runCertsRevoke(args []string) {
	fs := flag.NewFlagSet("certs revoke", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem certs revoke <agent-id|master-cn>")
		os.Exit(2)
	}
	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}
	id := fs.Arg(0)
	added, kind, err := addRevocationToConfig(*cfgPath, id)
	if err != nil {
		fatalf("%v", err)
	}
	if !added {
		fmt.Printf("%s %q was already revoked; no change.\n", kind, id)
		return
	}
	fmt.Printf("Revoked %s %q.\n", kind, id)
	fmt.Println()
	fmt.Println("Effects on this server:")
	fmt.Println("  - the next /v1/events or /v1/sync/events from this identity gets HTTP 403")
	fmt.Println("  - existing in-flight TLS sessions are not interrupted (they finish out their batch);")
	fmt.Println("    the next reconnect is gated")
	fmt.Println()
	fmt.Println("Realm propagation: peers learn about this tombstone on their next")
	fmt.Println("/v1/sync/config cycle (typically within sync_interval_seconds).")
	fmt.Println()
	fmt.Println("Restart the daemon for the change to take effect:")
	fmt.Println("  sudo simplesiem stop && sudo simplesiem start")
}

// listRevoked prints every revoked agent and master with the
// timestamp of revocation. Read-only; no admin needed.
func listRevoked(args []string) {
	fs := flag.NewFlagSet("certs revoked", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	cfg := loadConfig(*cfgPath)
	if len(cfg.Server.AgentRevoked) == 0 && len(cfg.Server.MasterRevoked) == 0 {
		fmt.Println("No revoked agents or masters.")
		return
	}
	if len(cfg.Server.AgentRevoked) > 0 {
		fmt.Println("Revoked agents:")
		ids := make([]string, 0, len(cfg.Server.AgentRevoked))
		for id := range cfg.Server.AgentRevoked {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Printf("  %s   (revoked %s)\n", id, cfg.Server.AgentRevoked[id])
		}
	}
	if len(cfg.Server.MasterRevoked) > 0 {
		fmt.Println("Revoked masters:")
		cns := make([]string, 0, len(cfg.Server.MasterRevoked))
		for cn := range cfg.Server.MasterRevoked {
			cns = append(cns, cn)
		}
		sort.Strings(cns)
		for _, cn := range cns {
			fmt.Printf("  %s   (revoked %s)\n", cn, cfg.Server.MasterRevoked[cn])
		}
	}
}

// copyStringMap is a tiny helper used by snapshotRevoked, mergeRevoked,
// and the serverState init. Returns nil for a nil input so callers can
// treat "unset" and "empty map" identically.
func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// dropRevocationTombstones removes the supplied agent IDs / master
// CNs from the persisted revoked maps AND clears their unrevoke
// intent entries (so the next sync cycle doesn't see "stale" intents
// counting toward a future re-revoke quorum). Returns the count of
// tombstones actually removed.
func dropRevocationTombstones(cfgPath string, agentIDs, masterCNs []string) (int, error) {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	removed := 0
	for _, id := range agentIDs {
		if _, ok := cfg.Server.AgentRevoked[id]; ok {
			delete(cfg.Server.AgentRevoked, id)
			removed++
		}
		if cfg.Server.AgentUnrevokeIntent != nil {
			delete(cfg.Server.AgentUnrevokeIntent, id)
		}
	}
	for _, cn := range masterCNs {
		if _, ok := cfg.Server.MasterRevoked[cn]; ok {
			delete(cfg.Server.MasterRevoked, cn)
			removed++
		}
		if cfg.Server.MasterUnrevokeIntent != nil {
			delete(cfg.Server.MasterUnrevokeIntent, cn)
		}
	}
	if removed == 0 {
		return 0, nil
	}
	if err := saveConfig(cfgPath, cfg); err != nil {
		return 0, err
	}
	return removed, nil
}
