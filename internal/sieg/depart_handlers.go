package sieg

import (
	"encoding/json"
	"io"
	"net/http"
)

// handleAgentDepart is the server-side handler for an agent's
// graceful departure (invoked by `simplesiem uninstall` on the
// agent host before the binary removes itself).
//
// Authentication: same mTLS gate as /v1/heartbeat. The caller's
// CN must equal the agent_id in the request body so an agent can
// only un-enroll itself.
//
// Effect: remove the agent_id from the server's allowlist on disk
// (so a future enrollment with the same ID re-asks for a PSK and
// goes through the standard handshake) AND emit a meta event so
// the operator can see in `simplesiem triage --type meta` that the
// agent left intentionally vs. just stopped heartbeating. Per-agent
// events on disk are NOT touched — the spec says "keeps the logs."
func (s *serverState) handleAgentDepart(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	cn := clientCN(r)
	if cn == "" {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	var req struct {
		AgentID string `json:"agent_id"`
	}
	_ = json.Unmarshal(body, &req)
	// Defence-in-depth: an agent presenting cert CN=foo cannot ask
	// to un-enroll bar. The auth gate already proves CN identity;
	// this just refuses bogus requests where the body lies.
	if req.AgentID != "" && req.AgentID != cn {
		http.Error(w, "agent_id does not match cert CN", http.StatusForbidden)
		return
	}

	// Remove from the in-memory allowlist + persist back to config.json.
	s.allowlistMu.Lock()
	delete(s.allowlist, cn)
	s.allowlistMu.Unlock()
	_ = removeFromConfigAllowlist(s.configPath, cn)

	// Strip the departing agent from every network-allowlist entry's
	// owners list. Orphaned gateway entries are pruned (they were only
	// in the allowlist because this agent vouched for them).
	if s.networkAllowlist != nil {
		s.networkAllowlist.RemoveOwnerFromAll(cn)
	}

	if st, err := s.storageFor(cn); err == nil && st != nil {
		st.Write("meta", map[string]any{
			"event":  "agent_departed",
			"agent":  cn,
			"reason": "agent invoked graceful uninstall",
			"hint":   "future enrollments with this id need a fresh PSK exchange",
		})
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// handleMasterDepart removes the departing master's CN from
// master_cns so it can no longer authenticate against /v1/sync/* or
// trigger remote rotations / pushes. Called by the master's
// uninstall path. Same mTLS gate; CN must match a registered master.
func (s *serverState) handleMasterDepart(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.peerAuthorized(r) {
		http.Error(w, "not a recognised peer", http.StatusForbidden)
		return
	}
	cn := clientCN(r)
	if cn == "" {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	s.masterMu.Lock()
	out := s.masterCNs[:0]
	for _, mcn := range s.masterCNs {
		if mcn != cn {
			out = append(out, mcn)
		}
	}
	s.masterCNs = out
	s.masterMu.Unlock()

	if st, err := s.storageFor("_server"); err == nil && st != nil {
		st.Write("meta", map[string]any{
			"event":  "master_departed",
			"master": cn,
			"reason": "master invoked graceful uninstall",
		})
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// handleCollectorDepart frees the single-collector slot when the
// paired collector uninstalls itself. The server's collector_cn
// config field is cleared so a future collector enrollment can
// take the slot.
func (s *serverState) handleCollectorDepart(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.peerAuthorized(r) {
		http.Error(w, "not a recognised peer", http.StatusForbidden)
		return
	}
	cn := clientCN(r)
	if cn == "" {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	_ = clearCollectorCNFromConfig(s.configPath, cn)
	if st, err := s.storageFor("_server"); err == nil && st != nil {
		st.Write("meta", map[string]any{
			"event":     "collector_departed",
			"collector": cn,
			"reason":    "collector invoked graceful uninstall",
		})
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// removeFromConfigAllowlist atomically rewrites config.json to drop
// agentID from the agent_allowlist. Concurrent writers are guarded
// by allowlistEditMu, the same mutex /v1/enroll uses to add agents.
func removeFromConfigAllowlist(cfgPath, agentID string) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	out := cfg.Server.AgentAllowlist[:0]
	changed := false
	for _, x := range cfg.Server.AgentAllowlist {
		if x == agentID {
			changed = true
			continue
		}
		out = append(out, x)
	}
	if !changed {
		return nil
	}
	cfg.Server.AgentAllowlist = out
	return saveConfig(cfgPath, cfg)
}

// clearCollectorCNFromConfig clears server.collector_cn in
// config.json when the matching collector departs. Only clears when
// the field actually matches the departing CN — don't accidentally
// wipe a different collector's slot.
func clearCollectorCNFromConfig(cfgPath, collectorCN string) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	if cfg.Server.CollectorCN != collectorCN {
		return nil
	}
	cfg.Server.CollectorCN = ""
	return saveConfig(cfgPath, cfg)
}
