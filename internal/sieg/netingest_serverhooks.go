package sieg

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// handleCollectorGatewayReport handles the same body shape as
// handleAgentGatewayReport, but auth gates on the collector CN +
// the request itself goes against /v1/collector/gateway. Mounted on
// both server and master listeners so a collector paired with either
// can report.
func (s *serverState) handleCollectorGatewayReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorize(r) {
		s.logAuthFailure(r, "collector_gateway_report")
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
		OldIP  string `json:"old_ip"`
		OldMAC string `json:"old_mac"`
		NewIP  string `json:"new_ip"`
		NewMAC string `json:"new_mac"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	if s.networkAllowlist == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	peerID := "collector:" + cn
	if req.OldIP == "" && req.OldMAC == "" {
		_, err := s.networkAllowlist.AddOrUpdateGateway(req.NewIP, req.NewMAC, peerID)
		if err != nil {
			http.Error(w, "add: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		if err := s.networkAllowlist.RotateGatewayForPeer(peerID, req.OldIP, req.OldMAC, req.NewIP, req.NewMAC); err != nil {
			http.Error(w, "rotate: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAgentGatewayReport receives `{old_ip, old_mac, new_ip, new_mac}`
// from an agent and updates the network-allowlist accordingly. Auth:
// the same mTLS gate as /v1/heartbeat (authorize()).
func (s *serverState) handleAgentGatewayReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorize(r) {
		s.logAuthFailure(r, "agent_gateway_report")
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
		OldIP  string `json:"old_ip"`
		OldMAC string `json:"old_mac"`
		NewIP  string `json:"new_ip"`
		NewMAC string `json:"new_mac"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	if s.networkAllowlist == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if req.OldIP == "" && req.OldMAC == "" {
		// initial registration
		_, err := s.networkAllowlist.AddOrUpdateGateway(req.NewIP, req.NewMAC, cn)
		if err != nil {
			http.Error(w, "add: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		if err := s.networkAllowlist.RotateGatewayForPeer(cn, req.OldIP, req.OldMAC, req.NewIP, req.NewMAC); err != nil {
			http.Error(w, "rotate: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// serverState extension methods used by the network-ingest endpoints.
// Kept in this dedicated file so reverting the feature later is a
// single-file delete.

// requireMaster returns true iff the caller presented an mTLS cert
// whose CN is in masterCNs.
func (s *serverState) requireMaster(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	s.masterMu.RLock()
	defer s.masterMu.RUnlock()
	for _, m := range s.masterCNs {
		if m == cn {
			return true
		}
	}
	return false
}

// requireMasterOrPeer accepts either an enrolled master OR a realm
// peer (matched by URL host of one of realm.peers).
func (s *serverState) requireMasterOrPeer(r *http.Request) bool {
	if s.requireMaster(r) {
		return true
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	s.realmMu.RLock()
	defer s.realmMu.RUnlock()
	for _, p := range s.realmPeers {
		host := serverHostFromURL(p)
		if host == cn || strings.HasSuffix(cn, "-"+host) {
			return true
		}
	}
	return false
}

// allowMasterPushAllowlist mirrors the per-server consent flag. Read
// fresh from disk to honour hot-reload.
func (s *serverState) allowMasterPushAllowlist() bool {
	cfg := loadConfig(s.configPath)
	return cfg.Server.NetworkIngest.MasterCanPushAllowlist
}

// metaLogger returns the _server meta storage if available.
func (s *serverState) metaLogger() *Storage {
	if storage, err := s.storageFor("_server"); err == nil {
		return storage
	}
	return nil
}

