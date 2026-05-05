package sieg

import (
	"encoding/json"
	"io"
	"net/http"
)

// handleCollectorGatewayReportMaster mirrors the server-side handler
// but routes the gateway entry into the master's allowlist store.
// Auth: caller must present an mTLS cert whose CN matches the master's
// recorded CollectorCN (single-slot rule).
func (m *masterListenerState) handleCollectorGatewayReportMaster(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !m.requireCollectorMTLS(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cn := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cn = r.TLS.PeerCertificates[0].Subject.CommonName
	}
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
	store := newNetworkAllowlist(networkAllowlistPath(), m.storage)
	_ = store.Load()
	peerID := "collector:" + cn
	if req.OldIP == "" && req.OldMAC == "" {
		if _, err := store.AddOrUpdateGateway(req.NewIP, req.NewMAC, peerID); err != nil {
			http.Error(w, "add: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		if err := store.RotateGatewayForPeer(peerID, req.OldIP, req.OldMAC, req.NewIP, req.NewMAC); err != nil {
			http.Error(w, "rotate: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
