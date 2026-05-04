package sieg

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Master-driven CA rotation: a privileged push from a master to each
// server it manages. Default-deny; the server only honours the
// trigger when the operator has explicitly set
// `server.master_can_rotate_ca: true` AND the calling cert's CN is
// in master_cns AND the master is not revoked. Even then, the master
// presenting a valid client cert is the sole proof — the operation
// is high-trust and gated by the explicit per-server opt-in.

// MasterRotateCARequest is the body of POST /v1/master/rotate-ca.
// Years carries through to performCARotation; defaults to 10.
type MasterRotateCARequest struct {
	Years int `json:"years"`
}

// MasterRotateCAResponse mirrors CARotationResult plus the legacy
// realm name + this server's selfPeerID + the new CA cert PEM. The
// master MUST write NewCAPem to its per-server <config>/master/<peer>/ca.pem
// before the next handshake — otherwise the server's freshly hot-
// reloaded server cert (signed by the new CA) won't validate against
// the master's stale CA file and subsequent calls fail with
// "x509: certificate signed by unknown authority".
type MasterRotateCAResponse struct {
	CARotationResult
	RealmName string `json:"realm_name"`
	PeerID    string `json:"peer_id"`
	NewCAPem  string `json:"new_ca_pem"`
}

// handleMasterRotateCA initiates a CA rotation on this server, driven
// by an authenticated master. The work is identical to what the
// operator would do via `simplesiem certs init-rotate`; the master
// is only authorised to TRIGGER it, not to choose CA parameters
// beyond validity years.
func (s *serverState) handleMasterRotateCA(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.masterCanRotate {
		http.Error(w, "server.master_can_rotate_ca is false; rotation refused", http.StatusForbidden)
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

	var req MasterRotateCARequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Years <= 0 {
		req.Years = 10
	}

	cfg := loadConfig(s.configPath)
	res, err := performCARotation(cfg, req.Years)
	if err != nil {
		s.broadcastErr("master_rotate_ca", err)
		http.Error(w, "rotation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.trust.rebuild(); err != nil {
		s.broadcastErr("master_rotate_ca", fmt.Errorf("rebuild trust bundle: %v", err))
	}

	if mst, gerr := s.storageFor("_server"); gerr == nil {
		mst.Write("meta", map[string]any{
			"event":            "ca_rotated_by_master",
			"master_cn":        cn,
			"new_ca_path":      res.NewCAPath,
			"legacy_archived":  res.LegacyArchivedTo,
			"server_cert_path": res.ServerCertPath,
		})
	}

	s.realmMu.RLock()
	realm := s.realmName
	s.realmMu.RUnlock()
	newCAPem := ""
	if data, err := os.ReadFile(res.NewCAPath); err == nil {
		newCAPem = string(data)
	}
	resp := MasterRotateCAResponse{
		CARotationResult: res,
		RealmName:        realm,
		PeerID:           s.selfPeerID,
		NewCAPem:         newCAPem,
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// MasterFinalizeCAResponse is what /v1/master/finalize-rotate returns.
type MasterFinalizeCAResponse struct {
	Removed   int    `json:"removed"`
	RealmName string `json:"realm_name"`
	PeerID    string `json:"peer_id"`
}

// handleMasterFinalizeCA removes every legacy CA on this server.
// Same authorization as handleMasterRotateCA: master_can_rotate_ca
// gates both, since finalize-rotate is the symmetric cleanup of
// init-rotate and revoking the privilege should be atomic.
func (s *serverState) handleMasterFinalizeCA(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.masterCanRotate {
		http.Error(w, "server.master_can_rotate_ca is false; finalize refused", http.StatusForbidden)
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

	removed, err := performCAFinalize()
	if err != nil {
		http.Error(w, "finalize failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.trust.rebuild(); err != nil {
		s.broadcastErr("master_finalize_ca", fmt.Errorf("rebuild trust bundle: %v", err))
	}

	if mst, gerr := s.storageFor("_server"); gerr == nil {
		mst.Write("meta", map[string]any{
			"event":     "ca_finalized_by_master",
			"master_cn": cn,
			"removed":   removed,
		})
	}

	s.realmMu.RLock()
	realm := s.realmName
	s.realmMu.RUnlock()
	resp := MasterFinalizeCAResponse{
		Removed:   removed,
		RealmName: realm,
		PeerID:    s.selfPeerID,
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// MasterCAStatusResponse is what GET /v1/master/ca-status returns.
// Used by master catchup to decide whether a server is behind on its
// rotation policy, and by `master rotate-ca-status` for operator
// visibility into fleet state.
type MasterCAStatusResponse struct {
	RealmName    string `json:"realm_name"`
	PeerID       string `json:"peer_id"`
	CANotBefore  string `json:"ca_not_before"` // RFC3339; the active CA's NotBefore (backdated 1h for clock skew)
	CANotAfter   string `json:"ca_not_after"`  // RFC3339
	CASubjectCN  string `json:"ca_subject_cn"` // human-readable identifier
	LegacyCount  int    `json:"legacy_count"`  // entries in <state>/legacy_cas/

	// LastRotatedAt is the RFC3339 timestamp of the most recent
	// successful rotation, written by performCARotation. Empty
	// string means "this server has never rotated since install".
	// Used by master catchup as the authoritative comparison point
	// against rotation_realms[realm] — comparing against
	// CANotBefore is unreliable because of the 1h backdating.
	LastRotatedAt string `json:"last_rotated_at"`
}

// handleMasterCAStatus is GET /v1/master/ca-status. Read-only; same
// authorization as the rotate endpoints (master_can_rotate_ca opt-in
// + master in master_cns + not revoked). The opt-in gate applies
// because exposing CA cert metadata to anyone holding a master cert
// would leak fleet-wide rotation state to a partially-trusted master.
func (s *serverState) handleMasterCAStatus(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.masterCanRotate {
		http.Error(w, "server.master_can_rotate_ca is false", http.StatusForbidden)
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

	cfg := loadConfig(s.configPath)
	caPath := cfg.Server.CACert
	data, err := os.ReadFile(caPath)
	if err != nil {
		http.Error(w, "read CA: "+err.Error(), http.StatusInternalServerError)
		return
	}
	block, _ := pem.Decode(data)
	if block == nil {
		http.Error(w, "CA is not PEM", http.StatusInternalServerError)
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		http.Error(w, "parse CA: "+err.Error(), http.StatusInternalServerError)
		return
	}
	legacyCount := 0
	if entries, err := os.ReadDir(legacyCAsDir()); err == nil {
		for _, e := range entries {
			if !e.IsDir() && len(e.Name()) > 4 && e.Name()[len(e.Name())-4:] == ".pem" {
				legacyCount++
			}
		}
	}
	s.realmMu.RLock()
	realm := s.realmName
	s.realmMu.RUnlock()
	resp := MasterCAStatusResponse{
		RealmName:     realm,
		PeerID:        s.selfPeerID,
		CANotBefore:   cert.NotBefore.UTC().Format(time.RFC3339),
		CANotAfter:    cert.NotAfter.UTC().Format(time.RFC3339),
		CASubjectCN:   cert.Subject.CommonName,
		LegacyCount:   legacyCount,
		LastRotatedAt: readLastCARotation(),
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}
