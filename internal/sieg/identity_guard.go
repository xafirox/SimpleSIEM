package sieg

import (
	"net/http"
	"sync"
	"time"
)

// identityGuardWindow is how long we consider another presenter of
// the same client cert "still active." If a different source IP
// shows up holding the same cert inside this window, it's almost
// certainly a duplicate-identity scenario (a restored backup whose
// original is still running, or a misconfigured clone) and we
// reject. A 60s window covers two heartbeat cycles by default
// (default reauth/heartbeat is 30s), giving the original agent
// plenty of activity to claim its slot before we'd ever consider
// the second one.
const identityGuardWindow = 60 * time.Second

// identityRec tracks the last observed (IP, ts) pair for one CN.
// Keyed by CN in serverState.identityState. Mutated only under
// serverState.identityMu.
type identityRec struct {
	lastIP string
	lastTS time.Time
}

// identityCheck enforces the duplicate-identity rule on an
// authenticated request. Returns true to allow, false to reject;
// the caller writes the HTTP response either way.
//
// First-seen CNs are recorded and allowed. Subsequent requests from
// the SAME (CN, IP) update the timestamp. Requests with a DIFFERENT
// IP arriving inside identityGuardWindow are rejected and an
// `identity_conflict` meta event is emitted into the per-host log so
// an operator running `simplesiem triage --type meta` sees the event
// without having to enable verbose logs.
//
// Outside the window a new IP wins (the previous occupant has been
// silent for a full minute — assume it died). This avoids permanent
// blackholing when a host genuinely changes IP and its last
// heartbeat was the disappearing one.
func (s *serverState) identityCheck(r *http.Request, cn string) bool {
	if cn == "" {
		// Bearer-token-only auth path doesn't have a cert identity to
		// guard; the bearer token IS the identity. Skip the check.
		return true
	}
	ip := remoteIP(r)
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	if s.identityState == nil {
		s.identityState = map[string]identityRec{}
	}
	now := time.Now()
	rec, ok := s.identityState[cn]
	if !ok {
		s.identityState[cn] = identityRec{lastIP: ip, lastTS: now}
		return true
	}
	// Same IP — refresh and allow.
	if rec.lastIP == ip {
		rec.lastTS = now
		s.identityState[cn] = rec
		return true
	}
	// Different IP; still inside the window? Reject.
	if now.Sub(rec.lastTS) < identityGuardWindow {
		s.recordIdentityConflict(cn, ip, rec)
		return false
	}
	// Window expired — new occupant takes over.
	s.identityState[cn] = identityRec{lastIP: ip, lastTS: now}
	return true
}

func (s *serverState) recordIdentityConflict(cn, newIP string, rec identityRec) {
	// Emit into the offender's per-host meta log so the event is
	// directly visible in `simplesiem triage --host <cn> --type meta`.
	// Best-effort: a storage error here must NOT block the rejection
	// from happening, so swallow the error path.
	st, err := s.storageFor(cn)
	if err != nil || st == nil {
		return
	}
	st.Write("meta", map[string]any{
		"event":         "identity_conflict",
		"cn":            cn,
		"new_ip":        newIP,
		"prior_ip":      rec.lastIP,
		"prior_seen":    rec.lastTS.UTC().Format(time.RFC3339Nano),
		"window_secs":   int(identityGuardWindow.Seconds()),
		"action":        "rejected",
		"hint":          "two daemons hold the same client cert; restore likely happened while original was still running. Stop the original or wait for its heartbeat to lapse beyond the guard window.",
	})
}

// identityMuField + identityStateField are the additions to
// serverState. We keep their *types* declared here so a future code
// review can find the guard's storage by grepping "identity_guard".
//
// Wired into serverState in server.go:
//
//	identityMu    sync.Mutex
//	identityState map[string]identityRec
var _ = sync.Mutex{}
