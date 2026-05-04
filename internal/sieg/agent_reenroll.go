package sieg

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// as11 — when an agent's cert is revoked or its agent_id is removed
// from the server's allowlist, the agent gets HTTP 403 from the server.
// Without this code, the agent would log the rejection and continue
// shipping into the void (events spool locally + drop).
//
// With this:
//   1. The PSK is saved to disk at first successful enrollment
//      (`<state>/agent_enroll.psk`, mode 0600). This is the agent's
//      ticket back to the server's trust graph if its cert is ever
//      revoked. Treat the file with the same care as the cert key —
//      anyone with read access to it could enroll a fresh cert under
//      the agent's CN.
//   2. The heartbeat loop watches for 403 responses (cert-rejection /
//      allowlist-removal). On detection, the agent emits
//      meta:agent_cert_revoked and switches into re-enrollment mode.
//   3. Re-enrollment runs runAgentEnrollment with the saved PSK; on
//      success it emits meta:agent_reenrolled and the next TLS
//      handshake transparently picks up the new cert (agentTLSConfig
//      uses GetClientCertificate which re-reads from disk on each
//      handshake).
//   4. Re-enrollment runs at MOST once per minute to avoid hammering
//      a server that has rotated its PSK (in which case the agent
//      stays in degraded mode until an operator fixes the PSK).
//
// Trade-off: storing the PSK on the agent makes re-enrollment
// possible without operator action. The alternative (require operator
// to re-enroll by hand on every revocation) is operationally
// expensive when the goal of revocation is to recover from a rotated
// CA or a misconfigured allowlist. If the threat model precludes
// PSK-on-disk, set agent.no_local_storage=true (which already gates
// many on-disk fallbacks) — todo: extend that flag to also gate
// PSK persistence.

// agentEnrollPSKPath returns the path of the saved enrollment PSK on
// the agent. Lives under the same state dir that holds the spool, so
// uninstall --purge wipes it along with everything else.
func agentEnrollPSKPath() string {
	return filepath.Join(defaultStateDir(), "agent_enroll.psk")
}

// saveAgentEnrollPSK persists the PSK that just enrolled this agent
// so as11 can retry on revocation. Best-effort: write failures are
// logged but don't fail the enrollment (re-enrollment will simply
// require manual intervention for that agent).
func saveAgentEnrollPSK(psk string) error {
	path := agentEnrollPSKPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSpace(psk)+"\n"), 0o600); err != nil {
		return fmt.Errorf("write PSK: %w", err)
	}
	return nil
}

// readAgentEnrollPSK loads the saved PSK. Returns ("", error) if the
// file doesn't exist (which is fine on a fresh install — the agent
// hasn't been enrolled yet) or is unreadable.
func readAgentEnrollPSK() (string, error) {
	data, err := os.ReadFile(agentEnrollPSKPath())
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(data))
	if !strings.HasPrefix(s, enrollPSKPrefix) {
		return "", fmt.Errorf("saved PSK at %s is malformed (missing %q prefix)", agentEnrollPSKPath(), enrollPSKPrefix)
	}
	return s, nil
}

// reenrollState tracks the cooldown between re-enroll attempts so a
// permanently rotated PSK doesn't trigger an attempt on every 403.
type reenrollState struct {
	lastAttempt atomic.Int64 // unix nano of the last attempt
}

var globalReenrollState reenrollState

// tryAgentReenroll runs a single re-enrollment cycle if the cooldown
// has elapsed. Returns (attempted, err) — attempted=false means we
// skipped due to cooldown / missing PSK, NOT a failure. err is the
// re-enroll error if attempted=true and it failed.
//
// The cooldown is 60s by default; aggressive enough to catch a quick
// "operator fixed allowlist" scenario, conservative enough to not
// flood a permanently-rotated PSK.
//
// On success, this also closes any idle connections on the supplied
// transport so the next request opens a fresh TLS handshake using
// the newly-written cert/key.
func tryAgentReenroll(acfg AgentConfig, hostname string, log *Storage, tr *http.Transport) (bool, error) {
	const cooldown = 60 * time.Second
	now := time.Now().UnixNano()
	last := globalReenrollState.lastAttempt.Load()
	if last != 0 && time.Duration(now-last) < cooldown {
		return false, nil
	}
	psk, perr := readAgentEnrollPSK()
	if perr != nil {
		// No PSK saved: this agent was enrolled the old-fashioned way
		// (manual cert copy) or pre-as11. Operator will have to
		// re-enroll by hand.
		return false, nil
	}
	if !globalReenrollState.lastAttempt.CompareAndSwap(last, now) {
		// Another goroutine claimed this cycle.
		return false, nil
	}

	log.Write("meta", map[string]any{
		"event":  "agent_cert_revoked",
		"hint":   "server returned 403; attempting re-enrollment with saved PSK",
		"server": acfg.ServerURL,
	})

	er, err := runAgentEnrollment(acfg, hostname, psk)
	if err != nil {
		log.Write("errors", map[string]any{
			"collector": "agent_reenroll",
			"error":     err.Error(),
			"hint":      "saved PSK may have been rotated on the server; on the server run `simplesiem certs psk show` and update this agent",
		})
		log.Write("meta", map[string]any{
			"event": "agent_reenroll_failed",
			"error": err.Error(),
		})
		return true, err
	}

	// Drop idle connections so the next request opens a fresh TLS
	// handshake using the just-written cert. Without this, the http
	// keep-alive pool would keep using the old (revoked) handshake
	// until the connection times out.
	if tr != nil {
		tr.CloseIdleConnections()
	}

	log.Write("meta", map[string]any{
		"event":        "agent_reenrolled",
		"server":       acfg.ServerURL,
		"realm":        er.RealmName,
		"failover_n":   len(er.RealmPeers),
		"hint":         "fresh cert + CA written; shipper transparently picks up the new identity on the next handshake",
	})
	return true, nil
}
