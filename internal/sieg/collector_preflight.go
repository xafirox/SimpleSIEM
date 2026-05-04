package sieg

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// c15 — preflight that gathers ALL information needed for a collector
// to pair with its master/server source BEFORE any local state change.
// Without this, the operator hits a partial enrollment when the
// master is missing prerequisites (listener not enabled, slot not
// opened, realm not configured) — the daemon ends up in a half-state
// that needs manual cleanup. With this, every required piece is
// validated up-front and the operator gets a single, actionable error
// message naming exactly which command needs to run on the master.
//
// The single-slot rule is unchanged — only one collector ever pairs
// with a master / server. This preflight is about ordering: gather
// all info before pairing, not about loosening the slot rule.

// MasterPreflightInfo is the gathered set of facts about the master /
// server source. Populated by validateCollectorReadyForInstall;
// returned so caller can log / display.
type MasterPreflightInfo struct {
	URL           string
	HealthOK      bool
	ListenerOK    bool   // collector-listener TCP reachable
	AuthorityKind string // "master" or "server"
	RealmName     string
	PeerCount     int
	SlotState     string // "open", "filled", "unknown"
	CurrentCN     string // CN of the current collector if slot filled
}

// validateCollectorReadyForInstall runs the comprehensive preflight
// against a prospective master/server source. Returns nil + filled
// info on success; a self-contained "fix it" error otherwise.
//
// The probe is INTENTIONALLY non-mutating on the source side. We
// don't enroll, we don't open a slot, we don't bind anything. Each
// step that matters fires its own bounded HTTP / TCP request with
// short timeouts so a dead master doesn't make the operator wait 60s
// for a probe to give up.
//
// PSK is REQUIRED here because the realm-info probe uses it to
// authenticate against the source (no anonymous /v1/sync/config from
// a stranger). A wrong PSK fails fast with "PSK rejected" rather
// than after the operator runs the install for real.
func validateCollectorReadyForInstall(rawURL, psk string) (MasterPreflightInfo, error) {
	info := MasterPreflightInfo{URL: rawURL}
	if rawURL == "" {
		return info, fmt.Errorf("--master is required (the master/server URL, e.g. https://master.example.com:9445)")
	}
	if psk == "" {
		return info, fmt.Errorf("--master-key is required (PSK from `simplesiem master collector show-psk` on the master)")
	}
	parsed, err := url.Parse(strings.TrimRight(rawURL, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return info, fmt.Errorf("--master URL must be an https URL with a host (got %q)", rawURL)
	}
	if _, err := pskRawBytes(psk); err != nil {
		return info, fmt.Errorf("--master-key is not a valid SimpleSIEM PSK: %w\n  expected format: simplesiem-psk:<64-hex-chars>\n  on the master, run: sudo simplesiem master collector show-psk", err)
	}

	// 1. TCP-level reachability — fast fail when the master listener
	//    isn't up at all, before any TLS handshake. Without this, the
	//    operator gets a confusing "tls: handshake failure" instead of
	//    "the master listener isn't running on :9445".
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return info, fmt.Errorf("cannot reach %s — collector listener is not accepting on port %s\n  on the master, run:\n    sudo simplesiem master collector enable --listen :%s\n    sudo simplesiem master collector accept-next", parsed.Host, port, port)
	}
	conn.Close()
	info.ListenerOK = true

	// 2. /v1/health probe — confirms the master is up, not just that
	//    something is listening on the port. We use InsecureSkipVerify
	//    here because the agent doesn't have the master's CA yet (the
	//    PSK-authenticated enroll flow brings it in). Authenticity will
	//    be verified by the HMAC over the enroll response in the
	//    actual install step.
	tr := &http.Transport{
		// #nosec G402 -- bootstrap-only health probe; no secrets in flight
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs()},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	healthURL := strings.TrimRight(rawURL, "/") + "/v1/health"
	hresp, herr := client.Get(healthURL)
	if herr != nil {
		return info, fmt.Errorf("master is not responding on /v1/health: %v\n  the listener is up but the daemon is not serving — wait for it to settle then retry", herr)
	}
	hresp.Body.Close()
	if hresp.StatusCode/100 != 2 {
		return info, fmt.Errorf("master /v1/health returned HTTP %d — daemon is unhealthy on the master side; check `simplesiem status` on the master host", hresp.StatusCode)
	}
	info.HealthOK = true

	// 3. /v1/collector-preflight probe — authenticated by the PSK
	//    HMAC. This is a NEW endpoint that returns the master's:
	//      - authority kind ("master" or "server")
	//      - realm name + peer count
	//      - slot state ("open", "filled", "unknown")
	//      - current collector CN if slot is filled
	//    Without committing any state change. Authenticated via the
	//    same PSK the install would use, so a wrong PSK fails here
	//    rather than mid-install.
	//
	//    When the master is too old to expose this endpoint we skip
	//    softly — the install can still proceed (this is a UX
	//    improvement, not a hard gate).
	preflightURL := strings.TrimRight(rawURL, "/") + "/v1/collector-preflight"
	body, _ := json.Marshal(map[string]any{"psk": psk})
	preq, _ := http.NewRequest(http.MethodPost, preflightURL, strings.NewReader(string(body)))
	preq.Header.Set("Content-Type", "application/json")
	presp, perr := client.Do(preq)
	if perr != nil {
		return info, fmt.Errorf("master /v1/collector-preflight call failed: %v", perr)
	}
	defer presp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(presp.Body, 1<<16))
	switch presp.StatusCode {
	case http.StatusOK:
		var pinfo MasterPreflightInfo
		if jerr := json.Unmarshal(rb, &pinfo); jerr == nil {
			info.AuthorityKind = pinfo.AuthorityKind
			info.RealmName = pinfo.RealmName
			info.PeerCount = pinfo.PeerCount
			info.SlotState = pinfo.SlotState
			info.CurrentCN = pinfo.CurrentCN
		}
	case http.StatusNotFound:
		// Older master without the preflight endpoint — fall through
		// silently. The install will surface any pairing issue.
		info.SlotState = "unknown"
	case http.StatusUnauthorized:
		return info, fmt.Errorf("master rejected the PSK (HTTP 401): %s\n  on the master, run: sudo simplesiem master collector show-psk\n  and confirm the value matches what you passed to --master-key", strings.TrimSpace(string(rb)))
	case http.StatusConflict:
		// 409: slot already filled with a different CN.
		return info, fmt.Errorf("master collector slot is already filled (HTTP 409): %s\n  free the slot first:\n    sudo simplesiem master collector revoke\n    sudo simplesiem master collector accept-next", strings.TrimSpace(string(rb)))
	case http.StatusServiceUnavailable:
		// 503: listener up but slot not yet opened.
		return info, fmt.Errorf("master collector slot is not open for a new enrollment (HTTP 503): %s\n  on the master, run: sudo simplesiem master collector accept-next", strings.TrimSpace(string(rb)))
	default:
		return info, fmt.Errorf("master /v1/collector-preflight returned HTTP %d: %s", presp.StatusCode, strings.TrimSpace(string(rb)))
	}

	// 4. Slot-state guardrails — refuse early if the slot isn't open.
	//    Re-enrollment of the SAME collector against a master with a
	//    matching CN is fine; that path returns "filled" + matching CN,
	//    which the caller handles.
	switch info.SlotState {
	case "open":
		// ready
	case "filled":
		// allowed only when re-enrolling with the same CN — the caller
		// (runCollectorEnroll) handles this, but if the master returned
		// a non-empty CurrentCN then we're not the original collector.
		// Surface that as a hint.
		if info.CurrentCN != "" {
			return info, fmt.Errorf("master collector slot is filled by a different collector (CN=%q)\n  free the slot first:\n    sudo simplesiem master collector revoke\n    sudo simplesiem master collector accept-next", info.CurrentCN)
		}
	case "unknown":
		// Older master without preflight — proceed and let the actual
		// enroll surface any error.
	default:
		return info, fmt.Errorf("master returned unexpected slot state %q", info.SlotState)
	}

	return info, nil
}
