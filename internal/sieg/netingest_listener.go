package sieg

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Network-ingest listener. Binds UDP / TCP / TLS-syslog (RFC 5425)
// listeners on the SimpleSIEM server (or master). Frames are validated
// against the sticky-IP allowlist and emitted as SimpleSIEM events.
//
// Config knobs (cfg.Server.NetworkIngest / cfg.Master.NetworkIngest):
//   enabled            - explicit on-switch (default false)
//   syslog_udp_listen  - e.g. ":514"; empty = disabled
//   syslog_tcp_listen  - e.g. ":514"; empty = disabled
//   syslog_tls_listen  - e.g. ":6514"; empty = disabled
//   tls_cert_mode      - "server"|"operator"|"selfsigned" (default selfsigned)
//   tls_cert / tls_key - filled when mode=operator
//   max_frame_bytes    - hard cap (default 64 KiB)
//   max_frames_per_source_per_second - default 1000
//   bind_explicit      - require operator opt-in for non-loopback
//   rdns_cache_ttl_seconds - default 300

type networkIngestState struct {
	cfg       NetworkIngestConfig
	allowlist *networkAllowlist
	logger    *Storage // _server or _master meta logger
	stamps    func(host string) (*Storage, error)
	rules     func() []*alertRule
	alertSink func(map[string]any) // existing alert pipeline hook
	attack    *attackDetector
	quarStore *Storage // _unauthenticated/syslog dir storage

	udpConn net.PacketConn
	tcpLn   net.Listener
	tlsLn   net.Listener

	rate          map[string]*rateBucket
	rateMu        sync.Mutex
	maxFrameBytes int

	rdnsMu    sync.Mutex
	rdnsCache map[string]rdnsEntry
	rdnsTTL   time.Duration

	dropCounters atomic.Int64
}

type rateBucket struct {
	tokens    int
	lastReset time.Time
	max       int
}

type rdnsEntry struct {
	name string
	at   time.Time
}

// startNetworkIngest spins up listeners per the config. Returns nil
// (no-op) when disabled, refused on agent/standalone/collector modes,
// or when no listen address is set.
func startNetworkIngest(ctx context.Context, wg *sync.WaitGroup, cfg Config, mode string,
	allowlist *networkAllowlist, metaLogger *Storage,
	stamps func(host string) (*Storage, error),
	rules func() []*alertRule, alertSink func(map[string]any)) (*networkIngestState, error) {

	ic := pickNetworkIngestConfig(cfg, mode)
	if !ic.Enabled {
		return nil, nil
	}
	if mode != "server" && mode != "master" {
		// Refused on agent / standalone / collector. Operators who set
		// enabled:true on those modes get a meta event so the misconfig
		// is visible.
		if metaLogger != nil {
			metaLogger.Write("meta", map[string]any{
				"event": "network_ingest_refused",
				"mode":  mode,
				"hint":  "network ingest is server/master-only; remove .network_ingest.enabled",
			})
		}
		return nil, fmt.Errorf("network_ingest is server/master-only (got %s)", mode)
	}
	if !ic.BindExplicit {
		if hasNonLoopbackBind(ic.SyslogUDPListen) ||
			hasNonLoopbackBind(ic.SyslogTCPListen) ||
			hasNonLoopbackBind(ic.SyslogTLSListen) {
			return nil, fmt.Errorf("non-loopback bind requires bind_explicit:true")
		}
	}
	maxF := ic.MaxFrameBytes
	if maxF <= 0 {
		maxF = 64 * 1024
	}
	det := newAttackDetector(attackPatternsPath())
	// Quarantine storage for unauthenticated frames. Lives under
	// <log_dir>/_unauthenticated/ so investigators can grep one
	// place for all suspicious traffic. Best-effort — failure to
	// open the store doesn't kill the listener; frames still go
	// through validation, just without quarantine persistence.
	quar, _ := stamps("_unauthenticated")
	st := &networkIngestState{
		cfg:           ic,
		allowlist:     allowlist,
		logger:        metaLogger,
		stamps:        stamps,
		rules:         rules,
		alertSink:     alertSink,
		attack:        det,
		quarStore:     quar,
		rate:          map[string]*rateBucket{},
		maxFrameBytes: maxF,
		rdnsCache:     map[string]rdnsEntry{},
		rdnsTTL:       time.Duration(rdnsTTLSeconds(ic)) * time.Second,
	}
	// Hot-reload watcher for the attack-pattern sidecar.
	wg.Add(1)
	go func() {
		defer wg.Done()
		newAttackPatternsWatcher(det, attackPatternsPath(), metaLogger).run(ctx)
	}()

	// UDP listener
	if ic.SyslogUDPListen != "" {
		conn, err := net.ListenPacket("udp", ic.SyslogUDPListen)
		if err != nil {
			return nil, fmt.Errorf("network ingest udp bind %q: %w", ic.SyslogUDPListen, err)
		}
		st.udpConn = conn
		wg.Add(1)
		go func() { defer wg.Done(); st.serveUDP(ctx) }()
	}
	// TCP cleartext listener
	if ic.SyslogTCPListen != "" {
		ln, err := net.Listen("tcp", ic.SyslogTCPListen)
		if err != nil {
			return nil, fmt.Errorf("network ingest tcp bind %q: %w", ic.SyslogTCPListen, err)
		}
		st.tcpLn = ln
		wg.Add(1)
		go func() { defer wg.Done(); st.serveTCP(ctx, ln, false) }()
	}
	// TLS listener
	if ic.SyslogTLSListen != "" {
		tlsCfg, info, err := buildNetworkIngestTLS(cfg, ic)
		if err != nil {
			return nil, fmt.Errorf("network ingest tls config: %w", err)
		}
		if info != "" && metaLogger != nil {
			metaLogger.Write("meta", map[string]any{
				"event":  "network_ingest_tls_cert",
				"detail": info,
			})
		}
		ln, err := tls.Listen("tcp", ic.SyslogTLSListen, tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("network ingest tls bind %q: %w", ic.SyslogTLSListen, err)
		}
		st.tlsLn = ln
		wg.Add(1)
		go func() { defer wg.Done(); st.serveTCP(ctx, ln, true) }()
	}
	if metaLogger != nil {
		metaLogger.Write("meta", map[string]any{
			"event":          "network_ingest_started",
			"udp_listen":     ic.SyslogUDPListen,
			"tcp_listen":     ic.SyslogTCPListen,
			"tls_listen":     ic.SyslogTLSListen,
			"max_frame_bytes": maxF,
		})
	}
	return st, nil
}

func rdnsTTLSeconds(ic NetworkIngestConfig) int {
	if ic.RDNSCacheTTLSeconds <= 0 {
		return 300
	}
	return ic.RDNSCacheTTLSeconds
}

// clonePayloadForAlert returns a shallow copy of the network-ingest
// attack payload safe to embed in an alert that will be written to a
// different Storage. Without this, the alert-storage writer races the
// meta-storage writer that's mutating the original (adding _seq, _prev,
// _hash) and verify reports the alert's chain hash mismatch. Shallow
// is enough — the payload's values are scalars or already-frozen
// slices/maps from the attackPattern struct.
func clonePayloadForAlert(p map[string]any) map[string]any {
	out := make(map[string]any, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}


func hasNonLoopbackBind(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// ":514" form - host is empty
		return true
	}
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	return !ip.IsLoopback()
}

// serveUDP loops reading frames + dispatching them. UDP frames have
// no connection state, so each datagram = one frame.
func (st *networkIngestState) serveUDP(ctx context.Context) {
	buf := make([]byte, st.maxFrameBytes+1)
	go func() {
		<-ctx.Done()
		_ = st.udpConn.Close()
	}()
	for {
		_ = st.udpConn.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := st.udpConn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		// Note: oversize is no longer dropped at the boundary — we let
		// handleFrame truncate + flag instead. The buffer is sized
		// maxFrameBytes+1 so we can distinguish "exactly the cap" from
		// "exceeded the cap" — the +1th byte is read iff the datagram
		// was larger than the cap.
		raw := string(buf[:n])
		host, _ := splitHost(src.String())
		// handleFrame's own len(raw) > maxFrameBytes check sets the
		// truncated flag and trims. No double-marking here.
		st.handleFrame(raw, host, false, "syslog_udp")
	}
}

// serveTCP handles cleartext TCP and TLS connections. Each connection
// streams newline-delimited frames.
func (st *networkIngestState) serveTCP(ctx context.Context, ln net.Listener, useTLS bool) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go st.handleTCPConn(ctx, conn, useTLS)
	}
}

func (st *networkIngestState) handleTCPConn(ctx context.Context, conn net.Conn, useTLS bool) {
	defer conn.Close()
	host, _ := splitHost(conn.RemoteAddr().String())
	r := bufio.NewReaderSize(conn, st.maxFrameBytes+1)
	deadline := 60 * time.Second
	transport := "syslog_tcp"
	if useTLS {
		transport = "syslog_tls"
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(deadline))
		line, err := r.ReadString('\n')
		// ReadString returns the data read so far even on error
		// (ErrBufferFull, EOF). Process whatever was buffered before
		// returning — otherwise a frame that fills the buffer without
		// a trailing newline would be silently dropped instead of
		// stored truncated.
		if line != "" {
			st.handleFrame(strings.TrimRight(line, "\r\n"), host, useTLS, transport)
		}
		if err != nil {
			return
		}
	}
}

// handleFrame validates, parses, and emits one frame. All security
// checks happen before parser invocation. Frames that fail allowlist
// validation are NOT dropped — they're persisted in
// <log_dir>/_unauthenticated/syslog/<date>.jsonl with an
// `authenticated: false` flag, so investigators have full context.
// Attack-pattern detection runs FIRST (before allowlist) so that
// rogue-source attacks still alert.
//
// Wrapped in a recover so a panic on hostile input (e.g., a buggy
// regex with catastrophic backtracking) doesn't bring down the
// daemon — the frame is logged as a panic event and processing
// continues for the next frame.
func (st *networkIngestState) handleFrame(raw, sourceIP string, viaTLS bool, transport string) {
	defer func() {
		if r := recover(); r != nil {
			if st.logger != nil {
				st.logger.Write("errors", map[string]any{
					"collector": "network_ingest",
					"error":     fmt.Sprintf("frame validation panic: %v", r),
					"source_ip": sourceIP,
					"transport": transport,
				})
			}
		}
	}()
	st.handleFrameInner(raw, sourceIP, viaTLS, transport)
}

// handleFrameInner is the actual frame validation body — extracted so
// the public handleFrame can wrap it in a recover.
func (st *networkIngestState) handleFrameInner(raw, sourceIP string, viaTLS bool, transport string) {
	if raw == "" {
		return
	}
	// Rate-limit is the listener's only DoS gate. Drop unconditionally —
	// storing every frame would defeat the rate limit's purpose.
	if !st.allowSource(sourceIP) {
		st.recordDrop("rate_limited", sourceIP)
		return
	}
	// Oversize: store the first max_frame_bytes with a truncated:true
	// flag (extreme size IS itself an attack indicator and the partial
	// payload helps investigations).
	truncated := false
	if len(raw) > st.maxFrameBytes {
		raw = raw[:st.maxFrameBytes]
		truncated = true
	}
	mac, _ := arpResolve(sourceIP)
	mac = normaliseMAC(mac)
	// Attack detection runs on EVERY frame, before allowlist validation.
	// Hits emit a high-severity meta event + alert and tag the frame
	// with attack_indicators.
	hits := st.attack.ScanAll(raw)
	entry, exact, ipOnly := st.allowlist.Lookup(sourceIP, mac)
	authenticated := false
	unauthReason := ""
	switch {
	case exact && (entry.Stale || entry.PendingRevalidation):
		unauthReason = "entry_stale"
	case exact && entry.TLSRequired && !viaTLS:
		unauthReason = "cleartext_refused"
	case exact:
		authenticated = true
	case ipOnly && entry != nil && entry.TLSRequired && !viaTLS:
		// IP matches a TLS-required vendor entry but MAC doesn't —
		// double-fail: a cleartext frame from an untrusted MAC
		// claiming a TLS-required vendor's IP is the worst combo.
		// Surface the stricter reason so operators see the TLS
		// violation rather than just "MAC mismatch".
		unauthReason = "cleartext_refused"
	case ipOnly:
		unauthReason = "mac_mismatch"
	default:
		unauthReason = "unknown_source_ip"
	}
	frame := parseSyslog(raw)
	fields := frame.toEventFields()
	fields["source_ip"] = sourceIP
	fields["source_mac"] = mac
	fields["transport"] = transport
	fields["authenticated"] = authenticated
	if !authenticated {
		fields["unauth_reason"] = unauthReason
	}
	if truncated {
		fields["truncated"] = true
	}
	if len(hits) > 0 {
		ind := make([]map[string]any, 0, len(hits))
		for _, p := range hits {
			ind = append(ind, map[string]any{
				"name":        p.Name,
				"tactic":      p.Tactic,
				"technique":   p.Technique,
				"description": p.Description,
			})
		}
		fields["attack_indicators"] = ind
		// First match drives the primary tactic/technique tag so the
		// alert lands in the right MITRE coverage bucket.
		fields["tactic"] = hits[0].Tactic
		fields["technique"] = hits[0].Technique
	}
	host := ""
	if authenticated {
		host = entry.Label
		if host == "" {
			host = st.lookupRDNS(sourceIP)
		}
		if host == "" {
			host = sourceIP
		}
		host = sanitiseHost(host)
		fields["host"] = host
		if entry.Vendor != "" {
			fields["vendor"] = entry.Vendor
		}
		storage, err := st.stamps(host)
		if err != nil {
			st.recordDrop("storage_open_failed", sourceIP)
			return
		}
		storage.Write("syslog", fields)
	} else {
		// Quarantine the frame in _unauthenticated/syslog/. Label is
		// the source IP itself so investigators can grep + sort by IP.
		host = sanitiseHost(sourceIP)
		fields["host"] = "_unauthenticated"
		fields["device_ip"] = sourceIP
		if st.quarStore != nil {
			st.quarStore.Write("syslog", fields)
		}
	}
	st.emitValidationStatus(unauthReason, sourceIP, mac, entry, hits, authenticated, viaTLS, raw)
	if authenticated {
		// Rules engine fires only on AUTHENTICATED frames so a rogue
		// attacker can't fabricate fake alerts by spamming the listener
		// with rule-matching content.
		st.evaluateRules(host, fields)
	}
}

// emitValidationStatus surfaces the (un)authenticated decision + any
// attack hits via meta events and the alert pipeline. The raw frame
// is passed in so the indicator excerpt + the alert payload carry
// enough context for forensic search.
func (st *networkIngestState) emitValidationStatus(
	unauthReason, ip, mac string, entry *networkSource,
	hits []attackPattern, authenticated, viaTLS bool, raw string,
) {
	// Attack alert always fires at high severity.
	if len(hits) > 0 {
		first := hits[0]
		payload := map[string]any{
			"event":         "network_ingest_attack_detected",
			"reason":        first.Name,
			"tactic":        first.Tactic,
			"technique":     first.Technique,
			"description":   first.Description,
			"severity":      "high",
			"source_ip":     ip,
			"source_mac":    mac,
			"authenticated": authenticated,
			"unauth_reason": unauthReason,
			"indicator":     indicatorString(&first, raw),
			"frame_excerpt": frameExcerpt(raw),
			"all_hits":      attackHitsCompact(hits),
		}
		if entry != nil {
			payload["allowlisted_mac"] = entry.MAC
			payload["vendor"] = entry.Vendor
			payload["label"] = entry.Label
		}
		if st.logger != nil {
			st.logger.Write("meta", payload)
		}
		// Snapshot payload BEFORE the meta writer's queue picks it up —
		// once enqueued, the meta-storage writer goroutine will mutate
		// payload (add _seq/_prev/_hash). Embedding the live map in the
		// alert map causes a write race: the alert-storage writer
		// marshals alert (with payload as a nested ref) concurrently
		// with the meta writer mutating payload, producing a hash
		// computed over a transient state but a stored line with the
		// final state — verify then reports a chain mismatch.
		payloadSnap := clonePayloadForAlert(payload)
		alert := map[string]any{
			"event":         "rule_match",
			"rule":          "network_ingest_attack_detected",
			"severity":      "high",
			"host":          ip,
			"matched_event": payloadSnap,
			"original":      payloadSnap,
			"tactic":        first.Tactic,
			"technique":     first.Technique,
		}
		// Write the alert to the per-host alerts log so `simplesiem
		// alerts` and other read-side tooling see it. Authenticated
		// frames go under <entry.label>/alerts/; unauthenticated
		// frames go under _unauthenticated/alerts/.
		alertHost := "_unauthenticated"
		if entry != nil && authenticated && entry.Label != "" {
			alertHost = sanitiseHost(entry.Label)
		}
		if alertStorage, err := st.stamps(alertHost); err == nil && alertStorage != nil {
			alertStorage.Write("alerts", alert)
		}
		if st.alertSink != nil {
			st.alertSink(alert)
		}
	}
	// Allowlist failures still get a meta event for operator visibility.
	if !authenticated {
		severity := "low"
		switch unauthReason {
		case "mac_mismatch":
			severity = "high"
		case "cleartext_refused":
			severity = "high"
		case "entry_stale":
			severity = "medium"
		}
		payload := map[string]any{
			"event":         "network_ingest_unauthenticated",
			"reason":        unauthReason,
			"source_ip":     ip,
			"source_mac":    mac,
			"severity":      severity,
			"transport":     transportName(viaTLS),
			"frame_stored":  true,
			"location":      "<log_dir>/_unauthenticated/syslog/",
		}
		if entry != nil {
			payload["allowlisted_mac"] = entry.MAC
			payload["vendor"] = entry.Vendor
			payload["label"] = entry.Label
		}
		if st.logger != nil {
			st.logger.Write("meta", payload)
		}
		// High-severity unauth reasons go through the alert pipeline so
		// webhooks / syslog-forwarders / incidents see them too.
		if st.alertSink != nil && (severity == "high" || severity == "critical") {
			// Same race-avoidance contract as the attack-detected path
			// above: snapshot payload before embedding it in the alert,
			// because the meta-storage writer goroutine will mutate the
			// original (adding _seq/_prev/_hash) concurrently with any
			// alert sink that marshals alert.
			payloadSnap := clonePayloadForAlert(payload)
			alert := map[string]any{
				"event":         "rule_match",
				"rule":          "network_ingest_unauthenticated",
				"severity":      severity,
				"host":          ip,
				"matched_event": payloadSnap,
				"original":      payloadSnap,
			}
			st.alertSink(alert)
		}
	}
}

func attackHitsCompact(hits []attackPattern) []map[string]any {
	out := make([]map[string]any, 0, len(hits))
	for _, p := range hits {
		out = append(out, map[string]any{
			"name":      p.Name,
			"tactic":    p.Tactic,
			"technique": p.Technique,
		})
	}
	return out
}

func transportName(viaTLS bool) string {
	if viaTLS {
		return "syslog_tls"
	}
	return "syslog_udp_or_tcp"
}

func (st *networkIngestState) evaluateRules(host string, fields map[string]any) {
	rules := st.rules()
	if len(rules) == 0 {
		return
	}
	for _, r := range rules {
		if !matchRule(r, "syslog", fields) {
			continue
		}
		if st.alertSink == nil {
			continue
		}
		// fields was just enqueued to a per-label storage (line 492 /
		// 500); its writer goroutine will mutate the map (adding
		// _seq/_prev/_hash). Snapshot before embedding so an alert
		// sink that marshals alert doesn't race that mutation.
		fieldsSnap := clonePayloadForAlert(fields)
		alert := map[string]any{
			"event":         "rule_match",
			"rule":          r.Name,
			"severity":      r.Severity,
			"host":          host,
			"matched_event": fieldsSnap,
			"original":      fieldsSnap,
		}
		st.alertSink(alert)
	}
}

func (st *networkIngestState) recordDrop(reason, ip string) {
	st.dropCounters.Add(1)
	if st.logger != nil && reason == "rate_limited" {
		st.logger.Write("meta", map[string]any{
			"event":     "network_ingest_rate_limited",
			"reason":    reason,
			"source_ip": ip,
		})
	} else if st.logger != nil && reason == "oversize" {
		st.logger.Write("meta", map[string]any{
			"event":     "network_ingest_oversize",
			"source_ip": ip,
		})
	}
}

func (st *networkIngestState) allowSource(ip string) bool {
	if ip == "" {
		return true
	}
	limit := st.cfg.MaxFramesPerSourcePerSecond
	if limit <= 0 {
		limit = 1000
	}
	now := time.Now()
	st.rateMu.Lock()
	defer st.rateMu.Unlock()
	b, ok := st.rate[ip]
	if !ok {
		b = &rateBucket{tokens: limit, lastReset: now, max: limit}
		st.rate[ip] = b
	}
	if now.Sub(b.lastReset) >= time.Second {
		b.tokens = b.max
		b.lastReset = now
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

func (st *networkIngestState) lookupRDNS(ip string) string {
	st.rdnsMu.Lock()
	if e, ok := st.rdnsCache[ip]; ok && time.Since(e.at) < st.rdnsTTL {
		st.rdnsMu.Unlock()
		return e.name
	}
	st.rdnsMu.Unlock()
	names, err := net.LookupAddr(ip)
	name := ""
	if err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	st.rdnsMu.Lock()
	st.rdnsCache[ip] = rdnsEntry{name: name, at: time.Now()}
	st.rdnsMu.Unlock()
	return name
}

// sanitiseHost turns an arbitrary string into a value safe to use as a
// path component. Same approach as the existing X-SimpleSIEM-Host
// validation: refuse path-traversal characters and drop separators.
func sanitiseHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return "unknown"
	}
	// reject path-traversal-ish content
	if strings.Contains(h, "..") || strings.ContainsAny(h, `/\`) {
		return "unknown"
	}
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			return r
		}
		return -1
	}, h)
	if out == "" {
		return "unknown"
	}
	return out
}

func splitHost(addr string) (string, string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, ""
	}
	return host, port
}

// ----------------------------------------------------------------------
// TLS posture for the syslog listener.
// ----------------------------------------------------------------------

// buildNetworkIngestTLS implements the three modes:
//   "server"     - reuse the existing server.cert / server.key
//   "operator"   - read tls_cert / tls_key from config
//   "selfsigned" - auto-generate at <state>/network_ingest/cert.pem,
//                  print SHA-256 fingerprint via meta event
//
// Returns the *tls.Config plus a free-form description string that
// goes into the meta event (e.g. the fingerprint for selfsigned).
func buildNetworkIngestTLS(cfg Config, ic NetworkIngestConfig) (*tls.Config, string, error) {
	mode := strings.ToLower(strings.TrimSpace(ic.TLSCertMode))
	if mode == "" {
		mode = "selfsigned"
	}
	switch mode {
	case "server":
		cert, err := tls.LoadX509KeyPair(cfg.Server.Cert, cfg.Server.Key)
		if err != nil {
			return nil, "", fmt.Errorf("server cert load: %w", err)
		}
		fp := certFingerprint(cert)
		return &tls.Config{
			MinVersion:       tls.VersionTLS13,
			Certificates:     []tls.Certificate{cert},
			CurvePreferences: pqHybridCurvePrefs(),
		}, "mode=server fingerprint=" + fp, nil
	case "operator":
		if ic.TLSCert == "" || ic.TLSKey == "" {
			return nil, "", fmt.Errorf("mode=operator requires tls_cert + tls_key")
		}
		cert, err := tls.LoadX509KeyPair(ic.TLSCert, ic.TLSKey)
		if err != nil {
			return nil, "", err
		}
		fp := certFingerprint(cert)
		return &tls.Config{
			MinVersion:       tls.VersionTLS13,
			Certificates:     []tls.Certificate{cert},
			CurvePreferences: pqHybridCurvePrefs(),
		}, "mode=operator fingerprint=" + fp, nil
	case "selfsigned":
		cert, fp, err := loadOrCreateSelfSignedNetworkIngestCert(cfg)
		if err != nil {
			return nil, "", err
		}
		return &tls.Config{
			MinVersion:       tls.VersionTLS13,
			Certificates:     []tls.Certificate{cert},
			CurvePreferences: pqHybridCurvePrefs(),
		}, "mode=selfsigned fingerprint=" + fp, nil
	}
	return nil, "", fmt.Errorf("unknown tls_cert_mode %q", mode)
}

func certFingerprint(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.Certificate[0])
	hex := make([]byte, 0, len(sum)*3)
	const hexd = "0123456789abcdef"
	for i, b := range sum {
		if i > 0 {
			hex = append(hex, ':')
		}
		hex = append(hex, hexd[b>>4], hexd[b&0xf])
	}
	return string(hex)
}

func loadOrCreateSelfSignedNetworkIngestCert(cfg Config) (tls.Certificate, string, error) {
	dir := filepath.Join(cfg.StateDir, "network_ingest")
	_ = os.MkdirAll(dir, 0o700)
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, certFingerprint(c), nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "simplesiem-network-ingest"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         false,
	}
	for _, ip := range localIPv4s() {
		tpl.IPAddresses = append(tpl.IPAddresses, net.ParseIP(ip))
	}
	tpl.IPAddresses = append(tpl.IPAddresses, net.ParseIP("127.0.0.1"))
	hostname, _ := os.Hostname()
	if hostname != "" {
		tpl.DNSNames = []string{hostname}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, "", err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return c, certFingerprint(c), nil
}
