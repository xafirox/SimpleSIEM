package sieg

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Realm join is the PSK-authenticated handshake that brings a new
// server into an existing realm without anyone copying CA private
// keys. Each server keeps its own CA; the join exchanges the *public*
// CA cert + the realm's existing peer list, populates each peer's
// trust bundle, and atomically updates `server.realm.peers` on both
// ends. From that point on, agents enrolled with one peer fail over
// to any other peer transparently — every peer trusts every peer's
// CA, so client certs validate end-to-end without re-enrollment.
//
// The threat model is the same as agent enrollment: a PSK is the
// shared secret. Anyone with a server's PSK can either enroll an
// agent OR have a server signed-by-them join the realm. The PSK
// rotates with `simplesiem certs psk rotate --force` and operators
// who want strict role separation can use one PSK for agent
// onboarding and rotate after the realm is settled.

// RealmJoinRequest is the joining server's body to /v1/realm/join.
type RealmJoinRequest struct {
	PSK         string `json:"psk"`
	JoinerURL   string `json:"joiner_url"`    // https://<host>:<port>
	JoinerID    string `json:"joiner_id"`     // peerIDFromURL(JoinerURL); validated server-side
	JoinerCAPem string `json:"joiner_ca_pem"` // joining server's own CA cert (public)
}

// RealmPeerCA is one entry in the join response's trust set.
type RealmPeerCA struct {
	URL   string `json:"url"`
	ID    string `json:"id"`
	CAPem string `json:"ca_pem"`
}

// RealmJoinResponse carries the realm name, the existing peer list
// (the joiner unions its own URL with these), and the public CA of
// every existing peer. The joiner writes each CA into its trust
// bundle so it accepts certs from any peer it might fail over to.
//
// Hmac is computed over a canonical JSON of the response (excluding
// Hmac itself), keyed by the PSK raw bytes — same construction as
// agent enrollment's HMAC, so a MITM that doesn't know the PSK can't
// substitute peer URLs or CAs.
type RealmJoinResponse struct {
	RealmName string        `json:"realm_name"`
	Peers     []string      `json:"peers"`
	PeerCAs   []RealmPeerCA `json:"peer_cas"`
	Hmac      string        `json:"hmac"`
}

// handleRealmJoin processes /v1/realm/join. PSK-authenticated. On
// success: writes the joiner's CA into the local trust bundle, adds
// the joiner's URL to server.realm.peers in config, rebuilds the
// in-memory bundle so subsequent connections trust the joiner, and
// returns the realm's current peer list + their CAs so the joiner
// can populate its own trust bundle in one round-trip.
func (s *serverState) handleRealmJoin(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := remoteIP(r)
	if !s.enrollLimiter.allow(ip) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req RealmJoinRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Auth: same PSK that drives /v1/enroll and /v1/enroll-master.
	currentPSK, perr := readEnrollPSK()
	if perr != nil || currentPSK == "" {
		currentPSK = s.enrollPSK
	}
	gotRaw, gerr := pskRawBytes(req.PSK)
	wantRaw, werr := pskRawBytes(currentPSK)
	if gerr != nil || werr != nil || subtle.ConstantTimeCompare(gotRaw, wantRaw) != 1 {
		s.logAuthFailure(r, "realm/join")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Validate joiner_url + joiner_id.
	parsed, perr := url.Parse(req.JoinerURL)
	if perr != nil || parsed.Scheme != "https" || parsed.Host == "" {
		http.Error(w, "joiner_url must be an https URL with a host", http.StatusBadRequest)
		return
	}
	expectedID := peerIDFromURL(req.JoinerURL)
	if expectedID == "" {
		http.Error(w, "could not derive peer id from joiner_url", http.StatusBadRequest)
		return
	}
	if req.JoinerID != "" && req.JoinerID != expectedID {
		http.Error(w, "joiner_id does not match peerIDFromURL(joiner_url)", http.StatusBadRequest)
		return
	}
	joinerID := expectedID
	if !validHostName.MatchString(joinerID) {
		http.Error(w, "joiner_id contains characters not safe for a filename", http.StatusBadRequest)
		return
	}
	if joinerID == s.selfPeerID {
		http.Error(w, "cannot join a realm with yourself", http.StatusBadRequest)
		return
	}

	// Validate joiner CA: parseable, IsCA, well-formed PEM.
	caBlock, _ := pem.Decode([]byte(req.JoinerCAPem))
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		http.Error(w, "joiner_ca_pem is not a CERTIFICATE PEM block", http.StatusBadRequest)
		return
	}
	joinerCert, perr := x509.ParseCertificate(caBlock.Bytes)
	if perr != nil {
		http.Error(w, "joiner_ca_pem parse: "+perr.Error(), http.StatusBadRequest)
		return
	}
	if !joinerCert.IsCA {
		http.Error(w, "joiner_ca_pem is not a CA certificate (BasicConstraints CA=false)", http.StatusBadRequest)
		return
	}

	// Persist the joiner's CA into our trust bundle so we accept
	// agents enrolled with the joiner on subsequent connections.
	if _, err := writePeerCA(joinerID, req.JoinerCAPem); err != nil {
		s.broadcastErr("realm/join", fmt.Errorf("write joiner CA: %v", err))
		http.Error(w, "could not persist joiner CA", http.StatusInternalServerError)
		return
	}
	if err := s.trust.rebuild(); err != nil {
		s.broadcastErr("realm/join", fmt.Errorf("rebuild trust bundle: %v", err))
		// Don't fail the request — the CA file is on disk; next request
		// will pick it up via the per-handshake GetConfigForClient.
	}

	// Atomically add joiner_url to server.realm.peers and bump
	// config_version so the change propagates via /v1/sync/config.
	added, ver, err := addRealmPeerToConfig(s.configPath, req.JoinerURL)
	if err != nil {
		s.broadcastErr("realm/join", fmt.Errorf("update realm.peers: %v", err))
		http.Error(w, "could not persist realm.peers", http.StatusInternalServerError)
		return
	}
	if added {
		s.realmMu.Lock()
		if !contains(s.realmPeers, req.JoinerURL) {
			s.realmPeers = append(s.realmPeers, req.JoinerURL)
		}
		s.realmConfigVer = ver
		s.realmMu.Unlock()
	}

	// Build the response: own CA + every peer CA on disk + the realm
	// name + the existing peer list (without the joiner — they know
	// their own URL).
	ownCAPem, err := os.ReadFile(filepath.Join(s.certsDir, "ca.pem"))
	if err != nil {
		s.broadcastErr("realm/join", fmt.Errorf("read own CA: %v", err))
		http.Error(w, "server missing own CA", http.StatusServiceUnavailable)
		return
	}

	s.realmMu.RLock()
	realm := s.realmName
	peers := append([]string{}, s.realmPeers...)
	s.realmMu.RUnlock()

	// Strip the joiner's URL from the returned peers so the joiner
	// doesn't add itself to its own peers list.
	filtered := make([]string, 0, len(peers))
	for _, p := range peers {
		if p == req.JoinerURL {
			continue
		}
		filtered = append(filtered, p)
	}

	// Collect peer CAs: ours + any other peer CAs we have on disk.
	peerCAs := []RealmPeerCA{
		{URL: selfPeerURL(s.selfPeerID, s.http.Addr), ID: s.selfPeerID, CAPem: string(ownCAPem)},
	}
	if entries, derr := os.ReadDir(realmPeerCAsDir()); derr == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
				continue
			}
			id := strings.TrimSuffix(e.Name(), ".pem")
			if id == joinerID || id == s.selfPeerID {
				continue
			}
			data, rerr := os.ReadFile(filepath.Join(realmPeerCAsDir(), e.Name()))
			if rerr != nil {
				continue
			}
			// Find this peer's URL by matching against realm.peers.
			peerURL := ""
			for _, p := range filtered {
				if peerIDFromURL(p) == id {
					peerURL = p
					break
				}
			}
			peerCAs = append(peerCAs, RealmPeerCA{URL: peerURL, ID: id, CAPem: string(data)})
		}
	}
	sort.Slice(peerCAs, func(i, j int) bool { return peerCAs[i].ID < peerCAs[j].ID })

	resp := RealmJoinResponse{
		RealmName: realm,
		Peers:     filtered,
		PeerCAs:   peerCAs,
	}
	resp.Hmac = computeRealmJoinHMAC(wantRaw, resp.RealmName, resp.Peers, resp.PeerCAs)

	if mst, gerr := s.storageFor("_server"); gerr == nil {
		mst.Write("meta", map[string]any{
			"event":     "realm_join_accepted",
			"joiner_id": joinerID,
			"joiner_url": req.JoinerURL,
			"newly_added": added,
			"remote": r.RemoteAddr,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	_, _ = w.Write(out)
}

// addRealmPeerToConfig atomically appends url to server.realm.peers
// (idempotent) and bumps server.realm.config_version. Returns
// (newlyAdded, newVersion, err). Serialised through the same global
// mutex other config edits use so concurrent edits don't race.
func addRealmPeerToConfig(cfgPath, peerURL string) (bool, int64, error) {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	for _, x := range cfg.Server.Realm.Peers {
		if x == peerURL {
			return false, cfg.Server.Realm.ConfigVersion, nil
		}
	}
	cfg.Server.Realm.Peers = append(cfg.Server.Realm.Peers, peerURL)
	ver := time.Now().UnixNano()
	cfg.Server.Realm.ConfigVersion = ver
	if err := saveConfig(cfgPath, cfg); err != nil {
		return false, 0, err
	}
	return true, ver, nil
}

// addRealmPeersToConfig is the bulk variant the joiner uses to merge
// the responder's peer list into its own config. Same atomicity
// guarantees as addRealmPeerToConfig.
func addRealmPeersToConfig(cfgPath string, peerURLs []string, realmName string) (int, int64, error) {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	have := map[string]bool{}
	for _, p := range cfg.Server.Realm.Peers {
		have[p] = true
	}
	added := 0
	for _, p := range peerURLs {
		if p == "" || have[p] {
			continue
		}
		cfg.Server.Realm.Peers = append(cfg.Server.Realm.Peers, p)
		have[p] = true
		added++
	}
	if realmName != "" {
		cfg.Server.Realm.Name = realmName
	}
	ver := time.Now().UnixNano()
	cfg.Server.Realm.ConfigVersion = ver
	if err := saveConfig(cfgPath, cfg); err != nil {
		return 0, 0, err
	}
	return added, ver, nil
}

// computeRealmJoinHMAC returns hex(HMAC-SHA384(pskRaw, canonical(json))).
// The canonical form sorts peers and peer_cas by ID so re-ordering by
// a MITM doesn't produce a valid HMAC. Upgraded to SHA-384 for parity
// with the P-384 cert family.
func computeRealmJoinHMAC(pskRaw []byte, realm string, peers []string, peerCAs []RealmPeerCA) string {
	pCopy := append([]string{}, peers...)
	sort.Strings(pCopy)
	cCopy := append([]RealmPeerCA{}, peerCAs...)
	sort.Slice(cCopy, func(i, j int) bool { return cCopy[i].ID < cCopy[j].ID })
	payload := struct {
		Realm   string        `json:"realm"`
		Peers   []string      `json:"peers"`
		PeerCAs []RealmPeerCA `json:"peer_cas"`
	}{realm, pCopy, cCopy}
	buf, _ := json.Marshal(payload)
	mac := hmac.New(sha512.New384, pskRaw)
	mac.Write(buf)
	return hex.EncodeToString(mac.Sum(nil))
}

// selfPeerURL composes a URL the join responder reports as its own.
// Prefers https://<self>:<port> derived from selfPeerID + listen,
// falls back to https://<self>:9443 if listen has no port.
func selfPeerURL(self string, listen string) string {
	port := "9443"
	if i := strings.LastIndex(listen, ":"); i >= 0 && i+1 < len(listen) {
		if p := listen[i+1:]; p != "" {
			port = p
		}
	}
	return "https://" + self + ":" + port
}

// runRealmCmd dispatches `simplesiem realm <subcommand>`. Matches the
// shape of `simplesiem master <subcommand>`.
func runRealmCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem realm <join|rename> [args]

  join <peer-url> --key <PSK>   Join an existing realm via a PSK-driven
                                handshake. Sends this server's own CA to
                                <peer-url>, receives the realm's peer list
                                and their CAs, and writes everything to disk
                                so the daemon trusts every peer on its next
                                start (or immediately if already running).
                                The PSK comes from the target peer's
                                `+"`simplesiem certs psk show`"+`.

  rename <new-name> [-y]        Rename this server's realm. Refused on
                                agent / collector / standalone mode. Refused
                                on a server when a master is present (use
                                `+"`simplesiem master realm rename`"+` instead).
                                Propagates to peers via /v1/sync/config
                                last-write-wins on config_version.

If --key is omitted, you'll be prompted for it interactively.
If <peer-url> is omitted, you'll be prompted for it too.`)
		os.Exit(2)
	}
	switch args[0] {
	case "join":
		runRealmJoin(args[1:])
	case "rename":
		runRealmRename(args[1:])
	case "migrate":
		runRealmMigrate(args[1:])
	default:
		fatalf("unknown realm subcommand: %s", args[0])
	}
}

// runRealmJoin is the operator-side of the join handshake. Loads
// this server's own CA, calls the target peer's /v1/realm/join,
// validates the response HMAC, persists every returned peer CA into
// <state>/realm/peer_cas/, merges the peer list + realm name into
// our config.json, and prints a restart hint.
func runRealmJoin(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "key": true, "yes": true})
	fs := flag.NewFlagSet("realm join", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	psk := fs.String("key", "", "enrollment PSK from the target peer")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	_ = fs.Parse(args)

	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}

	peerURL := strings.TrimRight(fs.Arg(0), "/")
	if peerURL == "" {
		peerURL = strings.TrimRight(strings.TrimSpace(promptInput("Enter the URL of an existing realm peer (e.g. https://siem-a.example.com:9443): ")), "/")
	}
	if peerURL == "" {
		fatalf("peer URL is required")
	}
	parsed, perr := url.Parse(peerURL)
	if perr != nil || parsed.Scheme != "https" || parsed.Host == "" {
		fatalf("peer URL must be an https URL with a host (got %q)", peerURL)
	}

	if *psk == "" {
		*psk = strings.TrimSpace(promptInput("Enter the enrollment PSK from " + peerURL + " (`simplesiem certs psk show` on that host): "))
	}
	if *psk == "" {
		fatalf("--key (enrollment PSK) is required")
	}

	cfg := loadConfig(*cfgPath)
	if cfg.Server.CACert == "" {
		fatalf("server.ca_cert is empty in %s — run `simplesiem certs init` on this host first", *cfgPath)
	}
	ownCAPem, err := os.ReadFile(cfg.Server.CACert)
	if err != nil {
		fatalf("read own CA at %s: %v\n  hint: run `simplesiem certs init` on this host before joining a realm", cfg.Server.CACert, err)
	}
	selfID := deriveSelfPeerID(cfg.Server.Listen)
	selfURL := selfPeerURL(selfID, cfg.Server.Listen)

	if !*yes {
		fmt.Printf("This will join %s as a peer of %s.\n", selfURL, peerURL)
		fmt.Printf("Realm name will be inherited from the target peer.\n")
		if !confirmYes() {
			fmt.Println("aborted.")
			os.Exit(1)
		}
	}

	body, _ := json.Marshal(RealmJoinRequest{
		PSK:         *psk,
		JoinerURL:   selfURL,
		JoinerID:    selfID,
		JoinerCAPem: string(ownCAPem),
	})
	// Bootstrap TLS with InsecureSkipVerify since we don't yet have
	// the target's CA. The HMAC over the response (keyed by the PSK)
	// is what defeats MITM here — same construction agent enrollment uses.
	// #nosec G402 -- bootstrap-only; HMAC-over-PSK authenticates the response.
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs()}, TLSHandshakeTimeout: 10 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPost, peerURL+"/v1/realm/join", bytes.NewReader(body))
	if err != nil {
		fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fatalf("contact peer: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		fatalf("peer rejected join (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var jr RealmJoinResponse
	if err := json.Unmarshal(rb, &jr); err != nil {
		fatalf("parse peer response: %v", err)
	}
	if jr.RealmName == "" || len(jr.PeerCAs) == 0 || jr.Hmac == "" {
		fatalf("peer response missing required fields (realm_name, peer_cas, hmac)")
	}

	// Verify HMAC.
	pskRaw, perr := pskRawBytes(*psk)
	if perr != nil {
		fatalf("--key: %v", perr)
	}
	expected := computeRealmJoinHMAC(pskRaw, jr.RealmName, jr.Peers, jr.PeerCAs)
	if subtle.ConstantTimeCompare([]byte(jr.Hmac), []byte(expected)) != 1 {
		fatalf("response HMAC mismatch — possible MITM, or PSK on peer differs from --key value")
	}

	// Name-collision guardrail. The realm name is a label, not an
	// identity — two unrelated single-server installs both running with
	// the default name "default" would silently merge into one realm
	// here. We can't detect "same realm" cryptographically (CAs are
	// per-server), but we CAN detect the case where:
	//   (a) the local realm name == the peer's realm name, AND
	//   (b) the peer URL is NOT already in our local peer list.
	// That combination is overwhelmingly the accidental-merge shape.
	// Block and require explicit confirmation when interactive; warn
	// loudly when --yes was passed (automation flows opted in already).
	localName := strings.TrimSpace(cfg.Server.Realm.Name)
	peerName := strings.TrimSpace(jr.RealmName)
	alreadyKnown := false
	for _, p := range cfg.Server.Realm.Peers {
		if strings.EqualFold(strings.TrimRight(p, "/"), peerURL) {
			alreadyKnown = true
			break
		}
	}
	if localName != "" && peerName != "" && strings.EqualFold(localName, peerName) && !alreadyKnown {
		warning := []string{
			"",
			"WARNING: realm name collision detected.",
			"  this server's realm name: " + localName,
			"  peer's realm name:        " + peerName,
			"  peer URL:                 " + peerURL,
			"",
			"  These names match but the peer isn't in this server's known peer list.",
			"  Joining will MERGE the two realms — every event/agent/master that one",
			"  side trusts becomes accessible to the other. There is no automatic",
			"  unmerge: recovery requires manually editing each side's config.json",
			"  and clearing peer_cas.",
			"",
			"  If both sides happened to use the default name on independent installs,",
			"  abort here and rename one (`server.realm.name` in config.json) before",
			"  re-trying. If you genuinely meant to merge them, proceed.",
			"",
		}
		for _, line := range warning {
			fmt.Fprintln(os.Stderr, line)
		}
		if *yes {
			fmt.Fprintln(os.Stderr, "  --yes was passed; proceeding with the merge anyway.")
			fmt.Fprintln(os.Stderr, "")
		} else {
			if !confirmYes("Proceed with the merge? [y/N] ") {
				fmt.Println("aborted; nothing changed.")
				os.Exit(1)
			}
		}
	}

	// Persist every returned peer CA into our trust bundle.
	written := 0
	for _, ca := range jr.PeerCAs {
		// Validate before writing.
		blk, _ := pem.Decode([]byte(ca.CAPem))
		if blk == nil || blk.Type != "CERTIFICATE" {
			fmt.Fprintf(os.Stderr, "  skip %s: ca_pem is not a CERTIFICATE block\n", ca.ID)
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil || !cert.IsCA {
			fmt.Fprintf(os.Stderr, "  skip %s: ca_pem is not a CA cert\n", ca.ID)
			continue
		}
		if !validHostName.MatchString(ca.ID) {
			fmt.Fprintf(os.Stderr, "  skip %s: id is not a safe filename component\n", ca.ID)
			continue
		}
		if _, werr := writePeerCA(ca.ID, ca.CAPem); werr != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: %v\n", ca.ID, werr)
			continue
		}
		written++
	}

	// Merge peer URLs (the responder + every other peer it knows
	// about) into our local realm config and adopt the realm name.
	// We prefer the responder's CANONICAL URL from jr.PeerCAs[0] over
	// the URL the operator typed because peerAuthorized on the
	// responder side stores its OWN identity by hostname (the cert's
	// CN). If the operator dialed by IP, recording that IP-form URL
	// here would mean peerIDFromURL("https://10.0.0.1:9443") = "10.0.0.1"
	// — which never matches the responder's cert CN, so any future
	// outbound call to the responder would 403 at peerAuthorized.
	// Using the canonical URL keeps the asymmetry from creeping in.
	canonicalPeer := peerURL
	if len(jr.PeerCAs) > 0 && jr.PeerCAs[0].URL != "" {
		// handleRealmJoin always emits its own self-URL as the first
		// PeerCA entry (selfPeerURL(s.selfPeerID, s.http.Addr)), so
		// PeerCAs[0].URL is the responder's canonical URL by
		// construction.
		canonicalPeer = jr.PeerCAs[0].URL
	}
	allPeers := append([]string{canonicalPeer}, jr.Peers...)
	added, ver, err := addRealmPeersToConfig(*cfgPath, allPeers, jr.RealmName)
	if err != nil {
		fatalf("save config: %v", err)
	}

	fmt.Println("Joined realm", jr.RealmName)
	fmt.Println("  realm:        ", jr.RealmName, "(adopted)")
	fmt.Println("  peers:        ", len(allPeers), "URLs (", added, "newly added to config)")
	for _, p := range allPeers {
		fmt.Println("                  ", p)
	}
	fmt.Println("  trust bundle: ", written, "peer CAs written to", realmPeerCAsDir())
	fmt.Println("  config:       ", *cfgPath, "(realm.peers updated, version", ver, ")")
	// Auto-restart so the new trust bundle is in effect immediately.
	// Without this, agent failover and peer-sync handshakes keep
	// rejecting peer certs until the operator manually restarts.
	if isRunning() {
		restartCommand(nil)
	}
	fmt.Println()
	fmt.Println("Other peers in the realm will learn about this server")
	fmt.Println("automatically on the next /v1/sync/config cycle.")
}

// promptInput is a minimal stdin-line reader for interactive prompts.
// Returns "" on EOF or read error so callers can validate uniformly.
// Uses the package-level stdinReader (defined in interactive.go) so
// multiple sequential prompts never lose each other's buffered input.
func promptInput(prompt string) string {
	fmt.Print(prompt)
	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return strings.TrimRight(line, "\r\n")
	}
	return strings.TrimRight(line, "\r\n")
}
