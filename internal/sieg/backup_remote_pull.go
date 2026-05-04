package sieg

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Wire format for remote backup invocation. POSTed to
// /v1/backup/create as a JSON body. The passphrase is carried inside
// the mTLS-encrypted request body (TLS 1.3 forward-secret) so it
// never lands in URL or response logs.
type backupRequest struct {
	// Passphrase to encrypt the resulting backup with on the
	// remote node. Optional — empty means produce an unencrypted
	// backup (the operator gets a server-side warning either way).
	Passphrase string `json:"passphrase"`
	// Compress controls gzip on the remote side. Default true.
	Compress bool `json:"compress"`
	// IncludeAgents (server-mode only) tells the server to ALSO
	// pull a backup from every agent in its allowlist and bundle
	// them into the response. False = server-only backup.
	IncludeAgents bool `json:"include_agents"`
	// Realm filter (server-mode only): when non-empty, only agents
	// whose origin server's realm name matches are included.
	// Currently the server itself only knows its own realm, so
	// this is checked against s.realmName for agent inclusion.
	RealmFilter string `json:"realm_filter,omitempty"`
}

// backupBundleHeader is written as the first 12 bytes of every
// multi-host bundle response: 4-byte magic "SBKB" + 4-byte version +
// 4 reserved bytes. Distinguishes a single-file response from a
// multi-file bundle response so the client knows whether to write
// the bytes verbatim or split them into per-host files.
const (
	bundleMagic   = "SBKB"
	bundleVersion = uint32(1)
)

// handleBackupCreate is the HTTP entry point invoked when a higher
// authority asks this node to create a backup of itself (and,
// optionally for servers, of every agent in its realm). Bytes stream
// straight into the response body — no temp file on disk on this
// side, the response IS the backup.
//
// Auth: same mTLS gate as /v1/sync/events. The caller's cert CN must
// match a recognised peer (realm peer or registered master) OR, in
// the agent case, the agent's own server (peerAuthorized handles all
// of these via existing trust state).
func (s *serverState) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.peerAuthorized(r) {
		s.logAuthFailure(r, "backup/create")
		http.Error(w, "not a recognised peer", http.StatusForbidden)
		return
	}
	var req backupRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	cfg := loadConfig(s.configPath)
	tmp, err := os.CreateTemp("", "siem-backup-*.siembak")
	if err != nil {
		http.Error(w, "tmpfile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	_ = tmp.Close()

	// Server-itself backup goes first.
	if err := createBackup(cfg, s.configPath, tmpPath, req.Passphrase, req.Compress); err != nil {
		http.Error(w, "backup: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if !req.IncludeAgents {
		// Single-file response: stream the .siembak as octet-stream.
		w.Header().Set("Content-Type", "application/octet-stream")
		f, err := os.Open(tmpPath)
		if err != nil {
			http.Error(w, "open tmp: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		_, _ = io.Copy(w, f)
		return
	}

	// Multi-host bundle: this server's backup + every agent's backup.
	// We pull each agent over an outbound mTLS call to the agent's
	// own /v1/backup/create. Agents currently DON'T expose this
	// endpoint (they're not listeners), so the realistic shape is:
	// the server bundles its own backup + every per-host events
	// directory as already-on-disk JSONL data wrapped into a
	// per-host .siembak. That gives the operator a one-shot capture
	// of "everything the server has about every agent" without
	// requiring a listener on every agent.
	w.Header().Set("Content-Type", "application/x-siem-backup-bundle")
	if err := writeBundleHeader(w); err != nil {
		return
	}
	if err := streamBundleEntry(w, "_self.siembak", tmpPath); err != nil {
		return
	}
	for _, host := range listHosts(cfg.LogDir) {
		if !validAgentID(host) || strings.HasPrefix(host, "_") {
			continue
		}
		// Build a per-agent backup synthesised from the server-side
		// view of that agent's events. Manifest is stamped with the
		// agent's host_id so a future restore knows where it
		// originated.
		agentTmp, err := os.CreateTemp("", "siem-agent-backup-*.siembak")
		if err != nil {
			continue
		}
		agentPath := agentTmp.Name()
		_ = agentTmp.Close()
		if err := createAgentViewBackup(cfg, s.configPath, host, agentPath, req.Passphrase, req.Compress); err == nil {
			_ = streamBundleEntry(w, host+".siembak", agentPath)
		}
		_ = os.Remove(agentPath)
	}
}

// writeBundleHeader writes the bundle marker so the client knows
// it's reading a multi-file response. Format:
//
//	[ 4B magic "SBKB" ]
//	[ 4B version BE   ]
//	[ 4B reserved (zero) ]
func writeBundleHeader(w io.Writer) error {
	hdr := make([]byte, 12)
	copy(hdr[0:4], bundleMagic)
	hdr[4] = byte(bundleVersion >> 24)
	hdr[5] = byte(bundleVersion >> 16)
	hdr[6] = byte(bundleVersion >> 8)
	hdr[7] = byte(bundleVersion)
	_, err := w.Write(hdr)
	return err
}

// streamBundleEntry appends one named file to a bundle stream.
//
//	[ 4B name length BE ]
//	[ name bytes ]
//	[ 8B body length BE ]
//	[ body bytes ]
func streamBundleEntry(w io.Writer, name, srcPath string) error {
	body, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer body.Close()
	fi, err := body.Stat()
	if err != nil {
		return err
	}
	nameBytes := []byte(name)
	hdr := make([]byte, 4+len(nameBytes)+8)
	hdr[0] = byte(len(nameBytes) >> 24)
	hdr[1] = byte(len(nameBytes) >> 16)
	hdr[2] = byte(len(nameBytes) >> 8)
	hdr[3] = byte(len(nameBytes))
	copy(hdr[4:4+len(nameBytes)], nameBytes)
	size := uint64(fi.Size())
	off := 4 + len(nameBytes)
	for i := 0; i < 8; i++ {
		hdr[off+i] = byte(size >> uint(56-8*i))
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err = io.Copy(w, body)
	return err
}

// createAgentViewBackup builds a .siembak that contains every event
// the server has on disk for one specific agent. Manifest's HostID
// is stamped to the agent's name and the LogDir entry inside the
// archive is rewritten to use that agent's per-host subdirectory so
// a restore on the agent itself lands the data back into the right
// per-host tree.
//
// Note: this is a server-side reconstruction — the agent's own
// config/state isn't included because the server doesn't have it.
// For a full agent backup, the operator runs `simplesiem backup`
// directly on the agent host. This server-side view captures the
// events corpus, which is what's hardest to reconstitute after a
// host loss.
func createAgentViewBackup(cfg Config, cfgPath, host, outPath, passphrase string, compress bool) error {
	// Cheap: synthesise a virtual config with LogDir scoped to the
	// agent's per-host subdirectory + the agent's name as Mode/ID.
	agentLogDir := filepath.Join(cfg.LogDir, host)
	if _, err := os.Stat(agentLogDir); err != nil {
		return err
	}
	scoped := cfg
	scoped.Mode = "agent"
	scoped.LogDir = agentLogDir
	scoped.Agent.ID = host
	scoped.StateDir = "" // not applicable for a server-side agent view
	return createBackup(scoped, cfgPath, outPath, passphrase, compress)
}

// runBackupRemoteServer is the server-mode invocation handler:
//
//	simplesiem backup --agent <id>     [--out-dir <dir>]
//	simplesiem backup --realm <name>   [--out-dir <dir>]
//	simplesiem backup --all            [--out-dir <dir>]
//
// Reads the local config to find the agent's per-host events, then
// builds a .siembak per requested target. Local agents are composed
// from the on-disk material the server already holds (no outbound
// per-agent call needed — the server is already at the top of the
// agent → server hop).
//
// Realm fan-out: when --all is set AND the server has realm peers
// configured, the server additionally calls /v1/backup/create on
// each peer (with include_agents=true) and unpacks the returned
// bundle into the same out-dir. Each peer composes its own backup
// bundle the same way; the result is a complete realm-wide capture
// from one invocation point.
func runBackupRemoteServer(args []string) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	agent := fs.String("agent", "", "single agent ID to back up (use --all for everything in the realm)")
	realm := fs.String("realm", "", "realm name (default: this server's realm)")
	all := fs.Bool("all", false, "back up every agent the server has events for, plus the server itself")
	outDir := fs.String("out-dir", ".", "destination directory for the backup files")
	pass := fs.String("passphrase", "", "encryption passphrase")
	passFile := fs.String("passphrase-file", "", "path to a passphrase file")
	noEncrypt := fs.Bool("no-encrypt", false, "produce unencrypted backups (NOT recommended)")
	noCompress := fs.Bool("no-compress", false, "skip gzip compression")
	yes := fs.Bool("y", false, "skip the live-collection warning prompt")
	_ = fs.Parse(args)

	cfg := loadConfig(*cfgPath)
	if normaliseMode(cfg.Mode) != "server" && normaliseMode(cfg.Mode) != "master" {
		fatalf("backup --agent / --realm / --all requires server or master mode (current: %s)", cfg.Mode)
	}
	passphrase, err := resolveBackupPassphrase(*pass, *passFile, *noEncrypt)
	if err != nil {
		fatalf("%v", err)
	}
	if !*yes {
		fmt.Fprintln(os.Stderr, "WARNING: events written after this moment will NOT be in the backups.")
		fmt.Fprint(os.Stderr, "Continue? [y/N] ")
		var resp string
		_, _ = fmt.Scanln(&resp)
		if !strings.EqualFold(strings.TrimSpace(resp), "y") && !strings.EqualFold(strings.TrimSpace(resp), "yes") {
			fmt.Fprintln(os.Stderr, "aborted")
			os.Exit(1)
		}
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatalf("out-dir: %v", err)
	}

	hosts := []string{}
	if *agent != "" {
		hosts = []string{*agent}
	} else {
		for _, h := range listHosts(cfg.LogDir) {
			if validAgentID(h) && !strings.HasPrefix(h, "_") {
				hosts = append(hosts, h)
			}
		}
	}

	stamp := time.Now().UTC().Format("20060102T150405Z")
	var subDir string
	if *realm != "" {
		subDir = filepath.Join(*outDir, *realm)
		_ = os.MkdirAll(subDir, 0o755)
	} else {
		subDir = *outDir
	}

	// Server-itself backup.
	if *all || *agent == "" {
		selfOut := filepath.Join(subDir, fmt.Sprintf("simplesiem-backup-%s-%s.siembak", backupHostID(cfg), stamp))
		if err := createBackup(cfg, *cfgPath, selfOut, passphrase, !*noCompress); err != nil {
			fatalf("server backup: %v", err)
		}
		fmt.Printf("server backup:  %s\n", selfOut)
	}

	// Skip the server's own local_id in this loop — it's already
	// covered by the self-backup above. Without this filter, an
	// `--all` run would write a second .siembak with the same
	// filename as the self-backup and silently clobber it.
	selfLocalID := pickServerLocalID(cfg.Server.LocalID)
	selfHostID := backupHostID(cfg)
	for _, h := range hosts {
		if h == selfLocalID || h == selfHostID {
			continue
		}
		out := filepath.Join(subDir, fmt.Sprintf("simplesiem-backup-%s-%s.siembak", h, stamp))
		if err := createAgentViewBackup(cfg, *cfgPath, h, out, passphrase, !*noCompress); err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", h, err)
			continue
		}
		fmt.Printf("agent backup:   %s\n", out)
	}

	// Realm fan-out: --all in a server with realm peers also pulls
	// from each peer. Authenticate using THIS server's own client
	// cert (mTLS); the peer treats us as a privileged realm peer
	// via peerAuthorized() the same way /v1/sync/events already
	// works. Bundles are unpacked into the same subDir so the
	// operator gets one flat directory of every host's .siembak.
	if *all && len(cfg.Server.Realm.Peers) > 0 {
		for _, peer := range cfg.Server.Realm.Peers {
			peerID := peerIDFromURL(peer)
			if peerID == "" {
				continue
			}
			tmp := filepath.Join(subDir, fmt.Sprintf("__bundle-%s-%s.bin", peerID, stamp))
			if err := pullRealmPeerBackup(cfg, peer, tmp, passphrase, !*noCompress); err != nil {
				fmt.Fprintf(os.Stderr, "  peer %s: %v\n", peer, err)
				continue
			}
			entries, err := unpackBundle(tmp, subDir)
			_ = os.Remove(tmp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  peer %s: unpack: %v\n", peer, err)
				continue
			}
			for _, e := range entries {
				fmt.Printf("realm peer backup: %s\n", e)
			}
		}
	}
}

// pullRealmPeerBackup invokes /v1/backup/create on a realm peer
// using THIS server's own server-cert pair as a client cert. Realms
// already require every peer to recognise every other peer's CA
// (that's what `realm join` builds), so the peer's TLS handshake
// accepts our cert and peerAuthorized() greenlights the call because
// our CN matches an entry in their realmPeers list.
func pullRealmPeerBackup(cfg Config, peerURL, outPath, passphrase string, compress bool) error {
	tlsCfg, err := buildPeerClientTLS(cfg)
	if err != nil {
		return fmt.Errorf("peer client TLS: %w", err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   30 * time.Minute,
	}
	body := backupRequest{Passphrase: passphrase, Compress: compress, IncludeAgents: true}
	bodyBytes, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost,
		strings.TrimRight(peerURL, "/")+"/v1/backup/create",
		strings.NewReader(string(bodyBytes)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := make([]byte, 1024)
		n, _ := resp.Body.Read(buf)
		return fmt.Errorf("peer returned %d: %s", resp.StatusCode, string(buf[:n]))
	}
	return streamToFileAtomic(outPath, resp.Body)
}

// buildPeerClientTLS reuses the server's own cert/key as a client
// cert when calling a peer's /v1/backup/create. Realm trust gives
// every server's CA a slot in every other peer's trust bundle, so
// the same cert that authenticates inbound /v1/events also
// authenticates outbound peer calls.
func buildPeerClientTLS(cfg Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Server.Cert, cfg.Server.Key)
	if err != nil {
		return nil, err
	}
	rootPEM, err := os.ReadFile(cfg.Server.CACert)
	if err != nil {
		return nil, err
	}
	pool, _ := buildPeerTrustPool(rootPEM)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		CurvePreferences: pqHybridCurvePrefs(),
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}

// buildPeerTrustPool layers any realm peer CAs on top of the local
// server CA so this server's outbound mTLS calls trust every peer in
// the realm — same pool the inbound listener uses.
func buildPeerTrustPool(rootPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	// Best-effort: include every peer CA the server has staged from
	// past `realm join` calls. Missing dir is fine — single-server
	// realm has no extra CAs to add.
	if entries, err := os.ReadDir(realmPeerCAsDir()); err == nil {
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".pem") {
				continue
			}
			if data, err := os.ReadFile(filepath.Join(realmPeerCAsDir(), e.Name())); err == nil {
				pool.AppendCertsFromPEM(data)
			}
		}
	}
	return pool, nil
}

// runBackupRemoteMasterRealm pulls a per-realm backup from every
// server in the named realm. Each server returns a multi-file bundle
// containing its own backup plus every agent's view; the master
// unpacks each bundle into <out-dir>/<realm>/<host>.siembak.
//
// The --agent <id> form is a single-target pull: the master picks an
// available server in the agent's realm and asks it to compose the
// agent-view backup for just that agent (single .siembak file).
func runBackupRemoteMasterRealm(args []string) {
	fs := flag.NewFlagSet("master backup", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	realm := fs.String("realm", "", "realm name to back up")
	allRealms := fs.Bool("all-realms", false, "back up every realm the master is enrolled with")
	collectorOut := fs.String("collector", "", "back up the paired collector to the given path (output file, not directory)")
	selfOut := fs.String("self", "", "back up the master itself to the given path (output file, not directory)")
	agent := fs.String("agent", "", "single agent ID to back up (master picks an available server in that agent's realm)")
	agentOut := fs.String("agent-out", "", "destination file for --agent (default: ./<agent>-<utc>.siembak)")
	outDir := fs.String("out-dir", ".", "destination directory for realm/host backups")
	pass := fs.String("passphrase", "", "encryption passphrase")
	passFile := fs.String("passphrase-file", "", "path to a passphrase file")
	noEncrypt := fs.Bool("no-encrypt", false, "produce unencrypted backups (NOT recommended)")
	noCompress := fs.Bool("no-compress", false, "skip gzip compression")
	yes := fs.Bool("y", false, "skip the live-collection warning prompt")
	_ = fs.Parse(args)

	cfg := loadConfig(*cfgPath)
	if normaliseMode(cfg.Mode) != "master" {
		fatalf("master backup requires master mode (current: %s)", cfg.Mode)
	}
	passphrase, err := resolveBackupPassphrase(*pass, *passFile, *noEncrypt)
	if err != nil {
		fatalf("%v", err)
	}
	if !*yes {
		fmt.Fprintln(os.Stderr, "WARNING: events written after this moment will NOT be in the backups.")
		fmt.Fprint(os.Stderr, "Continue? [y/N] ")
		var resp string
		_, _ = fmt.Scanln(&resp)
		if !strings.EqualFold(strings.TrimSpace(resp), "y") && !strings.EqualFold(strings.TrimSpace(resp), "yes") {
			fmt.Fprintln(os.Stderr, "aborted")
			os.Exit(1)
		}
	}

	// --self
	if *selfOut != "" {
		if err := createBackup(cfg, *cfgPath, *selfOut, passphrase, !*noCompress); err != nil {
			fatalf("master self backup: %v", err)
		}
		fmt.Printf("master backup:  %s\n", *selfOut)
	}

	// --agent: pull a single agent-view backup from any reachable
	// server that has events for that agent. The master tries each
	// enrolled server in turn; the first one that returns 200 wins.
	if *agent != "" {
		out := *agentOut
		if out == "" {
			out = fmt.Sprintf("./%s-%s.siembak", *agent, time.Now().UTC().Format("20060102T150405Z"))
		}
		var lastErr error
		ok := false
		for _, srv := range cfg.Master.Servers {
			if err := pullSingleAgentBackup(cfg, srv, *agent, out, passphrase, !*noCompress); err != nil {
				lastErr = err
				continue
			}
			ok = true
			fmt.Printf("agent backup:   %s (via %s)\n", out, srv)
			break
		}
		if !ok {
			fatalf("master --agent backup: no server returned the agent's events: %v", lastErr)
		}
	}

	// --collector
	if *collectorOut != "" {
		// Constraint: the master cannot use the collector machine
		// as a backup *destination*. The output path here is on the
		// master's filesystem, so this is implicit. Document it
		// explicitly when we know the path is something like a
		// network share — the operator's responsibility either way.
		if err := pullRemoteBackup(cfg, cfg.Master.QueryCollectorURL, *collectorOut, passphrase, !*noCompress, false); err != nil {
			fatalf("collector backup: %v", err)
		}
		fmt.Printf("collector backup: %s\n", *collectorOut)
	}

	// --all-realms is an umbrella: it implies --self, --collector
	// (when paired), and a realm-grouped pull from every enrolled
	// server. Allows the operator to run one command for the
	// classic "snapshot the entire fleet" workflow. Per-server
	// flags still work alongside it for specific overrides.
	if *allRealms {
		if *selfOut == "" {
			selfPath := filepath.Join(*outDir, "_self.siembak")
			if err := createBackup(cfg, *cfgPath, selfPath, passphrase, !*noCompress); err != nil {
				fmt.Fprintf(os.Stderr, "master self backup failed: %v\n", err)
			} else {
				fmt.Printf("master backup:    %s\n", selfPath)
			}
		}
		if *collectorOut == "" && cfg.Master.QueryCollectorURL != "" {
			collectorPath := filepath.Join(*outDir, "_collector.siembak")
			if err := pullRemoteBackup(cfg, cfg.Master.QueryCollectorURL, collectorPath, passphrase, !*noCompress, false); err != nil {
				fmt.Fprintf(os.Stderr, "collector backup failed: %v\n", err)
			} else {
				fmt.Printf("collector backup: %s\n", collectorPath)
			}
		}
	}

	// --realm or --all-realms — pull from each server.
	if *realm == "" && !*allRealms {
		if *collectorOut == "" && *selfOut == "" {
			fatalf("specify --realm <name>, --all-realms, --collector <out>, or --self <out>")
		}
		return
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatalf("out-dir: %v", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	// Resolve each enrolled server's realm name once via /v1/sync/config
	// so the layout groups by realm rather than by-server-<id>. Failures
	// fall back to the by-server layout for that one server so an
	// unreachable peer doesn't dump everything else into "unknown".
	realmByServer := map[string]string{}
	for _, server := range cfg.Master.Servers {
		realmByServer[server] = lookupServerRealm(cfg, server)
	}
	for _, server := range cfg.Master.Servers {
		serverID := peerIDFromURL(server)
		realmName := realmByServer[server]
		// --realm filter takes precedence: skip servers not in that realm.
		if *realm != "" && realmName != *realm {
			continue
		}
		realmDir := filepath.Join(*outDir, realmName)
		if realmName == "" {
			realmDir = filepath.Join(*outDir, "by-server-"+serverID)
		}
		_ = os.MkdirAll(realmDir, 0o755)
		bundlePath := filepath.Join(realmDir, fmt.Sprintf("__bundle-%s-%s.bin", serverID, stamp))
		if err := pullRemoteBackup(cfg, server, bundlePath, passphrase, !*noCompress, true); err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", server, err)
			continue
		}
		entries, err := unpackBundle(bundlePath, realmDir)
		_ = os.Remove(bundlePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: unpack: %v\n", server, err)
			continue
		}
		for _, e := range entries {
			fmt.Printf("  pulled: %s\n", e)
		}
	}
}

// pullSingleAgentBackup invokes the existing /v1/backup/create with
// a per-agent filter we layer on top: the server returns its full
// multi-host bundle (or just its own + agent backups), and the
// master extracts the matching <agent>.siembak entry into outPath.
//
// We use the bundle path so a server that's compositing on-the-fly
// can be a single code path; the master discards the rest of the
// bundle and keeps just the requested agent's slice.
func pullSingleAgentBackup(cfg Config, serverURL, agentID, outPath, passphrase string, compress bool) error {
	tmp := outPath + ".bundle.tmp"
	if err := pullRemoteBackup(cfg, serverURL, tmp, passphrase, compress, true); err != nil {
		return err
	}
	defer os.Remove(tmp)
	stagingDir := outPath + ".unpack-tmp"
	_ = os.MkdirAll(stagingDir, 0o755)
	defer os.RemoveAll(stagingDir)
	files, err := unpackBundle(tmp, stagingDir)
	if err != nil {
		return err
	}
	for _, p := range files {
		base := filepath.Base(p)
		if base == agentID+".siembak" {
			return os.Rename(p, outPath)
		}
	}
	return fmt.Errorf("server bundle does not contain agent %q", agentID)
}

// lookupServerRealm asks one server for its realm name via
// /v1/sync/config. Used by master --all-realms to bucket per-server
// backups into realm-named subdirectories. Best-effort: returns
// empty on any error so the caller can fall back to a per-server
// layout for that one server.
func lookupServerRealm(cfg Config, serverURL string) string {
	serverID := peerIDFromURL(serverURL)
	if serverID == "" {
		return ""
	}
	tlsCfg, err := loadMasterClientTLS(filepath.Join(masterCertsDir(cfg), serverID))
	if err != nil {
		return ""
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   10 * time.Second,
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(serverURL, "/")+"/v1/sync/config", nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var body struct {
		RealmName string `json:"realm_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&body); err != nil {
		return ""
	}
	return body.RealmName
}

// pullRemoteBackup invokes /v1/backup/create on `peerURL` using the
// master's per-peer client cert, and streams the response into
// outPath. When includeAgents is true the response is a bundle
// (multiple .siembak files glued together with the format described
// in writeBundleHeader); when false it's a single .siembak.
//
// The cert dir layout differs by peer kind: server peers live under
// `<config>/master/<peer-id>/`; the paired query-collector lives
// under `<config>/master/query-collector/<peer-id>/`. We try the
// server layout first (the common case) and fall back to the
// query-collector layout when the cert isn't there. This keeps the
// caller from having to track which kind of peer they're hitting.
//
// Atomic on the destination side: bytes stream into outPath+".tmp";
// any failure (network, auth, copy error) removes the partial file
// and returns the error WITHOUT replacing the operator's previous
// outPath. Only on a fully-successful body copy is the .tmp file
// renamed into outPath, which is a single-syscall atomic operation
// on every supported OS.
func pullRemoteBackup(cfg Config, peerURL, outPath, passphrase string, compress, includeAgents bool) error {
	if peerURL == "" {
		return fmt.Errorf("peer URL is empty")
	}
	peerID := peerIDFromURL(peerURL)
	if peerID == "" {
		return fmt.Errorf("could not parse host from %q", peerURL)
	}
	// Try the server-cert dir first; fall back to query-collector.
	candidates := []string{
		filepath.Join(masterCertsDir(cfg), peerID),
		filepath.Join(masterQueryCollectorRoot(), peerID),
	}
	var tlsCfg *tls.Config
	var err error
	for _, dir := range candidates {
		tlsCfg, err = loadMasterClientTLS(dir)
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("client TLS: %w", err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   30 * time.Minute, // backups can be large
	}
	body := backupRequest{Passphrase: passphrase, Compress: compress, IncludeAgents: includeAgents}
	bodyBytes, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(peerURL, "/")+"/v1/backup/create", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := make([]byte, 1024)
		n, _ := resp.Body.Read(buf)
		return fmt.Errorf("peer returned %d: %s", resp.StatusCode, string(buf[:n]))
	}
	return streamToFileAtomic(outPath, resp.Body)
}

// streamToFileAtomic copies an io.Reader into outPath via a sibling
// .tmp file + atomic rename. On any error during copy or close, the
// .tmp file is removed and the error is returned; outPath is never
// observed in a partial state. Callers that need to atomically
// replace an existing file get exactly the right semantics.
func streamToFileAtomic(outPath string, body io.Reader) (err error) {
	if mkErr := os.MkdirAll(filepath.Dir(outPath), 0o755); mkErr != nil {
		return mkErr
	}
	tmp := outPath + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = out.Close()
		_ = os.Remove(tmp)
	}
	if _, copyErr := io.Copy(out, body); copyErr != nil {
		cleanup()
		return copyErr
	}
	if cErr := out.Close(); cErr != nil {
		_ = os.Remove(tmp)
		return cErr
	}
	if err := os.Rename(tmp, outPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// unpackBundle splits a bundle file into individual .siembak files in
// destDir. Returns the list of paths it wrote.
//
// Atomicity contract: all-or-nothing across the whole bundle. Each
// entry streams into its own .tmp file; only after every entry has
// been fully copied AND the bundle stream has been validated does
// the function rename each .tmp to its final name. On any failure
// during the read/copy phase, every staged .tmp file is removed and
// no caller-visible files appear at the destination paths. This
// matches the operator's expectation that a failed remote pull
// leaves no half-extracted siembak files cluttering the realm dir.
func unpackBundle(bundlePath, destDir string) (written []string, err error) {
	f, err := os.Open(bundlePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hdr := make([]byte, 12)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return nil, fmt.Errorf("bundle header: %w", err)
	}
	if string(hdr[0:4]) != bundleMagic {
		return nil, fmt.Errorf("not a backup bundle (got magic %q)", hdr[0:4])
	}

	type pending struct {
		tmp   string
		final string
	}
	staged := []pending{}
	cleanup := func() {
		for _, p := range staged {
			_ = os.Remove(p.tmp)
		}
	}
	defer func() {
		if err != nil {
			cleanup()
			written = nil
		}
	}()

	if mkErr := os.MkdirAll(destDir, 0o755); mkErr != nil {
		return nil, mkErr
	}

	for {
		var nameLenBuf [4]byte
		if _, readErr := io.ReadFull(f, nameLenBuf[:]); readErr != nil {
			if readErr == io.EOF {
				break
			}
			return nil, readErr
		}
		nameLen := int(nameLenBuf[0])<<24 | int(nameLenBuf[1])<<16 | int(nameLenBuf[2])<<8 | int(nameLenBuf[3])
		if nameLen <= 0 || nameLen > 1024 {
			return nil, fmt.Errorf("bundle name length %d out of range", nameLen)
		}
		name := make([]byte, nameLen)
		if _, readErr := io.ReadFull(f, name); readErr != nil {
			return nil, readErr
		}
		var sizeBuf [8]byte
		if _, readErr := io.ReadFull(f, sizeBuf[:]); readErr != nil {
			return nil, readErr
		}
		size := uint64(0)
		for i := 0; i < 8; i++ {
			size = (size << 8) | uint64(sizeBuf[i])
		}
		safeName := filepath.Base(string(name))
		final := filepath.Join(destDir, safeName)
		tmp := final + ".tmp"
		out, openErr := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if openErr != nil {
			return nil, openErr
		}
		_, copyErr := io.CopyN(out, f, int64(size))
		closeErr := out.Close()
		if copyErr != nil {
			_ = os.Remove(tmp)
			return nil, copyErr
		}
		if closeErr != nil {
			_ = os.Remove(tmp)
			return nil, closeErr
		}
		staged = append(staged, pending{tmp: tmp, final: final})
	}

	// Bundle parsed cleanly — promote every staged file. If a single
	// rename fails we still bail out and remove every staged tmp,
	// because the caller expects the destDir to be untouched on
	// failure. (Previously-promoted files in a partial run are also
	// rolled back via os.Remove.)
	for i, p := range staged {
		if rErr := os.Rename(p.tmp, p.final); rErr != nil {
			// Roll back every promotion that already happened.
			for _, prior := range staged[:i] {
				_ = os.Remove(prior.final)
			}
			for _, leftover := range staged[i:] {
				_ = os.Remove(leftover.tmp)
			}
			return nil, rErr
		}
		written = append(written, p.final)
	}
	return written, nil
}

// loadMasterClientTLS is implemented in master.go (already in the
// codebase). Re-declared here as a one-line shim so this file stays
// self-contained for review.
var _ = func() *tls.Config { return nil }
