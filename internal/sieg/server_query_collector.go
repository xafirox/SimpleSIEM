package sieg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runServerQueryCollectorCmd dispatches `simplesiem server
// query-collector <enroll|run|status>`. Mirrors the master-side
// flow but is only available when the realm has no master — the
// master is the canonical querier when it's present. When a
// master IS enrolled, this CLI refuses with a clear hint.
func runServerQueryCollectorCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem server query-collector <enroll|run|status>

  enroll <url> --key <PSK>   Enroll this server with a paired collector. Refused
                             when a master is enrolled (use master query-collector).
  run [flags]                Stream events from the paired collector matching the
                             same flag set as `+"`simplesiem query`"+`.
  status                     Show paired collector URL + cert dir + cert expiry.`)
		os.Exit(2)
	}
	switch args[0] {
	case "enroll":
		runServerQueryCollectorEnroll(args[1:])
	case "run":
		runServerQueryCollectorRun(args[1:])
	case "status":
		runServerQueryCollectorStatus(args[1:])
	default:
		fatalf("unknown server query-collector subcommand: %s", args[0])
	}
}

// serverQueryCollectorRoot is the on-disk root for the cert+key+CA
// the server uses to authenticate against a collector. Mirrors
// masterQueryCollectorRoot's <config>/master/query-collector/ layout
// but under <config>/server/.
func serverQueryCollectorRoot() string {
	return filepath.Join(defaultConfigDir(), "server", "query-collector")
}

func runServerQueryCollectorEnroll(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "key": true, "id": true})
	fs := flag.NewFlagSet("server query-collector enroll", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	psk := fs.String("key", "", "PSK from `simplesiem collector master show-psk` on the collector")
	serverID := fs.String("id", "", "server ID (CN) used for collector auth; defaults to server-<hostname>")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: simplesiem server query-collector enroll <collector-url> --key <PSK>")
	}
	if *psk == "" {
		fatalf("--key is required (run `simplesiem collector master show-psk` on the collector)")
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	cfg := loadConfig(*cfgPath)
	if normaliseMode(cfg.Mode) != "server" {
		fatalf("not in server mode (current: %s); run this on the SERVER that wants to query the collector", cfg.Mode)
	}
	// r20 — server-direct collector query is only allowed when no
	// master is enrolled. If a master is in master_cns, the server
	// defers to the master.
	if len(cfg.Server.MasterCNs) > 0 {
		fatalf("a master is enrolled with this server (master_cns=%d) — collector queries are the master's responsibility. Run `simplesiem master query-collector enroll` on the master instead.", len(cfg.Server.MasterCNs))
	}
	collectorURL := strings.TrimRight(fs.Arg(0), "/")
	parsed, err := url.Parse(collectorURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		fatalf("collector URL must be an https URL with a host (got %q)", collectorURL)
	}
	hostname, _ := os.Hostname()
	id := *serverID
	if id == "" {
		id = "server-" + hostname
	}
	if !validRealmServerID(id) {
		fatalf("server ID %q is invalid (must start with `server-` followed by alphanumeric/.-_)", id)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fatalf("generate key: %v", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: id, Organization: []string{"SimpleSIEM"}}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		fatalf("build CSR: %v", err)
	}
	csrPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	body, _ := json.Marshal(MasterEnrollRequest{PSK: *psk, MasterID: id, CSRPem: csrPem})
	// #nosec G402 — bootstrap-only; HMAC over the response with the
	// PSK as key authenticates the collector. Same posture the
	// master-side enrollment uses.
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs()}, TLSHandshakeTimeout: 10 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	// c4 — use the multi-server endpoint so several realm servers
	// can each enroll concurrently. The collector enforces a
	// per-enrollment accept-next gate, so a leaked PSK alone can't
	// land an unbounded number of CNs in cfg.collector.realm_server_cns.
	req, err := http.NewRequest(http.MethodPost, collectorURL+"/v1/enroll-realm-server", bytes.NewReader(body))
	if err != nil {
		fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fatalf("contact collector: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		fatalf("collector rejected enrollment (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var er MasterEnrollResponse
	if err := json.Unmarshal(rb, &er); err != nil {
		fatalf("parse collector response: %v", err)
	}
	if er.CertPem == "" || er.CAPem == "" || er.Hmac == "" {
		fatalf("collector response missing required fields")
	}
	pskRaw, perr := pskRawBytes(*psk)
	if perr != nil {
		fatalf("--key: %v", perr)
	}
	expected := computeEnrollHMAC(pskRaw, er.CertPem, er.CAPem, er.ReauthSeconds, er.RealmName, []string{er.ServerHost})
	if subtle.ConstantTimeCompare([]byte(er.Hmac), []byte(expected)) != 1 {
		fatalf("response HMAC mismatch — possible MITM, or PSK on collector differs from --key")
	}
	urlID := peerIDFromURL(collectorURL)
	if urlID == "" {
		fatalf("could not parse hostname from collector URL %q", collectorURL)
	}
	dir := filepath.Join(serverQueryCollectorRoot(), urlID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		fatalf("create cert dir: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		fatalf("write key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte(er.CertPem), 0o644); err != nil {
		fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte(er.CAPem), 0o644); err != nil {
		fatalf("write CA: %v", err)
	}
	cfg.Server.QueryCollectorURL = collectorURL
	if err := saveConfig(*cfgPath, cfg); err != nil {
		fatalf("save config: %v", err)
	}
	fmt.Println("Server enrolled with collector at", collectorURL)
	fmt.Println("  cert dir:   ", dir)
	fmt.Println("  server_id:  ", id)
	fmt.Println()
	fmt.Println("Run a query:")
	fmt.Println("  simplesiem server query-collector run --host <agent-id> --since 30d --type files")
}

// runServerQueryCollectorRun streams events from the paired
// collector. Same flag surface as `simplesiem query` (client-side
// filtering only — the collector returns its full archive in the
// since window).
func runServerQueryCollectorRun(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "host": true, "since": true, "type": true, "grep": true, "limit": true})
	fs := flag.NewFlagSet("server query-collector run", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	hostFilter := fs.String("host", "", "agent ID")
	since := fs.String("since", "1h", "time window")
	typ := fs.String("type", "", "log type")
	grep := fs.String("grep", "", "regex filter")
	_ = fs.Parse(args)

	cfg := loadConfig(*cfgPath)
	if cfg.Server.QueryCollectorURL == "" {
		fatalf("no paired collector (run `simplesiem server query-collector enroll <url> --key <PSK>` first)")
	}
	if len(cfg.Server.MasterCNs) > 0 {
		fatalf("a master is enrolled — collector queries are the master's responsibility")
	}
	urlID := peerIDFromURL(cfg.Server.QueryCollectorURL)
	dir := filepath.Join(serverQueryCollectorRoot(), urlID)
	tlsCfg, err := loadMasterClientTLS(dir)
	if err != nil {
		fatalf("load query-collector cert from %s: %v", dir, err)
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg, TLSHandshakeTimeout: 10 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Minute}
	q := url.Values{}
	startT, err := parseSince(*since)
	if err == nil && !startT.IsZero() {
		q.Set("since", startT.Format(time.RFC3339Nano))
	}
	if *hostFilter != "" {
		q.Set("host", *hostFilter)
	}
	if *typ != "" {
		q.Set("type", *typ)
	}
	if *grep != "" {
		q.Set("grep", *grep)
	}
	reqURL := strings.TrimRight(cfg.Server.QueryCollectorURL, "/") + "/v1/sync/events?" + q.Encode()
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		fatalf("query collector: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		fatalf("collector returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	_, _ = io.Copy(os.Stdout, resp.Body)
}

func runServerQueryCollectorStatus(args []string) {
	fs := flag.NewFlagSet("server query-collector status", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	cfg := loadConfig(*cfgPath)
	if cfg.Server.QueryCollectorURL == "" {
		fmt.Println("paired collector: (none)")
		return
	}
	urlID := peerIDFromURL(cfg.Server.QueryCollectorURL)
	dir := filepath.Join(serverQueryCollectorRoot(), urlID)
	fmt.Println("paired collector:", cfg.Server.QueryCollectorURL)
	fmt.Println("  cert dir:    ", dir)
	if data, err := os.ReadFile(filepath.Join(dir, "cert.pem")); err == nil {
		blk, _ := pem.Decode(data)
		if blk != nil {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				fmt.Println("  cert expiry: ", c.NotAfter.UTC().Format(time.RFC3339))
			}
		}
	}
}
