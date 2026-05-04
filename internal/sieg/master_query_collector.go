package sieg

import (
	"bufio"
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
	"regexp"
	"strings"
	"time"
)

// `simplesiem master query-collector ...`
//
// Two-step model:
//
//   1. enroll <url> --key <psk>
//      Master generates a keypair locally, sends a CSR to the
//      collector's /v1/enroll-master, gets a client cert back. The
//      cert + key + CA bundle are written under
//      <config>/master/query-collector/<peer-id>/.
//
//   2. run [--host X --since 30d --type files --grep ...]
//      Master uses the client cert to call /v1/sync/events on the
//      collector, applies the same flag set as `simplesiem query`,
//      and streams matching events to stdout.
//
// The master never duplicates the collector's archive locally. Each
// query is a fresh round-trip. This is the "long-tail retention"
// pattern: the master runs with a small retention window for
// real-time triage, the collector keeps the long archive, and the
// master reaches back into the archive on demand without a giant
// local store.

// masterQueryCollectorRoot is the on-disk root for the cert+key+CA
// the master uses to authenticate against a collector. Per-collector
// keyed by peerIDFromURL of the collector's master-listener URL.
func masterQueryCollectorRoot() string {
	return filepath.Join(defaultConfigDir(), "master", "query-collector")
}

func runMasterQueryCollectorCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem master query-collector <enroll|run|status>

  enroll <collector-url> --key <PSK>
        Enroll this master with a paired collector (single-master
        rule on the collector side). Generates a keypair locally,
        receives a signed cert; writes under
        <config>/master/query-collector/<host>/.

  run [--host X --since 1h --until ... --type files --grep ... --limit N]
        Stream events from the collector matching the filters. Same
        flag set as `+"`simplesiem query`"+`. Output is NDJSON on stdout —
        pipe through `+"`jq -r .ts`"+`, etc.

  status                Show paired collector URL + cert dir + cert expiry.`)
		os.Exit(2)
	}
	switch args[0] {
	case "enroll":
		runMasterQueryCollectorEnroll(args[1:])
	case "run":
		runMasterQueryCollectorRun(args[1:])
	case "status":
		runMasterQueryCollectorStatus(args[1:])
	default:
		fatalf("unknown master query-collector subcommand: %s", args[0])
	}
}

func runMasterQueryCollectorEnroll(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "key": true, "id": true})
	fs := flag.NewFlagSet("master query-collector enroll", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	psk := fs.String("key", "", "PSK from `simplesiem collector master show-psk` on the collector")
	masterID := fs.String("id", "", "master ID (CN); defaults to master-<hostname>")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: simplesiem master query-collector enroll <collector-url> --key <PSK>")
	}
	if *psk == "" {
		fatalf("--key is required (run `simplesiem collector master show-psk` on the collector)")
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	collectorURL := strings.TrimRight(fs.Arg(0), "/")
	parsed, err := url.Parse(collectorURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		fatalf("collector URL must be an https URL with a host (got %q)", collectorURL)
	}
	hostname, _ := os.Hostname()
	id := *masterID
	if id == "" {
		id = "master-" + hostname
	}
	if !validMasterID(id) {
		fatalf("master ID %q is invalid", id)
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
	// PSK as key authenticates the collector.
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, CurvePreferences: pqHybridCurvePrefs()}, TLSHandshakeTimeout: 10 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPost, collectorURL+"/v1/enroll-master", bytes.NewReader(body))
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
	dir := filepath.Join(masterQueryCollectorRoot(), urlID)
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
	// Persist the URL so `run` doesn't need it on every call.
	allowlistEditMu.Lock()
	cfg := loadConfig(*cfgPath)
	cfg.Master.QueryCollectorURL = collectorURL
	if err := saveConfig(*cfgPath, cfg); err != nil {
		allowlistEditMu.Unlock()
		fatalf("save config: %v", err)
	}
	allowlistEditMu.Unlock()
	fmt.Println("Master enrolled with collector at", collectorURL)
	fmt.Println("  cert dir:    ", dir)
	fmt.Println("  master_id:   ", id)
	fmt.Println()
	fmt.Println("Now run a query:")
	fmt.Println("  simplesiem master query-collector run --host <agent-id> --since 30d --type files")
}

func runMasterQueryCollectorStatus(args []string) {
	fs := flag.NewFlagSet("master query-collector status", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	_ = fs.Parse(args)
	cfg := loadConfig(*cfgPath)
	fmt.Println("Master query-collector pairing:")
	if cfg.Master.QueryCollectorURL == "" {
		fmt.Println("  (no collector paired — run `master query-collector enroll <url> --key <PSK>` first)")
		return
	}
	fmt.Println("  collector_url:", cfg.Master.QueryCollectorURL)
	urlID := peerIDFromURL(cfg.Master.QueryCollectorURL)
	dir := filepath.Join(masterQueryCollectorRoot(), urlID)
	fmt.Println("  cert dir:     ", dir)
	if data, err := os.ReadFile(filepath.Join(dir, "cert.pem")); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			if cert, perr := x509.ParseCertificate(block.Bytes); perr == nil {
				fmt.Printf("  cert expires: %s %s (%s left)\n", displayTS(cert.NotAfter).Format(time.RFC3339), displayTZ(), time.Until(cert.NotAfter).Round(time.Hour))
			}
		}
	}
}

func runMasterQueryCollectorRun(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true, "type": true, "since": true, "until": true, "grep": true, "limit": true, "host": true, "field": true})
	fs := flag.NewFlagSet("master query-collector run", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	typ := fs.String("type", "", "log type filter (network/files/auth/...)")
	since := fs.String("since", "1h", "relative (1h, 30m, 7d) or RFC3339 timestamp")
	until := fs.String("until", "", "upper bound: 'now', RFC3339, ...")
	grep := fs.String("grep", "", "regex filter on raw JSON line")
	limit := fs.Int("limit", 0, "max lines emitted (0 = no limit)")
	hostFilter := fs.String("host", "", "restrict to one agent ID or origin")
	var ffsRaw fieldFilterList
	fs.Var(&ffsRaw, "field", "structured filter (repeatable), e.g. --field path=*=authorized_keys")
	_ = fs.Parse(args)
	ffs := ffsRaw.compiled()

	cfg := loadConfig(*cfgPath)
	if cfg.Master.QueryCollectorURL == "" {
		fatalf("no collector paired — run `simplesiem master query-collector enroll <url> --key <PSK>` first")
	}
	urlID := peerIDFromURL(cfg.Master.QueryCollectorURL)
	if urlID == "" {
		fatalf("config has invalid master.query_collector_url")
	}
	dir := filepath.Join(masterQueryCollectorRoot(), urlID)
	tlsCfg, err := loadMasterClientTLS(dir)
	if err != nil {
		fatalf("load client cert: %v\n  hint: re-enroll with `simplesiem master query-collector enroll <url> --key <PSK>`", err)
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg.Clone(), TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Minute}

	sinceT, err := parseSince(*since)
	if err != nil {
		fatalf("--since: %v", err)
	}
	var untilT time.Time
	if *until != "" {
		untilT, err = parseTimeRef(*until)
		if err != nil {
			fatalf("--until: %v", err)
		}
	}
	var re *regexp.Regexp
	if *grep != "" {
		re, err = regexp.Compile(*grep)
		if err != nil {
			fatalf("--grep: %v", err)
		}
	}

	q := url.Values{}
	if !sinceT.IsZero() {
		q.Set("since", sinceT.Format(time.RFC3339Nano))
	}
	reqURL := strings.TrimRight(cfg.Master.QueryCollectorURL, "/") + "/v1/sync/events?" + q.Encode()
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
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		fatalf("collector returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	emitted := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		var ev map[string]any
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		// Apply remaining filters client-side. The since filter is
		// already handled server-side via the query string. The other
		// filters live here so the collector doesn't need to grow a
		// full query parser; the master applies them on the streamed
		// rows the same way `simplesiem query` does locally.
		if !untilT.IsZero() {
			if rs, _ := ev["received_at"].(string); rs != "" {
				if t, perr := time.Parse(time.RFC3339Nano, rs); perr == nil && t.After(untilT) {
					continue
				}
			}
		}
		if *typ != "" {
			if et, _ := ev["type"].(string); et != *typ {
				continue
			}
		}
		if *hostFilter != "" {
			if eh, _ := ev["host"].(string); eh != *hostFilter {
				if origin, _ := ev["origin_server"].(string); origin != *hostFilter {
					continue
				}
			}
		}
		if re != nil && !re.Match(line) {
			continue
		}
		if len(ffs) > 0 {
			ok := true
			for _, ff := range ffs {
				if !ff.m.test(ev[ff.key]) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}
		out.Write(line)
		out.WriteByte('\n')
		emitted++
		if *limit > 0 && emitted >= *limit {
			break
		}
	}
}
