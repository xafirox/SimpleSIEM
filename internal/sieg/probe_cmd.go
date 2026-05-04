package sieg

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// runProbeCmd is a small HTTP probe used by the UAT (and operators
// debugging TLS) to fetch a URL using the same TLS posture the
// simplesiem daemon enforces — X25519MLKEM768 + TLS 1.3. Debian-12
// stock curl can't speak X25519MLKEM768, so /v1/health and /metrics
// fetches from inside the rig need a Go-based probe.
//
//	simplesiem probe <url>
//	  -bearer <token>          Authorization: Bearer <token>
//	  -insecure                skip TLS verification (for testing)
//	  -cert <pem>              client cert PEM
//	  -key <pem>               client key PEM
//	  -ca <pem>                CA bundle PEM
//	  -code-only               print HTTP status code only
//	  -timeout <dur>           default 10s
func runProbeCmd(args []string) {
	args = permuteArgs(args, map[string]bool{
		"bearer": true, "cert": true, "key": true, "ca": true,
		"timeout": true,
	})
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	bearer := fs.String("bearer", "", "Authorization: Bearer token")
	insecure := fs.Bool("insecure", false, "skip TLS verification")
	certPath := fs.String("cert", "", "client cert PEM")
	keyPath := fs.String("key", "", "client key PEM")
	caPath := fs.String("ca", "", "CA bundle PEM")
	codeOnly := fs.Bool("code-only", false, "print HTTP status code only")
	timeoutStr := fs.String("timeout", "10s", "request timeout")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: simplesiem probe <url> [-bearer <token>] [-insecure] [-cert <pem> -key <pem>] [-ca <pem>] [-code-only]")
	}
	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		fatalf("--timeout %q: %v", *timeoutStr, err)
	}
	tlsCfg := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: pqHybridCurvePrefs(),
	}
	// #nosec G402 -- testing/diagnostic flag; documented escape hatch
	if *insecure {
		tlsCfg.InsecureSkipVerify = true
	}
	if *caPath != "" {
		pool, err := loadCAPool(*caPath)
		if err != nil {
			fatalf("load CA: %v", err)
		}
		tlsCfg.RootCAs = pool
	}
	if *certPath != "" && *keyPath != "" {
		cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			fatalf("load client keypair: %v", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg}
	client := &http.Client{Transport: tr, Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, fs.Arg(0), nil)
	if err != nil {
		fatalf("build request: %v", err)
	}
	if *bearer != "" {
		req.Header.Set("Authorization", "Bearer "+*bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if *codeOnly {
		fmt.Println(resp.StatusCode)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	fmt.Printf("HTTP %d\n", resp.StatusCode)
	for k, v := range resp.Header {
		for _, vv := range v {
			fmt.Printf("%s: %s\n", k, vv)
		}
	}
	fmt.Println()
	_, _ = os.Stdout.Write(body)
}
