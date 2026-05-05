package sieg

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// startCollectorGatewayReporter polls the collector host's default
// gateway every minute and reports the (IP, MAC) tuple to the
// collector's configured source (master or server). Mirrors
// startAgentGatewayReporter — collectors NEVER bind a network ingest
// listener, but their own gateway needs to be in the realm-wide
// allowlist so any frame the master/server later receives that
// claims to come from this collector's gateway is accepted.

func startCollectorGatewayReporter(ctx context.Context, wg *sync.WaitGroup, cfg Config, logger *Storage) {
	if cfg.Collector.SourceURL == "" {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var lastIP, lastMAC string
		t := time.NewTimer(15 * time.Second)
		defer t.Stop()
		interval := 60 * time.Second
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			t.Reset(interval)
			if isContainerEnv() {
				continue
			}
			gateways, err := discoverGatewaysAndMACs()
			if err != nil || len(gateways) == 0 {
				continue
			}
			g := gateways[0]
			if g.IP == "" || g.MAC == "" {
				continue
			}
			if g.IP == lastIP && g.MAC == lastMAC {
				continue
			}
			body := struct {
				OldIP  string `json:"old_ip"`
				OldMAC string `json:"old_mac"`
				NewIP  string `json:"new_ip"`
				NewMAC string `json:"new_mac"`
			}{lastIP, lastMAC, g.IP, g.MAC}
			if err := postCollectorGatewayReport(cfg, body); err == nil {
				if logger != nil {
					logger.Write("meta", map[string]any{
						"event":   "gateway_changed",
						"role":    "collector",
						"old_ip":  lastIP,
						"old_mac": lastMAC,
						"new_ip":  g.IP,
						"new_mac": g.MAC,
					})
				}
				lastIP, lastMAC = g.IP, g.MAC
			}
		}
	}()
}

func postCollectorGatewayReport(cfg Config, body any) error {
	tcfg, err := collectorClientTLS(cfg)
	if err != nil {
		return err
	}
	c := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tcfg},
		Timeout:   10 * time.Second,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	urls := []string{
		strings.TrimRight(cfg.Collector.SourceURL, "/") + "/v1/collector/gateway",
	}
	for _, p := range cfg.Collector.FailoverServers {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		urls = append(urls, p+"/v1/collector/gateway")
	}
	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(data))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		if httpStatusOK(resp.StatusCode) || resp.StatusCode == http.StatusNoContent {
			return nil
		}
	}
	return lastErr
}

// collectorClientTLS builds the mTLS config the collector uses to
// dial its source. Mirrors the existing collector-pull TLS setup —
// per-source cert/key/ca live under <CertsDir>/<source-host>/.
func collectorClientTLS(cfg Config) (*tls.Config, error) {
	src := cfg.Collector.SourceURL
	host := serverHostFromURL(src)
	dir := filepath.Join(cfg.Collector.CertsDir, host)
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, err
	}
	caBytes, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caBytes)
	return &tls.Config{
		Certificates:     []tls.Certificate{cert},
		RootCAs:          pool,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: pqHybridCurvePrefs(),
	}, nil
}
