package sieg

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// agentGatewayReporter polls this host's default gateway every minute
// and reports the (IP, MAC) tuple to the agent's enrolled server. The
// server uses the report to populate the network-allowlist with a
// gateway entry owned by this agent's CN.
//
// Per the design: agents NEVER bind a network ingest listener. They
// only report their own gateway state up to the server.

func startAgentGatewayReporter(ctx context.Context, wg *sync.WaitGroup, cfg AgentConfig, logger *Storage) {
	if cfg.ServerURL == "" {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var lastIP, lastMAC string
		// First report after a short warmup so enrollment / cert load
		// has fully completed.
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
			// Skip inside a container — same reasoning as the
			// auto-discovery server side.
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
			if err := postAgentGatewayReport(cfg, body); err == nil {
				if logger != nil {
					logger.Write("meta", map[string]any{
						"event":   "gateway_changed",
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

func postAgentGatewayReport(cfg AgentConfig, body any) error {
	tcfg, err := agentTLSConfig(cfg)
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
	urls := []string{strings.TrimRight(cfg.ServerURL, "/") + "/v1/agent/gateway"}
	for _, p := range cfg.FailoverServers {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		urls = append(urls, p+"/v1/agent/gateway")
	}
	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(data))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SimpleSIEM-Host", cfg.ID)
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		if httpStatusOK(resp.StatusCode) || resp.StatusCode == http.StatusNoContent {
			return nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return lastErr
	}
	// silently treat 4xx as transient
	return nil
}

// agentTLSConfig is implemented in agent.go; we add a wrapper here to
// avoid importing http internals at the call site.
var _ = tls.VersionTLS13
