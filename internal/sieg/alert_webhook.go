package sieg

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// alertWebhookDispatcher posts every fired alert as JSON to each
// configured URL in cfg.Server.AlertWebhooks. Async + bounded queue
// so a slow webhook can't block the rule-engine hot path; severity
// filter so operators can wire low-noise channels (Slack #alerts)
// to high-severity only without dropping the event entirely.
//
// Failure model: 3 retries with exponential backoff (1s, 4s, 16s);
// drop with a counter increment after that. Drops are reported into
// _server/meta as `meta:alert_webhook_drops` every 30s so an
// operator who wired a wrong URL sees the impact without grepping
// stderr.
type alertWebhookDispatcher struct {
	urls     []string
	minSev   int // 0=low, 1=medium, 2=high, 3=critical
	queue    chan map[string]any
	client   *http.Client
	stopOnce sync.Once
	done     chan struct{}
	logger   *Storage
	metrics  *metricsCollector // optional; nil OK
	dropped  uint64
}

const (
	sevLow      = 0
	sevMedium   = 1
	sevHigh     = 2
	sevCritical = 3
)

// severityRank maps a string severity to an int for comparison.
// Unknown / missing → low so the alert still ships (better noisy
// than silent for a misconfigured rule).
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return sevCritical
	case "high":
		return sevHigh
	case "medium", "med":
		return sevMedium
	case "low", "info", "":
		return sevLow
	}
	return sevLow
}

// newAlertWebhookDispatcher returns nil when no webhooks are
// configured — callers handle nil-receiver as "feature disabled."
// The returned dispatcher starts a single sender goroutine; one
// stream of POSTs serialises across webhooks (cheap; the queue is
// what absorbs bursts).
func newAlertWebhookDispatcher(cfg ServerConfig, logger *Storage, metrics *metricsCollector) *alertWebhookDispatcher {
	urls := []string{}
	for _, u := range cfg.AlertWebhooks {
		u = strings.TrimSpace(u)
		if u != "" {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		return nil
	}
	d := &alertWebhookDispatcher{
		urls:    urls,
		minSev:  severityRank(cfg.AlertWebhookMinSeverity),
		queue:   make(chan map[string]any, 1024),
		done:    make(chan struct{}),
		logger:  logger,
		metrics: metrics,
		client: &http.Client{
			// Operator-controlled URL: keep TLS validation strict by
			// default. If an operator has a self-signed internal
			// webhook receiver they need to add its CA to the host
			// trust store rather than disabling validation here.
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
			},
			Timeout: 15 * time.Second,
		},
	}
	go d.run()
	go d.dropFlusher()
	return d
}

// dispatch enqueues an alert for delivery. Non-blocking: if the
// queue is full (1024 alerts pending), the alert is dropped with a
// counter bump rather than stalling the rule engine. A queue this
// deep means the operator's webhook target is broken; the chain-on-
// disk + replicated-event copies still preserve the alert event
// itself, only the notification side-channel drops.
func (d *alertWebhookDispatcher) dispatch(alert map[string]any) {
	if d == nil {
		return
	}
	if severityRank(strField(alert, "severity")) < d.minSev {
		return
	}
	select {
	case d.queue <- alert:
	case <-d.done:
	default:
		atomic.AddUint64(&d.dropped, 1)
	}
}

func (d *alertWebhookDispatcher) run() {
	for {
		select {
		case <-d.done:
			return
		case alert := <-d.queue:
			body, err := json.Marshal(alert)
			if err != nil {
				continue
			}
			for _, url := range d.urls {
				d.deliverWithRetry(url, body)
			}
		}
	}
}

// deliverWithRetry POSTs the alert to one URL with exponential
// backoff between attempts. Final failure increments the drop
// counter so the periodic drop-flush gives the operator visibility.
func (d *alertWebhookDispatcher) deliverWithRetry(url string, body []byte) {
	delays := []time.Duration{0, time.Second, 4 * time.Second, 16 * time.Second}
	for attempt, delay := range delays {
		if delay > 0 {
			select {
			case <-d.done:
				return
			case <-time.After(delay):
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "simplesiem/"+version)
		resp, err := d.client.Do(req)
		cancel()
		if err == nil {
			ok := resp.StatusCode/100 == 2
			resp.Body.Close()
			if ok {
				return
			}
			// 4xx is permanent — the receiver doesn't like the
			// payload. No point retrying with the same body.
			if resp.StatusCode/100 == 4 {
				atomic.AddUint64(&d.dropped, 1)
				return
			}
		}
		_ = attempt
	}
	atomic.AddUint64(&d.dropped, 1)
}

func (d *alertWebhookDispatcher) dropFlusher() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-d.done:
			return
		case <-t.C:
		}
		if n := atomic.SwapUint64(&d.dropped, 0); n > 0 {
			if d.logger != nil {
				d.logger.Write("meta", map[string]any{
					"event": "alert_webhook_drops",
					"count": n,
					"hint":  "increase webhook responsiveness or check receiver URL — alerts are still in the local alerts log",
				})
			}
			d.metrics.addAlertWebhookDrops(n)
		}
	}
}

// Stop is idempotent — safe to call from multiple shutdown paths.
func (d *alertWebhookDispatcher) Stop() {
	if d == nil {
		return
	}
	d.stopOnce.Do(func() {
		close(d.done)
	})
}

