package sieg

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// alertSyslogDispatcher forwards every fired alert as an RFC 5424
// syslog message to a single configured collector. Used by ops teams
// who already have Splunk / Elastic / rsyslog pipelines and want
// SimpleSIEM alerts to land there alongside the rest of their fleet
// telemetry, without standing up a separate webhook receiver.
//
// Failure model: best-effort UDP / TCP send. UDP is fire-and-forget
// (no retries — UDP loss is the operator's existing reality). TCP
// has one retry with a 1s backoff; further failures bump the drop
// counter, surfaced via meta:alert_syslog_drops every 30s.
//
// Severity filter mirrors the webhook dispatcher: alerts below
// `alert_syslog.severity_min` are skipped before the queue.
type alertSyslogDispatcher struct {
	network     string // "udp" / "tcp" / "udp6" / "tcp6"
	address     string // e.g. "syslog.example.com:514"
	facility    int    // 0..23, RFC 5424 facility
	tag         string // appname / msgid prefix
	minSev      int
	queue       chan map[string]any
	conn        net.Conn
	connMu      sync.Mutex
	done        chan struct{}
	stopOnce    sync.Once
	logger      *Storage
	metrics     *metricsCollector
	dropped     uint64
	hostname    string
	dialBackoff time.Duration
}

// newAlertSyslogDispatcher returns nil when no syslog endpoint is
// configured — callers handle nil-receiver as "feature disabled."
func newAlertSyslogDispatcher(cfg ServerConfig, logger *Storage, metrics *metricsCollector) *alertSyslogDispatcher {
	sc := cfg.AlertSyslog
	addr := strings.TrimSpace(sc.Address)
	if addr == "" {
		return nil
	}
	network := strings.ToLower(strings.TrimSpace(sc.Network))
	switch network {
	case "":
		network = "udp"
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
	default:
		// Unknown network — disable the dispatcher rather than
		// silently dropping every alert. The operator gets a clear
		// log line on startup; the alerts continue to reach disk.
		if logger != nil {
			logger.Write("errors", map[string]any{
				"collector": "alert_syslog",
				"error":     "unknown network: " + sc.Network,
				"hint":      "use 'udp', 'tcp', 'udp6', or 'tcp6' (or omit for udp default)",
			})
		}
		return nil
	}
	tag := strings.TrimSpace(sc.Tag)
	if tag == "" {
		tag = "simplesiem"
	}
	facility := sc.Facility
	if facility < 0 || facility > 23 {
		facility = 16 // local0
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "-"
	}
	d := &alertSyslogDispatcher{
		network:  network,
		address:  addr,
		facility: facility,
		tag:      tag,
		minSev:   severityRank(sc.SeverityMin),
		queue:    make(chan map[string]any, 1024),
		done:     make(chan struct{}),
		logger:   logger,
		metrics:  metrics,
		hostname: host,
	}
	go d.run()
	go d.dropFlusher()
	return d
}

// dispatch enqueues an alert. Same non-blocking semantics as the
// webhook dispatcher: if the queue is full the alert is dropped
// rather than stalling the rule engine.
func (d *alertSyslogDispatcher) dispatch(alert map[string]any) {
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

func (d *alertSyslogDispatcher) run() {
	for {
		select {
		case <-d.done:
			d.closeConn()
			return
		case alert := <-d.queue:
			d.send(alert)
		}
	}
}

// send formats one alert as RFC 5424 and writes it. UDP gets one
// shot; TCP gets one re-dial on send failure, then drops. RFC 5424
// limits the priority to 0..191 (3 severity bits + 5 facility bits
// shifted up).
func (d *alertSyslogDispatcher) send(alert map[string]any) {
	body, err := json.Marshal(alert)
	if err != nil {
		atomic.AddUint64(&d.dropped, 1)
		return
	}
	syslogSev := alertSeverityToSyslog(strField(alert, "severity"))
	pri := d.facility*8 + syslogSev
	rule := strField(alert, "rule")
	msgID := "rule_match"
	if rule != "" {
		msgID = rule
	}
	// RFC 5424 frame: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
	// PROCID = "-" (stateless), STRUCTURED-DATA = "-" (we put everything in JSON MSG body).
	now := time.Now().UTC().Format(time.RFC3339)
	frame := fmt.Sprintf("<%d>1 %s %s %s - %s - %s\n",
		pri, now, d.hostname, d.tag, msgID, body)
	for attempt := 0; attempt < 2; attempt++ {
		if err := d.write([]byte(frame)); err == nil {
			return
		}
		if d.network == "udp" || d.network == "udp4" || d.network == "udp6" {
			break // UDP isn't retried — packet's gone or it isn't.
		}
		// TCP retry: drop the connection so write() re-dials.
		d.closeConn()
		time.Sleep(time.Second)
	}
	atomic.AddUint64(&d.dropped, 1)
}

func (d *alertSyslogDispatcher) write(b []byte) error {
	d.connMu.Lock()
	defer d.connMu.Unlock()
	if d.conn == nil {
		// Avoid hammering a down receiver: if the last dial failed
		// recently, sleep the remaining backoff before retrying.
		if d.dialBackoff > 0 {
			time.Sleep(d.dialBackoff)
		}
		c, err := net.DialTimeout(d.network, d.address, 5*time.Second)
		if err != nil {
			if d.dialBackoff < 30*time.Second {
				d.dialBackoff = d.dialBackoff*2 + time.Second
			}
			return err
		}
		d.dialBackoff = 0
		d.conn = c
	}
	_ = d.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := d.conn.Write(b)
	if err != nil {
		// Force re-dial on next send.
		_ = d.conn.Close()
		d.conn = nil
	}
	return err
}

func (d *alertSyslogDispatcher) closeConn() {
	d.connMu.Lock()
	defer d.connMu.Unlock()
	if d.conn != nil {
		_ = d.conn.Close()
		d.conn = nil
	}
}

func (d *alertSyslogDispatcher) dropFlusher() {
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
					"event": "alert_syslog_drops",
					"count": n,
					"hint":  "syslog receiver " + d.address + " refused or unreachable — alerts are still in the local alerts log",
				})
			}
			d.metrics.addAlertSyslogDrops(n)
		}
	}
}

// Stop is idempotent — safe to call from multiple shutdown paths.
func (d *alertSyslogDispatcher) Stop() {
	if d == nil {
		return
	}
	d.stopOnce.Do(func() {
		close(d.done)
	})
}

// alertSeverityToSyslog maps SimpleSIEM's 4-tier severity to a
// reasonable RFC 5424 severity number (0=emergency .. 7=debug).
//
//	critical → 2 (Critical)
//	high     → 3 (Error)
//	medium   → 4 (Warning)
//	low      → 5 (Notice)
//
// The mapping is opinionated but predictable — operators can always
// re-classify in their downstream syslog config.
func alertSeverityToSyslog(s string) int {
	switch severityRank(s) {
	case sevCritical:
		return 2
	case sevHigh:
		return 3
	case sevMedium:
		return 4
	default:
		return 5
	}
}
