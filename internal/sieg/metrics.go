package sieg

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// metricsCollector aggregates counters that the operator's Prometheus
// scraper picks up at /metrics. Hand-rolled text format — pulling in
// the full prometheus/client_golang dependency just for counters is
// disproportionate to the value (six counters and a couple of gauges).
//
// Metric names follow Prometheus convention: simplesiem_<subsystem>_<units>_total
// for counters, simplesiem_<subsystem>_<units> for gauges. Help text
// describes "what" not "how" so operators can build dashboards without
// reading the source.
type metricsCollector struct {
	// Atomic counters for the hot path. No labels (single-value).
	eventsIngestedTotal    uint64
	eventsRejectedTotal    uint64
	alertWebhookDropsTotal uint64
	alertSyslogDropsTotal  uint64
	httpAuthFailuresTotal  uint64

	// Per-host / per-rule counters: lock-protected map. Update freq
	// is at most one increment per ingested batch, not per event, so
	// the mutex is a non-issue in practice.
	mu               sync.Mutex
	eventsByHostType map[hostTypeKey]uint64
	alertFiresByRule map[ruleSevKey]uint64
	agentsActive     map[string]bool // CN -> seen-recently set
}

type hostTypeKey struct {
	host    string
	logType string
}

type ruleSevKey struct {
	rule string
	sev  string
}

func newMetricsCollector() *metricsCollector {
	return &metricsCollector{
		eventsByHostType: map[hostTypeKey]uint64{},
		alertFiresByRule: map[ruleSevKey]uint64{},
		agentsActive:     map[string]bool{},
	}
}

// recordIngest is called once per accepted event. Tally happens under
// the per-host counters too so we can answer "events from agent X
// today" via the timestamped Prometheus rate query.
func (m *metricsCollector) recordIngest(host, logType string) {
	if m == nil {
		return
	}
	atomic.AddUint64(&m.eventsIngestedTotal, 1)
	m.mu.Lock()
	m.eventsByHostType[hostTypeKey{host: host, logType: logType}]++
	if host != "" && host != "_server" && host != "_master" && host != "_collector" {
		m.agentsActive[host] = true
	}
	m.mu.Unlock()
}

// recordReject increments the rejected-events counter (rule-engine
// rejected, allowlist rejected, gzip-bomb rejected, etc.). Distinct
// from ingested so dashboards can surface the ratio directly.
func (m *metricsCollector) recordReject() {
	if m == nil {
		return
	}
	atomic.AddUint64(&m.eventsRejectedTotal, 1)
}

func (m *metricsCollector) recordAlertFire(rule, severity string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.alertFiresByRule[ruleSevKey{rule: rule, sev: severity}]++
	m.mu.Unlock()
}

func (m *metricsCollector) recordAuthFailure() {
	if m == nil {
		return
	}
	atomic.AddUint64(&m.httpAuthFailuresTotal, 1)
}

// addAlertWebhookDrops + addAlertSyslogDrops are called by the
// dispatchers' periodic flushers so the collector mirrors the same
// counter the meta:alert_*_drops events surface. Doing it here too
// lets Prometheus alert on drops without parsing meta events.
func (m *metricsCollector) addAlertWebhookDrops(n uint64) {
	if m == nil {
		return
	}
	atomic.AddUint64(&m.alertWebhookDropsTotal, n)
}

func (m *metricsCollector) addAlertSyslogDrops(n uint64) {
	if m == nil {
		return
	}
	atomic.AddUint64(&m.alertSyslogDropsTotal, n)
}

// renderPrometheus writes the collector's current counters as
// Prometheus text-format exposition. Help and TYPE lines come first
// per metric family, then label-value rows. Ordering is deterministic
// so diff-based debugging works.
func (m *metricsCollector) renderPrometheus(w http.ResponseWriter) {
	if m == nil {
		http.Error(w, "metrics collector not initialised", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	fmt.Fprintln(w, "# HELP simplesiem_events_ingested_total Total events accepted from agents and stored.")
	fmt.Fprintln(w, "# TYPE simplesiem_events_ingested_total counter")
	fmt.Fprintf(w, "simplesiem_events_ingested_total %d\n", atomic.LoadUint64(&m.eventsIngestedTotal))

	fmt.Fprintln(w, "# HELP simplesiem_events_rejected_total Events refused at ingest (rule, allowlist, gzip-bomb, decode-error).")
	fmt.Fprintln(w, "# TYPE simplesiem_events_rejected_total counter")
	fmt.Fprintf(w, "simplesiem_events_rejected_total %d\n", atomic.LoadUint64(&m.eventsRejectedTotal))

	fmt.Fprintln(w, "# HELP simplesiem_http_auth_failures_total Authentication failures on the server's HTTP endpoints.")
	fmt.Fprintln(w, "# TYPE simplesiem_http_auth_failures_total counter")
	fmt.Fprintf(w, "simplesiem_http_auth_failures_total %d\n", atomic.LoadUint64(&m.httpAuthFailuresTotal))

	fmt.Fprintln(w, "# HELP simplesiem_alert_webhook_drops_total Alerts dropped from the webhook dispatch queue (overflow / 4xx / max-retry exhaustion).")
	fmt.Fprintln(w, "# TYPE simplesiem_alert_webhook_drops_total counter")
	fmt.Fprintf(w, "simplesiem_alert_webhook_drops_total %d\n", atomic.LoadUint64(&m.alertWebhookDropsTotal))

	fmt.Fprintln(w, "# HELP simplesiem_alert_syslog_drops_total Alerts dropped from the syslog dispatch queue.")
	fmt.Fprintln(w, "# TYPE simplesiem_alert_syslog_drops_total counter")
	fmt.Fprintf(w, "simplesiem_alert_syslog_drops_total %d\n", atomic.LoadUint64(&m.alertSyslogDropsTotal))

	m.mu.Lock()
	hostByType := make([]struct {
		k hostTypeKey
		v uint64
	}, 0, len(m.eventsByHostType))
	for k, v := range m.eventsByHostType {
		hostByType = append(hostByType, struct {
			k hostTypeKey
			v uint64
		}{k, v})
	}
	ruleByFire := make([]struct {
		k ruleSevKey
		v uint64
	}, 0, len(m.alertFiresByRule))
	for k, v := range m.alertFiresByRule {
		ruleByFire = append(ruleByFire, struct {
			k ruleSevKey
			v uint64
		}{k, v})
	}
	agentCount := len(m.agentsActive)
	m.mu.Unlock()

	fmt.Fprintln(w, "# HELP simplesiem_agents_active Number of distinct agent CNs that have shipped at least one event since daemon start.")
	fmt.Fprintln(w, "# TYPE simplesiem_agents_active gauge")
	fmt.Fprintf(w, "simplesiem_agents_active %d\n", agentCount)

	sort.Slice(hostByType, func(i, j int) bool {
		if hostByType[i].k.host != hostByType[j].k.host {
			return hostByType[i].k.host < hostByType[j].k.host
		}
		return hostByType[i].k.logType < hostByType[j].k.logType
	})
	if len(hostByType) > 0 {
		fmt.Fprintln(w, "# HELP simplesiem_events_by_host_type_total Per-host per-type ingest counter.")
		fmt.Fprintln(w, "# TYPE simplesiem_events_by_host_type_total counter")
		for _, kv := range hostByType {
			fmt.Fprintf(w, "simplesiem_events_by_host_type_total{host=%q,type=%q} %d\n",
				escapeLabelValue(kv.k.host), escapeLabelValue(kv.k.logType), kv.v)
		}
	}

	sort.Slice(ruleByFire, func(i, j int) bool {
		if ruleByFire[i].k.rule != ruleByFire[j].k.rule {
			return ruleByFire[i].k.rule < ruleByFire[j].k.rule
		}
		return ruleByFire[i].k.sev < ruleByFire[j].k.sev
	})
	if len(ruleByFire) > 0 {
		fmt.Fprintln(w, "# HELP simplesiem_alert_fires_total Rule fires by rule name and severity.")
		fmt.Fprintln(w, "# TYPE simplesiem_alert_fires_total counter")
		for _, kv := range ruleByFire {
			fmt.Fprintf(w, "simplesiem_alert_fires_total{rule=%q,severity=%q} %d\n",
				escapeLabelValue(kv.k.rule), escapeLabelValue(kv.k.sev), kv.v)
		}
	}
}

// escapeLabelValue applies the Prometheus exposition escaping rules
// for label-value strings: backslash, double-quote, newline.
func escapeLabelValue(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
