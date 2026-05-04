package sieg

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMetrics_RenderPrometheusFormat exercises the exposition format:
// HELP/TYPE lines, label escaping, sorted output. Doesn't validate
// every counter — just that the families are present after we record
// some events.
func TestMetrics_RenderPrometheusFormat(t *testing.T) {
	m := newMetricsCollector()
	m.recordIngest("agent-a", "auth")
	m.recordIngest("agent-a", "auth")
	m.recordIngest("agent-b", "files")
	m.recordReject()
	m.recordAlertFire("brute-force", "high")
	m.recordAlertFire("brute-force", "high")
	m.recordAuthFailure()
	m.addAlertWebhookDrops(7)
	m.addAlertSyslogDrops(3)

	rr := httptest.NewRecorder()
	m.renderPrometheus(rr)
	body := rr.Body.String()

	wants := []string{
		"# HELP simplesiem_events_ingested_total",
		"# TYPE simplesiem_events_ingested_total counter",
		"simplesiem_events_ingested_total 3",
		"simplesiem_events_rejected_total 1",
		"simplesiem_http_auth_failures_total 1",
		"simplesiem_alert_webhook_drops_total 7",
		"simplesiem_alert_syslog_drops_total 3",
		"simplesiem_agents_active 2",
		`simplesiem_events_by_host_type_total{host="agent-a",type="auth"} 2`,
		`simplesiem_events_by_host_type_total{host="agent-b",type="files"} 1`,
		`simplesiem_alert_fires_total{rule="brute-force",severity="high"} 2`,
	}
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("metrics body missing line %q\n--- body ---\n%s", w, body)
		}
	}
}

// TestMetrics_LabelEscaping verifies that backslashes, double-quotes,
// and newlines in label values are escaped per the Prometheus spec.
func TestMetrics_LabelEscaping(t *testing.T) {
	got := escapeLabelValue(`host"with\"quote and\backslash` + "\nnewline")
	want := `host\"with\\\"quote and\\backslash\nnewline`
	if got != want {
		t.Errorf("escapeLabelValue:\ngot:  %q\nwant: %q", got, want)
	}
}

// TestMetrics_NilReceiverNoOps confirms every counter API tolerates a
// nil collector — the integration sites use `s.metrics.recordIngest(...)`
// without an explicit nil-check, so a daemon that didn't initialise the
// collector must not panic on the hot path.
func TestMetrics_NilReceiverNoOps(t *testing.T) {
	var m *metricsCollector
	m.recordIngest("h", "t")
	m.recordReject()
	m.recordAlertFire("r", "high")
	m.recordAuthFailure()
	m.addAlertWebhookDrops(1)
	m.addAlertSyslogDrops(1)
}
