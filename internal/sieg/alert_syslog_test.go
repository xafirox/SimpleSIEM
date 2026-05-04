package sieg

import (
	"net"
	"strings"
	"testing"
	"time"
)

// TestAlertSyslog_DispatchesUDP brings up an in-test UDP listener,
// configures the dispatcher to point at it, dispatches an alert, and
// confirms the receiver got an RFC 5424-shaped packet with the rule
// name and severity-priority encoded.
func TestAlertSyslog_DispatchesUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	cfg := ServerConfig{
		AlertSyslog: AlertSyslogConfig{
			Network:     "udp",
			Address:     pc.LocalAddr().String(),
			Facility:    16, // local0
			Tag:         "simplesiem-test",
			SeverityMin: "low",
		},
	}
	d := newAlertSyslogDispatcher(cfg, nil, nil)
	if d == nil {
		t.Fatal("newAlertSyslogDispatcher returned nil with valid address")
	}
	defer d.Stop()

	d.dispatch(map[string]any{
		"event":    "rule_match",
		"rule":     "test-rule",
		"severity": "high",
	})

	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	got := string(buf[:n])
	// Priority for facility=16, severity=high(=3): 16*8+3 = 131.
	if !strings.HasPrefix(got, "<131>1 ") {
		t.Errorf("frame priority: got %q, want prefix '<131>1 '", got[:min(20, len(got))])
	}
	if !strings.Contains(got, "simplesiem-test") {
		t.Errorf("frame missing tag: %q", got)
	}
	if !strings.Contains(got, "test-rule") {
		t.Errorf("frame missing rule MSGID: %q", got)
	}
	if !strings.Contains(got, `"rule":"test-rule"`) {
		t.Errorf("frame missing JSON body: %q", got)
	}
}

// TestAlertSyslog_SeverityFilter verifies alerts below severity_min
// never reach the wire.
func TestAlertSyslog_SeverityFilter(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	cfg := ServerConfig{
		AlertSyslog: AlertSyslogConfig{
			Network:     "udp",
			Address:     pc.LocalAddr().String(),
			Tag:         "test",
			SeverityMin: "high",
		},
	}
	d := newAlertSyslogDispatcher(cfg, nil, nil)
	defer d.Stop()
	d.dispatch(map[string]any{"event": "rule_match", "rule": "low-rule", "severity": "low"})
	d.dispatch(map[string]any{"event": "rule_match", "rule": "med-rule", "severity": "medium"})

	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, _, err := pc.ReadFrom(buf); err == nil {
		t.Error("expected no datagram (both alerts below min severity), but received one")
	}
}

// TestAlertSyslog_NoAddressReturnsNil confirms an empty address means
// "feature disabled" rather than panicking on dispatch.
func TestAlertSyslog_NoAddressReturnsNil(t *testing.T) {
	d := newAlertSyslogDispatcher(ServerConfig{}, nil, nil)
	if d != nil {
		t.Errorf("newAlertSyslogDispatcher with empty address: got %v, want nil", d)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
