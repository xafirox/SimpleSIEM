package sieg

import (
	"strings"
	"testing"
)

// TestEventSummary_HostIONoDestinations verifies the s7 fix: when bytes
// flowed but no TCP/UDP flow was visible at poll time (ICMP, raw, or
// sub-poll-lifetime), triage spells out "no active TCP/UDP socket at
// poll time" so the operator doesn't read empty destinations as a
// broken collector.
func TestEventSummary_HostIONoDestinations(t *testing.T) {
	ev := Event{
		Type: "traffic",
		Data: map[string]any{
			"event":      "host_io",
			"bytes_sent": float64(64),
			"bytes_recv": float64(64),
		},
	}
	got := eventSummary(ev)
	if !strings.Contains(got, "no active TCP/UDP socket at poll time") {
		t.Fatalf("missing ICMP/raw note: %q", got)
	}
}

// TestEventSummary_HostIOPerIface verifies per_iface is rendered when
// present (sorted by bytes_sent descending, top 3).
func TestEventSummary_HostIOPerIface(t *testing.T) {
	ev := Event{
		Type: "traffic",
		Data: map[string]any{
			"event":      "host_io",
			"bytes_sent": float64(2048),
			"bytes_recv": float64(1024),
			"per_iface": []any{
				map[string]any{"name": "eth0", "bytes_sent": float64(2000), "bytes_recv": float64(1000)},
				map[string]any{"name": "lo", "bytes_sent": float64(48), "bytes_recv": float64(24)},
			},
		},
	}
	got := eventSummary(ev)
	if !strings.Contains(got, "eth0") {
		t.Fatalf("missing eth0 in per_iface render: %q", got)
	}
	if !strings.Contains(got, "lo") {
		t.Fatalf("missing lo in per_iface render: %q", got)
	}
}

func TestEventSummary_AuthUserAdded(t *testing.T) {
	ev := Event{
		Type: "auth",
		Data: map[string]any{
			"event": "user_added",
			"user":  "alice",
			"uid":   "1001",
			"gid":   "1001",
			"home":  "/home/alice",
			"shell": "/bin/bash",
		},
	}
	got := eventSummary(ev)
	for _, want := range []string{"user_added", "alice", "uid=1001", "home=/home/alice", "shell=/bin/bash"} {
		if !strings.Contains(got, want) {
			t.Errorf("eventSummary missing %q in %q", want, got)
		}
	}
}
