package sieg

import (
	"os"
	"testing"
)

// TestPickServerLocalID_ExplicitWins locks in that a configured
// server.local_id beats the hostname when it's a valid agent ID.
func TestPickServerLocalID_ExplicitWins(t *testing.T) {
	got := pickServerLocalID("siem-prod-01")
	if got != "siem-prod-01" {
		t.Errorf("got %q, want siem-prod-01", got)
	}
}

// TestPickServerLocalID_InvalidExplicitFallsBack ensures a misconfigured
// local_id (e.g. with a path separator) doesn't get used as a directory
// component — a server with `"local_id": "../foo"` must not be able to
// escape the log dir; the fallback handles that.
func TestPickServerLocalID_InvalidExplicitFallsBack(t *testing.T) {
	got := pickServerLocalID("../escape")
	hn, _ := os.Hostname()
	if validAgentID(hn) {
		if got != hn {
			t.Errorf("got %q, want hostname %q", got, hn)
		}
	} else if got != "_localhost" {
		t.Errorf("got %q, want _localhost", got)
	}
}

// TestPickServerLocalID_EmptyUsesHostname covers the default path: no
// explicit override → use the OS hostname. On platforms where the
// hostname returns empty or invalid (e.g. minimal containers without
// /etc/hostname), the fallback to "_localhost" must kick in instead of
// returning an empty string that NewStorage would refuse.
func TestPickServerLocalID_EmptyUsesHostname(t *testing.T) {
	got := pickServerLocalID("")
	if got == "" {
		t.Error("pickServerLocalID returned empty string")
	}
	if !validAgentID(got) {
		t.Errorf("pickServerLocalID returned invalid agent ID: %q", got)
	}
}
