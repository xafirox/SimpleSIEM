//go:build darwin

package sieg

import "testing"

func TestParseDarwinAuthLine_SSH(t *testing.T) {
	tests := []struct {
		ndjson  string
		wantEv  string
		wantRes string
		wantU   string
		wantR   string
	}{
		{
			`{"eventMessage":"Accepted password for alice from 10.0.0.5 port 54321 ssh2","processImagePath":"/usr/sbin/sshd"}`,
			"ssh_login", "success", "alice", "10.0.0.5",
		},
		{
			`{"eventMessage":"Failed password for alice from 10.0.0.5 port 54321 ssh2","processImagePath":"/usr/sbin/sshd"}`,
			"ssh_login", "failed", "alice", "10.0.0.5",
		},
		{
			`{"eventMessage":"Failed password for invalid user bob from 10.0.0.5 port 54321 ssh2","processImagePath":"/usr/sbin/sshd"}`,
			"ssh_login", "failed", "bob", "10.0.0.5",
		},
		{
			`{"eventMessage":"Invalid user bob from 10.0.0.5 port 54321","processImagePath":"/usr/sbin/sshd"}`,
			"ssh_login", "invalid_user", "bob", "10.0.0.5",
		},
	}
	for _, tc := range tests {
		got := parseDarwinAuthLine([]byte(tc.ndjson))
		if got == nil {
			t.Errorf("parseDarwinAuthLine(%q) returned nil", tc.ndjson)
			continue
		}
		if got["event"] != tc.wantEv ||
			got["result"] != tc.wantRes ||
			got["user"] != tc.wantU ||
			got["remote"] != tc.wantR {
			t.Errorf("parseDarwinAuthLine: got %+v want event=%s result=%s user=%s remote=%s",
				got, tc.wantEv, tc.wantRes, tc.wantU, tc.wantR)
		}
	}
}

func TestParseDarwinAuthLine_Sudo(t *testing.T) {
	line := `{"eventMessage":"alice : TTY=ttys000 ; PWD=/Users/alice ; USER=root ; COMMAND=/bin/bash -i","processImagePath":"/usr/bin/sudo"}`
	got := parseDarwinAuthLine([]byte(line))
	if got == nil {
		t.Fatal("expected sudo to parse")
	}
	if got["event"] != "sudo" || got["user"] != "alice" || got["target"] != "root" {
		t.Errorf("got %+v", got)
	}
	if got["command"] != "/bin/bash -i" {
		t.Errorf("command=%v", got["command"])
	}
}

func TestParseDarwinAuthLine_Noise(t *testing.T) {
	noisy := []string{
		``,
		`{"eventMessage":"random kernel message","processImagePath":"/sbin/launchd"}`,
		`not json`,
	}
	for _, line := range noisy {
		if got := parseDarwinAuthLine([]byte(line)); got != nil {
			t.Errorf("expected nil for %q, got %+v", line, got)
		}
	}
}

// TestExtractDarwinTimestamp_Formats covers the layouts emitted by
// `log show` and `log stream --style ndjson` across recent macOS
// versions. extractDarwinTimestamp is what the backfill watermark
// anchors on, so robustness here directly affects "did we lose
// events on the gap?".
func TestExtractDarwinTimestamp_Formats(t *testing.T) {
	cases := []string{
		`{"timestamp":"2026-05-02 18:22:33.123456-0400","eventMessage":"x"}`,
		`{"timestamp":"2026-05-02 18:22:33-0400","eventMessage":"x"}`,
		`{"timestamp":"2026-05-02T18:22:33.123456-04:00","eventMessage":"x"}`,
	}
	for _, c := range cases {
		ts := extractDarwinTimestamp([]byte(c))
		if ts.IsZero() {
			t.Errorf("extractDarwinTimestamp returned zero for %q", c)
		}
		if ts.Year() != 2026 || ts.Month() != 5 || ts.Day() != 2 {
			t.Errorf("date wrong for %q: got %v", c, ts)
		}
	}
}

func TestExtractDarwinTimestamp_BadInput(t *testing.T) {
	cases := []string{
		``,
		`{"timestamp":""}`,
		`{"timestamp":"not a date"}`,
		`not even json`,
	}
	for _, c := range cases {
		ts := extractDarwinTimestamp([]byte(c))
		if !ts.IsZero() {
			t.Errorf("extractDarwinTimestamp expected zero for %q, got %v", c, ts)
		}
	}
}
