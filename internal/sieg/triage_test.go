package sieg

import (
	"testing"
	"time"
)

func TestParseTimeRef(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
	}{
		{"now", false},
		{"NOW", false},
		{"2026-04-25T13:48:35Z", false},
		{"2026-04-25T13:48:35.123Z", false},
		{"14:30", false},
		{"2pm", false},
		{"2:30pm", false},
		{"12am", false},
		{"12pm", false},
		{"2pm today", false},
		{"2pm yesterday", false},
		{"2pm tomorrow", false},
		{"2026-04-25", false},
		{"2026-04-25 14:30", false},
		{"2026-04-25 2pm", false},
		{"", true},
		{"gibberish", true},
		{"25:00", true}, // hour out of range
		{"13pm", true},  // pm with hour > 12
	}
	for _, tc := range tests {
		_, err := parseTimeRef(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseTimeRef(%q) err=%v wantErr=%v", tc.in, err, tc.wantErr)
		}
	}
}

func TestParseClock(t *testing.T) {
	tests := []struct {
		in           string
		wantH, wantM int
		wantOK       bool
	}{
		{"14:30", 14, 30, true},
		{"14:30:45", 14, 30, true},
		{"2pm", 14, 0, true},
		{"2:30pm", 14, 30, true},
		{"12am", 0, 0, true},
		{"12pm", 12, 0, true},
		{"1am", 1, 0, true},
		{"11pm", 23, 0, true},
		{"0", 0, 0, true},
		{"23", 23, 0, true},
		{"24", 0, 0, false},
		{"-1", 0, 0, false},
		{"abc", 0, 0, false},
		{"13pm", 0, 0, false},
	}
	for _, tc := range tests {
		h, m, _, ok := parseClock(tc.in)
		if ok != tc.wantOK {
			t.Errorf("parseClock(%q) ok=%v want=%v", tc.in, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if h != tc.wantH || m != tc.wantM {
			t.Errorf("parseClock(%q) = %d:%d, want %d:%d", tc.in, h, m, tc.wantH, tc.wantM)
		}
	}
}

func TestProviderLabel(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"ym-in-f113.1e100.net", "Google"},
		{"server.googleusercontent.com", "Google"},
		{"ec2-54-1-2-3.compute-1.amazonaws.com", "AWS"},
		{"d111.cloudfront.net", "AWS CloudFront"},
		{"foo.cloudflare.com", "Cloudflare"},
		{"objects-us-east-1.akamaihd.net", "Akamai"},
		{"cdn.fbcdn.net", "Meta/Facebook"},
		{"x.github.com", "GitHub"},
		{"archive.ubuntu.com", "Canonical/Ubuntu"},
		{"unknown.example.org", ""},
		{"", ""},
	}
	for _, tc := range tests {
		got := providerLabel(tc.host)
		if got != tc.want {
			t.Errorf("providerLabel(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestRenderTarget(t *testing.T) {
	tests := []struct {
		host, remote, want string
	}{
		{"ym-in-f113.1e100.net", "1.2.3.4:80", "Google [ym-in-f113.1e100.net] (1.2.3.4:80)"},
		{"unknown.example.com", "1.2.3.4:80", "unknown.example.com (1.2.3.4:80)"},
		{"", "1.2.3.4:80", "1.2.3.4:80 (no PTR)"},
		{"unknown.example.com", "", "unknown.example.com"},
		{"", "", ""},
	}
	for _, tc := range tests {
		got := renderTarget(tc.host, tc.remote)
		if got != tc.want {
			t.Errorf("renderTarget(%q, %q) = %q, want %q", tc.host, tc.remote, got, tc.want)
		}
	}
}

func TestParseSince(t *testing.T) {
	now := time.Now()
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"30s", 30 * time.Second},
		{"30m", 30 * time.Minute},
		{"2h", 2 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
	}
	for _, tc := range tests {
		got, err := parseSince(tc.in)
		if err != nil {
			t.Errorf("parseSince(%q) err=%v", tc.in, err)
			continue
		}
		// parseSince returns now - dur. Allow 5s slop for execution time.
		diff := now.Sub(got) - tc.want
		if diff < -5*time.Second || diff > 5*time.Second {
			t.Errorf("parseSince(%q) = %v ago, want %v", tc.in, now.Sub(got), tc.want)
		}
	}
	if _, err := parseSince("garbage"); err == nil {
		t.Error("parseSince(garbage) expected error")
	}
}
