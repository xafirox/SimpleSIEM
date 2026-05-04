package sieg

import (
	"strings"
	"testing"
)

func TestSuggestForBadCommand(t *testing.T) {
	tests := []struct {
		cmd      string
		rest     []string
		wantWord string // substring the suggestion must include
	}{
		{"--at", []string{"now", "--window", "5m"}, "triage --at now --window 5m"},
		{"--pid", []string{"1234"}, "triage --pid 1234"},
		{"--grep", []string{"evil.com"}, "triage --grep evil.com"},
		{"--severity", []string{"high"}, "alerts --severity high"},
		{"--limit", []string{"50"}, "query --limit 50"},
		{"--date", []string{"2026-04-29"}, "verify --date 2026-04-29"},
		{"--mode", []string{"agent"}, "install --mode agent"},
		{"--unknown", []string{}, "triage"}, // default fallback
		{"-at=now", []string{}, "triage -at=now"},
		// non-flag should keep the old "unknown command" wording
		{"banana", []string{}, "unknown command: banana"},
	}
	for _, tc := range tests {
		got := suggestForBadCommand(tc.cmd, tc.rest)
		if !strings.Contains(got, tc.wantWord) {
			t.Errorf("suggestForBadCommand(%q, %v) = %q, want it to contain %q",
				tc.cmd, tc.rest, got, tc.wantWord)
		}
	}
}
