package sieg

import (
	"path/filepath"
	"testing"
)

// TestSafeHostName_RejectsTraversal locks in the agent-ID validation. The
// regex was previously permissive enough to accept "..", which let a
// caller controlling X-SimpleSIEM-Host (or holding a CA-signed cert with
// CN="..") escape the log directory via filepath.Join. Keep this test if
// you change validHostName.
func TestSafeHostName_RejectsTraversal(t *testing.T) {
	base := t.TempDir()

	bad := []string{
		"",        // empty
		".",       // CWD
		"..",      // parent — the canonical traversal
		"...",     // pure dots
		"..foo",   // leading-dot variants
		".foo",    // hidden-file style
		"a/b",     // path separator
		"a\\b",    // windows separator
		"a..b",    // embedded ..
		"a/../b",  // explicit traversal
		"con",     // windows reserved
		"PRN",     // case-insensitive reserved
		"nul",     // ditto
		"x" + filepath.FromSlash("/y"), // any path-like host
	}
	for _, h := range bad {
		if safeHostName(base, h) {
			t.Errorf("safeHostName(%q) = true, want false", h)
		}
	}

	good := []string{
		"a",
		"laptop-01",
		"prod.web.04",
		"agent_42",
		"A1",
		"abc-def_ghi.example.com",
	}
	for _, h := range good {
		if !safeHostName(base, h) {
			t.Errorf("safeHostName(%q) = false, want true", h)
		}
	}

	// Length boundary: 128 chars is OK, 129 isn't.
	const okLen = 128
	const badLen = 129
	makeName := func(n int) string {
		out := make([]byte, n)
		for i := range out {
			out[i] = 'a'
		}
		return string(out)
	}
	if !safeHostName(base, makeName(okLen)) {
		t.Errorf("safeHostName(%d-char name) rejected, expected accept", okLen)
	}
	if safeHostName(base, makeName(badLen)) {
		t.Errorf("safeHostName(%d-char name) accepted, expected reject", badLen)
	}
}
