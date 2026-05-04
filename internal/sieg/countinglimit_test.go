package sieg

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestCountingLimitReader_StopsAtLimit ensures the reader caps the byte
// count and signals truncation, defeating the gzip-bomb attack class
// (compressed body bounded but decompressed stream isn't).
func TestCountingLimitReader_StopsAtLimit(t *testing.T) {
	src := bytes.NewReader([]byte(strings.Repeat("a", 10000)))
	cr := &countingLimitReader{r: src, limit: 100}
	got, err := io.ReadAll(cr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 100 {
		t.Errorf("got %d bytes, want 100", len(got))
	}
	if !cr.truncated {
		t.Error("expected truncated=true after exceeding limit")
	}
}

func TestCountingLimitReader_NotTruncatedUnderLimit(t *testing.T) {
	src := bytes.NewReader([]byte("hello"))
	cr := &countingLimitReader{r: src, limit: 100}
	got, err := io.ReadAll(cr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want hello", got)
	}
	if cr.truncated {
		t.Error("should not be truncated when under limit")
	}
}

func TestValidAgentID(t *testing.T) {
	good := []string{"a", "laptop-01", "prod.web.04", "agent_42",
		"abc-def_ghi.example.com", "A1"}
	bad := []string{
		"", ".", "..", "...", "..foo", ".foo", "a/b", "a\\b",
		"a..b", "a/../b", "con", "PRN", "nul", "COM1", "lpt9",
	}
	for _, id := range good {
		if !validAgentID(id) {
			t.Errorf("validAgentID(%q) = false, want true", id)
		}
	}
	for _, id := range bad {
		if validAgentID(id) {
			t.Errorf("validAgentID(%q) = true, want false", id)
		}
	}
}
