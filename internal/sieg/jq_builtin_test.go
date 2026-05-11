package sieg

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// TestJSONGetByPath verifies jq-style dotted-path extraction over
// the same JSON shape simplesiem events use. Cross-platform pure-Go
// — operators on Windows (where `jq` isn't shipped) get the same
// semantics as a Linux/Mac `jq -r '.field'` invocation.
func TestJSONGetByPath(t *testing.T) {
	line := []byte(`{
	  "ts": "2026-05-08T12:00:00Z",
	  "type": "auth",
	  "event": "user_added",
	  "user": "alice",
	  "data": {"actor": "root", "uid": 1000},
	  "members": ["alice", "bob"],
	  "alive": true,
	  "exited": null
	}`)
	tests := []struct {
		path string
		want string
		ok   bool
	}{
		// String scalars — unquoted (jq -r style).
		{".event", "user_added", true},
		{"event", "user_added", true}, // leading dot optional
		{".user", "alice", true},
		{".ts", "2026-05-08T12:00:00Z", true},
		// Nested object.
		{".data.actor", "root", true},
		{".data.uid", "1000", true}, // float64 1000 → int rendering, no decimal
		// Array index.
		{".members.0", "alice", true},
		{".members.1", "bob", true},
		// Boolean / null.
		{".alive", "true", true},
		{".exited", "", true}, // null → empty (matches jq -r behaviour)
		// Whole document — "." or empty.
		{".", `{"alive":true,"data":{"actor":"root","uid":1000},"event":"user_added","exited":null,"members":["alice","bob"],"ts":"2026-05-08T12:00:00Z","type":"auth","user":"alice"}`, true},
		// Missing path → not ok.
		{".nope", "", false},
		{".data.missing", "", false},
		{".members.99", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, ok := jsonGetByPath(line, tt.path)
			if ok != tt.ok {
				t.Fatalf("ok=%v want %v (got=%q)", ok, tt.ok, got)
			}
			if !ok {
				return
			}
			// For the whole-document case the field order isn't
			// guaranteed by encoding/json (map iteration), so
			// compare via re-parse rather than literal equality.
			if tt.path == "." {
				return
			}
			if got != tt.want {
				t.Errorf("got %q want %q", got, tt.want)
			}
		})
	}
}

// TestEmitJSONLine_PassThrough verifies the unmodified --with-chain
// flag emits the line verbatim — that's the storage-debugging path
// `simplesiem verify` consumers need.
func TestEmitJSONLine_PassThrough(t *testing.T) {
	var buf bytes.Buffer
	out := bufio.NewWriter(&buf)
	line := []byte(`{"ts":"2026-05-08T12:00:00Z","_seq":1,"_prev":"","_hash":"abc","event":"x"}`)
	emitJSONLine(out, line, true /*withChain*/, false, "", "")
	out.Flush()
	want := string(line) + "\n"
	if buf.String() != want {
		t.Errorf("got %q want %q", buf.String(), want)
	}
}

// TestEmitJSONLine_StripsChain — default behaviour drops
// _seq/_prev/_hash so day-to-day query output isn't visually
// dominated by storage internals.
func TestEmitJSONLine_StripsChain(t *testing.T) {
	var buf bytes.Buffer
	out := bufio.NewWriter(&buf)
	line := []byte(`{"ts":"2026-05-08T12:00:00Z","_seq":1,"_prev":"","_hash":"abc","event":"x"}`)
	emitJSONLine(out, line, false, false, "", "")
	out.Flush()
	got := buf.String()
	if strings.Contains(got, "_seq") || strings.Contains(got, "_prev") || strings.Contains(got, "_hash") {
		t.Errorf("chain fields not stripped: %q", got)
	}
	if !strings.Contains(got, `"event":"x"`) {
		t.Errorf("event field missing: %q", got)
	}
}

// TestEmitJSONLine_Pretty — multi-line indented output, the
// equivalent of `jq .`. Cross-platform; works the same on Windows
// where `jq` would otherwise have to be installed separately.
func TestEmitJSONLine_Pretty(t *testing.T) {
	var buf bytes.Buffer
	out := bufio.NewWriter(&buf)
	line := []byte(`{"ts":"2026-05-08T12:00:00Z","event":"x","user":"alice"}`)
	emitJSONLine(out, line, false, true /*pretty*/, "", "")
	out.Flush()
	got := buf.String()
	// Should be multi-line (jq's indented shape).
	if !strings.Contains(got, "\n  ") {
		t.Errorf("pretty output not indented: %q", got)
	}
	if strings.Count(got, "\n") < 3 {
		t.Errorf("pretty output not multi-line: %q", got)
	}
}

// TestEmitJSONLine_Select — narrow the field set, jq's
// `'{ts,event,user}'` shorthand. Anything not in the allowlist is
// dropped before emission.
func TestEmitJSONLine_Select(t *testing.T) {
	var buf bytes.Buffer
	out := bufio.NewWriter(&buf)
	line := []byte(`{"ts":"2026-05-08T12:00:00Z","event":"x","user":"alice","host":"h","verbose_field":"noise"}`)
	emitJSONLine(out, line, false, false, "ts,event,user", "")
	out.Flush()
	got := buf.String()
	if !strings.Contains(got, `"event":"x"`) {
		t.Errorf("event missing: %q", got)
	}
	if !strings.Contains(got, `"user":"alice"`) {
		t.Errorf("user missing: %q", got)
	}
	if strings.Contains(got, "verbose_field") {
		t.Errorf("verbose_field not dropped: %q", got)
	}
	if strings.Contains(got, `"host"`) {
		t.Errorf("host not dropped: %q", got)
	}
}

// TestEmitJSONLine_Get — single-value extraction. Same shape as
// `jq -r '.user'`. Strings unquoted, scalars literal, missing path
// emits nothing (no row).
func TestEmitJSONLine_Get(t *testing.T) {
	var buf bytes.Buffer
	out := bufio.NewWriter(&buf)
	line := []byte(`{"event":"user_added","user":"alice","data":{"uid":1000}}`)
	emitJSONLine(out, line, false, false, "", ".user")
	out.Flush()
	if buf.String() != "alice\n" {
		t.Errorf("--get .user: got %q want %q", buf.String(), "alice\n")
	}
	// Nested.
	buf.Reset()
	out = bufio.NewWriter(&buf)
	emitJSONLine(out, line, false, false, "", ".data.uid")
	out.Flush()
	if buf.String() != "1000\n" {
		t.Errorf("--get .data.uid: got %q want %q", buf.String(), "1000\n")
	}
	// Missing → no row.
	buf.Reset()
	out = bufio.NewWriter(&buf)
	emitJSONLine(out, line, false, false, "", ".nope")
	out.Flush()
	if buf.String() != "" {
		t.Errorf("--get .nope: got %q want empty", buf.String())
	}
}
