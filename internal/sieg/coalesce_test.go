package sieg

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// captureStdout redirects os.Stdout to a pipe and returns the captured
// output. Used to test print* functions that don't take an io.Writer.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

func mkFileEvent(ts time.Time, path, ev string) Event {
	return Event{
		TS:   ts,
		Type: "files",
		Data: map[string]any{"event": ev, "path": path, "user": "root"},
	}
}

// TestPrintTriageMulti_CoalescesConsecutiveDuplicates writes events to
// a temp dir, then runs printTriageMulti and asserts:
//   - 50 identical "modified" events become one line with "(×50 over ...)"
//   - a different event in the middle of duplicates is NOT hidden
//   - the pivot is always emitted in full (>> marker) even if its
//     summary matches surrounding events
func TestPrintTriageMulti_CoalescesConsecutiveDuplicates(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStorage(dir, 0, 0, 256)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}

	base := time.Now().UTC()
	// Write: 30 identical modify, 1 created (different summary), 30 more modify.
	for i := 0; i < 30; i++ {
		st.Write("files", map[string]any{
			"event": "modified", "path": "/tmp/x", "user": "root",
			"ts": base.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano),
		})
	}
	st.Write("files", map[string]any{
		"event": "created", "path": "/tmp/y", "user": "root",
		"ts": base.Add(40 * time.Millisecond).Format(time.RFC3339Nano),
	})
	for i := 0; i < 30; i++ {
		st.Write("files", map[string]any{
			"event": "modified", "path": "/tmp/x", "user": "root",
			"ts": base.Add(time.Duration(50+i) * time.Millisecond).Format(time.RFC3339Nano),
		})
	}
	st.Close()

	pivot := Event{TS: base.Add(40 * time.Millisecond), Type: "files",
		Data: map[string]any{"event": "created", "path": "/tmp/y", "user": "root"}}
	out := captureStdout(t, func() {
		printTriageMulti([]searchRoot{{base: dir, host: ""}}, pivot, time.Hour, "")
	})

	t.Logf("output:\n%s", out)

	// 1) The two duplicate runs should each appear once with a count.
	xCount := strings.Count(out, "modified /tmp/x")
	if xCount != 2 {
		t.Errorf("expected 2 lines for /tmp/x (one per run), got %d", xCount)
	}
	// 2) The output must contain a "×N" suffix on the duplicate runs.
	if !strings.Contains(out, "(×30 over") && !strings.Contains(out, "(×30)") {
		t.Error("expected a (×30) suffix on the coalesced duplicate run")
	}
	// 3) The middle "created /tmp/y" event must remain visible.
	if !strings.Contains(out, "created /tmp/y") {
		t.Error("the different middle event got hidden inside the coalescing")
	}
	// 4) The pivot row uses ">>" — it must appear in the output.
	if !strings.Contains(out, ">>") {
		t.Error("pivot marker >> not present in output")
	}
}

// TestPrintTriageMulti_DoesNotCoalesceAlerts ensures alert rows always
// render in full so severity colours and --explain sub-lines aren't lost.
func TestPrintTriageMulti_DoesNotCoalesceAlerts(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStorage(dir, 0, 0, 256)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		st.Write("alerts", map[string]any{
			"event": "rule_match", "rule": "same_rule", "severity": "high",
			"matched_type": "files", "matched_event": "created",
			"ts": base.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano),
		})
	}
	st.Close()

	pivot := Event{TS: base, Type: "marker", Data: map[string]any{"event": "time_marker"}}
	out := captureStdout(t, func() {
		printTriageMulti([]searchRoot{{base: dir, host: ""}}, pivot, time.Hour, "")
	})
	count := strings.Count(out, "rule=same_rule")
	if count != 5 {
		t.Errorf("expected 5 alert rows in full (no coalescing), got %d\noutput:\n%s", count, out)
	}
}
