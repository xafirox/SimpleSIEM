package sieg

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMatchers_CIDR exercises the new CIDR matcher in both positive
// and negative form.
func TestMatchers_CIDR(t *testing.T) {
	rulesJSON := `[{
	  "name": "internal-traffic",
	  "severity": "low",
	  "match": {"source_ip": {"cidr": "10.0.0.0/8"}}
	}]`
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rulesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	rule := rules[0]
	if !matchRule(rule, "network", map[string]any{"source_ip": "10.1.2.3"}) {
		t.Error("CIDR match should succeed for 10.1.2.3 in 10.0.0.0/8")
	}
	if matchRule(rule, "network", map[string]any{"source_ip": "8.8.8.8"}) {
		t.Error("CIDR match should NOT succeed for 8.8.8.8 in 10.0.0.0/8")
	}
}

// TestMatchers_NotCIDR_NonIP confirms the closed-deny semantics: a
// non-IP value in `not_cidr` field returns true (it's trivially NOT
// in any of the listed networks).
func TestMatchers_NotCIDR_NonIP(t *testing.T) {
	m, err := parseMatcher(map[string]any{"not_cidr": "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.test("not-an-ip") {
		t.Error("not_cidr should accept non-IP values")
	}
	if m.test("10.0.0.5") {
		t.Error("not_cidr should reject in-range IP")
	}
}

// TestMatchers_InFile verifies the set-file matcher reads the file
// and matches values from it; also that reload picks up new lines.
func TestMatchers_InFile(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "blocklist.txt")
	if err := os.WriteFile(listPath, []byte("# header comment\n1.2.3.4\nbad.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := parseMatcher(map[string]any{"in_file": listPath})
	if err != nil {
		t.Fatal(err)
	}
	if !m.test("1.2.3.4") {
		t.Error("in_file should match a listed value")
	}
	if !m.test("bad.example.com") {
		t.Error("in_file should match listed hostname")
	}
	if m.test("9.9.9.9") {
		t.Error("in_file should NOT match an unlisted value")
	}
	// Force the matcher to allow a re-check by aging lastChecked.
	m.set.mu.Lock()
	m.set.lastChecked = time.Now().Add(-time.Hour)
	m.set.mu.Unlock()
	// Append a line to the file. Must also bump mtime so the loader
	// re-reads (refresh is gated on mtime advance).
	if err := os.WriteFile(listPath, []byte("1.2.3.4\nbad.example.com\nnew.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// On filesystems with sub-second mtime (most Linux/macOS) we need
	// to wait at least 1ns past the previous mtime, but go's
	// FileInfo.ModTime is whatever the OS records. Bump it explicitly:
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(listPath, future, future)
	if !m.test("new.example.com") {
		t.Error("in_file matcher should pick up the new line after mtime bump")
	}
}

// TestMatchers_Numeric verifies gt/lt/ge/le on a numeric event field.
func TestMatchers_Numeric(t *testing.T) {
	m, err := parseMatcher(map[string]any{"gt": float64(100)})
	if err != nil {
		t.Fatal(err)
	}
	if !m.test(150) {
		t.Error("gt 100 should accept 150")
	}
	if m.test(50) {
		t.Error("gt 100 should reject 50")
	}
	if !m.test("250") {
		t.Error("gt 100 should accept stringified 250")
	}
}

// TestRule_TimeOfDay confirms the time-of-day clause gates firing.
// We construct a rule whose window is the current minute (so it
// matches now) and another whose window is the opposite half of
// the day (so it doesn't).
func TestRule_TimeOfDay(t *testing.T) {
	now := time.Now()
	startMin := now.Hour()*60 + now.Minute()
	wrap := func(m int) string {
		m = ((m % 1440) + 1440) % 1440
		return formatHHMM(m)
	}
	currentWindow := wrap(startMin-1) + "-" + wrap(startMin+1)
	oppositeWindow := wrap(startMin+360) + "-" + wrap(startMin+361)

	r := &alertRule{TimeOfDay: currentWindow}
	if !r.inTimeWindow(now) {
		t.Errorf("rule should be in window %s at %s", currentWindow, now.Format("15:04"))
	}
	r2 := &alertRule{TimeOfDay: oppositeWindow}
	if r2.inTimeWindow(now) {
		t.Errorf("rule should NOT be in window %s at %s", oppositeWindow, now.Format("15:04"))
	}
}

func formatHHMM(m int) string {
	h := m / 60
	mm := m % 60
	out := ""
	if h < 10 {
		out += "0"
	}
	out += itoa(h) + ":"
	if mm < 10 {
		out += "0"
	}
	out += itoa(mm)
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestRule_Sequence_FiresOnFullMatch confirms a 2-step sequence rule
// fires only when both events arrive in order, by the same group_by
// key, within the configured window.
func TestRule_Sequence_FiresOnFullMatch(t *testing.T) {
	rulesJSON := `[{
	  "name": "fail-then-success",
	  "severity": "high",
	  "sequence": {
	    "steps": [
	      {"event": "auth_failed"},
	      {"event": "auth_success"}
	    ],
	    "within": "5s",
	    "group_by": "remote"
	  }
	}]`
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rulesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	r := rules[0]
	// Step 1 alone should not fire.
	if ok, _ := r.shouldFire("auth", map[string]any{"event": "auth_failed", "remote": "1.2.3.4"}); ok {
		t.Error("sequence rule should not fire on step 1 alone")
	}
	// Step 2 from the same key fires.
	if ok, _ := r.shouldFire("auth", map[string]any{"event": "auth_success", "remote": "1.2.3.4"}); !ok {
		t.Error("sequence rule should fire when both steps complete in window")
	}
}

// TestRule_Sequence_DifferentKeyDoesNotComplete verifies the
// group_by isolates state by key — a fail on one IP and a success
// on another shouldn't fire.
func TestRule_Sequence_DifferentKeyDoesNotComplete(t *testing.T) {
	rulesJSON := `[{
	  "name": "fail-then-success",
	  "severity": "high",
	  "sequence": {
	    "steps": [
	      {"event": "auth_failed"},
	      {"event": "auth_success"}
	    ],
	    "within": "5s",
	    "group_by": "remote"
	  }
	}]`
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rulesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	r := rules[0]
	r.shouldFire("auth", map[string]any{"event": "auth_failed", "remote": "1.2.3.4"})
	if ok, _ := r.shouldFire("auth", map[string]any{"event": "auth_success", "remote": "5.6.7.8"}); ok {
		t.Error("sequence rule should NOT fire when steps come from different group_by keys")
	}
}

// TestRule_Sequence_TimeoutResets ensures a step-1 match more than
// `within` ago is forgotten before the step-2 event arrives.
func TestRule_Sequence_TimeoutResets(t *testing.T) {
	rulesJSON := `[{
	  "name": "fail-then-success",
	  "severity": "high",
	  "sequence": {
	    "steps": [
	      {"event": "auth_failed"},
	      {"event": "auth_success"}
	    ],
	    "within": "100ms",
	    "group_by": "remote"
	  }
	}]`
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rulesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	r := rules[0]
	r.shouldFire("auth", map[string]any{"event": "auth_failed", "remote": "1.2.3.4"})
	time.Sleep(150 * time.Millisecond)
	if ok, _ := r.shouldFire("auth", map[string]any{"event": "auth_success", "remote": "1.2.3.4"}); ok {
		t.Error("sequence should NOT fire when step 2 arrives after the within window")
	}
}

// TestRule_Annotations_PassThrough confirms that notes/runbook/tactic/
// technique are parsed off the JSON and stored on the rule object.
// (Storage flows them into the alert payload when the rule fires.)
func TestRule_Annotations_PassThrough(t *testing.T) {
	rulesJSON := `[{
	  "name": "ssh-bf",
	  "severity": "high",
	  "match": {"event": "auth_failed"},
	  "notes": "Too many failed SSH",
	  "runbook_url": "https://runbook.example.com/ssh-bf",
	  "tactic": "TA0006",
	  "technique": "T1110.001"
	}]`
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(rulesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	r := rules[0]
	if r.Notes == "" || r.RunbookURL == "" || r.Tactic != "TA0006" || r.Technique != "T1110.001" {
		t.Errorf("annotations parsed wrong: notes=%q runbook=%q tactic=%q technique=%q",
			r.Notes, r.RunbookURL, r.Tactic, r.Technique)
	}
}
