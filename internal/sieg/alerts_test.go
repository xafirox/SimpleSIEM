package sieg

import (
	"testing"
	"time"
)

// helper: build a rule from compact match map for tests.
func mkRule(t *testing.T, match map[string]any) *alertRule {
	t.Helper()
	r := &alertRule{Name: "test", Match: map[string]matcher{}}
	for k, v := range match {
		m, err := parseMatcher(v)
		if err != nil {
			t.Fatalf("parseMatcher(%q): %v", v, err)
		}
		r.Match[k] = m
	}
	return r
}

func TestMatchRule_ExactString(t *testing.T) {
	r := mkRule(t, map[string]any{"event": "ssh_login", "type": "auth"})
	if !matchRule(r, "auth", map[string]any{"event": "ssh_login"}) {
		t.Error("expected match for exact strings")
	}
	if matchRule(r, "auth", map[string]any{"event": "process_start"}) {
		t.Error("unexpected match: event differs")
	}
	if matchRule(r, "files", map[string]any{"event": "ssh_login"}) {
		t.Error("unexpected match: type differs")
	}
}

func TestMatchRule_Substring(t *testing.T) {
	r := mkRule(t, map[string]any{"path": "*=authorized_keys"})
	if !matchRule(r, "files", map[string]any{"path": "/root/.ssh/authorized_keys"}) {
		t.Error("expected substring match")
	}
	if matchRule(r, "files", map[string]any{"path": "/root/.ssh/known_hosts"}) {
		t.Error("unexpected substring match")
	}
}

func TestMatchRule_Regex(t *testing.T) {
	r := mkRule(t, map[string]any{"path": `~=/(etc|lib)/systemd/system/.*\.service$`})
	if !matchRule(r, "files", map[string]any{"path": "/etc/systemd/system/foo.service"}) {
		t.Error("expected regex match")
	}
	if matchRule(r, "files", map[string]any{"path": "/etc/systemd/system/foo.timer"}) {
		t.Error("unexpected regex match: wrong extension")
	}
}

func TestMatchRule_AnyOf(t *testing.T) {
	r := mkRule(t, map[string]any{"result": []any{"failed", "invalid_user"}})
	for _, v := range []string{"failed", "invalid_user"} {
		if !matchRule(r, "auth", map[string]any{"result": v}) {
			t.Errorf("expected any-of to match %q", v)
		}
	}
	if matchRule(r, "auth", map[string]any{"result": "success"}) {
		t.Error("unexpected any-of match for 'success'")
	}
}

func TestMatchRule_NumericField(t *testing.T) {
	r := mkRule(t, map[string]any{"port": "22"})
	if !matchRule(r, "auth", map[string]any{"port": float64(22)}) {
		t.Error("expected numeric coercion to match")
	}
	if !matchRule(r, "auth", map[string]any{"port": "22"}) {
		t.Error("expected string-equal numeric to match")
	}
}

func TestShouldFire_Threshold(t *testing.T) {
	r := mkRule(t, map[string]any{"event": "ssh_login", "result": "failed"})
	r.Threshold = &thresholdConfig{Count: 3, Window: time.Minute, GroupBy: "remote"}

	ev := func(remote string) map[string]any {
		return map[string]any{"event": "ssh_login", "result": "failed", "remote": remote}
	}

	for i := 0; i < 2; i++ {
		fire, _ := r.shouldFire("auth", ev("10.0.0.1"))
		if fire {
			t.Errorf("event %d: should not fire below threshold", i)
		}
	}
	fire, extra := r.shouldFire("auth", ev("10.0.0.1"))
	if !fire {
		t.Fatal("third event should fire")
	}
	if extra["count"].(int) != 3 {
		t.Errorf("count=%v want 3", extra["count"])
	}
	if extra["group_value"].(string) != "10.0.0.1" {
		t.Errorf("group_value=%v want 10.0.0.1", extra["group_value"])
	}

	// Different group_by value tracks independently.
	fire, _ = r.shouldFire("auth", ev("192.168.1.1"))
	if fire {
		t.Error("first event for new group should not fire")
	}
}

func TestShouldFire_Dedup(t *testing.T) {
	r := mkRule(t, map[string]any{"event": "x"})
	r.DedupWindow = time.Second
	r.DedupKey = "key"
	ev := map[string]any{"event": "x", "key": "k1"}
	fire, _ := r.shouldFire("any", ev)
	if !fire {
		t.Fatal("first event should fire")
	}
	fire, _ = r.shouldFire("any", ev)
	if fire {
		t.Error("second event within dedup window should be suppressed")
	}
	// Different key bypasses dedup.
	ev2 := map[string]any{"event": "x", "key": "k2"}
	fire, _ = r.shouldFire("any", ev2)
	if !fire {
		t.Error("event with different dedup_key should fire")
	}
}

func TestLoadRules_Validation(t *testing.T) {
	// loadRules requires file IO; we only test that empty match is rejected
	// at the parser/builder level via parseMatcher accepting nothing odd.
	// (Full file-based validation belongs in an integration test.)
	if _, err := parseMatcher(map[string]any{"unknown": "kind"}); err == nil {
		t.Error("parseMatcher should reject unsupported types")
	}
}
