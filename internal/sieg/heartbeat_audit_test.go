package sieg

import (
	"bufio"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRecordAgentHeartbeat_DualWrite verifies that a successful heartbeat
// emits the meta:agent_heartbeat event under BOTH the per-agent host
// directory and the _server pseudo-host directory. Without the dual
// write, an operator running `simplesiem tail --type meta --grep
// heartbeat` on the server would miss the event when tail's searchRoots
// happened to skip the freshly-created per-agent dir (the as4 manual-
// test failure mode).
func TestRecordAgentHeartbeat_DualWrite(t *testing.T) {
	dir := t.TempDir()
	st := &serverState{
		base:      dir,
		group:     newStorageGroup(dir),
		storages:  map[string]*Storage{},
		queueSize: 64,
	}
	t.Cleanup(st.closeAll)

	// Fake request — recordAgentHeartbeat only reads RemoteAddr via
	// remoteIP(), so a bare httptest.NewRequest is enough.
	req := httptest.NewRequest("GET", "/v1/heartbeat", nil)
	req.RemoteAddr = "10.0.0.5:34567"

	st.recordAgentHeartbeat("agent-x", req)

	// Storage writes are async — give the writer goroutine up to 2s
	// to flush before failing the assertion.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hostHas(t, dir, "agent-x") && hostHas(t, dir, "_server") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("meta:agent_heartbeat did not land under both <dir>/agent-x/meta and <dir>/_server/meta within 2s")
}

// hostHas returns true when today's meta JSONL under <base>/<host>/meta
// contains a line with `"event":"agent_heartbeat"` for this agent.
func hostHas(t *testing.T, base, host string) bool {
	t.Helper()
	today := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(base, host, "meta", today+".jsonl")
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var obj map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &obj); err != nil {
			continue
		}
		ev, _ := obj["event"].(string)
		if ev != "agent_heartbeat" {
			continue
		}
		// Match the expected agent ID for the per-host dir; the
		// _server dir mirrors the same line so both contain it.
		ag, _ := obj["agent"].(string)
		if ag == "agent-x" {
			return true
		}
	}
	return false
}

// TestRecordAgentHeartbeat_HostLastSeenBumped verifies that the
// liveness map is bumped on every authorised heartbeat. The silence
// detector reads this map; without the bump, an agent that's
// heartbeating without sending any events would be flagged silent
// after 5 min even though it's healthily alive.
func TestRecordAgentHeartbeat_HostLastSeenBumped(t *testing.T) {
	dir := t.TempDir()
	st := &serverState{
		base:      dir,
		group:     newStorageGroup(dir),
		storages:  map[string]*Storage{},
		queueSize: 64,
	}
	t.Cleanup(st.closeAll)

	req := httptest.NewRequest("GET", "/v1/heartbeat", nil)
	req.RemoteAddr = "10.0.0.5:34567"
	before := time.Now().UTC().Add(-time.Second)
	st.recordAgentHeartbeat("agent-y", req)

	st.hostLivenessMu.RLock()
	ts, ok := st.hostLastSeen["agent-y"]
	st.hostLivenessMu.RUnlock()
	if !ok {
		t.Fatal("hostLastSeen entry missing after recordAgentHeartbeat")
	}
	if !ts.After(before) {
		t.Fatalf("hostLastSeen for agent-y is %v, expected after %v", ts, before)
	}
}

// TestPrintHostsLive_AllowlistDriven verifies the new hosts-list
// derivation: in-allowlist hosts with recent activity show as LIVE,
// allowlist hosts without recent activity show as STALE, and
// directories not in the allowlist surface as orphans (instead of
// pretending to be live agents the way the old directory-walk did).
func TestPrintHostsLive_AllowlistDriven(t *testing.T) {
	dir := t.TempDir()
	// One live host (allowlisted, recent file), one stale (allowlisted,
	// old file), one orphan (dir exists, not in allowlist).
	mkLog := func(host string, modAge time.Duration) {
		t.Helper()
		typeDir := filepath.Join(dir, host, "meta")
		if err := os.MkdirAll(typeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(typeDir, time.Now().UTC().Format("2006-01-02")+".jsonl")
		if err := os.WriteFile(path, []byte("{}\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		when := time.Now().Add(-modAge)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
	}
	mkLog("agent-live", 30*time.Second)
	mkLog("agent-stale", 30*time.Minute)
	mkLog("agent-orphan", 30*time.Second)
	allow := []string{"agent-live", "agent-stale"}
	allowSet := map[string]struct{}{"agent-live": {}, "agent-stale": {}}

	live, stale, orphan := classifyHostLiveness(dir, allow, allowSet, 10*time.Minute)
	if !sliceContains(live, "agent-live") {
		t.Errorf("agent-live not classified as live: %v", live)
	}
	if !sliceContains(stale, "agent-stale") {
		t.Errorf("agent-stale not classified as stale: %v", stale)
	}
	if !sliceContains(orphan, "agent-orphan") {
		t.Errorf("agent-orphan not classified as orphan: %v", orphan)
	}
	// The classify call MUST NOT label a stale host as live just
	// because the dir exists — that was the bug operators kept
	// hitting via the old listHosts() output.
	if sliceContains(live, "agent-stale") {
		t.Errorf("agent-stale should not appear in live")
	}
}

func sliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

