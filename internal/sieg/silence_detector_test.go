package sieg

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgentSilenceDetector_FiresAfterThreshold(t *testing.T) {
	dir := t.TempDir()
	st := &serverState{
		base:      dir,
		group:     newStorageGroup(dir),
		storages:  map[string]*Storage{},
		queueSize: 64,
		allowlist: map[string]struct{}{"agent-z": {}},
	}
	t.Cleanup(st.closeAll)
	d := newAgentSilenceDetector(st, 50*time.Millisecond)

	// Bump hostLastSeen via a fake heartbeat.
	req := httptest.NewRequest("GET", "/v1/heartbeat", nil)
	req.RemoteAddr = "10.0.0.6:1234"
	st.recordAgentHeartbeat("agent-z", req)

	// Tick once IMMEDIATELY: last-seen is fresh, no alert.
	d.tick()

	// Wait past the threshold, then tick: alert fires.
	time.Sleep(80 * time.Millisecond)
	d.tick()

	// Fresh tick should now have an alert recorded under both
	// the per-agent dir and _server.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if metaContains(t, dir, "agent-z", "agent_silent_anomaly") &&
			metaContains(t, dir, "_server", "agent_silent_anomaly") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !metaContains(t, dir, "agent-z", "agent_silent_anomaly") {
		t.Fatalf("agent_silent_anomaly missing under <dir>/agent-z/meta")
	}
	if !metaContains(t, dir, "_server", "agent_silent_anomaly") {
		t.Fatalf("agent_silent_anomaly missing under <dir>/_server/meta")
	}

	// Recovery path: bump last-seen and tick again — recovered event.
	st.recordAgentHeartbeat("agent-z", req)
	d.tick()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if metaContains(t, dir, "agent-z", "agent_silent_recovered") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("agent_silent_recovered missing after recovery tick")
}

func TestAgentSilenceDetector_NoAlertForUnseenAgent(t *testing.T) {
	dir := t.TempDir()
	st := &serverState{
		base:      dir,
		group:     newStorageGroup(dir),
		storages:  map[string]*Storage{},
		queueSize: 64,
		allowlist: map[string]struct{}{"never-connected": {}},
	}
	t.Cleanup(st.closeAll)
	d := newAgentSilenceDetector(st, 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	d.tick()
	// hostLastSeen[never-connected] is zero — detector must NOT
	// fire for a host we've never observed (can't tell silence
	// from "agent has not started yet").
	today := time.Now().UTC().Format("2006-01-02")
	if data, err := readFileIfExists(filepath.Join(dir, "_server", "meta", today+".jsonl")); err == nil {
		if strings.Contains(string(data), "agent_silent_anomaly") {
			t.Fatal("detector falsely fired for an agent that's never been heard from")
		}
	}
}

func metaContains(t *testing.T, base, host, eventName string) bool {
	t.Helper()
	today := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(base, host, "meta", today+".jsonl")
	data, err := readFileIfExists(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), `"event":"`+eventName+`"`)
}

func readFileIfExists(path string) ([]byte, error) {
	return os.ReadFile(path)
}
