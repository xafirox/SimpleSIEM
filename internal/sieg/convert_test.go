package sieg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRehomeLegacyLogs_MovesKnownTypesOnly(t *testing.T) {
	dir := t.TempDir()
	for _, t := range []string{"network", "files", "alerts", "user_dir"} {
		if err := os.Mkdir(filepath.Join(dir, t), 0o755); err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(dir, t, "marker"), []byte("x"), 0o644); err != nil {
			panic(err)
		}
	}
	moved, err := rehomeLegacyLogs(dir)
	if err != nil {
		t.Fatalf("rehome: %v", err)
	}
	if moved != 3 {
		t.Errorf("moved=%d, want 3 (network, files, alerts)", moved)
	}
	// Known types should now live under _legacy/<type>.
	for _, name := range []string{"network", "files", "alerts"} {
		marker := filepath.Join(dir, "_legacy", name, "marker")
		if _, err := os.Stat(marker); err != nil {
			t.Errorf("missing %s after rehome: %v", marker, err)
		}
	}
	// Unknown directory must NOT have been touched.
	if _, err := os.Stat(filepath.Join(dir, "user_dir", "marker")); err != nil {
		t.Errorf("rehome touched a non-log-type dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "_legacy", "user_dir")); !os.IsNotExist(err) {
		t.Errorf("rehome should not have moved user_dir: %v", err)
	}
}

func TestRehomeLegacyLogs_AvoidsClobber(t *testing.T) {
	dir := t.TempDir()
	// Pre-existing _legacy/files dir from a prior conversion.
	_ = os.MkdirAll(filepath.Join(dir, "_legacy", "files"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "_legacy", "files", "old"), []byte("old"), 0o644)
	_ = os.MkdirAll(filepath.Join(dir, "files"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "files", "new"), []byte("new"), 0o644)

	moved, err := rehomeLegacyLogs(dir)
	if err != nil {
		t.Fatalf("rehome: %v", err)
	}
	if moved != 1 {
		t.Errorf("moved=%d, want 1", moved)
	}
	// Existing _legacy/files preserved as-is
	if _, err := os.Stat(filepath.Join(dir, "_legacy", "files", "old")); err != nil {
		t.Errorf("clobbered prior _legacy/files: %v", err)
	}
	// New collision-rehomed dir created
	if _, err := os.Stat(filepath.Join(dir, "_legacy", "files.1", "new")); err != nil {
		t.Errorf("expected files.1 to hold the new content: %v", err)
	}
}

func TestSaveConfig_RoundTripsAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")

	// Write an initial config so the backup branch fires.
	if err := os.WriteFile(path, []byte(`{"mode":"standalone"}`), 0o640); err != nil {
		t.Fatal(err)
	}

	cfg := defaultConfig()
	cfg.Mode = "agent"
	cfg.Agent.ID = "foo"
	cfg.Agent.ServerURL = "https://x:9443"

	if err := saveConfig(path, cfg); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("backup not written: %v", err)
	}

	// Round-trip the new config: the JSON must parse and preserve the values we set.
	data, _ := os.ReadFile(path)
	var got Config
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("written config doesn't parse: %v", err)
	}
	if got.Mode != "agent" || got.Agent.ID != "foo" || got.Agent.ServerURL != "https://x:9443" {
		t.Errorf("config didn't round-trip: %+v", got)
	}
}
