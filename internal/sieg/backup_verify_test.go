package sieg

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBackupVerify_CleanRoundtrip creates a real backup, runs the
// verify pass, and confirms 0 problems.
func TestBackupVerify_CleanRoundtrip(t *testing.T) {
	src := t.TempDir()
	cfgDir := filepath.Join(src, "etc")
	stateDir := filepath.Join(src, "state")
	logDir := filepath.Join(src, "logs")
	for _, d := range []string{cfgDir, stateDir, logDir} {
		_ = os.MkdirAll(d, 0o755)
	}
	cfgPath := filepath.Join(cfgDir, "config.json")
	writeFile(t, cfgPath, `{"mode":"standalone"}`)

	// Write a Storage-format JSONL so we have a real chain to walk.
	g := newStorageGroup(logDir)
	s, err := g.Open("", 0, 64*1024*1024, 256)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		s.Write("network", map[string]any{"event": "x", "i": i})
	}
	s.Close()

	cfg := Config{Mode: "standalone", LogDir: logDir, StateDir: stateDir}
	out := filepath.Join(t.TempDir(), "v.siembak")
	if err := createBackup(cfg, cfgPath, out, "passphrase", true); err != nil {
		t.Fatal(err)
	}

	res, err := verifyBackup(out, "passphrase", false)
	if err != nil {
		t.Fatalf("verifyBackup: %v", err)
	}
	if res.problemFiles != 0 {
		t.Errorf("clean backup: problemFiles=%d, want 0; details: %v", res.problemFiles, res.problemDetail)
	}
	if res.fileCount == 0 {
		t.Errorf("clean backup: fileCount=0, expected at least 1 .jsonl")
	}
	if res.eventCount == 0 {
		t.Errorf("clean backup: eventCount=0, expected at least 20 events")
	}
}

// TestBackupVerify_DetectsTamperedFrame verifies that flipping a
// byte inside the encrypted payload trips the AEAD check during
// header / frame-stream read. The verify call returns an error
// (not a clean problem report) — frame-level tampering means the
// backup is unrestorable, not just inconsistent.
func TestBackupVerify_DetectsTamperedFrame(t *testing.T) {
	src := t.TempDir()
	cfgPath := filepath.Join(src, "config.json")
	writeFile(t, cfgPath, `{"mode":"standalone"}`)
	cfg := Config{Mode: "standalone", LogDir: src, StateDir: src}
	out := filepath.Join(t.TempDir(), "v.siembak")
	if err := createBackup(cfg, cfgPath, out, "pp", true); err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the middle of the file (past the header,
	// inside a ciphertext frame).
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 200 {
		t.Skip("backup too small to corrupt mid-stream")
	}
	data[len(data)/2] ^= 0xFF
	_ = os.WriteFile(out, data, 0o600)

	if _, err := verifyBackup(out, "pp", false); err == nil {
		t.Errorf("expected verify to fail on tampered backup, got nil")
	}
}

// TestBackupVerify_WrongPassphrase confirms a wrong passphrase
// returns an error at the FIRST frame (before any tar parsing
// happens) — same property as inspect.
func TestBackupVerify_WrongPassphrase(t *testing.T) {
	src := t.TempDir()
	cfgPath := filepath.Join(src, "config.json")
	writeFile(t, cfgPath, `{"mode":"standalone"}`)
	cfg := Config{Mode: "standalone", LogDir: src, StateDir: src}
	out := filepath.Join(t.TempDir(), "v.siembak")
	if err := createBackup(cfg, cfgPath, out, "right-passphrase", true); err != nil {
		t.Fatal(err)
	}

	if _, err := verifyBackup(out, "wrong-passphrase", false); err == nil {
		t.Errorf("expected wrong-passphrase to fail verify, got nil")
	}
}
