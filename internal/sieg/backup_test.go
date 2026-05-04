package sieg

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBackupRoundtrip_Encrypted creates a synthetic install,
// produces an encrypted+compressed backup, then restores it into a
// scratch destination and verifies every file came back byte-for-byte.
func TestBackupRoundtrip_Encrypted(t *testing.T) {
	src := t.TempDir()
	cfgDir := filepath.Join(src, "etc")
	stateDir := filepath.Join(src, "state")
	logDir := filepath.Join(src, "logs")
	for _, d := range []string{cfgDir, stateDir, logDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := filepath.Join(cfgDir, "config.json")
	writeFile(t, cfgPath, `{"mode":"standalone","log_dir":"`+escape(logDir)+`","state_dir":"`+escape(stateDir)+`"}`)
	writeFile(t, filepath.Join(cfgDir, "rules.json"), `[]`)
	writeFile(t, filepath.Join(stateDir, "secret.psk"), "simplesiem-psk:"+hex.EncodeToString(randomBytes(32)))
	// Multi-MB log file so the chunked frame writer is exercised.
	bigLog := filepath.Join(logDir, "network", "2026-05-02.jsonl")
	if err := os.MkdirAll(filepath.Dir(bigLog), 0o755); err != nil {
		t.Fatal(err)
	}
	bigContent := bytes.Repeat([]byte(`{"event":"x"}`+"\n"), 200_000)
	writeFile(t, bigLog, string(bigContent))

	cfg := Config{
		Mode:     "standalone",
		LogDir:   logDir,
		StateDir: stateDir,
	}
	out := filepath.Join(t.TempDir(), "backup.siembak")
	const passphrase = "correct horse battery staple"
	if err := createBackup(cfg, cfgPath, out, passphrase, true); err != nil {
		t.Fatalf("createBackup: %v", err)
	}

	// Inspect — no extraction.
	m, err := inspectBackup(out, passphrase)
	if err != nil {
		t.Fatalf("inspectBackup: %v", err)
	}
	if !m.Encrypted || !m.Compressed {
		t.Errorf("expected encrypted+compressed; got enc=%v comp=%v", m.Encrypted, m.Compressed)
	}
	if m.LogDir != logDir {
		t.Errorf("LogDir manifest: got %q want %q", m.LogDir, logDir)
	}

	// Wrong passphrase must fail.
	if _, err := inspectBackup(out, "wrong"); err == nil {
		t.Errorf("expected wrong-passphrase failure, got nil")
	}

	// Restore into fresh paths.
	dst := t.TempDir()
	overrides := restoreOverrides{
		configDir: filepath.Join(dst, "etc"),
		stateDir:  filepath.Join(dst, "state"),
		logDir:    filepath.Join(dst, "logs"),
	}
	if _, err := restoreBackup(out, passphrase, false, overrides); err != nil {
		t.Fatalf("restoreBackup: %v", err)
	}

	expectFile(t, filepath.Join(overrides.configDir, "config.json"))
	expectFile(t, filepath.Join(overrides.configDir, "rules.json"))
	expectFile(t, filepath.Join(overrides.stateDir, "secret.psk"))
	got, err := os.ReadFile(filepath.Join(overrides.logDir, "network", "2026-05-02.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bigContent) {
		t.Errorf("big log contents mismatch: got %d bytes want %d", len(got), len(bigContent))
	}
}

// TestBackupRoundtrip_Plain verifies the unencrypted path works and
// that --no-encrypt produces a file with the encrypted flag clear.
func TestBackupRoundtrip_Plain(t *testing.T) {
	src := t.TempDir()
	cfgPath := filepath.Join(src, "config.json")
	writeFile(t, cfgPath, `{"mode":"standalone"}`)
	cfg := Config{Mode: "standalone", LogDir: src, StateDir: src}
	out := filepath.Join(t.TempDir(), "backup.siembak")
	if err := createBackup(cfg, cfgPath, out, "", false); err != nil {
		t.Fatalf("createBackup: %v", err)
	}
	m, err := inspectBackup(out, "")
	if err != nil {
		t.Fatalf("inspectBackup: %v", err)
	}
	if m.Encrypted || m.Compressed {
		t.Errorf("expected plain; got enc=%v comp=%v", m.Encrypted, m.Compressed)
	}
}

// TestBackupTruncationDetected verifies that a backup file truncated
// before the final-frame marker is rejected at read time. Without
// this, an interrupted scp would silently restore part of the data.
func TestBackupTruncationDetected(t *testing.T) {
	src := t.TempDir()
	cfgPath := filepath.Join(src, "config.json")
	writeFile(t, cfgPath, `{"mode":"standalone"}`)
	writeFile(t, filepath.Join(src, "data.log"), strings.Repeat("x", 4*1024*1024))
	cfg := Config{Mode: "standalone", LogDir: src, StateDir: src}
	out := filepath.Join(t.TempDir(), "backup.siembak")
	if err := createBackup(cfg, cfgPath, out, "pp", true); err != nil {
		t.Fatalf("createBackup: %v", err)
	}
	// Lop off the last 64 bytes — guaranteed to land inside or before
	// the final frame's tag, breaking either the auth or the framing.
	fi, _ := os.Stat(out)
	if err := os.Truncate(out, fi.Size()-64); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectBackup(out, "pp"); err == nil {
		t.Errorf("expected truncation/auth failure, got nil")
	}
}

// TestBackupPassphraseRequired verifies the CLI's default-encrypted
// posture: empty passphrase + no --no-encrypt is a hard error.
func TestBackupPassphraseRequired(t *testing.T) {
	if _, err := resolveBackupPassphrase("", "", false); err == nil {
		t.Errorf("expected error when no passphrase + no --no-encrypt")
	}
	if _, err := resolveBackupPassphrase("pp", "", true); err == nil {
		t.Errorf("expected error when --no-encrypt combined with --passphrase")
	}
	pp, err := resolveBackupPassphrase("", "", true)
	if err != nil || pp != "" {
		t.Errorf("--no-encrypt: got %q,%v want \"\",nil", pp, err)
	}
	pp, err = resolveBackupPassphrase("hunter2", "", false)
	if err != nil || pp != "hunter2" {
		t.Errorf("plain passphrase: got %q,%v", pp, err)
	}
}

// helpers

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func expectFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected file present after restore: %s (%v)", path, err)
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func escape(s string) string {
	// Quick-and-dirty backslash escape for embedding Windows paths in
	// JSON literals inside test fixtures.
	return strings.ReplaceAll(s, `\`, `\\`)
}
