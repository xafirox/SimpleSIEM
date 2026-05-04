package sieg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPreflightStart_ServerMissingCA is the regression for "convert ->
// server, hit start, daemon silently dies." When the CA is missing,
// preflight names `certs init` as the single command to fix it.
func TestPreflightStart_ServerMissingCA(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.json")
	body := `{
  "mode": "server",
  "log_dir": "` + filepath.ToSlash(dir) + `/logs",
  "server": {
    "listen": ":9443",
    "cert": "` + filepath.ToSlash(dir) + `/certs/server.pem",
    "key":  "` + filepath.ToSlash(dir) + `/certs/server.key",
    "ca_cert": "` + filepath.ToSlash(dir) + `/certs/ca.pem",
    "require_client_cert": true
  }
}`
	if err := os.WriteFile(cfg, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	err := preflightStart(cfg)
	if err == nil {
		t.Fatal("expected preflight to reject server mode with no cert files")
	}
	msg := err.Error()
	if !strings.Contains(msg, "CA missing") || !strings.Contains(msg, "certs init") {
		t.Errorf("error should name the missing CA and certs init as the fix: got %q", msg)
	}
}

// TestPreflightStart_ServerMissingServerCertOnly covers the case the
// user reported: they ran `certs init` (CA exists), then `start`, and
// got the same generic "missing cert files" error that didn't tell
// them about `certs server`. Preflight now distinguishes "CA missing"
// from "CA present but server cert missing" and points at the right
// command for each.
func TestPreflightStart_ServerMissingServerCertOnly(t *testing.T) {
	dir := t.TempDir()
	certsDir := filepath.Join(dir, "certs")
	_ = os.MkdirAll(certsDir, 0o750)
	// CA in place (init was run)
	_ = os.WriteFile(filepath.Join(certsDir, "ca.pem"), []byte("(stub)"), 0o644)
	// server.pem and server.key absent (certs server was NOT run)
	cfg := filepath.Join(dir, "cfg.json")
	body := `{
  "mode": "server",
  "log_dir": "` + filepath.ToSlash(dir) + `/logs",
  "server": {
    "cert": "` + filepath.ToSlash(certsDir) + `/server.pem",
    "key":  "` + filepath.ToSlash(certsDir) + `/server.key",
    "ca_cert": "` + filepath.ToSlash(certsDir) + `/ca.pem",
    "require_client_cert": true
  }
}`
	if err := os.WriteFile(cfg, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	err := preflightStart(cfg)
	if err == nil {
		t.Fatal("preflight should reject server mode without server.cert")
	}
	msg := err.Error()
	if !strings.Contains(msg, "CA exists") {
		t.Errorf("error should distinguish CA-exists case: got %q", msg)
	}
	if !strings.Contains(msg, "certs server") {
		t.Errorf("error should name `certs server` as the fix: got %q", msg)
	}
}

// TestPreflightStart_StandalonePassesWithoutCerts ensures the new
// preflight doesn't break the existing standalone install flow.
func TestPreflightStart_StandalonePassesWithoutCerts(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfg, []byte(`{"mode":"standalone"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := preflightStart(cfg); err != nil {
		t.Errorf("standalone preflight should succeed without certs, got: %v", err)
	}
}

// TestPreflightStart_ServerSucceedsWhenFilesExist confirms the happy
// path: preflight allows start once the operator has placed the cert
// bundle.
func TestPreflightStart_ServerSucceedsWhenFilesExist(t *testing.T) {
	dir := t.TempDir()
	certsDir := filepath.Join(dir, "certs")
	_ = os.MkdirAll(certsDir, 0o750)
	for _, n := range []string{"server.pem", "server.key", "ca.pem"} {
		if err := os.WriteFile(filepath.Join(certsDir, n), []byte("(stub)"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "cfg.json")
	body := `{
  "mode": "server",
  "log_dir": "` + filepath.ToSlash(dir) + `/logs",
  "server": {
    "cert": "` + filepath.ToSlash(certsDir) + `/server.pem",
    "key":  "` + filepath.ToSlash(certsDir) + `/server.key",
    "ca_cert": "` + filepath.ToSlash(certsDir) + `/ca.pem",
    "require_client_cert": true
  }
}`
	if err := os.WriteFile(cfg, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := preflightStart(cfg); err != nil {
		t.Errorf("preflight should accept server mode with cert files present, got: %v", err)
	}
}

// TestPreflightStart_AgentMissingURL ensures agent mode without a
// server_url is rejected the same way.
func TestPreflightStart_AgentMissingURL(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfg, []byte(`{"mode":"agent"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	err := preflightStart(cfg)
	if err == nil {
		t.Fatal("agent without server_url should fail preflight")
	}
	if !strings.Contains(err.Error(), "server_url") {
		t.Errorf("error should mention server_url: %v", err)
	}
}
