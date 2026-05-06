package sieg

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestChainHead_RoundTrip confirms the signer scans on-disk events,
// produces a valid signature, and the verify path accepts it.
// Tampering with the heads field after signing must cause verify
// to fail.
func TestChainHead_RoundTrip(t *testing.T) {
	logDir := t.TempDir()
	stateDir := t.TempDir()

	// Build some real chain heads by writing events through Storage.
	g := newStorageGroup(logDir)
	s, err := g.Open("agent-a", 0, 64*1024*1024, 256)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		s.Write("auth", map[string]any{"event": "auth_failed", "user": "alice"})
	}
	s.Close()
	time.Sleep(200 * time.Millisecond)

	signer, err := newChainHeadSigner(logDir, stateDir, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	signer.signOnce()

	// Read back the signed record.
	files, err := chainHeadFiles(filepath.Join(logDir, "_chainhead"))
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one chainhead file, got %d (err=%v)", len(files), err)
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var rec signedChainHead
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Heads) == 0 {
		t.Fatal("expected at least one head entry")
	}
	if rec.Heads[0].Host != "agent-a" || rec.Heads[0].Type != "auth" {
		t.Errorf("first head wrong: %+v", rec.Heads[0])
	}

	// Verify the signature against the embedded public key.
	pub, err := parsePublicKeyPEM(rec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	headBody, _ := json.Marshal(rec.Heads)
	hash := sha512.Sum384(headBody)
	sigBytes, _ := hex.DecodeString(rec.Signature)
	if !ecdsa.VerifyASN1(pub, hash[:], sigBytes) {
		t.Fatal("signature should verify")
	}

	// Tamper: mutate one head's hash and confirm verify fails.
	rec.Heads[0].LastHash = "ffff" + rec.Heads[0].LastHash[4:]
	tamperedBody, _ := json.Marshal(rec.Heads)
	tHash := sha512.Sum384(tamperedBody)
	if ecdsa.VerifyASN1(pub, tHash[:], sigBytes) {
		t.Fatal("signature should NOT verify after tamper")
	}
}

// TestChainHead_KeyPersistsAcrossSigners confirms a signer reuses the
// existing key file rather than generating a new one each time.
func TestChainHead_KeyPersistsAcrossSigners(t *testing.T) {
	logDir := t.TempDir()
	stateDir := t.TempDir()

	g := newStorageGroup(logDir)
	s, _ := g.Open("agent-a", 0, 64*1024*1024, 256)
	s.Write("auth", map[string]any{"event": "auth_failed"})
	s.Close()
	time.Sleep(100 * time.Millisecond)

	s1, err := newChainHeadSigner(logDir, stateDir, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub1, _ := s1.key.PublicKey.X, s1.key.PublicKey.Y
	s2, err := newChainHeadSigner(logDir, stateDir, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _ := s2.key.PublicKey.X, s2.key.PublicKey.Y
	if pub1.Cmp(pub2) != 0 {
		t.Errorf("second signer didn't reuse the on-disk key (X mismatch)")
	}
}

// TestChainHead_SkipsReplicatedFiles confirms `.from-*.jsonl` files
// (replicated peer chains) are not signed by this host — only the
// origin's signer is authoritative for those.
func TestChainHead_SkipsReplicatedFiles(t *testing.T) {
	logDir := t.TempDir()

	// Set up a replicated-style file alongside a local one.
	mkfile := func(rel, content string) {
		full := filepath.Join(logDir, rel)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(content), 0o644)
	}
	line := `{"_seq":1,"_prev":"","_hash":"abc","event":"x","ts":"2026-05-02T12:00:00Z"}` + "\n"
	mkfile("agent-a/auth/2026-05-02.jsonl", line)
	mkfile("agent-a/auth/2026-05-02.from-peer-b.jsonl", line)

	heads, err := scanChainHeads(logDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(heads) != 1 {
		t.Errorf("scanChainHeads returned %d entries, want 1 (the .from-* file should be skipped)", len(heads))
	}
	for _, h := range heads {
		if h.File == "2026-05-02.from-peer-b.jsonl" {
			t.Error("scanChainHeads picked up a replicated file; that file is the peer's responsibility")
		}
	}
}
