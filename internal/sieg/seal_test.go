package sieg

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSealRoundtrip verifies that sealClosedLogFile + unsealLogFileForRetention
// round-trip without error on a regular file. The actual append-only /
// read-only attribute application is best-effort by design — on docker
// containers without CAP_LINUX_IMMUTABLE, on FAT/exFAT filesystems, and on
// SMB shares the seal is a silent no-op. What we assert here is the
// invariant: the calls return without panicking AND the file remains
// readable + writable from the daemon's process AFTER unseal.
//
// Cross-platform: the test runs the same way on Linux (chattr +a / -a),
// macOS (chflags sappnd / nosappnd), and Windows (SetFileAttributes ±
// FILE_ATTRIBUTE_READONLY). Each platform's seal_<os>.go provides the
// implementation; this test exercises the cross-platform interface.
func TestSealRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")
	if err := os.WriteFile(path, []byte("initial-content\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Seal — best-effort, ignore errors (sealing fails on FAT, in
	// Docker without CAP_LINUX_IMMUTABLE, etc.). The point is that
	// the function doesn't crash on these surfaces; production code
	// already discards the return value via _ = ...
	_ = sealClosedLogFile(path)

	// File still readable from the daemon's own process.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sealed file: %v", err)
	}
	if string(got) != "initial-content\n" {
		t.Errorf("content changed after seal: %q", got)
	}

	// Unseal — same best-effort contract.
	_ = unsealLogFileForRetention(path)

	// After unseal, os.Remove must succeed (the retention path
	// depends on this). On platforms where seal failed silently,
	// removal already works — the test still passes.
	if err := os.Remove(path); err != nil {
		t.Errorf("remove after unseal: %v", err)
	}
}

// TestSealMissingFile verifies that sealing / unsealing a non-existent
// path returns an error (not a panic) and doesn't leave a half-sealed
// state. The retention path depends on this: if a file was rotated +
// sealed, then concurrently moved by an operator, the next-cycle
// unseal must fail cleanly so the os.Remove that follows can also
// fail-and-skip without a daemon crash.
func TestSealMissingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows SetFileAttributes returns an error on missing
		// files; same property, just different syscall path.
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist.jsonl")
	// Both paths should return an error (file doesn't exist) without
	// panicking. The production caller discards the error.
	if err := sealClosedLogFile(missing); err == nil {
		t.Errorf("seal on missing file should error, got nil")
	}
	if err := unsealLogFileForRetention(missing); err == nil {
		t.Errorf("unseal on missing file should error, got nil")
	}
}
