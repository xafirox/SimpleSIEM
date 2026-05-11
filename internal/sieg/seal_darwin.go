//go:build darwin

package sieg

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// platformSealClosedLogFile applies the BSD `sappnd` (system
// append-only) flag via the chflags(2) syscall. Once set, even
// root cannot truncate, rewrite, or unlink the file without first
// clearing it — which is logged by the unified-logging system
// (Console.app, `log stream`).
//
// `sappnd` is the system-flag variant: clearing it requires the
// system to be in single-user mode below the secure level (which
// is the default on macOS desktop / server). On a multi-user box,
// even an admin terminal can clear it; on a single-purpose SIEM
// host with `sysctl kern.securelevel=1`, root itself can't clear
// it without a reboot.
//
// Pure-Go implementation: calls unix.Chflags(path, SF_APPEND)
// directly. No dependency on the chflags(1) binary — the project
// rule is "everything should not depend on having external tools",
// and chflags(1) ships with macOS but isn't guaranteed on every
// stripped image (CI runners, Docker images derived from FreeBSD
// userland, etc.).
//
// Best-effort: filesystems that don't support BSD flags (FAT,
// exFAT, SMB shares) return EOPNOTSUPP; we wrap and surface to the
// caller without halting.
func platformSealClosedLogFile(path string) error {
	if err := unix.Chflags(path, unix.SF_APPEND); err != nil {
		return wrapSealError(path, fmt.Errorf("chflags +sappnd: %w", err), nil)
	}
	return nil
}

func platformUnsealLogFile(path string) error {
	// Read current flags via Lstat (Stat_t.Flags) so we only
	// clear SF_APPEND and preserve anything else (uimmutable,
	// hidden, ...). The kernel's stat(2) returns flags in the
	// st_flags field on Darwin.
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return wrapSealError(path, fmt.Errorf("lstat: %w", err), nil)
	}
	flags := uint32(st.Flags) &^ uint32(unix.SF_APPEND)
	if err := unix.Chflags(path, int(flags)); err != nil {
		return wrapSealError(path, fmt.Errorf("chflags -sappnd: %w", err), nil)
	}
	return nil
}

func wrapSealError(path string, err error, out []byte) error {
	if len(out) == 0 {
		return &sealError{path: path, base: err}
	}
	return &sealError{path: path, base: err, output: string(out)}
}

type sealError struct {
	path   string
	base   error
	output string
}

func (e *sealError) Error() string {
	if e.output == "" {
		return "seal " + e.path + ": " + e.base.Error()
	}
	return "seal " + e.path + ": " + e.base.Error() + ": " + e.output
}

func (e *sealError) Unwrap() error { return e.base }
