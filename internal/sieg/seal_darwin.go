//go:build darwin

package sieg

import (
	"context"
	"os/exec"
	"time"
)

// platformSealClosedLogFile applies the BSD `sappnd` (system
// append-only) flag via `chflags`. Once set, even root cannot
// truncate, rewrite, or unlink the file without first running
// `chflags nosappnd` — which is logged by the unified-logging
// system (Console.app, `log stream`).
//
// `sappnd` is the system-flag variant: clearing it requires the
// system to be in single-user mode below the secure level (which
// is the default on macOS desktop / server). On a multi-user box,
// even an admin terminal can clear it; on a single-purpose SIEM
// host with `sysctl kern.securelevel=1`, root itself can't clear
// it without a reboot. We use `sappnd` rather than the user-flag
// `uappnd` because the threat model is "root attacker tries to
// scrub the logs" — we want the strongest available guarantee,
// not the weakest.
//
// Best-effort: filesystems that don't support BSD flags (FAT,
// exFAT, SMB shares, etc.) return ENOTSUP; we ignore the error and
// rely on the chain hash + remote replication for tamper detection
// on those volumes.
//
// Why exec(chflags) instead of syscall.Chflags: same rationale as
// the Linux side — chflags is in every macOS install, runs once per
// daily-file rotation, and a one-line shell-out is significantly
// less code than a platform-specific syscall wrapper for a non-hot
// path.
func platformSealClosedLogFile(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "chflags", "sappnd", path).CombinedOutput()
	if err != nil {
		return wrapSealError(path, err, out)
	}
	return nil
}

func platformUnsealLogFile(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "chflags", "nosappnd", path).CombinedOutput()
	if err != nil {
		return wrapSealError(path, err, out)
	}
	return nil
}

func wrapSealError(path string, err error, out []byte) error {
	if len(out) == 0 {
		return err
	}
	return &sealError{path: path, base: err, output: string(out)}
}

type sealError struct {
	path   string
	base   error
	output string
}

func (e *sealError) Error() string {
	return "seal " + e.path + ": " + e.base.Error() + ": " + e.output
}

func (e *sealError) Unwrap() error { return e.base }
