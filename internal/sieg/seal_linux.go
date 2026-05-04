//go:build linux

package sieg

import (
	"context"
	"os/exec"
	"time"
)

// platformSealClosedLogFile applies the append-only ext-family
// inode flag (`chattr +a`). Once set, even root cannot truncate,
// rewrite, or unlink the file without first running `chattr -a` —
// which is observable via auditd. Append-only writes (the daemon's
// own further activity, were any to occur) are still permitted, so
// applying this flag mid-day to a file that's still being appended
// to wouldn't break the daemon — but the daemon only seals on
// rotation when the file is closed, so the question is moot.
//
// Best-effort: filesystems that don't support FS_APPEND_FL (FAT,
// exFAT, NTFS via ntfs-3g without write-access, some network
// mounts) return EOPNOTSUPP / EINVAL; we ignore the error.
//
// Why exec(chattr) instead of ioctl(FS_IOC_SETFLAGS): chattr is in
// every coreutils install, the operation runs once per daily-file
// rotation (not in any hot path), and a one-line shell-out is
// dramatically less code than a platform-specific syscall wrapper
// for a marginal performance gain on a non-hot path.
func platformSealClosedLogFile(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "chattr", "+a", path).CombinedOutput()
	if err != nil {
		return wrapSealError(path, err, out)
	}
	return nil
}

func platformUnsealLogFile(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "chattr", "-a", path).CombinedOutput()
	if err != nil {
		return wrapSealError(path, err, out)
	}
	return nil
}

// wrapSealError flattens a CombinedOutput byte slice into a single
// error message so callers (which log the error) get useful context.
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
