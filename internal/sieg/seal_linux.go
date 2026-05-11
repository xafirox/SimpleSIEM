//go:build linux

package sieg

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// platformSealClosedLogFile applies the append-only ext-family
// inode flag (FS_APPEND_FL). Once set, even root cannot truncate,
// rewrite, or unlink the file without first clearing the flag —
// which is observable via auditd. Append-only writes (the daemon's
// own further activity, were any to occur) are still permitted, so
// applying this flag mid-day to a file that's still being appended
// to wouldn't break the daemon — but the daemon only seals on
// rotation when the file is closed, so the question is moot.
//
// Pure-Go implementation: opens the file, issues the FS_IOC_SETFLAGS
// ioctl directly. No dependency on the chattr(1) binary, which
// matches the project rule that "everything should not depend on
// having external tools" (chattr is part of e2fsprogs but stripped
// distro images and busybox-only containers omit it).
//
// Best-effort: filesystems that don't support FS_APPEND_FL (FAT,
// exFAT, NTFS via ntfs-3g without write-access, some network
// mounts) return EOPNOTSUPP / EINVAL; we wrap the error so the
// caller can log it but proceed.
func platformSealClosedLogFile(path string) error {
	return setInodeAppendOnly(path, true)
}

func platformUnsealLogFile(path string) error {
	return setInodeAppendOnly(path, false)
}

// setInodeAppendOnly toggles FS_APPEND_FL on the named file via
// the FS_IOC_GETFLAGS / FS_IOC_SETFLAGS ioctl pair. The two
// constants are the canonical values from <linux/fs.h>:
//
//	#define FS_APPEND_FL   0x00000020
//	#define FS_IOC_GETFLAGS _IOR('f', 1, long)
//	#define FS_IOC_SETFLAGS _IOW('f', 2, long)
//
// We need read-modify-write semantics (preserve other inode flags
// like FS_IMMUTABLE_FL the operator might already have set on the
// log dir) — which is why we GET first, OR/AND_NOT the bit, then
// SET back.
func setInodeAppendOnly(path string, on bool) error {
	const (
		fsAppendFl     = 0x00000020 // FS_APPEND_FL from <linux/fs.h>
		fsIocGetFlags  = 0x80086601 // _IOR('f', 1, long) on 64-bit Linux
		fsIocSetFlags  = 0x40086602 // _IOW('f', 2, long) on 64-bit Linux
	)
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return wrapSealError(path, err, nil)
	}
	defer f.Close()
	var flags uint32
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(fsIocGetFlags), uintptr(0)); errno != 0 {
		// Reading flags failed — the filesystem doesn't support
		// the ioctl (FAT, exFAT, NTFS, some FUSE mounts) or we
		// don't have permission. Return a wrapped error with the
		// errno; caller logs and proceeds.
		return wrapSealError(path, fmt.Errorf("ioctl FS_IOC_GETFLAGS: %v", errno), nil)
	}
	// The kernel writes flags into the third argument's POINTED-TO
	// memory, not the argument itself. unix.Syscall doesn't quite
	// give us that — we need IoctlGetInt or IoctlSetPointerInt.
	// Use the typed helper from x/sys/unix which handles the
	// pointer dance correctly.
	val, err := unix.IoctlGetInt(int(f.Fd()), uint(fsIocGetFlags))
	if err != nil {
		return wrapSealError(path, fmt.Errorf("ioctl FS_IOC_GETFLAGS: %w", err), nil)
	}
	flags = uint32(val)
	if on {
		flags |= fsAppendFl
	} else {
		flags &^= fsAppendFl
	}
	if err := unix.IoctlSetPointerInt(int(f.Fd()), uint(fsIocSetFlags), int(flags)); err != nil {
		return wrapSealError(path, fmt.Errorf("ioctl FS_IOC_SETFLAGS: %w", err), nil)
	}
	return nil
}

// wrapSealError adds the path to the error message. The third
// argument used to carry the chattr(1) stderr buffer; kept for
// signature compatibility with the macOS variant which still
// sees stderr from chflags(1).
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
