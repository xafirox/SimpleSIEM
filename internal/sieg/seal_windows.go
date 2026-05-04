//go:build windows

package sieg

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// platformSealClosedLogFile sets the FILE_ATTRIBUTE_READONLY bit on
// the closed daily file. NTFS doesn't expose a true "append-only"
// flag (the `attrib +a` archive-bit is unrelated and means
// "modified since last backup"), so we use READONLY: closed daily
// files are never reopened for write, so READONLY is functionally
// equivalent to "no further modification" for our purposes.
//
// READONLY blocks:
//
//   - WriteFile / SetEndOfFile (truncate)
//   - DeleteFile
//   - MoveFileEx
//   - SetFileInformationByHandle with REPLACE_INFO
//
// from any caller — including SYSTEM and Administrator — until the
// attribute is cleared. The clearing operation (SetFileAttributes
// removing READONLY) is logged in the Windows Event Log when audit
// policy is enabled, leaving the same audit-trail property as the
// Linux/macOS variants.
//
// Best-effort: returns the syscall error to the caller (logged but
// non-fatal). Filesystems mounted via SMB on a remote share that
// doesn't honour client-side attribute sets just no-op silently.
func platformSealClosedLogFile(path string) error {
	pathW, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := syscall.GetFileAttributes(pathW)
	if err != nil {
		return err
	}
	return syscall.SetFileAttributes(pathW, attrs|windows.FILE_ATTRIBUTE_READONLY)
}

func platformUnsealLogFile(path string) error {
	pathW, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := syscall.GetFileAttributes(pathW)
	if err != nil {
		return err
	}
	return syscall.SetFileAttributes(pathW, attrs&^windows.FILE_ATTRIBUTE_READONLY)
}
