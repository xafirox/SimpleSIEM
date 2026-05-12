//go:build windows

package sieg

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// applyFileMode mirrors POSIX mode semantics into a Windows DACL. Go's
// os.WriteFile ignores the mode argument on Windows — the file inherits
// from the parent directory, which on `C:\ProgramData\SimpleSIEM` ends
// up granting BUILTIN\Users `ReadAndExecute`. For files written with a
// "world-unreadable" intent (mode bits where the "other" triad has no
// read bit set), strip BUILTIN\Users from the DACL so the file matches
// the Linux 0o640 contract — only SYSTEM and Administrators retain
// access.
//
// Best-effort: an error here doesn't fail the write (the file is
// already on disk). Operator security is preserved by the parent dir's
// ACL even when the per-file tightening fails.
func applyFileMode(path string, mode os.FileMode) {
	if mode&0o004 != 0 {
		// "Other can read" — Linux-equivalent is world-readable, so no
		// tightening required on Windows.
		return
	}
	tightenWindowsACL(path)
}

// tightenWindowsACL builds a fresh DACL granting:
//   - NT AUTHORITY\SYSTEM           — Full Control
//   - BUILTIN\Administrators        — Full Control
//
// and replaces the file's DACL with it. The Owner of the file (left
// untouched) typically retains access through Administrators on a
// service-managed host. Network logins / BUILTIN\Users are removed.
func tightenWindowsACL(path string) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}

	// Well-known SIDs.
	var sidSystem *windows.SID
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		1, windows.SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0, &sidSystem); err != nil {
		return
	}
	defer windows.FreeSid(sidSystem)

	var sidAdmins *windows.SID
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2, windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sidAdmins); err != nil {
		return
	}
	defer windows.FreeSid(sidAdmins)

	// Build two explicit-access entries granting full control.
	access := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID,
				TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sidSystem),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID,
				TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sidAdmins),
			},
		},
	}

	acl, err := windows.ACLFromEntries(access, nil)
	if err != nil {
		return
	}

	// PROTECTED_DACL_SECURITY_INFORMATION blocks inheritance from the parent
	// (otherwise BUILTIN\Users would be reapplied from ProgramData).
	const flags = windows.DACL_SECURITY_INFORMATION |
		windows.PROTECTED_DACL_SECURITY_INFORMATION
	_ = windows.SetNamedSecurityInfo(
		windows.UTF16PtrToString(pathPtr),
		windows.SE_FILE_OBJECT,
		flags,
		nil, nil, acl, nil,
	)
	_ = unsafe.Pointer(pathPtr) // keep the pointer alive across the SetNamedSecurityInfo call
}
