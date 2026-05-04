package sieg

// sealClosedLogFile applies a platform-appropriate "no further
// modification" attribute to a daily log file that's just been
// closed. Linux uses `chattr +a` (append-only — even root can't
// truncate, rewrite, or unlink without first removing the flag);
// macOS uses `chflags sappnd` (system-append-only, the BSD
// equivalent); Windows uses the read-only file attribute via
// SetFileAttributes (closed files are never reopened for write so
// this is functionally equivalent to "no further modification").
//
// Best-effort by design — the hash chain in `_hash`/`_prev`/`_seq`
// is the authoritative tamper signal regardless of whether the OS
// flag was applied. A filesystem that doesn't support the flag (a
// FAT/exFAT USB target, a network share with limited attribute
// support) silently no-ops; the daemon proceeds without the extra
// guarantee. Failures are intentionally not propagated to writeNow
// — losing the seal is preferable to losing the event itself.
//
// Threat model: this is "speed bump" protection against root, not
// "wall" protection. An attacker with root can remove the flag and
// then tamper, but the flag-clearing operation:
//
//   - leaves an audit trail (auditd / Console / Event Log)
//   - cannot be combined with the modification in a single syscall
//   - is detectable post-hoc when the upstream master pulls the
//     events and finds the chain inconsistent vs. its replicated copy
//
// In combination with the existing aggressive-shipping defaults, an
// attacker has a tight window in which to (a) gain root, (b) clear
// flags, (c) tamper, (d) ship the cleaned-up state forward — before
// the events have already replicated to a server / master in a
// different administrative domain.
func sealClosedLogFile(path string) error {
	return platformSealClosedLogFile(path)
}

// unsealLogFileForRetention removes the seal so the daemon's own
// retention loop can delete the file. Same root caveat as
// sealClosedLogFile: an attacker with root can do this too, but the
// flag-clearing is observable (auditd / Console / Event Log) and
// non-atomic with the deletion that follows.
//
// Failures are non-fatal — if unseal fails, the subsequent
// os.Remove call simply fails too and the file stays on disk an
// extra cycle. Retention is best-effort by design (it tolerates
// mid-walk file additions / removals already), so a one-cycle
// delay on a stuck file is acceptable.
func unsealLogFileForRetention(path string) error {
	return platformUnsealLogFile(path)
}
