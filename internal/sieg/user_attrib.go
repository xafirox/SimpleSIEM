package sieg

import (
	"path/filepath"
	"strings"
)

// userFromPath returns the owning user account inferred from a
// filesystem path, or "" if no user can be determined.
//
// Recognised shapes (case-insensitive on the prefix; the username is
// returned with original casing):
//   - C:\Users\<name>\... (any drive letter)        Windows
//   - /Users/<name>/...                              macOS
//   - /home/<name>/...                               Linux
//   - /root or /root/...                             Linux root
//
// Paths outside these prefixes (system dirs like C:\WINDOWS, /etc,
// /var, /opt) return "" — the SIEM has no per-user attribution
// for system-owned files without kernel-level integration (ETW on
// Windows, fanotify on Linux, ESF on macOS).
func userFromPath(path string) string {
	if path == "" {
		return ""
	}
	p := filepath.ToSlash(path)
	pLower := strings.ToLower(p)

	if len(p) >= 4 && p[1] == ':' && strings.HasPrefix(pLower[2:], "/users/") {
		rest := p[len("X:/Users/"):]
		if i := strings.IndexByte(rest, '/'); i > 0 {
			return rest[:i]
		}
		return rest
	}
	if strings.HasPrefix(pLower, "/users/") {
		rest := p[len("/Users/"):]
		if i := strings.IndexByte(rest, '/'); i > 0 {
			return rest[:i]
		}
		return rest
	}
	if strings.HasPrefix(pLower, "/home/") {
		rest := p[len("/home/"):]
		if i := strings.IndexByte(rest, '/'); i > 0 {
			return rest[:i]
		}
		return rest
	}
	if pLower == "/root" || strings.HasPrefix(pLower, "/root/") {
		return "root"
	}
	return ""
}
