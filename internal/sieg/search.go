package sieg

import (
	"os"
	"path/filepath"
	"strings"
)

// resolveHostDirCase looks for a child directory of base whose name
// case-insensitively matches host. Returns the actual on-disk name
// when found, or "" when no match exists. Lets `query --host
// WINDOWSTEST1` find events stored under WindowsTest1 on a
// case-sensitive filesystem.
func resolveHostDirCase(base, host string) string {
	if host == "" {
		return ""
	}
	// Exact match wins — skip the directory scan when the operator
	// already typed the canonical case.
	if st, err := os.Stat(filepath.Join(base, host)); err == nil && st.IsDir() {
		return host
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if strings.EqualFold(e.Name(), host) {
			return e.Name()
		}
	}
	return ""
}

// searchRoot is one (base, host) pair to scan when reading events. Server
// mode produces one root per agent ID; standalone/agent mode produces one
// root for the local log directory.
type searchRoot struct {
	base string
	host string
}

// searchRoots returns the list of directories the read commands should
// walk for the given config + optional host filter:
//
//   - standalone:  one root, base = cfg.LogDir, host = ""
//   - agent:       one root, base = cfg.LogDir/_agent (only meta + errors live here),
//     plus the agent-forward dir if it exists locally
//   - server:      one root per agent if no filter; a single root if --host is set
//
// In server mode, an unknown --host is returned as a single root anyway
// so the caller can produce a clean "no events" response rather than a
// directory-walk error.
func searchRoots(cfg Config, hostFilter string) []searchRoot {
	mode := normaliseMode(cfg.Mode)
	locs := allStorageLocations(cfg)
	switch mode {
	case "server", "master":
		if hostFilter != "" {
			out := make([]searchRoot, 0, len(locs))
			for _, l := range locs {
				// Case-insensitive directory match: master receives events
				// labelled by cert CN (e.g. "WindowsTest1"), but operators
				// often query with the OS-reported computer name (e.g.
				// `$env:COMPUTERNAME` returns "WINDOWSTEST1" on Windows).
				// On Linux/Darwin filesystems the cases don't collide, so a
				// literal join would silently miss the data. Fall back to
				// scanning the parent for a case-insensitive match before
				// giving up.
				resolved := resolveHostDirCase(l, hostFilter)
				if resolved == "" {
					resolved = hostFilter
				}
				out = append(out, searchRoot{base: filepath.Join(l, resolved), host: resolved})
			}
			return out
		}
		// Union hosts across every configured storage location so a
		// failover that left some days under /var/log and others
		// under /mnt/extra still produces a single read view. Same
		// host present in two roots means two searchRoots — query
		// loops already de-dup via timestamp ordering.
		seen := map[string]bool{}
		out := make([]searchRoot, 0)
		for _, l := range locs {
			for _, h := range listHosts(l) {
				key := l + "|" + h
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, searchRoot{base: filepath.Join(l, h), host: h})
			}
		}
		return out
	case "agent":
		out := make([]searchRoot, 0, len(locs))
		for _, l := range locs {
			out = append(out, searchRoot{base: filepath.Join(l, "_agent"), host: ""})
		}
		return out
	}
	out := make([]searchRoot, 0, len(locs))
	for _, l := range locs {
		out = append(out, searchRoot{base: l, host: ""})
	}
	return out
}
