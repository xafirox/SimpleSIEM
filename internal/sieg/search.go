package sieg

import (
	"path/filepath"
)

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
				out = append(out, searchRoot{base: filepath.Join(l, hostFilter), host: hostFilter})
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
