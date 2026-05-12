//go:build windows

package sieg

import (
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// winOwnerCache memoises SID → "DOMAIN\\name" lookups. LookupAccountSid does a
// local SAM / domain DC round-trip on every call; in a busy directory
// (e.g. an installer dropping 5,000 files under the same SID) this would
// dominate the FileCollector goroutine. Cache lifetime = process; the
// SID→name mapping is effectively immutable for a running daemon.
var (
	winOwnerCacheMu sync.RWMutex
	winOwnerCache   = map[string]string{}
)

func lookupOwner(sid *windows.SID) string {
	if sid == nil {
		return ""
	}
	key := sid.String()
	winOwnerCacheMu.RLock()
	if n, ok := winOwnerCache[key]; ok {
		winOwnerCacheMu.RUnlock()
		return n
	}
	winOwnerCacheMu.RUnlock()
	account, domain, _, err := sid.LookupAccount("")
	name := ""
	if err == nil && account != "" {
		if domain != "" {
			name = domain + "\\" + account
		} else {
			name = account
		}
	}
	winOwnerCacheMu.Lock()
	winOwnerCache[key] = name
	winOwnerCacheMu.Unlock()
	return name
}

// addFileStat populates owner attribution on Windows by resolving the file's
// owner SID via GetNamedSecurityInfo + LookupAccountSid. Best-effort —
// permission-denied / file-deleted-before-lookup races degrade gracefully:
// the event still has size/mode/sha384 but no `user` field. The caller's
// path-derived fallback in Storage.Write (user_attrib.go, files under
// C:\Users\<name>\…) still applies for any file we couldn't open.
func addFileStat(rec map[string]any, st os.FileInfo, path string) {
	_ = st // mode / size already captured by the caller; we only add owner here
	if path == "" {
		return
	}
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return
	}
	rec["owner_sid"] = owner.String()
	if name := lookupOwner(owner); name != "" {
		// Strip the local-machine prefix so `user` reads cleanly. We
		// keep DOMAIN\name for actual domain accounts.
		if i := strings.IndexByte(name, '\\'); i > 0 {
			domain := name[:i]
			account := name[i+1:]
			// Heuristic: drop the prefix when it matches the host (a
			// local SAM account). Domain accounts keep DOMAIN\name so
			// queries can group by domain.
			if host, hErr := windows.ComputerName(); hErr == nil && strings.EqualFold(domain, host) {
				rec["user"] = account
				return
			}
		}
		rec["user"] = name
	}
}
