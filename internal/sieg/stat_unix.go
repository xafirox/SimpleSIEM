//go:build linux || darwin

package sieg

import (
	"os"
	"os/user"
	"strconv"
	"sync"
	"syscall"
)

// userCache memoises os/user.LookupId — it parses /etc/passwd on every call,
// which adds up fast during bulk filesystem churn (e.g. dpkg unpacking a
// package and touching thousands of files under the same uid).
var (
	userCacheMu sync.RWMutex
	userCache   = map[uint32]string{}
)

func usernameFromUID(uid uint32) string {
	userCacheMu.RLock()
	if n, ok := userCache[uid]; ok {
		userCacheMu.RUnlock()
		return n
	}
	userCacheMu.RUnlock()
	name := ""
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		name = u.Username
	}
	userCacheMu.Lock()
	userCache[uid] = name
	userCacheMu.Unlock()
	return name
}

func addFileStat(rec map[string]any, st os.FileInfo, _ string) {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		rec["uid"] = sys.Uid
		rec["gid"] = sys.Gid
		if name := usernameFromUID(sys.Uid); name != "" {
			rec["user"] = name
		}
	}
}
