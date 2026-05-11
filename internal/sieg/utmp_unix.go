//go:build linux || darwin

package sieg

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"runtime"
	"time"
)

// whoSnapshot reads the host's utmp file directly — no shell-out
// to who(1). The "everything-built-in" rule means we can't depend
// on coreutils/util-linux being present on every container image.
//
// On Linux: parses /var/run/utmp (or the legacy /run/utmp). The
// utmp(5) struct layout is documented and ABI-stable across glibc
// 2.4+ — the same byte layout every distro since 2006.
//
// On macOS: parses /var/run/utmpx (CGO-disabled gopsutil returns
// empty Users(), so this path is the only source). Apple's utmpx
// struct is in <utmpx.h>; the layout has been stable since 10.4.
//
// Cross-platform fallback: returns empty when no utmp is found
// (read-only image, namespace without /run mounted, etc.). Caller
// has gopsutil's host.Users as the primary source and falls back
// to this only when that returns empty.
func whoSnapshot(ctx context.Context) map[userSession]struct{} {
	out := map[userSession]struct{}{}
	switch runtime.GOOS {
	case "linux":
		return readUtmpLinux()
	case "darwin":
		return readUtmpxDarwin()
	}
	return out
}

// utmp record types (Linux + Darwin share the same enum).
const (
	utUserProcess = 7 // active session
	utDeadProcess = 8
)

// readUtmpLinux parses /var/run/utmp on Linux. Each entry is a
// fixed 384-byte struct:
//
//	struct utmp {
//	    short          ut_type;        // 2 bytes
//	    int32          ut_pid;         // 4 bytes (after 2 bytes alignment pad)
//	    char           ut_line[32];    // 32 bytes
//	    char           ut_id[4];       // 4 bytes
//	    char           ut_user[32];    // 32 bytes
//	    char           ut_host[256];   // 256 bytes
//	    struct exit_status ut_exit;    // 4 bytes
//	    int32          ut_session;     // 4 bytes
//	    struct timeval ut_tv;          // 8 bytes (sec, usec 32-bit on linux)
//	    int32          ut_addr_v6[4];  // 16 bytes
//	    char           __unused[20];   // 20 bytes
//	};
//
// Total: 384 bytes. We only care about ut_type==USER_PROCESS rows
// where ut_user is non-empty.
func readUtmpLinux() map[userSession]struct{} {
	out := map[userSession]struct{}{}
	for _, path := range []string{"/var/run/utmp", "/run/utmp"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		const recSize = 384
		for off := 0; off+recSize <= len(data); off += recSize {
			rec := data[off : off+recSize]
			ut_type := int16(binary.LittleEndian.Uint16(rec[0:2]))
			if ut_type != utUserProcess {
				continue
			}
			// Field offsets within the 384-byte record.
			line := cString(rec[8:8+32])
			user := cString(rec[44 : 44+32])
			host := cString(rec[76 : 76+256])
			tvSec := int32(binary.LittleEndian.Uint32(rec[336:340]))
			started := ""
			if tvSec > 0 {
				started = time.Unix(int64(tvSec), 0).UTC().Format(time.RFC3339)
			}
			if user == "" {
				continue
			}
			out[userSession{user: user, terminal: line, host: host, started: started}] = struct{}{}
		}
		if len(out) > 0 {
			return out
		}
	}
	return out
}

// readUtmpxDarwin parses /var/run/utmpx. Apple's struct utmpx is
// 628 bytes and laid out:
//
//	char    ut_user[256];       // 256 bytes
//	char    ut_id[4];           // 4 bytes
//	char    ut_line[32];        // 32 bytes
//	pid_t   ut_pid;             // 4 bytes (= int32)
//	short   ut_type;            // 2 bytes (+ 2 bytes alignment pad)
//	struct timeval ut_tv {      // 16 bytes on 64-bit Darwin
//	    int64 tv_sec;
//	    int32 tv_usec;          // + 4 bytes pad
//	};
//	char    ut_host[256];       // 256 bytes
//	__uint32_t ut_pad[16];      // 64 bytes
//
// Total: 628 + 4 alignment slack = 628 bytes (Apple uses pack/4).
//
// The header file says 628; the actual file uses fixed records of
// that size. We only need ut_user / ut_line / ut_host /
// ut_tv.tv_sec; everything else is parsed for offset bookkeeping
// and discarded.
func readUtmpxDarwin() map[userSession]struct{} {
	out := map[userSession]struct{}{}
	data, err := os.ReadFile("/var/run/utmpx")
	if err != nil {
		return out
	}
	const recSize = 628
	for off := 0; off+recSize <= len(data); off += recSize {
		rec := data[off : off+recSize]
		// ut_user @ 0..256
		user := cString(rec[0:256])
		// ut_line @ 260..292
		line := cString(rec[260:292])
		// ut_type @ 298..300 (after pid at 296..300, but Apple
		// puts type after pid with a 2-byte alignment pad; the
		// canonical offset for Apple's struct is 298).
		ut_type := int16(binary.LittleEndian.Uint16(rec[298:300]))
		if ut_type != utUserProcess {
			continue
		}
		// ut_tv @ 304..320 (sec=8, usec=4+pad=8)
		tvSec := int64(binary.LittleEndian.Uint64(rec[304:312]))
		started := ""
		if tvSec > 0 {
			started = time.Unix(tvSec, 0).UTC().Format(time.RFC3339)
		}
		// ut_host @ 320..576
		host := cString(rec[320:576])
		if user == "" {
			continue
		}
		out[userSession{user: user, terminal: line, host: host, started: started}] = struct{}{}
	}
	return out
}

// cString trims a NUL-padded byte slice into a Go string. utmp
// fields are fixed-width zero-padded; treating them as raw strings
// would include a long tail of \x00 bytes.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
