//go:build linux

package sieg

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// extraConn represents a flow that gopsutil's TCP/UDP enumeration
// doesn't see. On Linux that covers ICMP/ICMPv6 (both unprivileged
// SOCK_DGRAM in /proc/net/icmp and privileged SOCK_RAW in
// /proc/net/raw), plus every flow tracked by netfilter conntrack
// (/proc/net/nf_conntrack, when the kernel module is loaded — not
// available in stock Docker namespaces).
//
// Cross-platform: this file is Linux-only. Mac and Windows return
// empty results from the platform stub in conntrack_other.go.
type extraConn struct {
	pid        int32
	protocol   string // "icmp", "icmpv6", "raw", "udp", "tcp"
	localIP    string
	localPort  uint32
	remoteIP   string
	remotePort uint32
	status     string // "ACTIVE" / conntrack state ("ESTABLISHED", "TIME_WAIT", ...)
	source     string // "icmp", "icmp6", "raw", "raw6", "conntrack" — diagnostic
}

// platformExtraConns reads every kernel network table that gopsutil
// misses on this host. The order matters: nf_conntrack is most
// informative (every protocol, both directions, conntrack-tracked
// short flows) so it goes first; the per-protocol /proc files are
// fallbacks that catch sockets nf_conntrack didn't track (CT exempt,
// raw-socket sender bypasses, namespace without conntrack).
//
// Best-effort: any read error on one source is logged once but
// doesn't block the others. The caller is the network collector's
// polling loop; an empty return is the right behaviour when no
// source is available (no extra events, no spurious noise).
func (c *NetworkCollector) platformExtraConns() []extraConn {
	out := []extraConn{}
	// nf_conntrack first — it covers TCP/UDP/ICMP and is the only
	// source that reliably catches sub-second flows because conntrack
	// entries linger far past the socket's own lifetime.
	if entries, err := readNfConntrack(); err == nil {
		out = append(out, entries...)
	}
	// /proc/net/icmp + icmp6 — unprivileged SOCK_DGRAM ICMP sockets
	// (modern ping(8) when net.ipv4.ping_group_range allows the
	// caller's gid). Each row already has src+dst.
	if entries, err := readICMPSockets("/proc/net/icmp", "icmp"); err == nil {
		out = append(out, entries...)
	}
	if entries, err := readICMPSockets("/proc/net/icmp6", "icmpv6"); err == nil {
		out = append(out, entries...)
	}
	// /proc/net/raw + raw6 — privileged SOCK_RAW sockets (ping(8)
	// running with CAP_NET_RAW, the Docker default). Same hex
	// encoding as the TCP/UDP files.
	if entries, err := readICMPSockets("/proc/net/raw", "raw"); err == nil {
		out = append(out, entries...)
	}
	if entries, err := readICMPSockets("/proc/net/raw6", "raw6"); err == nil {
		out = append(out, entries...)
	}
	return out
}

// readICMPSockets parses one of:
//
//	/proc/net/icmp   — unprivileged ICMP (DGRAM)
//	/proc/net/icmp6
//	/proc/net/raw    — raw IPv4 sockets (catches root-ping)
//	/proc/net/raw6
//
// Format mirrors /proc/net/tcp:
//
//	  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
//	   0: 00000000:0001 00000000:0000 07 ...                                                          0       0 12345
//
// The local/rem addresses are hex little-endian for IPv4. For ICMP
// sockets, "rem_address" is 0 unless the socket is connected — which
// `ping` doesn't do. So we use "id" (the kernel folds the ICMP echo
// id into the local_port slot for SOCK_DGRAM ICMP) and read the
// destination from /proc/<pid>/fdinfo if the socket is connected.
//
// For raw sockets, rem_address is the destination IP set by sendto/
// connect — which IS what we want for ping(8) (it calls connect() on
// the raw socket before sendto()).
func readICMPSockets(path, label string) ([]extraConn, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []extraConn{}
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		// fields: [0]sl [1]local [2]remote [3]st [4]tx_queue [5]rx_queue
		// [6]tr [7]when [8]retrnsmt [9]uid [10]timeout [11]inode ...
		localIP, localPort, ok := parseProcNetAddr(fields[1])
		if !ok {
			continue
		}
		remoteIP, remotePort, _ := parseProcNetAddr(fields[2])
		// Skip rows where we have no destination — for ICMP this is
		// the unconnected sender state we'd need fdinfo to enrich,
		// and the row has zero forensic value without a peer.
		if remoteIP == "" || remoteIP == "0.0.0.0" || remoteIP == "::" {
			continue
		}
		inode, err := strconv.ParseUint(fields[11], 10, 64)
		if err != nil {
			continue
		}
		pid := inodeToPID(inode)
		out = append(out, extraConn{
			pid:        pid,
			protocol:   strings.TrimSuffix(label, "6"), // icmp/icmpv6 normalises to icmp; ditto raw/raw6
			localIP:    localIP,
			localPort:  uint32(localPort),
			remoteIP:   remoteIP,
			remotePort: uint32(remotePort),
			status:     "ACTIVE",
			source:     label,
		})
	}
	return out, nil
}

// readNfConntrack parses /proc/net/nf_conntrack (or the older
// /proc/net/ip_conntrack). One line per tracked flow:
//
//	ipv4     2 icmp     1 30 src=10.0.0.5 dst=8.8.8.8 type=8 code=0 id=1234 src=8.8.8.8 dst=10.0.0.5 type=0 code=0 id=1234 mark=0 use=2
//	ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=1.2.3.4 sport=44222 dport=443 src=1.2.3.4 dst=10.0.0.5 sport=443 dport=44222 ...
//
// The first src=/dst= pair is the original direction (caller →
// peer); the second is the reply. We emit the original direction
// only — the reply is the same flow viewed from the peer's side.
//
// Conntrack doesn't tag flows with a PID (kernel-side state, no
// process binding), so pid stays 0 here. Process attribution falls
// back to the existing /proc-based path when the same flow shows up
// in /proc/net/{tcp,udp,icmp,raw}.
//
// nf_conntrack isn't always available — disabled in containers
// without nf_conntrack.ko, missing on stripped kernels. The caller
// silently falls back to the per-protocol /proc files.
func readNfConntrack() ([]extraConn, error) {
	for _, path := range []string{"/proc/net/nf_conntrack", "/proc/net/ip_conntrack"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		defer f.Close()
		return parseNfConntrack(f)
	}
	return nil, fmt.Errorf("conntrack not available")
}

func parseNfConntrack(r io.Reader) ([]extraConn, error) {
	out := []extraConn{}
	sc := bufio.NewScanner(r)
	// Lines can be long with conntrack helper extensions.
	sc.Buffer(make([]byte, 64*1024), 256*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// fields[0] = ipv4|ipv6
		// fields[2] = tcp|udp|icmp|... (protocol name)
		// optional state token (ESTABLISHED/...) before src=
		proto := fields[2]
		if proto != "tcp" && proto != "udp" && proto != "icmp" && proto != "icmpv6" {
			continue
		}
		state := "ACTIVE"
		// State token (when present) is the field after the timeout.
		// Easiest extraction: parse src/dst/sport/dport from the
		// FIRST occurrence of each — the original direction.
		var (
			src, dst   string
			sport      uint32
			dport      uint32
			haveSrc    bool
			haveDst    bool
			haveSport  bool
			haveDport  bool
		)
		for _, tok := range fields {
			if !haveSrc && strings.HasPrefix(tok, "src=") {
				src = strings.TrimPrefix(tok, "src=")
				haveSrc = true
				continue
			}
			if haveSrc && !haveDst && strings.HasPrefix(tok, "dst=") {
				dst = strings.TrimPrefix(tok, "dst=")
				haveDst = true
				continue
			}
			if haveDst && !haveSport && strings.HasPrefix(tok, "sport=") {
				if p, err := strconv.ParseUint(strings.TrimPrefix(tok, "sport="), 10, 32); err == nil {
					sport = uint32(p)
					haveSport = true
				}
				continue
			}
			if haveDst && !haveDport && strings.HasPrefix(tok, "dport=") {
				if p, err := strconv.ParseUint(strings.TrimPrefix(tok, "dport="), 10, 32); err == nil {
					dport = uint32(p)
					haveDport = true
				}
				continue
			}
			// State for TCP appears as a plain word before src= —
			// keep it for the event when we see one of the conntrack
			// state names.
			switch tok {
			case "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT",
				"SYN_SENT", "SYN_RECV", "LAST_ACK", "CLOSING":
				state = tok
			}
		}
		if !haveSrc || !haveDst {
			continue
		}
		out = append(out, extraConn{
			pid:        0,
			protocol:   proto,
			localIP:    src,
			localPort:  sport,
			remoteIP:   dst,
			remotePort: dport,
			status:     state,
			source:     "conntrack",
		})
	}
	return out, sc.Err()
}

// parseProcNetAddr decodes the "ADDRESS:PORT" hex form used by every
// /proc/net/{tcp,udp,icmp,raw} file. The address is little-endian
// for IPv4 and big-endian byte-pairs for IPv6 (the kernel keeps the
// /proc rendering consistent across protocols). Returns ("", 0,
// false) on a malformed input.
func parseProcNetAddr(s string) (string, uint64, bool) {
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return "", 0, false
	}
	addrHex := s[:colon]
	portHex := s[colon+1:]
	port, err := strconv.ParseUint(portHex, 16, 32)
	if err != nil {
		return "", 0, false
	}
	switch len(addrHex) {
	case 8: // IPv4 little-endian
		b, err := hex.DecodeString(addrHex)
		if err != nil {
			return "", 0, false
		}
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0]), port, true
	case 32: // IPv6 — 4 little-endian dwords
		b, err := hex.DecodeString(addrHex)
		if err != nil {
			return "", 0, false
		}
		// Reverse each 4-byte group to get network byte order.
		out := make([]byte, 16)
		for i := 0; i < 4; i++ {
			out[i*4+0] = b[i*4+3]
			out[i*4+1] = b[i*4+2]
			out[i*4+2] = b[i*4+1]
			out[i*4+3] = b[i*4+0]
		}
		// Render as colon-separated hextet pairs.
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			(uint16(out[0])<<8)|uint16(out[1]),
			(uint16(out[2])<<8)|uint16(out[3]),
			(uint16(out[4])<<8)|uint16(out[5]),
			(uint16(out[6])<<8)|uint16(out[7]),
			(uint16(out[8])<<8)|uint16(out[9]),
			(uint16(out[10])<<8)|uint16(out[11]),
			(uint16(out[12])<<8)|uint16(out[13]),
			(uint16(out[14])<<8)|uint16(out[15])), port, true
	}
	return "", 0, false
}

// inodeToPID walks /proc/<pid>/fd/ looking for a symlink whose
// target matches "socket:[<inode>]". Returns 0 when no owning
// process is found (kernel-internal socket, or the process exited
// between the /proc/net/* read and our scan). Best-effort:
// permission denials on some PIDs are silently skipped.
//
// This is the inverse mapping the kernel doesn't expose directly —
// /proc/net/* gives inode but not PID, and /proc/<pid>/fd gives PID
// but the symlink target is the only place the inode appears.
// Cached pid->inode lookups would be faster but the cost is one map
// lookup per socket per poll, which is fine at our scale.
func inodeToPID(inode uint64) int32 {
	target := fmt.Sprintf("socket:[%d]", inode)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // permission denied / process gone
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				return int32(pid)
			}
		}
	}
	return 0
}
