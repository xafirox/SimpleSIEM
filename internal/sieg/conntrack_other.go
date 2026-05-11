//go:build !linux

package sieg

// extraConn mirrors the Linux conntrack_linux.go shape so callers
// don't have to OS-switch the type. Fields stay populated but the
// platform stub returns no entries — gopsutil's TCP/UDP enumeration
// is the only source on non-Linux.
type extraConn struct {
	pid        int32
	protocol   string
	localIP    string
	localPort  uint32
	remoteIP   string
	remotePort uint32
	status     string
	source     string
}

// platformExtraConns is a no-op on non-Linux. macOS and Windows
// would need a different mechanism to surface ICMP/raw destinations
// — `netstat -p icmp` parsing on Mac, ETW or Get-NetTCPConnection
// equivalents on Windows. Both are out of scope for the no-CGO
// pure-Go build; documented as a known gap in network-ingest.md.
func (c *NetworkCollector) platformExtraConns() []extraConn {
	return nil
}
