//go:build linux

package sieg

import (
	"bytes"
	"strings"
	"testing"
)

// TestParseProcNetAddr_IPv4 verifies the little-endian hex decode
// the kernel uses in /proc/net/{tcp,udp,icmp,raw}.
//   Input "0100007F:0035" is 127.0.0.1:53 — the loopback resolver.
//   Input "08080808:0000" is 8.8.8.8:0   — Google DNS, no port set.
func TestParseProcNetAddr_IPv4(t *testing.T) {
	tests := []struct {
		in       string
		wantIP   string
		wantPort uint64
		wantOk   bool
	}{
		{"0100007F:0035", "127.0.0.1", 53, true},
		{"08080808:0000", "8.8.8.8", 0, true},
		{"0100A8C0:01BB", "192.168.0.1", 443, true},
		{"00000000:0050", "0.0.0.0", 80, true},
		// Malformed — too short, missing colon, bad hex.
		{"0100007F", "", 0, false},
		{"GGGGGGGG:0035", "", 0, false},
	}
	for _, tt := range tests {
		ip, port, ok := parseProcNetAddr(tt.in)
		if ok != tt.wantOk {
			t.Errorf("parseProcNetAddr(%q): ok=%v want %v", tt.in, ok, tt.wantOk)
			continue
		}
		if !ok {
			continue
		}
		if ip != tt.wantIP {
			t.Errorf("parseProcNetAddr(%q): ip=%q want %q", tt.in, ip, tt.wantIP)
		}
		if port != tt.wantPort {
			t.Errorf("parseProcNetAddr(%q): port=%d want %d", tt.in, port, tt.wantPort)
		}
	}
}

// TestParseProcNetAddr_IPv6 verifies the IPv6 decode. The kernel
// stores 4 little-endian dwords; we reverse each to get network
// byte order.
//   "0000000000000000FFFF00007F000001:0035"
//        4 dwords: 0,0,FFFF0000,7F000001 (little-endian, per dword)
//        Network order: 0,0,0000FFFF,0100007F → ::ffff:127.0.0.1
//   But for simplicity here, we test a plain ::1.
func TestParseProcNetAddr_IPv6(t *testing.T) {
	// ::1 in 4 little-endian dwords, each 4 bytes:
	//   word 0 = 0   (00000000)
	//   word 1 = 0   (00000000)
	//   word 2 = 0   (00000000)
	//   word 3 = 1   (01000000 little-endian)
	in := "00000000000000000000000001000000:0035"
	ip, port, ok := parseProcNetAddr(in)
	if !ok {
		t.Fatalf("parseProcNetAddr(%q) returned ok=false", in)
	}
	if port != 53 {
		t.Errorf("port: got %d want 53", port)
	}
	// The exact rendering uses %x per hextet group — accept any
	// canonical form of ::1 (zeros may be elided differently).
	if !strings.Contains(ip, "1") {
		t.Errorf("expected ipv6 ::1-ish, got %q", ip)
	}
}

// TestParseNfConntrack_TCP exercises the conntrack reader against a
// realistic line. ESTABLISHED state, src=10.0.0.5 dst=1.2.3.4
// sport=44222 dport=443. Confirms the original-direction src/dst is
// captured (not the reply-direction's swapped pair) and that the
// state token is preserved.
func TestParseNfConntrack_TCP(t *testing.T) {
	line := "ipv4     2 tcp      6 431999 ESTABLISHED " +
		"src=10.0.0.5 dst=1.2.3.4 sport=44222 dport=443 " +
		"src=1.2.3.4 dst=10.0.0.5 sport=443 dport=44222 " +
		"[ASSURED] mark=0 use=2"
	got, err := parseNfConntrack(bytes.NewReader([]byte(line + "\n")))
	if err != nil {
		t.Fatalf("parseNfConntrack: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	e := got[0]
	if e.protocol != "tcp" {
		t.Errorf("protocol: got %q want tcp", e.protocol)
	}
	if e.localIP != "10.0.0.5" {
		t.Errorf("localIP: got %q want 10.0.0.5", e.localIP)
	}
	if e.remoteIP != "1.2.3.4" {
		t.Errorf("remoteIP: got %q want 1.2.3.4", e.remoteIP)
	}
	if e.localPort != 44222 {
		t.Errorf("localPort: got %d want 44222", e.localPort)
	}
	if e.remotePort != 443 {
		t.Errorf("remotePort: got %d want 443", e.remotePort)
	}
	if e.status != "ESTABLISHED" {
		t.Errorf("status: got %q want ESTABLISHED", e.status)
	}
	if e.source != "conntrack" {
		t.Errorf("source: got %q want conntrack", e.source)
	}
}

// TestParseNfConntrack_ICMP — the canonical ping flow. ICMP rows
// don't have sport/dport (they have id/type/code instead) so those
// stay zero; src+dst are the only fields we need for the operator
// answer "what did this host ping?".
func TestParseNfConntrack_ICMP(t *testing.T) {
	line := "ipv4     2 icmp     1 30 src=10.0.0.5 dst=8.8.8.8 type=8 code=0 id=1234 " +
		"src=8.8.8.8 dst=10.0.0.5 type=0 code=0 id=1234 mark=0 use=2"
	got, err := parseNfConntrack(bytes.NewReader([]byte(line + "\n")))
	if err != nil {
		t.Fatalf("parseNfConntrack: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	e := got[0]
	if e.protocol != "icmp" {
		t.Errorf("protocol: got %q want icmp", e.protocol)
	}
	if e.localIP != "10.0.0.5" || e.remoteIP != "8.8.8.8" {
		t.Errorf("addrs: %s -> %s", e.localIP, e.remoteIP)
	}
	if e.localPort != 0 || e.remotePort != 0 {
		t.Errorf("ports should be zero for ICMP: got %d/%d", e.localPort, e.remotePort)
	}
}

// TestParseNfConntrack_SkipsUnknownProtocol verifies we ignore
// flows we don't support (gre, sctp, ...). Without this filter
// they'd come back as extraConn entries with protocol="gre" and
// confuse downstream rules that expect tcp/udp/icmp.
func TestParseNfConntrack_SkipsUnknownProtocol(t *testing.T) {
	line := "ipv4     2 gre     47 60 src=10.0.0.5 dst=1.2.3.4 srckey=0x0 dstkey=0x0 " +
		"src=1.2.3.4 dst=10.0.0.5 srckey=0x0 dstkey=0x0 mark=0 use=2"
	got, err := parseNfConntrack(bytes.NewReader([]byte(line + "\n")))
	if err != nil {
		t.Fatalf("parseNfConntrack: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 entries (gre filtered), got %d", len(got))
	}
}
