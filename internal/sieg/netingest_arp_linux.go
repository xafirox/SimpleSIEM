//go:build linux

package sieg

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// osDefaultGateways parses /proc/net/route. Returns one entry per row
// with Destination=00000000.
func osDefaultGateways() ([]gatewayInfo, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []gatewayInfo{}
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		// fields: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
		if fields[1] != "00000000" {
			continue
		}
		iface := fields[0]
		gwHex := fields[2]
		ip, err := hexLEToIP(gwHex)
		if err != nil {
			continue
		}
		out = append(out, gatewayInfo{IP: ip, IFace: iface})
	}
	return out, sc.Err()
}

// hexLEToIP converts /proc/net/route's little-endian hex (e.g.
// "0100A8C0" -> "192.168.0.1").
func hexLEToIP(s string) (string, error) {
	if len(s) != 8 {
		return "", fmt.Errorf("hex len: %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0]), nil
}

// osArpResolve reads /proc/net/arp and returns the MAC for ip.
// Refreshes the kernel ARP table by opening a short-lived UDP
// "connection" to ip:9 (discard) — the kernel resolves the MAC on the
// link layer regardless of whether anything is listening on the port.
// Falls back to `ip neigh` and `arp -n` for hosts where /proc/net/arp
// isn't accessible.
func osArpResolve(ip string) (string, error) {
	if mac := readArpTable(ip); mac != "" {
		return mac, nil
	}
	// Force the kernel to resolve the MAC via a UDP-touch. No process
	// needs to listen — the kernel sends an ARP request on the link
	// layer regardless. Two-attempt loop is enough to win the race
	// between the ARP probe and reading /proc/net/arp.
	for i := 0; i < 3; i++ {
		c, err := net.DialTimeout("udp", net.JoinHostPort(ip, "9"), 500*time.Millisecond)
		if err == nil {
			_, _ = c.Write([]byte{0})
			_ = c.Close()
		}
		// Also try a TCP handshake — wakes up bridges that ignore
		// stray UDP probes (common in some container networks).
		c2, err2 := net.DialTimeout("tcp", net.JoinHostPort(ip, "1"), 200*time.Millisecond)
		if err2 == nil {
			_ = c2.Close()
		}
		// Tiny pause for the kernel to populate the neighbour table.
		time.Sleep(150 * time.Millisecond)
		if mac := readArpTable(ip); mac != "" {
			return mac, nil
		}
	}
	// `ip neigh show <ip>` (iproute2) is present on essentially every
	// modern Linux including stripped containers.
	if out, err := exec.Command("ip", "neigh", "show", ip).CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] == "lladdr" {
					if mac := normaliseMAC(fields[i+1]); mac != "" {
						return mac, nil
					}
				}
			}
		}
	}
	// Last-ditch: classic arp -n.
	if out, err := exec.Command("arp", "-n", ip).CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			if fields[0] == ip {
				if mac := normaliseMAC(fields[2]); mac != "" {
					return mac, nil
				}
			}
		}
	}
	return "", nil
}

func readArpTable(ip string) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[0] != ip {
			continue
		}
		flags, _ := strconv.ParseInt(fields[2], 16, 64)
		// 0x02 = ATF_COM (entry is complete). Skip incomplete entries.
		if flags&0x02 == 0 {
			continue
		}
		if mac := normaliseMAC(fields[3]); mac != "" {
			return mac
		}
	}
	return ""
}

// localIPv4s returns this host's IPv4 addresses (excluding loopback).
// Used for "is this frame coming from one of my own peers" checks.
func localIPv4s() []string {
	out := []string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifaces {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLoopback() {
					out = append(out, v4.String())
				}
			}
		}
	}
	return out
}
