package sieg

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Cross-platform default-gateway + ARP-lookup primitives. Each OS
// implementation is in netingest_arp_<os>.go behind a build tag.
// This file holds shared helpers and the public API.

// gatewayInfo is what discoverDefaultGateway returns.
type gatewayInfo struct {
	IP    string
	IFace string
	MAC   string
}

// discoverGatewaysAndMACs returns one gatewayInfo per default route on
// this host. Hosts with multiple NICs / policy-based routing produce
// multiple entries.
func discoverGatewaysAndMACs() ([]gatewayInfo, error) {
	gateways, err := osDefaultGateways()
	if err != nil {
		return nil, err
	}
	if isContainerEnv() {
		// Skip auto-add inside a container — the gateway is the
		// docker bridge and operators don't want that in the allowlist.
		return nil, errSkipContainer
	}
	out := make([]gatewayInfo, 0, len(gateways))
	for _, g := range gateways {
		if g.IP == "" {
			continue
		}
		mac, err := arpResolve(g.IP)
		if err != nil {
			// Keep the entry but with empty MAC; caller may flag for
			// re-validation.
			mac = ""
		}
		g.MAC = normaliseMAC(mac)
		out = append(out, g)
	}
	return out, nil
}

// arpResolve returns the MAC for the given IPv4 address as recorded in
// the local ARP table. Implemented per-OS. Empty MAC + nil error means
// "no entry found." Errors are reserved for unexpected failures.
func arpResolve(ip string) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "", fmt.Errorf("not an IP: %s", ip)
	}
	if parsed.To4() == nil {
		// IPv6 not supported in pass 1 (NDP plumbing deferred).
		return "", errIPv6Unsupported
	}
	return osArpResolve(parsed.String())
}

var (
	errSkipContainer    = fmt.Errorf("skip: container environment")
	errIPv6Unsupported  = fmt.Errorf("ipv6 NDP not supported in this version")
)

// isContainerEnv checks for /.dockerenv (Linux/macOS containers) or
// the Windows-container marker file.
func isContainerEnv() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat(`C:\.dockerenv`); err == nil {
		return true
	}
	return false
}

