//go:build windows

package sieg

import (
	"net"
	"os/exec"
	"strings"
)

// osDefaultGateways uses PowerShell's Get-NetRoute with a fallback to
// `route print -4`. Returns one entry per default route.
func osDefaultGateways() ([]gatewayInfo, error) {
	out := []gatewayInfo{}
	// Try PowerShell first — modern, structured output.
	psCmd := `Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ` +
		`Select-Object -ExpandProperty NextHop`
	if data, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command", psCmd).CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			ip := strings.TrimSpace(line)
			if ip == "" || ip == "0.0.0.0" {
				continue
			}
			out = append(out, gatewayInfo{IP: ip})
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	// Fallback: parse `route print -4`.
	data, err := exec.Command("route", "print", "-4").CombinedOutput()
	if err != nil {
		return out, nil
	}
	scanning := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "IPv4 Route Table") {
			scanning = true
			continue
		}
		if strings.Contains(line, "Persistent Routes") {
			scanning = false
		}
		if !scanning {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			out = append(out, gatewayInfo{IP: fields[2]})
		}
	}
	return out, nil
}

// osArpResolve uses `arp -a <ip>`.  Output:
//   Interface: 10.0.0.10 --- 0xa
//     Internet Address      Physical Address      Type
//     10.0.0.1              aa-bb-cc-dd-ee-ff     dynamic
func osArpResolve(ip string) (string, error) {
	// Prime the entry with a short ping.
	_ = exec.Command("ping", "-n", "1", "-w", "1000", ip).Run()
	data, err := exec.Command("arp", "-a", ip).CombinedOutput()
	if err != nil {
		return "", nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[0] != ip {
			continue
		}
		if mac := normaliseMAC(fields[1]); mac != "" {
			return mac, nil
		}
	}
	return "", nil
}

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
