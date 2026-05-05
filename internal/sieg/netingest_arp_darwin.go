//go:build darwin

package sieg

import (
	"net"
	"os/exec"
	"strings"
)

// osDefaultGateways parses `route -n get default` for each address
// family. Pass 1 covers IPv4 only.
func osDefaultGateways() ([]gatewayInfo, error) {
	out := []gatewayInfo{}
	cmd := exec.Command("route", "-n", "get", "default")
	stdout, err := cmd.Output()
	if err != nil {
		return out, nil // no default route is fine
	}
	g := gatewayInfo{}
	for _, line := range strings.Split(string(stdout), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(fields) != 2 {
			continue
		}
		k := strings.TrimSpace(fields[0])
		v := strings.TrimSpace(fields[1])
		switch k {
		case "gateway":
			g.IP = v
		case "interface":
			g.IFace = v
		}
	}
	if g.IP != "" {
		out = append(out, g)
	}
	return out, nil
}

// osArpResolve invokes `arp -n <ip>` and parses the line.
// macOS output looks like:
//   ? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
func osArpResolve(ip string) (string, error) {
	// Prime the table via `ping -c1 -W500` (-W is in ms on macOS).
	_ = exec.Command("ping", "-c1", "-W500", ip).Run()
	out, err := exec.Command("arp", "-n", ip).CombinedOutput()
	if err != nil {
		return "", nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		idx := strings.Index(line, " at ")
		if idx < 0 {
			continue
		}
		rest := line[idx+4:]
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "(incomplete)" {
			continue
		}
		if mac := normaliseMAC(fields[0]); mac != "" {
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
