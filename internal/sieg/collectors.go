package sieg

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/v3/host"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// hashFileSHA384 streams the file through SHA-384 and returns the
// hex digest. Used to enrich file create/modify events so detection
// rules can match on `sha384: { in_file: "malware.txt" }`.
func hashFileSHA384(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha512.New384()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type Collector interface {
	Start(ctx context.Context, wg *sync.WaitGroup)
}

// procCache holds recently-seen process metadata so NetworkCollector can
// attribute a connection to a command even if the process died by the time
// the connection table was read. Exited entries are kept for a short TTL so
// close/TIME_WAIT events can still resolve owners.
type procCache struct {
	mu   sync.RWMutex
	data map[int32]cachedProc
}

type cachedProc struct {
	user    string
	name    string
	cmdline []string
	ppid    int32
	exited  time.Time // zero value = still alive as far as we know
}

func newProcCache() *procCache {
	return &procCache{data: map[int32]cachedProc{}}
}

func (c *procCache) put(pid int32, user, name string, cmdline []string, ppid int32) {
	if pid <= 0 {
		return
	}
	c.mu.Lock()
	c.data[pid] = cachedProc{user: user, name: name, cmdline: cmdline, ppid: ppid}
	c.mu.Unlock()
}

func (c *procCache) markExited(pid int32) {
	c.mu.Lock()
	if e, ok := c.data[pid]; ok {
		e.exited = time.Now()
		c.data[pid] = e
	}
	c.mu.Unlock()
}

func (c *procCache) get(pid int32) (cachedProc, bool) {
	c.mu.RLock()
	e, ok := c.data[pid]
	c.mu.RUnlock()
	return e, ok
}

// sweep drops exited entries older than ttl. Called periodically.
func (c *procCache) sweep(ttl time.Duration) {
	cutoff := time.Now().Add(-ttl)
	c.mu.Lock()
	for pid, e := range c.data {
		if !e.exited.IsZero() && e.exited.Before(cutoff) {
			delete(c.data, pid)
		}
	}
	c.mu.Unlock()
}

// ---------- network ----------

type connKey struct {
	pid    int32
	local  string
	remote string
	status string
}

type NetworkCollector struct {
	storage   *Storage
	interval  time.Duration
	dnsCache  *dnsCache
	procCache *procCache
	health    *HealthMonitor
	state     *stateStore
	seen      map[connKey]time.Time
	// seenHosts is a per-window deduper for the DNS-lookup event
	// type. Reset hourly (so the same host doesn't emit a dns event
	// on every poll, but operators still see "this host appeared
	// again today"). Cross-platform synthetic — no OS-specific DNS
	// hooks. The remote_host value comes from the dnsCache reverse
	// lookup that connection_open already runs.
	seenHosts     map[string]time.Time
	seenHostsTick time.Time
	// pendingDNS tracks connections we emitted with empty remote_host
	// (cache cold at first sighting). Each subsequent poll retries
	// the lookup; when DNS finally resolves we emit a
	// connection_dns_resolved follow-up so triage can connect the
	// IP back to a hostname. Entries are dropped after 5 minutes
	// even if DNS never resolves so the map can't grow without bound.
	pendingDNS map[connKey]pendingDNSEntry
}

type pendingDNSEntry struct {
	added time.Time
	pid   int32
	user  string
	proc  string
	ip    string
	port  uint32
}

func (c *NetworkCollector) Start(ctx context.Context, wg *sync.WaitGroup) {
	runCollector(ctx, wg, "network", c.storage, c.loop)
}

func (c *NetworkCollector) loop(ctx context.Context) {
	c.seen = map[connKey]time.Time{}
	c.pendingDNS = map[connKey]pendingDNSEntry{}
	c.loadState()
	t := time.NewTicker(c.interval)
	defer t.Stop()
	checkpoint := time.NewTicker(time.Minute)
	defer checkpoint.Stop()
	for {
		c.health.Beat("network")
		c.poll(ctx)
		select {
		case <-ctx.Done():
			c.saveState()
			return
		case <-checkpoint.C:
			c.saveState()
		case <-t.C:
		}
	}
}

// loadState seeds c.seen with connections persisted at last shutdown so the
// next poll sees them as already-known and doesn't re-emit connection_open.
// Stale entries (>1h old) are dropped — the connection table changes, and
// we'd rather re-emit a few than incorrectly suppress real events.
//
// Also filters out kernel-placeholder rows (pid==0 + no real remote) that
// older builds may have written into state. Without the filter, an upgrade
// from a pre-filter daemon would emit a stale `connection_close
// 0.0.0.0:0` row on the next poll because the entry is in `seen` but
// missing from the current TCP/UDP enumeration.
func (c *NetworkCollector) loadState() {
	if c.state == nil {
		return
	}
	var st stateNetwork
	if err := c.state.Load("network", &st); err != nil {
		return
	}
	cutoff := time.Now().Add(-time.Hour)
	for _, e := range st.Conns {
		if e.Seen.Before(cutoff) {
			continue
		}
		if e.Pid == 0 && e.Remote == "" {
			continue
		}
		c.seen[connKey{pid: e.Pid, local: e.Local, remote: e.Remote, status: e.Status}] = e.Seen
	}
}

// maybeEmitDNS writes a `dns:lookup` event when (remote_host, process)
// hasn't been seen in the current 1h dedupe window. The synthetic
// stream means operators can write rules on remote_host across log
// types uniformly — and feeds first-seen detection naturally.
func (c *NetworkCollector) maybeEmitDNS(host, ip, process, user string) {
	now := time.Now()
	// Reset window every hour. Cheap — the map's expected size is
	// tens to a few hundred per host.
	if c.seenHostsTick.IsZero() || now.Sub(c.seenHostsTick) > time.Hour {
		c.seenHosts = map[string]time.Time{}
		c.seenHostsTick = now
	}
	if c.seenHosts == nil {
		c.seenHosts = map[string]time.Time{}
	}
	key := host + "\x1f" + process
	if _, ok := c.seenHosts[key]; ok {
		return
	}
	c.seenHosts[key] = now
	c.storage.Write("dns", map[string]any{
		"event":       "lookup",
		"remote_host": host,
		"remote_ip":   ip,
		"process":     process,
		"user":        user,
	})
}

// maybeEmitDNSQuery is the forward-lookup counterpart to maybeEmitDNS.
// Triggered when the network collector sees a flow to UDP/TCP port 53
// (i.e., the resolver itself, observed as an outbound socket — not
// the subsequent connection to the resolved IP). We can't see the
// actual question on the wire, but the cmdline of the originating
// process almost always carries it (curl/ssh/ping arguments are
// hostnames). The synthesized event answers "what did this host try
// to resolve, and which process asked?" — the most common operator
// triage need that pure socket polling otherwise misses.
//
// Dedup uses the same hourly window as maybeEmitDNS so a chatty
// process (e.g., a notebook with auto-reload) doesn't emit one row
// per query.
func (c *NetworkCollector) maybeEmitDNSQuery(query, process, user, resolverIP string) {
	if query == "" && resolverIP == "" {
		return
	}
	now := time.Now()
	if c.seenHostsTick.IsZero() || now.Sub(c.seenHostsTick) > time.Hour {
		c.seenHosts = map[string]time.Time{}
		c.seenHostsTick = now
	}
	if c.seenHosts == nil {
		c.seenHosts = map[string]time.Time{}
	}
	// "q\x1f" prefix keeps the query keyspace separate from the
	// reverse-PTR keyspace maybeEmitDNS uses, so a host that's both
	// queried-from-cmdline AND reverse-PTR-resolved still emits one
	// of each event class per window.
	key := "q\x1f" + query + "\x1f" + process
	if _, ok := c.seenHosts[key]; ok {
		return
	}
	c.seenHosts[key] = now
	ev := map[string]any{
		"event":    "query",
		"process":  process,
		"user":     user,
		"resolver": resolverIP,
	}
	if query != "" {
		ev["query"] = query
	}
	c.storage.Write("dns", ev)
}

// networkToolNames is the allowlist of process names whose cmdline
// argument is treated as a destination — the synthesis below emits a
// connection_open event for them even when the kernel socket is
// invisible to NetworkCollector. Keep it tight: every name here MUST
// be a tool whose primary first-positional argument is a host or URL.
// Adding shells, package managers, etc. would generate false-positive
// "connections" from `apt update` URLs etc. embedded in their
// cmdlines.
var networkToolNames = map[string]bool{
	"ping":       true,
	"ping6":      true,
	"traceroute": true,
	"traceroute6": true,
	"tracepath": true,
	"mtr":        true,
	"dig":        true,
	"nslookup":   true,
	"host":       true,
	"drill":      true,
	"curl":       true,
	"wget":       true,
	"ssh":        true,
	"scp":        true,
	"sftp":       true,
	"telnet":     true,
	"nc":         true,
	"netcat":     true,
	"ncat":       true,
	"socat":      true,
	"openssl":    true, // s_client / s_server invocations carry the host
}

// powerShellNetworkCmdlets are the PowerShell verb-noun cmdlets whose
// cmdline carries a destination host or URL. The process name is
// `powershell.exe` / `pwsh.exe`, not the cmdlet, so the
// networkToolNames map alone wouldn't match. isPowerShellNetworkInvocation
// keys off these substrings to widen the gate when the process is a
// shell. Names are lower-cased for comparison.
var powerShellNetworkCmdlets = []string{
	"invoke-webrequest",
	"invoke-restmethod",
	"test-netconnection",
	"test-connection",
	"resolve-dnsname",
	"new-object net.webclient",
	"new-object system.net.webclient",
	// Aliases — `iwr` and `irm` resolve to Invoke-WebRequest /
	// Invoke-RestMethod when typed at the prompt or in -Command. PowerShell
	// also exposes `wget` and `curl` as aliases for Invoke-WebRequest, but
	// those names are already in networkToolNames so don't need to be here.
	"iwr ",
	"irm ",
}

// resolveHostFast does a best-effort, time-bounded DNS lookup so the
// synth event carries resolved IPs alongside the hostname. The 200ms
// budget keeps the process_start hot path snappy on hosts whose
// resolver is slow or unreachable; on failure we just skip the IPs and
// keep the hostname-only event. Bare IPs short-circuit (no lookup).
func resolveHostFast(h string) []string {
	if h == "" {
		return nil
	}
	if ip := net.ParseIP(h); ip != nil {
		return []string{ip.String()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, h)
	if err != nil {
		return nil
	}
	return addrs
}

// isPowerShellNetworkInvocation reports whether a powershell or pwsh
// cmdline carries a network cmdlet whose first positional / -Uri
// argument is a destination. Matches `powershell -Command Invoke-WebRequest
// https://example.com`, the bare `Invoke-WebRequest -Uri ...` form, and
// the iwr/irm aliases.
func isPowerShellNetworkInvocation(processName string, cmdline []string) bool {
	if processName != "powershell" && processName != "pwsh" {
		return false
	}
	if len(cmdline) < 2 {
		return false
	}
	joined := strings.ToLower(strings.Join(cmdline[1:], " "))
	for _, c := range powerShellNetworkCmdlets {
		if strings.Contains(joined, c) {
			return true
		}
	}
	return false
}

// emitNetworkToolInvocation synthesizes a network:connection_open
// event from a process_start when the process is a known network
// tool. Closes the gap that's otherwise opened by:
//
//	1. Sub-poll-interval lifetimes (a one-shot ping(8) finishes
//	   in ~15 ms; gopsutil's 2s poll misses the socket).
//	2. SOCK_DGRAM ICMP, where /proc/net/icmp doesn't store the
//	   destination (the kernel uses sendto without connect).
//	3. nf_conntrack absent in the host's namespace (default in
//	   stripped Docker containers).
//
// The synthesized event has protocol="cmdline" so a downstream
// reader can distinguish it from a true socket-observed flow if
// needed (operator audit). The destination comes from
// extractHostHints — same parser the NetworkCollector uses for the
// existing cmdline_hosts enrichment, so behaviour is consistent.
//
// Cross-platform: pure cmdline parsing, no OS-specific calls.
// Equally effective on Mac and Windows where /proc isn't a thing.
func emitNetworkToolInvocation(storage *Storage, info procInfo, pid int32, created string) {
	name := strings.ToLower(strings.TrimSuffix(info.name, ".exe"))
	if !networkToolNames[name] && !isPowerShellNetworkInvocation(name, info.cmdline) {
		return
	}
	hosts := extractHostHints(info.cmdline)
	if len(hosts) == 0 {
		// Fallback: take the first non-flag positional argument.
		// Catches tools like `ping 8.8.8.8` where the IP itself
		// isn't a hostname so extractHostHints might skip it.
		for i := 1; i < len(info.cmdline); i++ {
			arg := info.cmdline[i]
			if arg == "" || strings.HasPrefix(arg, "-") {
				continue
			}
			hosts = []string{arg}
			break
		}
	}
	if len(hosts) == 0 {
		return
	}
	for _, h := range hosts {
		ips := resolveHostFast(h)
		event := map[string]any{
			"event":         "tool_invocation",
			"protocol":      "cmdline",
			"tool":          info.name,
			"remote":        h,
			"remote_host":   h,
			"pid":           pid,
			"process":       info.name,
			"user":          info.user,
			"cmdline":       info.cmdline,
			"cmdline_hosts": hosts,
			"hint":          "process_start synthesised network event — kernel socket may have closed before the next poll, but cmdline carried the destination",
		}
		if len(ips) > 0 {
			// `remote_ips` lets `query --grep <ip>` find the synth event
			// even when gopsutil missed the short-lived TCP. Operators
			// frequently search by resolved IP (firewall logs, threat
			// intel hits) rather than hostname.
			event["remote_ips"] = ips
		}
		if created != "" {
			event["created"] = created
		}
		storage.Write("network", event)
	}
}

// emitUserMgmtInvocation synthesizes auth-log events from a
// process_start when the process is a known user/group management
// tool. Closes the same coverage gap on the AUTH side that
// emitNetworkToolInvocation closes on the NETWORK side:
//
//	1. Container/distro images that don't ship rsyslogd/journald
//	   have no /var/log/auth.log for the AuthLogCollector to tail,
//	   so PAM-driven user_added events never fire from the auth
//	   collector path. The cmdline of useradd/usermod still carries
//	   the target user; we synthesize the same event shape.
//	2. macOS sysadminctl/dscl/dseditgroup events fire reliably
//	   through the unified-log AuthLogCollector when log stream is
//	   available, but on stripped Macs (CI runners, jailed user
//	   contexts) the cmdline path is the fallback.
//	3. Windows uses Event Log 4720/4726 which AuthLogCollector
//	   already handles via wevtutil. Cmdline synthesis here covers
//	   `net user <name> /add` and PowerShell `New-LocalUser` even
//	   when the audit policy ISN'T enabled (which is common on
//	   single-user workstations and CI hosts).
//
// Event shape matches the existing per-platform AuthLogCollector
// schema (event="user_added" with user / actor / group fields)
// so triage's eventSummary cases render uniformly. The synthesised
// event carries source="process_invocation" so a reader can tell
// it from a true PAM/Event-Log capture.
//
// Cross-platform: pure cmdline parsing, identical behaviour on
// Linux / Mac / Windows. No OS-specific syscalls.
func emitUserMgmtInvocation(storage *Storage, info procInfo, pid int32, created string) {
	name := strings.ToLower(info.name)
	// Strip trailing .exe so Windows New-LocalUser-via-PowerShell
	// runs (process name "powershell.exe") still match below.
	name = strings.TrimSuffix(name, ".exe")
	parsed := parseUserMgmtCmdline(name, info.cmdline)
	if len(parsed) == 0 {
		return
	}
	for _, ev := range parsed {
		ev["actor"] = info.user
		ev["pid"] = pid
		ev["process"] = info.name
		ev["cmdline"] = info.cmdline
		ev["source"] = "process_invocation"
		ev["hint"] = "synthesised from process_start cmdline — covers hosts without rsyslog/journald (Linux), unified-log (Mac stripped), or audit-policy enabled (Windows workstations)"
		if created != "" {
			ev["created"] = created
		}
		storage.Write("auth", ev)
	}
}

// parseUserMgmtCmdline decodes the cmdline of a user-management
// tool into one or more auth events. Returns []map (most cases
// produce one event; usermod -aG can produce two — the user_modified
// for the user AND user_added_to_group for each group). The events
// don't carry actor/pid/process/cmdline yet — the caller stamps
// those.
//
// Recognised tools (per platform):
//
//	Linux:   useradd adduser usermod userdel deluser passwd chage
//	         groupadd groupmod groupdel gpasswd chpasswd
//	macOS:   sysadminctl dscl dseditgroup
//	Windows: net (with user/localgroup subcommand), powershell
//	         (with *-LocalUser/*-LocalGroup cmdlets in cmdline)
func parseUserMgmtCmdline(name string, cmdline []string) []map[string]any {
	if len(cmdline) == 0 {
		return nil
	}
	switch name {
	// ----- Linux ------------------------------------------------
	case "useradd", "adduser":
		// Last non-flag arg is the username (covers `useradd -m -s
		// /bin/bash alice`, `adduser --system alice`, etc.).
		if u := lastPositional(cmdline); u != "" {
			return []map[string]any{{
				"event": "user_added",
				"user":  u,
			}}
		}
	case "userdel", "deluser":
		if u := lastPositional(cmdline); u != "" {
			return []map[string]any{{
				"event": "user_deleted",
				"user":  u,
			}}
		}
	case "usermod":
		// usermod has many shapes:
		//   usermod -aG sudo,wheel alice  → user_added_to_group for each group
		//   usermod -L alice              → user_modified (locked)
		//   usermod -p HASH alice         → password_changed
		//   usermod -s /bin/zsh alice     → user_modified
		// Always emit user_modified; if -aG is present, ALSO emit
		// user_added_to_group per group so triage rules that key on
		// the group-membership event still fire.
		target := lastPositional(cmdline)
		if target == "" {
			return nil
		}
		out := []map[string]any{{
			"event": "user_modified",
			"user":  target,
		}}
		// Look for -aG / --append --groups / -G GROUPS.
		for i, arg := range cmdline {
			if arg != "-aG" && arg != "-G" && arg != "--groups" {
				continue
			}
			if i+1 >= len(cmdline) {
				break
			}
			groups := strings.Split(cmdline[i+1], ",")
			for _, g := range groups {
				g = strings.TrimSpace(g)
				if g == "" {
					continue
				}
				out = append(out, map[string]any{
					"event": "user_added_to_group",
					"user":  target,
					"group": g,
				})
			}
			break
		}
		// -p is a password set (deprecated but still a thing).
		for _, arg := range cmdline {
			if arg == "-p" || arg == "--password" {
				out = append(out, map[string]any{
					"event": "password_changed",
					"user":  target,
				})
				break
			}
		}
		return out
	case "passwd":
		// `passwd alice` → password_changed for alice.
		// `passwd` (no args) → password_changed for invoking user
		//                     (caller fills actor; we don't know
		//                     until then; emit with actor=user).
		if u := lastPositional(cmdline); u != "" && u != "passwd" {
			return []map[string]any{{
				"event": "password_changed",
				"user":  u,
			}}
		}
		return []map[string]any{{
			"event": "password_changed",
			// user resolved from actor at the call site
		}}
	case "chage":
		if u := lastPositional(cmdline); u != "" {
			return []map[string]any{{
				"event": "password_changed",
				"user":  u,
				"hint":  "chage modifies password aging — operator considers this a credential-policy event (forced expiry, lock, etc.)",
			}}
		}
	case "chpasswd":
		// chpasswd reads from stdin (user:pass per line). We can't
		// see stdin; emit a generic password_changed for the actor.
		return []map[string]any{{
			"event": "password_changed",
			"hint":  "chpasswd reads user:password tuples from stdin — actual targets not visible from cmdline",
		}}
	case "groupadd":
		if g := lastPositional(cmdline); g != "" {
			return []map[string]any{{
				"event": "group_added",
				"group": g,
			}}
		}
	case "groupdel":
		if g := lastPositional(cmdline); g != "" {
			return []map[string]any{{
				"event": "group_deleted",
				"group": g,
			}}
		}
	case "groupmod":
		if g := lastPositional(cmdline); g != "" {
			return []map[string]any{{
				"event": "group_modified",
				"group": g,
			}}
		}
	case "gpasswd":
		// gpasswd -a USER GROUP    add USER to GROUP
		// gpasswd -d USER GROUP    remove USER from GROUP
		// gpasswd -A USERS GROUP   set group admins
		var (
			user  string
			group string
			ev    string
		)
		for i, arg := range cmdline {
			if arg == "-a" {
				ev = "user_added_to_group"
				if i+1 < len(cmdline) {
					user = cmdline[i+1]
				}
			} else if arg == "-d" {
				ev = "user_removed_from_group"
				if i+1 < len(cmdline) {
					user = cmdline[i+1]
				}
			}
		}
		group = lastPositional(cmdline)
		// Reject the case where lastPositional returned the user
		// (no group arg given); a real gpasswd call always has the
		// group as the trailing arg after USER.
		if group != "" && group == user {
			group = ""
		}
		if ev != "" && user != "" {
			return []map[string]any{{
				"event": ev,
				"user":  user,
				"group": group,
			}}
		}
	// ----- macOS ------------------------------------------------
	case "sysadminctl":
		// sysadminctl -addUser alice -password ...
		// sysadminctl -deleteUser alice
		// sysadminctl -resetPasswordFor alice -newPassword ...
		for i, arg := range cmdline {
			a := strings.TrimPrefix(arg, "-")
			if a != "addUser" && a != "deleteUser" && a != "resetPasswordFor" {
				continue
			}
			if i+1 >= len(cmdline) {
				continue
			}
			user := cmdline[i+1]
			ev := "user_modified"
			switch a {
			case "addUser":
				ev = "user_added"
			case "deleteUser":
				ev = "user_deleted"
			case "resetPasswordFor":
				ev = "password_changed"
			}
			return []map[string]any{{
				"event": ev,
				"user":  user,
			}}
		}
	case "dscl":
		// dscl . -create /Users/alice
		// dscl . -delete /Users/alice
		// dscl . -create /Groups/dev
		// dscl . -delete /Groups/dev
		var op, target string
		for i, arg := range cmdline {
			switch arg {
			case "-create", "-delete":
				if i+1 < len(cmdline) {
					op = strings.TrimPrefix(arg, "-")
					target = cmdline[i+1]
				}
			}
		}
		if op == "" || target == "" {
			return nil
		}
		switch {
		case strings.HasPrefix(target, "/Users/"):
			user := strings.TrimPrefix(target, "/Users/")
			ev := "user_added"
			if op == "delete" {
				ev = "user_deleted"
			}
			return []map[string]any{{
				"event": ev,
				"user":  user,
			}}
		case strings.HasPrefix(target, "/Groups/"):
			group := strings.TrimPrefix(target, "/Groups/")
			ev := "group_added"
			if op == "delete" {
				ev = "group_deleted"
			}
			return []map[string]any{{
				"event": ev,
				"group": group,
			}}
		}
	case "dseditgroup":
		// dseditgroup -o edit -a alice -t user admin
		// dseditgroup -o edit -d alice -t user admin
		var (
			op    string
			user  string
			group string
		)
		for i, arg := range cmdline {
			switch arg {
			case "-a":
				op = "add"
				if i+1 < len(cmdline) {
					user = cmdline[i+1]
				}
			case "-d":
				op = "del"
				if i+1 < len(cmdline) {
					user = cmdline[i+1]
				}
			}
		}
		// Trailing positional arg is the group (after `-t user`).
		if g := lastPositional(cmdline); g != "user" && g != "" {
			group = g
		}
		if op != "" && user != "" {
			ev := "user_added_to_group"
			if op == "del" {
				ev = "user_removed_from_group"
			}
			return []map[string]any{{
				"event": ev,
				"user":  user,
				"group": group,
			}}
		}
	// ----- Windows ----------------------------------------------
	case "net":
		// net user <name> [pwd] /add
		// net user <name> /delete
		// net localgroup <group> <user> /add
		// net localgroup <group> <user> /delete
		if len(cmdline) < 3 {
			return nil
		}
		sub := strings.ToLower(cmdline[1])
		switch sub {
		case "user":
			user := ""
			if len(cmdline) >= 3 {
				user = cmdline[2]
			}
			if user == "" {
				return nil
			}
			ev := ""
			for _, a := range cmdline {
				switch strings.ToLower(a) {
				case "/add":
					ev = "user_added"
				case "/delete":
					ev = "user_deleted"
				}
			}
			if ev != "" {
				return []map[string]any{{
					"event": ev,
					"user":  user,
				}}
			}
			// `net user alice newpassword` (no /add /delete) is a
			// password change.
			if len(cmdline) >= 4 && !strings.HasPrefix(cmdline[3], "/") {
				return []map[string]any{{
					"event": "password_changed",
					"user":  user,
				}}
			}
		case "localgroup":
			if len(cmdline) < 4 {
				return nil
			}
			group := cmdline[2]
			user := cmdline[3]
			ev := ""
			for _, a := range cmdline {
				switch strings.ToLower(a) {
				case "/add":
					ev = "user_added_to_group"
				case "/delete":
					ev = "user_removed_from_group"
				}
			}
			if ev != "" {
				return []map[string]any{{
					"event": ev,
					"user":  user,
					"group": group,
				}}
			}
		}
	case "powershell", "pwsh":
		// PowerShell cmdlets passed via -Command. We sniff the joined
		// cmdline for *-LocalUser / *-LocalGroup verbs. Not perfect
		// (operator can use `Invoke-Expression`-style obfuscation),
		// but covers the ordinary `New-LocalUser alice` / `Add-LocalGroupMember`
		// paths that any unsophisticated invocation uses.
		joined := strings.ToLower(strings.Join(cmdline, " "))
		switch {
		case strings.Contains(joined, "new-localuser"):
			return []map[string]any{{
				"event": "user_added",
				"user":  extractPSLocalUserArg(joined, "new-localuser"),
			}}
		case strings.Contains(joined, "remove-localuser"):
			return []map[string]any{{
				"event": "user_deleted",
				"user":  extractPSLocalUserArg(joined, "remove-localuser"),
			}}
		case strings.Contains(joined, "set-localuser") && strings.Contains(joined, "-password"):
			return []map[string]any{{
				"event": "password_changed",
				"user":  extractPSLocalUserArg(joined, "set-localuser"),
			}}
		case strings.Contains(joined, "add-localgroupmember"):
			return []map[string]any{{
				"event": "user_added_to_group",
				"user":  extractPSLocalUserArg(joined, "-member"),
				"group": extractPSLocalUserArg(joined, "add-localgroupmember"),
			}}
		case strings.Contains(joined, "remove-localgroupmember"):
			return []map[string]any{{
				"event": "user_removed_from_group",
				"user":  extractPSLocalUserArg(joined, "-member"),
				"group": extractPSLocalUserArg(joined, "remove-localgroupmember"),
			}}
		}
	}
	return nil
}

// lastPositional returns the trailing non-flag argument from a
// cmdline (skipping argv[0] which is the binary itself). Useful
// for tools where the username/group is always the last arg.
// Returns "" when every remaining arg is a flag.
func lastPositional(cmdline []string) string {
	for i := len(cmdline) - 1; i >= 1; i-- {
		arg := cmdline[i]
		if arg == "" {
			continue
		}
		// Skip flags. Don't skip flag VALUES — we want `usermod -G
		// admin alice` to return "alice", not "admin". The simplest
		// heuristic: a flag starts with "-" or "/"; a value never
		// does. False positives where the username starts with "-"
		// don't exist on a sane system.
		if strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "/") {
			continue
		}
		return arg
	}
	return ""
}

// extractPSLocalUserArg pulls the first quoted or unquoted token
// after a PowerShell verb / parameter in a cmdline string. Used
// only by the parseUserMgmtCmdline Windows branch — the cmdline
// has already been lower-cased so case-folding isn't needed.
//
// Example: extractPSLocalUserArg("new-localuser alice -password", "new-localuser")
// returns "alice".
func extractPSLocalUserArg(joined, after string) string {
	idx := strings.Index(joined, after)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(joined[idx+len(after):])
	// Drop leading separator characters PowerShell allows.
	rest = strings.TrimLeft(rest, ":= ")
	if rest == "" {
		return ""
	}
	// Take the first whitespace-delimited token, stripping quotes.
	end := strings.IndexAny(rest, " \t")
	if end < 0 {
		end = len(rest)
	}
	tok := strings.Trim(rest[:end], `"'`)
	return tok
}

func (c *NetworkCollector) saveState() {
	if c.state == nil || len(c.seen) == 0 {
		return
	}
	conns := make([]stateNetworkConn, 0, len(c.seen))
	for k, ts := range c.seen {
		conns = append(conns, stateNetworkConn{
			Pid: k.pid, Local: k.local, Remote: k.remote, Status: k.status, Seen: ts,
		})
	}
	_ = c.state.Save("network", stateNetwork{SavedAt: time.Now(), Conns: conns})
}

func protoName(typ uint32) string {
	switch typ {
	case uint32(syscall.SOCK_STREAM):
		return "tcp"
	case uint32(syscall.SOCK_DGRAM):
		return "udp"
	default:
		return fmt.Sprintf("type-%d", typ)
	}
}

func (c *NetworkCollector) poll(ctx context.Context) {
	conns, err := psnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		c.storage.Write("errors", map[string]any{
			"collector": "network", "error": err.Error(),
		})
		return
	}
	current := map[connKey]struct{}{}
	for _, k := range conns {
		switch k.Status {
		case "ESTABLISHED", "LISTEN", "SYN_SENT", "TIME_WAIT":
		default:
			continue
		}
		laddr := fmt.Sprintf("%s:%d", k.Laddr.IP, k.Laddr.Port)
		// gopsutil reports kernel-internal placeholder sockets with
		// Raddr.IP="0.0.0.0" rather than empty; treat that as "no
		// remote" to avoid emitting `connection_open 0.0.0.0:0 (no
		// PTR) by (no owner)` rows that have no operator value. Same
		// for "::" (IPv6 unspecified). Real connections always have
		// a non-zero peer address.
		raddr := ""
		if k.Raddr.IP != "" && k.Raddr.IP != "0.0.0.0" && k.Raddr.IP != "::" {
			raddr = fmt.Sprintf("%s:%d", k.Raddr.IP, k.Raddr.Port)
		}
		// Drop pure-placeholder rows: a PID-0 socket with no real
		// peer is the kernel's own listening / TIME_WAIT bookkeeping.
		// LISTEN sockets with a real PID are kept so the operator
		// still sees "this process is listening on :443".
		if k.Pid == 0 && raddr == "" {
			continue
		}
		key := connKey{pid: k.Pid, local: laddr, remote: raddr, status: k.Status}
		current[key] = struct{}{}
		if _, ok := c.seen[key]; ok {
			continue
		}
		c.seen[key] = time.Now()

		user, pname, cmdline := c.resolveOwner(k.Pid)
		var remoteHost string
		if k.Raddr.IP != "" {
			remoteHost = c.dnsCache.Lookup(ctx, k.Raddr.IP)
		}
		event := map[string]any{
			"event":       "connection_open",
			"status":      k.Status,
			"protocol":    protoName(k.Type),
			"local":       laddr,
			"remote":      raddr,
			"remote_host": remoteHost,
			"pid":         k.Pid,
			"process":     pname,
			"user":        user,
			"cmdline":     cmdline,
		}
		// When PTR fails, hostnames in the cmdline (curl URL, ssh target, etc.)
		// are usually the real destination. Record them so triage can show
		// "by curl -> example.com" even if the IP has no reverse record.
		hints := extractHostHints(cmdline)
		if len(hints) > 0 {
			event["cmdline_hosts"] = hints
		}
		c.storage.Write("network", event)
		// Forward-lookup synthesis: a flow to port 53 IS the DNS query
		// itself. The hostname being resolved isn't on the wire from
		// our vantage (we don't sniff packets, just observe sockets),
		// but the cmdline_hosts hint usually carries it (curl example.com,
		// ping example.com, ssh user@host, etc.). Emit one dns:query
		// event per distinct (host, process) tuple in the dedupe
		// window so an operator running `simplesiem query --grep
		// example.com` finds the lookup itself, not just the
		// subsequent TCP connection to the resolved IP.
		if k.Raddr.Port == 53 {
			for _, h := range hints {
				c.maybeEmitDNSQuery(h, pname, user, k.Raddr.IP)
			}
			if len(hints) == 0 {
				c.maybeEmitDNSQuery("", pname, user, k.Raddr.IP)
			}
		}
		// DNS event synthesis: when we observe a new (remote_host,
		// process) tuple in the current dedupe window, emit a
		// dns:lookup event into the new `dns` log type. Captures
		// the spirit of "DNS query logging" without per-platform
		// resolver interception. Operators can write rules on
		// remote_host / process_name / suspicious TLDs against
		// this stream the same way they would against a real
		// DNS query log.
		if remoteHost != "" {
			c.maybeEmitDNS(remoteHost, k.Raddr.IP, pname, user)
		} else if k.Raddr.IP != "" {
			// First sighting of this IP and the DNS cache was cold
			// — `c.dnsCache.Lookup` enqueued an async PTR. Track
			// the connection so the next poll can re-check the
			// cache and emit a follow-up `connection_dns_resolved`
			// event when the name is finally available. Without
			// this retry, the operator sees "(no PTR)" forever for
			// any flow that opened before the resolver replied.
			if c.pendingDNS == nil {
				c.pendingDNS = map[connKey]pendingDNSEntry{}
			}
			c.pendingDNS[key] = pendingDNSEntry{
				added: time.Now(),
				pid:   k.Pid,
				user:  user,
				proc:  pname,
				ip:    k.Raddr.IP,
				port:  k.Raddr.Port,
			}
		}
	}
	// Platform-supplemented sources: ICMP / raw sockets on Linux,
	// nf_conntrack-tracked flows when the kernel module is loaded.
	// Mac and Windows currently return an empty slice — gopsutil
	// covers TCP/UDP on those platforms; ICMP destinations need a
	// separate native API (netstat -p icmp / Get-NetTCPConnection +
	// ETW). Documented in the conntrack_other.go stub.
	for _, ec := range c.platformExtraConns() {
		laddr := fmt.Sprintf("%s:%d", ec.localIP, ec.localPort)
		raddr := ""
		if ec.remoteIP != "" && ec.remoteIP != "0.0.0.0" && ec.remoteIP != "::" {
			raddr = fmt.Sprintf("%s:%d", ec.remoteIP, ec.remotePort)
		}
		if raddr == "" {
			continue
		}
		key := connKey{pid: ec.pid, local: laddr, remote: raddr, status: ec.status}
		current[key] = struct{}{}
		if _, ok := c.seen[key]; ok {
			continue
		}
		c.seen[key] = time.Now()
		user, pname, cmdline := c.resolveOwner(ec.pid)
		remoteHost := c.dnsCache.Lookup(ctx, ec.remoteIP)
		event := map[string]any{
			"event":       "connection_open",
			"status":      ec.status,
			"protocol":    ec.protocol,
			"local":       laddr,
			"remote":      raddr,
			"remote_host": remoteHost,
			"pid":         ec.pid,
			"process":     pname,
			"user":        user,
			"cmdline":     cmdline,
			"source":      ec.source,
		}
		hints := extractHostHints(cmdline)
		if len(hints) > 0 {
			event["cmdline_hosts"] = hints
		}
		c.storage.Write("network", event)
		// Forward-DNS synthesis: same logic as the gopsutil branch.
		// Most extra-source flows are ICMP/raw (ping), but UDP/53
		// from conntrack also lands here — same dns:query event.
		if ec.remotePort == 53 {
			for _, h := range hints {
				c.maybeEmitDNSQuery(h, pname, user, ec.remoteIP)
			}
			if len(hints) == 0 {
				c.maybeEmitDNSQuery("", pname, user, ec.remoteIP)
			}
		}
		if remoteHost != "" {
			c.maybeEmitDNS(remoteHost, ec.remoteIP, pname, user)
		}
	}

	// DNS-resolved follow-up pass. Iterate pending entries from prior
	// polls; if the cache now has a name, emit a connection_dns_resolved
	// event so the operator can correlate the "(no PTR)" connection_open
	// row with the resolved hostname. Drop entries older than 5 minutes
	// or whose connection has already closed (no longer in c.seen) so
	// the map stays bounded.
	for key, p := range c.pendingDNS {
		if _, alive := c.seen[key]; !alive {
			delete(c.pendingDNS, key)
			continue
		}
		if time.Since(p.added) > 5*time.Minute {
			delete(c.pendingDNS, key)
			continue
		}
		host := c.dnsCache.Lookup(ctx, p.ip)
		if host == "" {
			continue
		}
		c.storage.Write("network", map[string]any{
			"event":       "connection_dns_resolved",
			"local":       key.local,
			"remote":      key.remote,
			"remote_host": host,
			"pid":         p.pid,
			"process":     p.proc,
			"user":        p.user,
			"hint":        "PTR for this IP arrived after the connection_open event; correlate by remote",
		})
		c.maybeEmitDNS(host, p.ip, p.proc, p.user)
		delete(c.pendingDNS, key)
	}
	for key, ts := range c.seen {
		if _, ok := current[key]; !ok {
			c.storage.Write("network", map[string]any{
				"event":      "connection_close",
				"status":     key.status,
				"local":      key.local,
				"remote":     key.remote,
				"pid":        key.pid,
				"duration_s": time.Since(ts).Round(time.Millisecond).Seconds(),
			})
			delete(c.seen, key)
		}
	}
}

// resolveOwner looks up process metadata for a PID, trying the shared cache
// first (populated by ProcessCollector) and falling back to a direct /proc
// read. When the fresh read succeeds, it seeds the cache so future events
// for the same PID don't re-read after the process exits.
func (c *NetworkCollector) resolveOwner(pid int32) (user, name string, cmdline []string) {
	if pid <= 0 {
		return "", "", nil
	}
	if c.procCache != nil {
		if e, ok := c.procCache.get(pid); ok {
			return e.user, e.name, e.cmdline
		}
	}
	p, err := process.NewProcess(pid)
	if err != nil {
		return "", "", nil
	}
	user, _ = p.Username()
	name, _ = p.Name()
	cmdline, _ = p.CmdlineSlice()
	ppid, _ := p.Ppid()
	if c.procCache != nil {
		c.procCache.put(pid, user, name, cmdline, ppid)
	}
	return
}

// extractHostHints pulls plausible hostnames out of a process's cmdline. It's
// used as a fallback when reverse DNS fails (most public IPs lack PTR records
// and return nothing for LookupAddr). If the process is `curl https://foo.com`,
// we get "foo.com" even though the raw IP doesn't resolve back.
func extractHostHints(cmdline []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || strings.ContainsAny(h, " \t\"'<>") {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	for _, arg := range cmdline {
		// URL form: scheme://host[:port]/...
		if strings.Contains(arg, "://") {
			if u, err := url.Parse(arg); err == nil {
				add(u.Hostname())
			}
			continue
		}
		// Bare host:port form (e.g. `ssh user@host:22` — take the host)
		if i := strings.Index(arg, "@"); i >= 0 && i < len(arg)-1 {
			rest := arg[i+1:]
			if j := strings.IndexAny(rest, ":/"); j > 0 {
				add(rest[:j])
			} else {
				add(rest)
			}
		}
	}
	return out
}

// ---------- files ----------

type FileCollector struct {
	storage   *Storage
	paths     []string
	recursive bool
	health    *HealthMonitor
	// passwdDiff turns /etc/passwd-style file modifications into
	// auth:user_added / user_deleted / group_added / etc. events.
	// Initialised lazily in loop() so callers don't have to.
	passwdDiff *passwdDiffer
}

func (c *FileCollector) Start(ctx context.Context, wg *sync.WaitGroup) {
	runCollector(ctx, wg, "files", c.storage, c.loop)
}

func (c *FileCollector) loop(ctx context.Context) {
	c.passwdDiff = newPasswdDiffer()
	// Seed the differ with the current state of every recognised
	// passwd-style file present at startup so the daemon doesn't
	// emit user_added for every account on the next modify (which
	// would happen if we waited for the first fsnotify event to
	// populate the cache).
	for _, candidate := range []string{
		"/etc/passwd", "/private/etc/passwd",
		"/etc/master.passwd", "/private/etc/master.passwd",
		"/etc/group", "/private/etc/group",
		"/etc/shadow", "/etc/gshadow",
	} {
		if _, err := os.Stat(candidate); err == nil {
			c.passwdDiff.observe(candidate)
		}
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		c.storage.Write("errors", map[string]any{
			"collector": "files", "error": err.Error(),
		})
		return
	}
	defer w.Close()

	// Watch budget. fsnotify on Linux uses inotify, on Windows uses
	// ReadDirectoryChangesW (one HANDLE per watched dir), on macOS
	// FSEvents (one FD). Each platform has a different cap and a
	// different *cost* per watch — Windows handle exhaustion crashes
	// the daemon's HTTP server, inotify ENOSPC stops new watches but
	// keeps existing ones, FSEvents is bounded by the process's FD
	// limit. The cap below is a sanity ceiling that aborts the walk
	// before any of those failure modes hit. Operators who need more
	// can either raise the OS limit or narrow file_watch_paths.
	const maxWatches = 8000
	var (
		watchCount  uint64
		watchAtCap  uint64
	)
	addWatchOne := func(p string) {
		if atomic.LoadUint64(&watchCount) >= maxWatches {
			atomic.AddUint64(&watchAtCap, 1)
			return
		}
		if werr := w.Add(p); werr != nil {
			c.storage.Write("errors", map[string]any{
				"collector": "files",
				"error":     "fsnotify watch failed: " + werr.Error(),
				"path":      p,
				"hint":      "raise OS watch limit (Linux: /proc/sys/fs/inotify/max_user_watches; Windows: handle table; macOS: ulimit -n) or narrow file_watch_paths",
			})
			return
		}
		atomic.AddUint64(&watchCount, 1)
	}
	// addWatch is the recursive walker. Run synchronously for non-
	// recursive watches and inside a goroutine for recursive ones —
	// `filepath.WalkDir` doesn't observe ctx, so on a huge tree
	// (the user's C:\Users symptom) it can run for minutes. Doing
	// it in the foreground would block the FileCollector's heartbeat
	// + event loop and trigger meta:collector_silent within 5
	// minutes. The async version lets the event-read loop start
	// immediately; subdirectories that show up after the loop
	// started are still picked up by the fsnotify Create handler
	// further down.
	addWatch := func(path string, async bool) {
		walk := func() {
			_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
				// Cheap ctx check on every entry — bounds the
				// "stop blocked because the walk hasn't finished"
				// case. WalkDir doesn't natively observe ctx.
				if ctx.Err() != nil {
					return filepath.SkipAll
				}
				if err != nil {
					return nil
				}
				if d.IsDir() {
					addWatchOne(p)
				}
				return nil
			})
		}
		if !c.recursive {
			addWatchOne(path)
			return
		}
		if !async {
			walk()
			return
		}
		go func() {
			defer func() { _ = recover() }()
			walk()
		}()
	}

	var watched, missing []string
	for _, p := range c.paths {
		if _, err := os.Stat(p); err != nil {
			missing = append(missing, p)
			continue
		}
		// Async-walk EVERY recursive root so the FileCollector
		// event-read loop starts immediately even when an operator
		// added a huge tree. The walk cost is paid in the
		// background; events from already-added subdirs flow
		// through fsnotify the moment they show up.
		addWatch(p, true /*async*/)
		watched = append(watched, p)
	}
	// Baseline reports both watched and skipped paths in one event,
	// not per-missing-path errors. The default watch list contains
	// platform-typical paths (e.g. /var/spool/cron, /etc/sudoers.d)
	// that are legitimately absent on minimal systems — those are
	// expected, not errors. Operators can still see the skipped list
	// for auditability.
	c.storage.Write("files", map[string]any{
		"event":     "baseline",
		"watched":   watched,
		"skipped":   missing,
		"max_watches": maxWatches,
		"hint":      "watch counts emitted in fsnotify_watch_status meta event after the recursive walk completes",
	})
	// Surface the final watch population periodically. A side
	// goroutine so we don't block the event-read loop waiting for
	// the async walks to settle. Respects ctx so it exits within
	// one tick of daemon shutdown; not tracked in any waitgroup
	// because a worst-case ~60s lag at shutdown is acceptable for
	// a diagnostic emitter (the daemon process exits anyway).
	go func() {
		defer func() { _ = recover() }()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				atCap := atomic.LoadUint64(&watchAtCap)
				cnt := atomic.LoadUint64(&watchCount)
				ev := map[string]any{
					"event":          "fsnotify_watch_status",
					"watch_count":    cnt,
					"max_watches":    maxWatches,
					"skipped_at_cap": atCap,
				}
				if atCap > 0 {
					ev["hint"] = "watch budget exceeded — narrow file_watch_paths or raise OS limit; subtrees beyond the cap are not monitored"
				}
				c.storage.Write("meta", ev)
			}
		}
	}()

	// FileCollector is event-driven, so a quiet host means no fsnotify
	// events. A separate ticker beats the heartbeat so HealthMonitor doesn't
	// flag the goroutine as silent during legitimately idle periods.
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()
	c.health.Beat("files")

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			c.health.Beat("files")
			continue
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			c.health.Beat("files")
			kind := ""
			switch {
			case ev.Op&fsnotify.Create != 0:
				kind = "created"
				if st, err := os.Stat(ev.Name); err == nil && st.IsDir() && c.recursive {
					// Sync walk for newly-created subdirs — they're
					// usually small and adding async noise to the
					// event-loop here doesn't help. The watch budget
					// gate inside addWatchOne keeps even pathological
					// "operator just untarred a 100k-file archive"
					// from blowing the cap.
					addWatch(ev.Name, false /*async*/)
				}
			case ev.Op&fsnotify.Write != 0:
				kind = "modified"
			case ev.Op&fsnotify.Remove != 0:
				kind = "deleted"
			case ev.Op&fsnotify.Rename != 0:
				kind = "renamed"
			case ev.Op&fsnotify.Chmod != 0:
				kind = "chmod"
			}
			if kind == "" {
				continue
			}
			rec := map[string]any{"event": kind, "path": ev.Name}
			if st, err := os.Stat(ev.Name); err == nil {
				rec["size"] = st.Size()
				rec["mode"] = fmt.Sprintf("%o", st.Mode())
				addFileStat(rec, st, ev.Name)
				// SHA-384 of file content on create/modify, capped at
				// 16 MiB so we don't block the watcher hashing a 5 GB
				// log. Hash failures (file deleted before we open,
				// permission denied) are non-fatal — emit the event
				// without sha384.
				if (kind == "created" || kind == "modified") && st.Mode().IsRegular() && st.Size() <= 16*1024*1024 {
					if sum, err := hashFileSHA384(ev.Name); err == nil {
						rec["sha384"] = sum
					}
				}
			}
			// Tag security-critical paths (passwd / shadow / sudoers /
			// SAM equivalents) so queries like `simplesiem query --grep
			// security_critical` surface direct edits to credential
			// stores even when no useradd/Add-LocalUser process ever
			// ran. Cross-references the cmdline-driven user_added
			// auth events so an operator looking at "what changed
			// /etc/passwd" sees both the file write AND the matching
			// useradd invocation.
			if scKind, sev := classifySecurityCriticalPath(ev.Name); scKind != "" {
				rec["security_critical"] = scKind
				rec["severity"] = sev
			}
			c.storage.Write("files", rec)
			// /etc/passwd-style diff → synthesised auth events.
			// Catches sub-poll-interval useradd / userdel that
			// ProcessCollector misses, AND direct edits (vi/sed)
			// that don't spawn a useradd process at all. Only fires
			// for the create/modify kinds — a delete of /etc/passwd
			// itself is its own (rare, alarming) event handled by
			// the security_critical tag.
			if (kind == "modified" || kind == "created") && c.passwdDiff != nil {
				for _, authEv := range c.passwdDiff.observe(ev.Name) {
					c.storage.Write("auth", authEv)
				}
			}
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			c.storage.Write("errors", map[string]any{
				"collector": "files", "error": err.Error(),
			})
		}
	}
}

// classifySecurityCriticalPath returns ("category", "severity") for
// paths the operator almost always wants to see touched. Cross-platform:
// Linux + Mac /etc paths, Windows SAM/SECURITY/SYSTEM hives, plus
// shell-RC files (persistence) and SSH key stores. A category of "" means
// the path isn't security-critical — caller skips the enrichment.
//
// Severity is "high" for credential stores (passwd/shadow/SAM) and
// "medium" for persistence vectors (cron, sudoers.d, shell RC files,
// systemd unit files, launchd plists). The triage tooling and rules
// can key on either field.
func classifySecurityCriticalPath(path string) (string, string) {
	// Normalise to forward-slash form so the same matchers work on
	// Windows. A literal `\` in the path becomes `/`.
	p := strings.ReplaceAll(path, `\`, `/`)
	pl := strings.ToLower(p)
	switch {
	// --- Credential stores: HIGH severity ---
	case p == "/etc/passwd", p == "/etc/shadow", p == "/etc/gshadow",
		p == "/etc/group", p == "/etc/master.passwd", p == "/etc/sudoers",
		p == "/private/etc/passwd", p == "/private/etc/master.passwd",
		p == "/private/etc/group", p == "/private/etc/sudoers":
		return "credential_store", "high"
	case strings.HasPrefix(p, "/etc/sudoers.d/"),
		strings.HasPrefix(p, "/private/etc/sudoers.d/"):
		return "sudoers_drop_in", "high"
	case strings.Contains(pl, "/system32/config/sam"),
		strings.Contains(pl, "/system32/config/security"),
		strings.Contains(pl, "/system32/config/system"):
		return "windows_registry_hive", "high"
	case strings.HasPrefix(p, "/var/db/dslocal/nodes/Default/users/"):
		return "macos_local_users", "high"
	// --- SSH keys / authorized hosts: HIGH ---
	case strings.HasSuffix(p, "/.ssh/authorized_keys"),
		strings.HasSuffix(p, "/.ssh/authorized_keys2"),
		strings.HasSuffix(p, "/.ssh/known_hosts"):
		return "ssh_keystore", "high"
	case strings.HasPrefix(p, "/etc/ssh/"):
		return "ssh_server_config", "high"
	// --- Cron / persistence: MEDIUM ---
	case strings.HasPrefix(p, "/etc/cron.d/"),
		strings.HasPrefix(p, "/etc/cron.hourly/"),
		strings.HasPrefix(p, "/etc/cron.daily/"),
		strings.HasPrefix(p, "/etc/cron.weekly/"),
		strings.HasPrefix(p, "/etc/cron.monthly/"),
		p == "/etc/crontab",
		strings.HasPrefix(p, "/var/spool/cron/"):
		return "cron_persistence", "medium"
	case strings.HasPrefix(p, "/etc/systemd/system/"),
		strings.HasPrefix(p, "/usr/lib/systemd/system/"),
		strings.HasPrefix(p, "/lib/systemd/system/"):
		return "systemd_unit", "medium"
	case strings.HasPrefix(p, "/Library/LaunchDaemons/"),
		strings.HasPrefix(p, "/Library/LaunchAgents/"),
		strings.HasPrefix(p, "/System/Library/LaunchDaemons/"),
		strings.HasPrefix(p, "/System/Library/LaunchAgents/"):
		return "launchd_persistence", "medium"
	case strings.Contains(pl, "/system32/tasks/"):
		return "windows_scheduled_task", "medium"
	// --- Shell RC files: MEDIUM (login persistence) ---
	case strings.HasSuffix(p, "/.bashrc"),
		strings.HasSuffix(p, "/.bash_profile"),
		strings.HasSuffix(p, "/.profile"),
		strings.HasSuffix(p, "/.zshrc"),
		strings.HasSuffix(p, "/.zprofile"),
		p == "/etc/profile",
		strings.HasPrefix(p, "/etc/profile.d/"),
		p == "/etc/bash.bashrc":
		return "shell_rc", "medium"
	}
	return "", ""
}

// ---------- auth ----------

type userSession struct {
	user     string
	terminal string
	host     string
	started  string
}

type AuthCollector struct {
	storage  *Storage
	interval time.Duration
	health   *HealthMonitor
}

func (c *AuthCollector) Start(ctx context.Context, wg *sync.WaitGroup) {
	runCollector(ctx, wg, "auth", c.storage, c.loop)
}

// snapshot: prefer gopsutil.host.Users (works on linux + windows and on darwin
// when built with cgo). Fallback to the `who` command on unix if it returns
// empty (darwin without cgo).
func (c *AuthCollector) snapshot(ctx context.Context) map[userSession]struct{} {
	out := map[userSession]struct{}{}
	if users, err := host.UsersWithContext(ctx); err == nil {
		for _, u := range users {
			started := ""
			if u.Started > 0 {
				started = time.Unix(int64(u.Started), 0).UTC().Format(time.RFC3339)
			}
			out[userSession{
				user:     u.User,
				terminal: u.Terminal,
				host:     u.Host,
				started:  started,
			}] = struct{}{}
		}
	}
	if len(out) == 0 && runtime.GOOS != "windows" {
		out = whoSnapshot(ctx)
	}
	return out
}

// whoSnapshot is implemented per platform in utmp_unix.go (Linux +
// macOS, parses /var/run/utmp{,x} directly — no shell-out to who(1))
// and utmp_other.go (Windows, no-op since gopsutil.host.Users()
// already covers Windows via NetWkstaUserEnum).

func (c *AuthCollector) loop(ctx context.Context) {
	prev := c.snapshot(ctx)
	users := make([]string, 0, len(prev))
	seenUsers := map[string]struct{}{}
	for k := range prev {
		if _, ok := seenUsers[k.user]; !ok {
			users = append(users, k.user)
			seenUsers[k.user] = struct{}{}
		}
	}
	c.storage.Write("auth", map[string]any{
		"event": "baseline_sessions", "count": len(prev), "users": users,
	})
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		c.health.Beat("auth")
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur := c.snapshot(ctx)
		for k := range cur {
			if _, ok := prev[k]; !ok {
				c.storage.Write("auth", map[string]any{
					"event":    "login",
					"user":     k.user,
					"terminal": k.terminal,
					"host":     k.host,
					"started":  k.started,
				})
			}
		}
		for k := range prev {
			if _, ok := cur[k]; !ok {
				c.storage.Write("auth", map[string]any{
					"event":    "logout",
					"user":     k.user,
					"terminal": k.terminal,
					"host":     k.host,
				})
			}
		}
		prev = cur
	}
}

// ---------- processes & traffic ----------

type procInfo struct {
	user       string
	name       string
	cmdline    []string
	ppid       int32
	createTime int64
	exePath    string // resolved executable path (gopsutil .Exe()); used for sha384 enrichment
}

type ProcessCollector struct {
	storage         *Storage
	interval        time.Duration
	trafficInterval time.Duration
	procCache       *procCache
	dnsCache        *dnsCache
	health          *HealthMonitor

	// icmpTracker reads /proc/net/snmp on each traffic emit and
	// reports deltas in InMsgs / OutMsgs / InEchos / OutEchos so a
	// `ping google.com` shows visible activity in the host_io row.
	// Linux-only: see icmp_linux.go for the parser; non-Linux
	// platforms get a stub that always reports zero deltas.
	icmpTracker icmpDeltaTracker

	// netDeltaPrev caches the previous gopsutil counter readings so
	// emitTraffic can ship `bytes_sent`/`bytes_recv` as DELTAS
	// rather than cumulative-since-interface-up. The cumulative
	// values move with /proc/net/dev, which is unsuitable for
	// "was traffic flowing during this poll" alerts — a single
	// 84-byte ping is invisible inside a 424 KB lifetime total.
	// Mapped by interface name; key "" holds the all-iface aggregate.
	netDeltaPrev map[string]ifaceCounter
}

type ifaceCounter struct {
	bytesSent   uint64
	bytesRecv   uint64
	packetsSent uint64
	packetsRecv uint64
	have        bool
}

// subSat does saturating subtraction on uint64. Used for byte/packet
// counter deltas where the kernel can occasionally reset a counter
// (interface down/up, /proc/net/dev rollover on 32-bit hosts under
// gopsutil's older fallback path); a saturating subtract reports
// 0 instead of wrapping into the multi-exabyte range and producing
// nonsense "the agent sent 18 EB this minute" rows.
func subSat(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

func (c *ProcessCollector) Start(ctx context.Context, wg *sync.WaitGroup) {
	runCollector(ctx, wg, "processes", c.storage, c.loop)
}

func snapshotProcs(ctx context.Context) map[int32]procInfo {
	out := map[int32]procInfo{}
	pids, err := process.PidsWithContext(ctx)
	if err != nil {
		return out
	}
	for _, pid := range pids {
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}
		user, _ := p.Username()
		name, _ := p.Name()
		cmdline, _ := p.CmdlineSlice()
		ctime, _ := p.CreateTime()
		ppid, _ := p.Ppid()
		// Best-effort executable path for SHA-384 enrichment.
		// gopsutil's Exe() works on Linux (/proc/PID/exe),
		// macOS (proc_pidpath), and Windows (NtQueryInformationProcess
		// / GetModuleFileNameEx). Permission errors are common for
		// cross-uid processes; we skip enrichment rather than fail.
		exe, _ := p.Exe()
		out[pid] = procInfo{user: user, name: name, cmdline: cmdline, ppid: ppid, createTime: ctime, exePath: exe}
	}
	return out
}

func (c *ProcessCollector) loop(ctx context.Context) {
	// Baseline the current process table at startup, seed the shared cache,
	// and record the daemon's start time so pre-existing processes can't be
	// misreported as "process_start" if /proc gives inconsistent createTime
	// readings across snapshots.
	daemonStart := time.Now()
	seen := snapshotProcs(ctx)
	for pid, info := range seen {
		c.procCache.put(pid, info.user, info.name, info.cmdline, info.ppid)
	}

	procTicker := time.NewTicker(c.interval)
	defer procTicker.Stop()
	trafficTicker := time.NewTicker(c.trafficInterval)
	defer trafficTicker.Stop()
	sweepTicker := time.NewTicker(time.Minute)
	defer sweepTicker.Stop()

	// Linux real-time process event listener (NETLINK_CONNECTOR
	// PROC_EVENTS). Fires on every fork/exec instantly — closes the
	// "curl finished before the next 2-second poll" gap that pure
	// /proc polling can't address. Returns ok=false on non-Linux,
	// no CAP_NET_ADMIN, or kernel built without CONFIG_PROC_EVENTS;
	// in any of those cases the polling tickers are the only path
	// (current behaviour, no regression). Events are deduped against
	// the polling `seen` map so a process caught by both channels
	// produces exactly one process_start.
	var pevents <-chan procExec
	if pl, ok := startProcEventListener(ctx); ok {
		pevents = pl.events
		defer pl.stop()
		c.storage.Write("meta", map[string]any{
			"event":  "proc_events_listener_started",
			"detail": "subscribed to NETLINK_CONNECTOR PROC_EVENTS — sub-poll-interval processes are now captured in real time",
		})
	} else {
		ev := map[string]any{
			"event": "proc_events_listener_unavailable",
			"hint":  "kernel proc-events feed not subscribable (non-Linux, no CAP_NET_ADMIN, or kernel built without CONFIG_PROC_EVENTS); falling back to /proc polling at process_interval cadence",
		}
		if e := procEventsLastErrString(); e != "" {
			ev["error"] = e
		}
		c.storage.Write("meta", ev)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-trafficTicker.C:
			c.health.Beat("traffic")
			c.emitTraffic(ctx)
			continue
		case <-sweepTicker.C:
			c.procCache.sweep(5 * time.Minute)
			continue
		case ev, ok := <-pevents:
			if !ok {
				// Listener died — fall back to ticker-only.
				pevents = nil
				continue
			}
			// Read the cmdline + exe RIGHT NOW, before the
			// process exits. /proc/<pid> may already be gone
			// for sub-millisecond exec()s; in that case we
			// emit a degraded event with just the pid so
			// the cmdline-tool synthesizer can still match
			// on later poll-derived data. Best-effort.
			info, ok := procFromPID(ctx, ev.pid)
			if !ok {
				continue
			}
			// Idempotency: if polling already grabbed this
			// pid (with same createTime), skip — duplicate
			// process_start would just confuse downstream.
			if prev, exists := seen[ev.pid]; exists && prev.createTime == info.createTime {
				continue
			}
			seen[ev.pid] = info
			c.procCache.put(ev.pid, info.user, info.name, info.cmdline, info.ppid)
			c.emitProcessStart(ev.pid, info, daemonStart)
			continue
		case <-procTicker.C:
		}
		c.health.Beat("processes")

		cur := snapshotProcs(ctx)
		for pid, info := range cur {
			prev, existed := seen[pid]
			isNew := !existed
			// A different createTime on the same PID means kernel recycled
			// the PID to a new process. Guard against ctime==0 noise from
			// /proc reads that fail during process startup.
			if existed && info.createTime > 0 && prev.createTime > 0 &&
				info.createTime != prev.createTime {
				isNew = true
			}
			if !isNew {
				continue
			}
			// Skip processes that were alive before the daemon started —
			// we don't know their actual start; flagging them as "new"
			// when the collector restarts would be misleading.
			if info.createTime > 0 &&
				time.UnixMilli(info.createTime).Before(daemonStart) {
				c.procCache.put(pid, info.user, info.name, info.cmdline, info.ppid)
				continue
			}
			c.procCache.put(pid, info.user, info.name, info.cmdline, info.ppid)
			c.emitProcessStart(pid, info, daemonStart)
		}
		for pid, info := range seen {
			if _, ok := cur[pid]; !ok {
				c.procCache.markExited(pid)
				c.storage.Write("processes", map[string]any{
					"event": "process_exit",
					"pid":   pid,
					"user":  info.user,
					"name":  info.name,
				})
			}
		}
		seen = cur
	}
}

// emitProcessStart writes a process_start event for one observed
// process. Pulled out of the polling loop so the netlink PROC_EVENTS
// fast path (which fires on every exec, possibly faster than the
// procTicker) can use the same emission shape — same fields, same
// SHA-384 enrichment, same cmdline-tool synthesis. Idempotency is
// the caller's responsibility (check `seen` before calling).
func (c *ProcessCollector) emitProcessStart(pid int32, info procInfo, daemonStart time.Time) {
	created := ""
	if info.createTime > 0 {
		created = time.UnixMilli(info.createTime).UTC().Format(time.RFC3339)
	}
	event := map[string]any{
		"event":   "process_start",
		"pid":     pid,
		"user":    info.user,
		"name":    info.name,
		"cmdline": info.cmdline,
		"created": created,
	}
	if info.ppid > 0 {
		event["ppid"] = info.ppid
		// parent_name + parent cmdline are best-effort: parent may
		// have already exited or never been seen. The cache holds
		// it either way thanks to the TTL-on-exit policy.
		if pe, ok := c.procCache.get(info.ppid); ok {
			if pe.name != "" {
				event["parent_name"] = pe.name
			}
			if len(pe.cmdline) > 0 {
				event["parent_cmdline"] = strings.Join(pe.cmdline, " ")
			}
			if pe.user != "" {
				event["parent_user"] = pe.user
			}
		}
	}
	// Executable SHA-384 — auditd's EXECVE-equivalent for detection
	// rules without the netlink dependency. Uses gopsutil's exe
	// path on Linux/Mac; Windows path comes through the same
	// procCache. Capped at 32 MiB so we don't block the collector
	// on a giant binary.
	if info.exePath != "" {
		if st, err := os.Stat(info.exePath); err == nil && st.Mode().IsRegular() && st.Size() <= 32*1024*1024 {
			if sum, err := hashFileSHA384(info.exePath); err == nil {
				event["sha384"] = sum
				event["exe_path"] = info.exePath
			}
		}
	}
	c.storage.Write("processes", event)
	// Network-tool synthesis: catches sub-poll-interval flows the
	// kernel-socket pollers can't see. ping/traceroute via SOCK_DGRAM
	// doesn't store its destination in /proc/net/icmp (kernel uses
	// sendto, never connect), and a one-shot curl/dig may finish
	// before the next NetworkCollector poll. The cmdline IS captured
	// here every time the process is sighted, and it carries the
	// destination — emit a connection_open into the network log type
	// so `simplesiem query --type network --grep <host>` finds the
	// activity even when the socket itself was invisible.
	emitNetworkToolInvocation(c.storage, info, pid, created)
	// User-management synthesis: same pattern, AUTH log type. Catches
	// useradd / passwd / sysadminctl / dscl / dseditgroup / net user
	// / Add-LocalUser invocations even when the host has no
	// rsyslog/journald (Linux container), no unified-log feed (Mac
	// stripped), or no audit-policy enabled (Windows workstation).
	emitUserMgmtInvocation(c.storage, info, pid, created)
}

// procFromPID looks up one PID's metadata via gopsutil. Used by the
// netlink PROC_EVENTS path to enrich an exec notification before
// the process exits — at that latency the kernel may already have
// torn down /proc/<pid>/, so we accept failure quietly.
func procFromPID(ctx context.Context, pid int32) (procInfo, bool) {
	p, err := process.NewProcess(pid)
	if err != nil {
		return procInfo{}, false
	}
	user, _ := p.Username()
	name, _ := p.Name()
	cmdline, _ := p.CmdlineSlice()
	ctime, _ := p.CreateTime()
	ppid, _ := p.Ppid()
	exe, _ := p.Exe()
	if name == "" && len(cmdline) == 0 {
		return procInfo{}, false
	}
	return procInfo{
		user:       user,
		name:       name,
		cmdline:    cmdline,
		ppid:       ppid,
		createTime: ctime,
		exePath:    exe,
	}, true
}

// emitTraffic writes host-wide byte counters plus one `active_connection`
// event per unique (user, process, remote, remote_host) flow. The flow list
// is also embedded in the host_io event as `destinations` so a reader sees
// both "how much went over the wire" and "which processes/hosts were talking"
// in one place. Per-connection byte accounting is out of scope (needs eBPF).
//
// Caveat for the s7 manual-test report: gopsutil's connection list is
// TCP/UDP only — ICMP (ping), raw sockets, and sub-poll-lifetime flows
// (a curl that finishes between polls) are NOT in `flows`. host_io
// still counts those bytes, so a non-zero bytes_sent with empty
// destinations is the canonical "we saw the bytes but couldn't
// attribute them" case. The destinations field is now ALWAYS present
// (possibly an empty array) so a reader can distinguish that from
// "the field was missing, maybe a buggy older daemon".
func (c *ProcessCollector) emitTraffic(ctx context.Context) {
	flows := c.collectFlows(ctx)
	if c.netDeltaPrev == nil {
		c.netDeltaPrev = map[string]ifaceCounter{}
	}

	if io, err := psnet.IOCountersWithContext(ctx, false); err == nil && len(io) > 0 {
		// bytes_sent / bytes_recv are DELTAS since the previous
		// emit, not lifetime counters. The first emit after daemon
		// start has no prior baseline and reports zero — same
		// rationale as icmpDeltaTracker. Cumulative values stay
		// available under *_total for callers that need raw stats.
		curAll := ifaceCounter{
			bytesSent:   io[0].BytesSent,
			bytesRecv:   io[0].BytesRecv,
			packetsSent: io[0].PacketsSent,
			packetsRecv: io[0].PacketsRecv,
			have:        true,
		}
		var dBytesSent, dBytesRecv, dPktSent, dPktRecv uint64
		if prev, ok := c.netDeltaPrev[""]; ok && prev.have {
			dBytesSent = subSat(curAll.bytesSent, prev.bytesSent)
			dBytesRecv = subSat(curAll.bytesRecv, prev.bytesRecv)
			dPktSent = subSat(curAll.packetsSent, prev.packetsSent)
			dPktRecv = subSat(curAll.packetsRecv, prev.packetsRecv)
		}
		c.netDeltaPrev[""] = curAll
		event := map[string]any{
			"event":              "host_io",
			"bytes_sent":         dBytesSent,
			"bytes_recv":         dBytesRecv,
			"packets_sent":       dPktSent,
			"packets_recv":       dPktRecv,
			"bytes_sent_total":   curAll.bytesSent,
			"bytes_recv_total":   curAll.bytesRecv,
			"packets_sent_total": curAll.packetsSent,
			"packets_recv_total": curAll.packetsRecv,
		}
		dests := flowsToDestList(flows)
		if dests == nil {
			dests = []map[string]any{}
		}
		event["destinations"] = dests
		// Per-interface breakdown when available. Lets a reader spot
		// "all the egress went out eth0 vs lo" without resorting to
		// `ip -s link`. Same delta-vs-cumulative split as the
		// aggregate above: bytes_sent/bytes_recv are deltas; raw
		// counters are kept under *_total for completeness.
		if perIface, ierr := psnet.IOCountersWithContext(ctx, true); ierr == nil && len(perIface) > 0 {
			rows := make([]map[string]any, 0, len(perIface))
			for _, p := range perIface {
				curIf := ifaceCounter{
					bytesSent:   p.BytesSent,
					bytesRecv:   p.BytesRecv,
					packetsSent: p.PacketsSent,
					packetsRecv: p.PacketsRecv,
					have:        true,
				}
				var dSent, dRecv, dPSent, dPRecv uint64
				if prev, ok := c.netDeltaPrev[p.Name]; ok && prev.have {
					dSent = subSat(curIf.bytesSent, prev.bytesSent)
					dRecv = subSat(curIf.bytesRecv, prev.bytesRecv)
					dPSent = subSat(curIf.packetsSent, prev.packetsSent)
					dPRecv = subSat(curIf.packetsRecv, prev.packetsRecv)
				}
				c.netDeltaPrev[p.Name] = curIf
				if dSent == 0 && dRecv == 0 && p.BytesSent == 0 && p.BytesRecv == 0 {
					// No history AND no current activity — skip.
					continue
				}
				rows = append(rows, map[string]any{
					"name":               p.Name,
					"bytes_sent":         dSent,
					"bytes_recv":         dRecv,
					"packets_sent":       dPSent,
					"packets_recv":       dPRecv,
					"bytes_sent_total":   curIf.bytesSent,
					"bytes_recv_total":   curIf.bytesRecv,
					"packets_sent_total": curIf.packetsSent,
					"packets_recv_total": curIf.packetsRecv,
				})
			}
			if len(rows) > 0 {
				event["per_iface"] = rows
			}
		}
		// ICMP deltas (Linux only). When non-zero, attach so
		// triage's host_io row reports the ping that the
		// connection-list path misses. First poll after daemon
		// start always reports zero (no prior baseline) so we
		// don't dump the host's lifetime ICMP counters into a
		// single noisy row.
		if _, delta := c.icmpTracker.snapshotDelta(); delta.nonZero() {
			event["icmp_in"] = delta.InMsgs
			event["icmp_out"] = delta.OutMsgs
			if delta.InEchos != 0 {
				event["icmp_echo_in"] = delta.InEchos
			}
			if delta.OutEchos != 0 {
				event["icmp_echo_out"] = delta.OutEchos
			}
			if delta.InEchoReps != 0 {
				event["icmp_echo_reply_in"] = delta.InEchoReps
			}
			if delta.OutEchoReps != 0 {
				event["icmp_echo_reply_out"] = delta.OutEchoReps
			}
		}
		c.storage.Write("traffic", event)
	}

	for k, count := range flows {
		event := map[string]any{
			"event":    "active_connection",
			"user":     k.user,
			"process":  k.proc,
			"remote":   k.remote,
			"protocol": k.proto,
			"count":    count,
		}
		if k.host != "" {
			event["remote_host"] = k.host
		}
		c.storage.Write("traffic", event)
	}
}

type flowKey struct {
	user, proc, remote, host, proto string
}

func (c *ProcessCollector) collectFlows(ctx context.Context) map[flowKey]int {
	flows := map[flowKey]int{}
	conns, err := psnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return flows
	}
	for _, cn := range conns {
		// Include in-flight, established, and recently-closed TCP states so
		// short-lived flows (apt fetch, curl) still appear in the rollup
		// even if they finished before the traffic ticker fired. UDP and
		// other socket types have no Status — keep those too.
		switch cn.Status {
		case "", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT",
			"FIN_WAIT_1", "FIN_WAIT_2", "LAST_ACK", "CLOSING", "SYN_SENT":
		default:
			continue
		}
		var user, name string
		if cn.Pid > 0 {
			if e, ok := c.procCache.get(cn.Pid); ok {
				user, name = e.user, e.name
			} else if p, err := process.NewProcess(cn.Pid); err == nil {
				user, _ = p.Username()
				name, _ = p.Name()
				ppid, _ := p.Ppid()
				c.procCache.put(cn.Pid, user, name, nil, ppid)
			}
		}
		remote := ""
		if cn.Raddr.IP != "" {
			remote = fmt.Sprintf("%s:%d", cn.Raddr.IP, cn.Raddr.Port)
		}
		if remote == "" {
			continue
		}
		var host string
		if c.dnsCache != nil {
			host = c.dnsCache.Lookup(ctx, cn.Raddr.IP)
		}
		flows[flowKey{user: user, proc: name, remote: remote, host: host, proto: protoName(cn.Type)}]++
	}
	return flows
}

// flowsToDestList produces a compact [{user, process, remote, remote_host,
// protocol, count}, ...] summary suitable for embedding into a host_io event.
// Left as []map[string]any (not []struct) so it round-trips cleanly through
// the map[string]any JSON pipeline the rest of the daemon uses.
func flowsToDestList(flows map[flowKey]int) []map[string]any {
	if len(flows) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(flows))
	for k, count := range flows {
		d := map[string]any{
			"remote":   k.remote,
			"protocol": k.proto,
			"count":    count,
		}
		if k.user != "" {
			d["user"] = k.user
		}
		if k.proc != "" {
			d["process"] = k.proc
		}
		if k.host != "" {
			d["remote_host"] = k.host
		}
		out = append(out, d)
	}
	return out
}
