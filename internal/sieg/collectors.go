package sieg

import (
	"bufio"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
}

func (c *NetworkCollector) Start(ctx context.Context, wg *sync.WaitGroup) {
	runCollector(ctx, wg, "network", c.storage, c.loop)
}

func (c *NetworkCollector) loop(ctx context.Context) {
	c.seen = map[connKey]time.Time{}
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
		raddr := ""
		if k.Raddr.IP != "" {
			raddr = fmt.Sprintf("%s:%d", k.Raddr.IP, k.Raddr.Port)
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
		if hints := extractHostHints(cmdline); len(hints) > 0 {
			event["cmdline_hosts"] = hints
		}
		c.storage.Write("network", event)
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
		}
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
}

func (c *FileCollector) Start(ctx context.Context, wg *sync.WaitGroup) {
	runCollector(ctx, wg, "files", c.storage, c.loop)
}

func (c *FileCollector) loop(ctx context.Context) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		c.storage.Write("errors", map[string]any{
			"collector": "files", "error": err.Error(),
		})
		return
	}
	defer w.Close()

	addWatch := func(path string) {
		if c.recursive {
			_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					if werr := w.Add(p); werr != nil {
						// inotify limit (ENOSPC), permission denied,
						// stale path. Surface to errors so operators
						// know events for this subtree aren't being
						// captured rather than silently swallowing it.
						c.storage.Write("errors", map[string]any{
							"collector": "files",
							"error":     "inotify watch failed: " + werr.Error(),
							"path":      p,
							"hint":      "raise /proc/sys/fs/inotify/max_user_watches or narrow file_watch_paths",
						})
					}
				}
				return nil
			})
		} else {
			if werr := w.Add(path); werr != nil {
				c.storage.Write("errors", map[string]any{
					"collector": "files",
					"error":     "inotify watch failed: " + werr.Error(),
					"path":      path,
				})
			}
		}
	}

	var watched, missing []string
	for _, p := range c.paths {
		if _, err := os.Stat(p); err != nil {
			missing = append(missing, p)
			continue
		}
		addWatch(p)
		watched = append(watched, p)
	}
	// Baseline reports both watched and skipped paths in one event,
	// not per-missing-path errors. The default watch list contains
	// platform-typical paths (e.g. /var/spool/cron, /etc/sudoers.d)
	// that are legitimately absent on minimal systems — those are
	// expected, not errors. Operators can still see the skipped list
	// for auditability.
	c.storage.Write("files", map[string]any{
		"event":   "baseline",
		"watched": watched,
		"skipped": missing,
	})

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
					addWatch(ev.Name)
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
				addFileStat(rec, st)
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
			c.storage.Write("files", rec)
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

func whoSnapshot(ctx context.Context) map[userSession]struct{} {
	out := map[userSession]struct{}{}
	cmd := exec.CommandContext(ctx, "who")
	data, err := cmd.Output()
	if err != nil {
		return out
	}
	scan := bufio.NewScanner(strings.NewReader(string(data)))
	for scan.Scan() {
		line := scan.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		user := fields[0]
		tty := fields[1]
		host := ""
		if i := strings.LastIndex(line, "("); i >= 0 {
			if j := strings.LastIndex(line, ")"); j > i {
				host = line[i+1 : j]
			}
		}
		started := ""
		if idx := strings.Index(line, tty); idx >= 0 {
			rest := line[idx+len(tty):]
			if p := strings.Index(rest, "("); p >= 0 {
				rest = rest[:p]
			}
			started = strings.TrimSpace(rest)
		}
		out[userSession{user: user, terminal: tty, host: host, started: started}] = struct{}{}
	}
	return out
}

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
				// parent_name + parent cmdline are best-effort:
				// parent may have already exited or never been
				// seen. The cache holds it either way thanks to
				// the TTL-on-exit policy.
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
			// Executable SHA-384 — auditd's EXECVE-equivalent for
			// detection rules without the netlink dependency. Uses
			// gopsutil's exe path on Linux/Mac; Windows path comes
			// through the same procCache. Capped at 32 MiB so we
			// don't block the collector on a giant binary; capping
			// is honest about what enrichment costs.
			if info.exePath != "" {
				if st, err := os.Stat(info.exePath); err == nil && st.Mode().IsRegular() && st.Size() <= 32*1024*1024 {
					if sum, err := hashFileSHA384(info.exePath); err == nil {
						event["sha384"] = sum
						event["exe_path"] = info.exePath
					}
				}
			}
			c.storage.Write("processes", event)
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

// emitTraffic writes host-wide byte counters plus one `active_connection`
// event per unique (user, process, remote, remote_host) flow. The flow list
// is also embedded in the host_io event as `destinations` so a reader sees
// both "how much went over the wire" and "which processes/hosts were talking"
// in one place. Per-connection byte accounting is out of scope (needs eBPF).
func (c *ProcessCollector) emitTraffic(ctx context.Context) {
	flows := c.collectFlows(ctx)

	if io, err := psnet.IOCountersWithContext(ctx, false); err == nil && len(io) > 0 {
		event := map[string]any{
			"event":        "host_io",
			"bytes_sent":   io[0].BytesSent,
			"bytes_recv":   io[0].BytesRecv,
			"packets_sent": io[0].PacketsSent,
			"packets_recv": io[0].PacketsRecv,
		}
		if dests := flowsToDestList(flows); len(dests) > 0 {
			event["destinations"] = dests
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
