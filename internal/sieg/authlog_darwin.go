//go:build darwin

package sieg

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// AuthLogCollector on macOS subprocesses `log stream --style ndjson` and
// parses the unified-logging entries for sshd, sudo, and su events. macOS
// retired plain-text auth files years ago — /var/log/auth.log doesn't
// exist, and /var/log/system.log is sparsely populated for security
// events. The unified log is the only complete source.
//
// Resume behaviour: the collector checkpoints the timestamp of every
// parsed event into <state>/authlog_darwin.json. On daemon restart it
// runs `log show --start <ts>` to backfill the gap before resuming the
// `log stream` subprocess; this mirrors the Linux file-tailer's
// inode+offset resume so an outage that fits inside the unified log's
// retention window doesn't lose events.
//
// The subprocess can die (oslog daemon hiccups, system sleep). loop
// wraps the run so runCollector's panic-and-restart catches it.
type AuthLogCollector struct {
	storage  *Storage
	paths    []string      // unused on darwin; kept for daemon.go compat
	interval time.Duration // unused on darwin; kept for daemon.go compat
	health   *HealthMonitor
	state    *stateStore
}

const stateAuthLogDarwinName = "authlog_darwin"

// backfillMaxLookback is the longest gap we'll attempt to recover from
// the unified log on startup. Outages longer than this are ignored —
// the unified log's own retention is uncertain on busy hosts and
// pulling a week of activity through `log show` is expensive.
const backfillMaxLookback = 24 * time.Hour

func (c *AuthLogCollector) Start(ctx context.Context, wg *sync.WaitGroup) {
	runCollector(ctx, wg, "authlog", c.storage, c.loop)
}

func (c *AuthLogCollector) loop(ctx context.Context) {
	// Keep predicate narrow — `log stream` without filtering floods the
	// pipe with thousands of events per second from kernel/system tasks.
	predicate := `process == "sshd" OR process == "sudo" OR process == "su" OR process == "login"`

	// Backfill the gap between the previously-seen event and now.
	// Tracks the high-water mark so the subsequent `log stream` doesn't
	// re-emit anything we already wrote. Best-effort: errors are logged
	// to errors/ but never block the stream.
	lastTS := c.backfillSinceLastSeen(ctx, predicate)
	c.health.Beat("authlog")

	cmd := exec.CommandContext(ctx, "log", "stream",
		"--predicate", predicate,
		"--style", "ndjson",
		"--info",
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.storage.Write("errors", map[string]any{"collector": "authlog", "error": err.Error()})
		return
	}
	if err := cmd.Start(); err != nil {
		c.storage.Write("errors", map[string]any{"collector": "authlog", "error": err.Error()})
		return
	}
	c.storage.Write("meta", map[string]any{
		"event": "authlog_tail_started", "source": "log stream",
	})

	// Heartbeat is event-driven (one beat per parsed line plus a periodic
	// safety beat) so HealthMonitor doesn't flag a quiet auth period.
	beat := time.NewTicker(30 * time.Second)
	defer beat.Stop()

	// Persist the current high-water timestamp every 30s while the
	// stream runs, so a daemon restart resumes from a recent point.
	persistTick := time.NewTicker(30 * time.Second)
	defer persistTick.Stop()
	var watermarkMu sync.Mutex
	watermark := lastTS

	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(stdout)
		// `log stream --style ndjson` lines can be long (eventMessage with
		// stack-style content), so bump the buffer.
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			c.health.Beat("authlog")
			line := scanner.Bytes()
			if ev := parseDarwinAuthLine(line); ev != nil {
				c.storage.Write("auth", ev)
			}
			// Update the watermark whether we kept the event or
			// not — the next backfill anchors on "we've definitely
			// seen everything up to here".
			if ts := extractDarwinTimestamp(line); !ts.IsZero() {
				watermarkMu.Lock()
				if ts.After(watermark) {
					watermark = ts
				}
				watermarkMu.Unlock()
			}
		}
	}()

	persist := func() {
		watermarkMu.Lock()
		ts := watermark
		watermarkMu.Unlock()
		if ts.IsZero() || c.state == nil {
			return
		}
		_ = c.state.Save(stateAuthLogDarwinName, stateAuthLogDarwin{LastEventTS: ts})
	}
	for {
		select {
		case <-ctx.Done():
			persist()
			_ = cmd.Process.Kill()
			<-scanDone
			// Reap the subprocess so we don't leave a zombie holding a
			// process slot. The kill above guarantees the wait returns;
			// any error is expected and uninteresting.
			_ = cmd.Wait()
			return
		case <-beat.C:
			c.health.Beat("authlog")
		case <-persistTick.C:
			persist()
		case <-scanDone:
			persist()
			// Stream ended unexpectedly. Panic so runCollector restarts
			// us with backoff. We've already emitted a meta start event;
			// the next start will emit another.
			err := cmd.Wait()
			panic(fmt.Sprintf("log stream exited: %v", err))
		}
	}
}

// backfillSinceLastSeen runs `log show --start <ts>` for the gap
// between the previously-seen event and the current time, parses
// each entry the same way the live stream does, and writes any
// matching events. Returns the timestamp of the most recent backfilled
// entry (zero if no resume state existed or the gap was wider than
// backfillMaxLookback). The live `log stream` then takes over from
// "now" without overlap.
func (c *AuthLogCollector) backfillSinceLastSeen(ctx context.Context, predicate string) time.Time {
	if c.state == nil {
		return time.Time{}
	}
	var resume stateAuthLogDarwin
	if err := c.state.Load(stateAuthLogDarwinName, &resume); err != nil {
		return time.Time{}
	}
	if resume.LastEventTS.IsZero() {
		return time.Time{}
	}
	gap := time.Since(resume.LastEventTS)
	if gap < 5*time.Second || gap > backfillMaxLookback {
		// Sub-5s gap is the no-restart-pause case (nothing to do);
		// gaps over the lookback are skipped to avoid pulling
		// hundreds of MB through `log show`.
		return resume.LastEventTS
	}
	startStr := resume.LastEventTS.Format("2006-01-02 15:04:05Z0700")
	cmd := exec.CommandContext(ctx, "log", "show",
		"--predicate", predicate,
		"--style", "ndjson",
		"--info",
		"--start", startStr,
	)
	out, err := cmd.StdoutPipe()
	if err != nil {
		c.storage.Write("errors", map[string]any{
			"collector": "authlog",
			"error":     fmt.Sprintf("backfill log show: %v", err),
		})
		return resume.LastEventTS
	}
	if err := cmd.Start(); err != nil {
		c.storage.Write("errors", map[string]any{
			"collector": "authlog",
			"error":     fmt.Sprintf("backfill start: %v", err),
		})
		return resume.LastEventTS
	}
	c.storage.Write("meta", map[string]any{
		"event": "authlog_backfill_started",
		"start": startStr,
		"gap_seconds": int(gap.Seconds()),
	})
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	count := 0
	last := resume.LastEventTS
	for scanner.Scan() {
		line := scanner.Bytes()
		if ev := parseDarwinAuthLine(line); ev != nil {
			c.storage.Write("auth", ev)
			count++
		}
		if ts := extractDarwinTimestamp(line); !ts.IsZero() && ts.After(last) {
			last = ts
		}
	}
	_ = cmd.Wait()
	c.storage.Write("meta", map[string]any{
		"event":  "authlog_backfill_complete",
		"events": count,
		"high_water": last.Format(time.RFC3339Nano),
	})
	if c.state != nil && !last.IsZero() {
		_ = c.state.Save(stateAuthLogDarwinName, stateAuthLogDarwin{LastEventTS: last})
	}
	return last
}

// extractDarwinTimestamp pulls the unified-log entry's timestamp out
// of the ndjson line. Format is "2026-05-02 18:22:33.123456-0400".
// Returns zero on parse error so the caller skips the watermark
// update for this line (the next valid line will catch up).
func extractDarwinTimestamp(line []byte) time.Time {
	var entry struct {
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(line, &entry); err != nil {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05.000000-0700",
		"2006-01-02 15:04:05-0700",
		time.RFC3339Nano,
	} {
		if t, err := time.Parse(layout, entry.Timestamp); err == nil {
			return t
		}
	}
	return time.Time{}
}

// darwinLogEntry is the subset of `log stream --style ndjson` fields we use.
// The full schema has 30+ fields; everything else is ignored.
type darwinLogEntry struct {
	EventMessage string `json:"eventMessage"`
	Process      string `json:"processImagePath"`
	Subsystem    string `json:"subsystem"`
}

var (
	// macOS sshd messages don't carry the bracketed PID like Linux does;
	// parsing anchors on the recognisable phrase only.
	reMacSSHAccepted = regexp.MustCompile(`Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)
	reMacSSHFailed   = regexp.MustCompile(`Failed\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)
	reMacSSHInvalid  = regexp.MustCompile(`Invalid user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)
	reMacSudoCmd     = regexp.MustCompile(`(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)$`)
	// macOS "su" emits "BAD SU <user> to <target> on <tty>" on failure;
	// success goes via PAM and varies by version. Parse what's stable.
	reMacSuFailed = regexp.MustCompile(`BAD SU\s+(\S+)\s+to\s+(\S+)\s+on\s+(\S+)`)
)

// parseDarwinAuthLine matches a single ndjson entry. Returns nil for entries
// that don't match a known auth pattern (most of them — even with a narrow
// predicate, `log stream` emits TLS handshake noise, keepalives, etc.).
func parseDarwinAuthLine(line []byte) map[string]any {
	var e darwinLogEntry
	if err := json.Unmarshal(line, &e); err != nil {
		return nil
	}
	msg := e.EventMessage
	proc := filepath.Base(e.Process)
	switch proc {
	case "sshd":
		if m := reMacSSHAccepted.FindStringSubmatch(msg); m != nil {
			return map[string]any{
				"event": "ssh_login", "method": m[1], "user": m[2],
				"remote": m[3], "port": m[4], "result": "success",
			}
		}
		if m := reMacSSHFailed.FindStringSubmatch(msg); m != nil {
			return map[string]any{
				"event": "ssh_login", "method": m[1], "user": m[2],
				"remote": m[3], "port": m[4], "result": "failed",
			}
		}
		if m := reMacSSHInvalid.FindStringSubmatch(msg); m != nil {
			return map[string]any{
				"event": "ssh_login", "user": m[1],
				"remote": m[2], "port": m[3], "result": "invalid_user",
			}
		}
	case "sudo":
		if m := reMacSudoCmd.FindStringSubmatch(msg); m != nil {
			return map[string]any{
				"event": "sudo", "user": m[1], "terminal": m[2],
				"pwd": m[3], "target": m[4], "command": m[5], "result": "ok",
			}
		}
	case "su":
		if m := reMacSuFailed.FindStringSubmatch(msg); m != nil {
			return map[string]any{
				"event": "su", "user": m[1], "target": m[2],
				"terminal": m[3], "result": "failed",
			}
		}
	}
	return nil
}
