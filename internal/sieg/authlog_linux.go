//go:build linux

package sieg

import (
	"bufio"
	"context"
	"io"
	"os"
	"regexp"
	"sync"
	"syscall"
	"time"
)

// stateAuthLog stores the inode + byte offset of the auth.log we were
// tailing, so on restart we resume from the same position rather than
// jumping to EOF and missing whatever happened during the downtime.
type stateAuthLog struct {
	Path  string `json:"path"`
	Inode uint64 `json:"inode"`
	Pos   int64  `json:"pos"`
}

// AuthLogCollector tails the system auth log (sshd, sudo, su, pam) and emits
// one structured event per recognised line. It complements the gopsutil-based
// AuthCollector, which only sees logged-in *sessions* — failed SSH attempts
// never reach `who`, so we have to parse the raw log.
//
// File handling: open at end (we don't replay history on first start), poll
// for new bytes, and reopen on inode change (logrotate or copytruncate).
type AuthLogCollector struct {
	storage  *Storage
	paths    []string
	interval time.Duration
	health   *HealthMonitor
	state    *stateStore

	f     *os.File
	inode uint64
	path  string
}

func (c *AuthLogCollector) Start(ctx context.Context, wg *sync.WaitGroup) {
	runCollector(ctx, wg, "authlog", c.storage, c.loop)
}

// pickPath returns the first existing path from the configured candidates.
// /var/log/auth.log on Debian/Ubuntu, /var/log/secure on RHEL/CentOS/Fedora.
func (c *AuthLogCollector) pickPath() string {
	for _, p := range c.paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (c *AuthLogCollector) openTail(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	c.path = path
	c.inode = inodeOf(f)

	// Resume from last known position if we have one for this file/inode.
	// Otherwise seek to end so we don't replay history on first start.
	if c.state != nil {
		var st stateAuthLog
		if err := c.state.Load("authlog", &st); err == nil &&
			st.Path == path && st.Inode == c.inode && st.Pos > 0 {
			if _, err := f.Seek(st.Pos, io.SeekStart); err != nil {
				f.Close()
				return err
			}
			c.f = f
			return nil
		}
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return err
	}
	c.f = f
	return nil
}

func (c *AuthLogCollector) saveState() {
	if c.state == nil || c.f == nil {
		return
	}
	pos, err := c.f.Seek(0, io.SeekCurrent)
	if err != nil {
		return
	}
	_ = c.state.Save("authlog", stateAuthLog{Path: c.path, Inode: c.inode, Pos: pos})
}

func (c *AuthLogCollector) loop(ctx context.Context) {
	tick := time.NewTicker(c.interval)
	defer tick.Stop()
	checkpoint := time.NewTicker(time.Minute)
	defer checkpoint.Stop()
	for {
		c.health.Beat("authlog")
		select {
		case <-ctx.Done():
			c.saveState()
			if c.f != nil {
				c.f.Close()
			}
			return
		case <-checkpoint.C:
			c.saveState()
		case <-tick.C:
		}

		if c.f == nil {
			p := c.pickPath()
			if p == "" {
				continue
			}
			if err := c.openTail(p); err != nil {
				c.storage.Write("errors", map[string]any{
					"collector": "authlog", "error": err.Error(),
				})
				continue
			}
			c.storage.Write("meta", map[string]any{
				"event": "authlog_tail_started", "path": p,
			})
		}

		// Detect rotation: same path now points at a different inode.
		if st, err := os.Stat(c.path); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok && uint64(sys.Ino) != c.inode {
				c.f.Close()
				c.f = nil
				continue
			}
		}

		r := bufio.NewReader(c.f)
		for {
			line, err := r.ReadString('\n')
			if line != "" {
				if ev := parseAuthLine(line); ev != nil {
					c.storage.Write("auth", ev)
				}
			}
			if err != nil {
				break
			}
		}
	}
}

func inodeOf(f *os.File) uint64 {
	st, err := f.Stat()
	if err != nil {
		return 0
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return uint64(sys.Ino)
	}
	return 0
}

// Patterns are deliberately permissive about the syslog prefix (timestamp,
// hostname, program[pid]:) — distros and journald format it differently. We
// anchor on the recognisable phrase ("Accepted password for", "sudo:    user
// :", etc.) and pull fields out of what follows.
var (
	reSSHAccepted = regexp.MustCompile(`sshd\[\d+\]:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)
	reSSHFailed   = regexp.MustCompile(`sshd\[\d+\]:\s+Failed\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)
	reSSHInvalid  = regexp.MustCompile(`sshd\[\d+\]:\s+Invalid user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)
	reSSHDisconn  = regexp.MustCompile(`sshd\[\d+\]:\s+Disconnected from(?: user\s+(\S+))?\s+(\S+)\s+port\s+(\d+)`)
	reSudoCmd     = regexp.MustCompile(`sudo:\s+(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)$`)
	reSudoFail    = regexp.MustCompile(`sudo:\s+pam_unix\(sudo:auth\):\s+authentication failure;.*?(?:user|ruser)=(\S+)`)
	reSuOpen      = regexp.MustCompile(`su(?:\[\d+\])?:\s+pam_unix\(su(?:-l)?:session\):\s+session opened for user\s+(\S+)\s+by\s+(\S+?)(?:\(uid=\d+\))?$`)
	reSuFailed    = regexp.MustCompile(`su(?:\[\d+\])?:\s+FAILED SU\s+\(to\s+(\S+)\)\s+(\S+)\s+on\s+(\S+)`)

	// Local-account lifecycle events. shadow-utils logs these on
	// every distro that uses the standard tooling. Without these
	// patterns, an operator who runs `useradd attacker` sees
	// nothing in `auth/` — only a generic process event from the
	// process collector — which is the s2 manual-test complaint:
	// "the simplesiem did log a new user, but using triage does
	// not reflect what happened, only that root started a process".
	reUserAdd     = regexp.MustCompile(`useradd\[\d+\]:\s+new user:\s+name=(\S+?),\s+UID=(\d+),\s+GID=(\d+)(?:,\s+home=(\S+?))?(?:,\s+shell=(\S+))?`)
	reUserAddGrp  = regexp.MustCompile(`useradd\[\d+\]:\s+add\s+'(\S+?)'\s+to\s+group\s+'(\S+?)'`)
	reUserDel     = regexp.MustCompile(`userdel\[\d+\]:\s+delete user\s+'(\S+?)'`)
	reUserMod     = regexp.MustCompile(`usermod\[\d+\]:\s+(?:change user\s+'(\S+?)'\s+(\S.+)|add\s+'(\S+?)'\s+to\s+group\s+'(\S+?)')`)
	reGroupAdd    = regexp.MustCompile(`groupadd\[\d+\]:\s+new group:\s+name=(\S+?),\s+GID=(\d+)`)
	reGroupDel    = regexp.MustCompile(`groupdel\[\d+\]:\s+group\s+'(\S+?)'\s+removed`)
	rePasswd      = regexp.MustCompile(`passwd\[\d+\]:\s+pam_unix\(passwd:chauthtok\):\s+password changed for\s+(\S+)`)
	reChsh        = regexp.MustCompile(`chsh\[\d+\]:\s+changed user\s+'(\S+?)'\s+shell to\s+'(\S+?)'`)
)

// parseAuthLine matches a single syslog line against the supported patterns
// and returns a structured event, or nil if nothing matched. Returning nil
// is the common case (most auth.log lines are noise we don't care about).
func parseAuthLine(line string) map[string]any {
	if m := reSSHAccepted.FindStringSubmatch(line); m != nil {
		return map[string]any{
			"event": "ssh_login", "method": m[1], "user": m[2],
			"remote": m[3], "port": m[4], "result": "success",
		}
	}
	if m := reSSHFailed.FindStringSubmatch(line); m != nil {
		return map[string]any{
			"event": "ssh_login", "method": m[1], "user": m[2],
			"remote": m[3], "port": m[4], "result": "failed",
		}
	}
	if m := reSSHInvalid.FindStringSubmatch(line); m != nil {
		return map[string]any{
			"event": "ssh_login", "user": m[1],
			"remote": m[2], "port": m[3], "result": "invalid_user",
		}
	}
	if m := reSSHDisconn.FindStringSubmatch(line); m != nil {
		return map[string]any{
			"event": "ssh_disconnect", "user": m[1],
			"remote": m[2], "port": m[3],
		}
	}
	if m := reSudoCmd.FindStringSubmatch(line); m != nil {
		return map[string]any{
			"event": "sudo", "user": m[1], "terminal": m[2],
			"pwd": m[3], "target": m[4], "command": m[5], "result": "ok",
		}
	}
	if m := reSudoFail.FindStringSubmatch(line); m != nil {
		return map[string]any{
			"event": "sudo", "user": m[1], "result": "failed",
		}
	}
	if m := reSuOpen.FindStringSubmatch(line); m != nil {
		return map[string]any{
			"event": "su", "target": m[1], "user": m[2], "result": "ok",
		}
	}
	if m := reSuFailed.FindStringSubmatch(line); m != nil {
		return map[string]any{
			"event": "su", "target": m[1], "user": m[2],
			"terminal": m[3], "result": "failed",
		}
	}
	if m := reUserAdd.FindStringSubmatch(line); m != nil {
		ev := map[string]any{
			"event": "user_added", "user": m[1], "uid": m[2], "gid": m[3],
		}
		if m[4] != "" {
			ev["home"] = m[4]
		}
		if m[5] != "" {
			ev["shell"] = m[5]
		}
		return ev
	}
	if m := reUserAddGrp.FindStringSubmatch(line); m != nil {
		return map[string]any{
			"event": "user_added_to_group", "user": m[1], "group": m[2],
		}
	}
	if m := reUserDel.FindStringSubmatch(line); m != nil {
		return map[string]any{"event": "user_deleted", "user": m[1]}
	}
	if m := reUserMod.FindStringSubmatch(line); m != nil {
		// Two alternation branches; pick whichever captured.
		if m[1] != "" {
			return map[string]any{
				"event": "user_modified", "user": m[1], "change": m[2],
			}
		}
		return map[string]any{
			"event": "user_added_to_group", "user": m[3], "group": m[4],
		}
	}
	if m := reGroupAdd.FindStringSubmatch(line); m != nil {
		return map[string]any{"event": "group_added", "group": m[1], "gid": m[2]}
	}
	if m := reGroupDel.FindStringSubmatch(line); m != nil {
		return map[string]any{"event": "group_deleted", "group": m[1]}
	}
	if m := rePasswd.FindStringSubmatch(line); m != nil {
		return map[string]any{"event": "password_changed", "user": m[1]}
	}
	if m := reChsh.FindStringSubmatch(line); m != nil {
		return map[string]any{
			"event": "user_shell_changed", "user": m[1], "shell": m[2],
		}
	}
	return nil
}
