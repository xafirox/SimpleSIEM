package sieg

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// passwdDiffer turns /etc/passwd, /etc/group, /etc/shadow file
// modifications into the same auth:user_added / auth:user_deleted
// / auth:group_added / auth:group_deleted events the
// AuthLogCollector emits from PAM messages and that
// emitUserMgmtInvocation emits from process_start.
//
// Why diff the file rather than rely on the process synthesizer:
//
//   - useradd / usermod / userdel often finish in ~100 ms — well
//     below the 2-second ProcessCollector default. Polling misses
//     them on hosts where CONFIG_CONNECTOR isn't compiled in (every
//     Docker Desktop kernel, plus stripped distro builds).
//   - Direct edits (`vi /etc/passwd`, `sed -i`, image-baking) never
//     spawn a useradd-style process at all.
//   - Catching the file change is a deterministic source of truth:
//     if a line was added, a user was added. If it was removed, the
//     user is gone.
//
// Cross-platform shape:
//   - Linux:   /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow
//   - macOS:   /etc/passwd, /private/etc/passwd, /etc/master.passwd,
//              /private/etc/master.passwd, /etc/group, /private/etc/group
//   - Windows: not applicable — accounts live in the SAM registry hive
//              which can't be tail/diffed from userspace. Existing
//              wevtutil-based AuthLogCollector covers Windows EventID
//              4720/4726 already.
//
// Implementation: in-memory cache of the last seen content keyed by
// path. On modify we read the new content, parse usernames, and
// diff the sets. Memory bound is small — even a host with 1000
// users keeps the cache under 100 KB.
type passwdDiffer struct {
	mu        sync.Mutex
	lastUsers map[string]map[string]string // path -> username -> shadow-line-hash (for shadow change detection)
	lastGroups map[string]map[string]string
}

func newPasswdDiffer() *passwdDiffer {
	return &passwdDiffer{
		lastUsers:  map[string]map[string]string{},
		lastGroups: map[string]map[string]string{},
	}
}

// recognise determines whether a path is one we should diff and,
// if so, what kind. Returns ("", "") to skip. The kind doubles as
// the hint we attach to emitted events so a triage reader sees
// "synthesised from /etc/passwd diff" not just a bare event.
func (d *passwdDiffer) recognise(path string) (kind, hint string) {
	base := strings.ToLower(filepath.Base(path))
	// Normalise Linux + macOS variants of the same file.
	switch base {
	case "passwd", "master.passwd":
		return "users", "diff of /etc/passwd-style file — useradd/userdel/direct edit"
	case "group":
		return "groups", "diff of /etc/group-style file — groupadd/groupdel/direct edit"
	case "shadow", "gshadow":
		return "shadow", "diff of /etc/shadow — password change for user(s)"
	}
	return "", ""
}

// observe is called by FileCollector right after a "created" or
// "modified" event for a path that recognise() approved. Returns
// the auth events to emit (caller stamps timestamps + writes them
// to the auth log type). On read failure or first sighting (no
// prior cache entry) returns nil — first sighting just seeds the
// cache so the NEXT modification produces a real diff.
func (d *passwdDiffer) observe(path string) []map[string]any {
	kind, hint := d.recognise(path)
	if kind == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch kind {
	case "users":
		return d.diffUsers(path, hint)
	case "groups":
		return d.diffGroups(path, hint)
	case "shadow":
		return d.diffShadow(path, hint)
	}
	return nil
}

// diffUsers handles /etc/passwd-style files. Each line is
// "username:x:uid:gid:gecos:home:shell". We index by username and
// remember the full line so a uid/gid/shell change is also
// detected as user_modified.
func (d *passwdDiffer) diffUsers(path, hint string) []map[string]any {
	cur, err := readPasswdLikeFile(path, 0)
	if err != nil {
		return nil
	}
	prev, hadPrev := d.lastUsers[path]
	d.lastUsers[path] = cur
	if !hadPrev {
		// First sighting after the daemon started watching this
		// path — seed cache, emit nothing. The daemon's own
		// startup mtime read shouldn't masquerade as a user_added
		// for every existing account.
		return nil
	}
	out := []map[string]any{}
	// Added: in cur, not in prev.
	for u, line := range cur {
		oldLine, existed := prev[u]
		if !existed {
			out = append(out, map[string]any{
				"event":       "user_added",
				"user":        u,
				"source":      "passwd_diff",
				"hint":        hint,
				"detail_path": path,
				"line":        redactPasswdLine(line),
			})
			continue
		}
		if oldLine != line {
			out = append(out, map[string]any{
				"event":       "user_modified",
				"user":        u,
				"source":      "passwd_diff",
				"hint":        hint,
				"detail_path": path,
				"old_line":    redactPasswdLine(oldLine),
				"new_line":    redactPasswdLine(line),
			})
		}
	}
	// Removed: in prev, not in cur.
	for u := range prev {
		if _, ok := cur[u]; ok {
			continue
		}
		out = append(out, map[string]any{
			"event":       "user_deleted",
			"user":        u,
			"source":      "passwd_diff",
			"hint":        hint,
			"detail_path": path,
		})
	}
	return out
}

// diffGroups handles /etc/group. Line shape:
//
//	groupname:x:gid:user1,user2,user3
//
// We track the group's name AND the comma-separated member list
// so a "alice added to sudo" edit produces a user_added_to_group
// event for each new member, not just a user_modified.
func (d *passwdDiffer) diffGroups(path, hint string) []map[string]any {
	cur, err := readPasswdLikeFile(path, 3) // members at field index 3
	if err != nil {
		return nil
	}
	prev, hadPrev := d.lastGroups[path]
	d.lastGroups[path] = cur
	if !hadPrev {
		return nil
	}
	out := []map[string]any{}
	for g, line := range cur {
		oldLine, existed := prev[g]
		if !existed {
			out = append(out, map[string]any{
				"event":       "group_added",
				"group":       g,
				"source":      "passwd_diff",
				"hint":        hint,
				"detail_path": path,
				"line":        line,
			})
			continue
		}
		if oldLine == line {
			continue
		}
		// Same group name, different content — diff the member
		// list. A new user in the comma list = user_added_to_group;
		// a removed user = user_removed_from_group.
		oldMembers := splitGroupMembers(oldLine)
		newMembers := splitGroupMembers(line)
		for m := range newMembers {
			if _, ok := oldMembers[m]; !ok && m != "" {
				out = append(out, map[string]any{
					"event":       "user_added_to_group",
					"user":        m,
					"group":       g,
					"source":      "passwd_diff",
					"hint":        hint,
					"detail_path": path,
				})
			}
		}
		for m := range oldMembers {
			if _, ok := newMembers[m]; !ok && m != "" {
				out = append(out, map[string]any{
					"event":       "user_removed_from_group",
					"user":        m,
					"group":       g,
					"source":      "passwd_diff",
					"hint":        hint,
					"detail_path": path,
				})
			}
		}
		// If the line changed but member list is the same, it's a
		// gid/name-edit — emit group_modified.
		if !sameStringSet(setKeys(oldMembers), setKeys(newMembers)) {
			// Already covered above.
		} else {
			out = append(out, map[string]any{
				"event":       "group_modified",
				"group":       g,
				"source":      "passwd_diff",
				"hint":        hint,
				"detail_path": path,
			})
		}
	}
	for g := range prev {
		if _, ok := cur[g]; ok {
			continue
		}
		out = append(out, map[string]any{
			"event":       "group_deleted",
			"group":       g,
			"source":      "passwd_diff",
			"hint":        hint,
			"detail_path": path,
		})
	}
	return out
}

// diffShadow handles /etc/shadow. We don't log the password hash —
// just emit a password_changed event for any line whose post-colon
// content changed. The previous content is hashed and remembered;
// we never write the hash itself to a log, so a SimpleSIEM event
// stream can't be replayed to recover credentials.
func (d *passwdDiffer) diffShadow(path, hint string) []map[string]any {
	cur, err := readPasswdLikeFile(path, -1) // -1 = hash the whole post-username segment
	if err != nil {
		return nil
	}
	prev, hadPrev := d.lastUsers[path]
	d.lastUsers[path] = cur
	if !hadPrev {
		return nil
	}
	out := []map[string]any{}
	for u, hashed := range cur {
		oldHashed, existed := prev[u]
		if !existed {
			continue // newly-added user is covered by /etc/passwd diff
		}
		if oldHashed != hashed {
			out = append(out, map[string]any{
				"event":       "password_changed",
				"user":        u,
				"source":      "passwd_diff",
				"hint":        hint,
				"detail_path": path,
			})
		}
	}
	return out
}

// readPasswdLikeFile reads a colon-delimited file (passwd / group /
// shadow style) into a map keyed by the first field (username or
// group name). Value is a stable representation of the rest of the
// line — for /etc/shadow we hash to avoid keeping cleartext password
// hashes in memory longer than the diff window. memberFieldIdx
// selects which field to keep verbatim:
//
//	-1 = hash the entire remainder (used for /etc/shadow)
//	 0 = full line minus the leading username
//	>0 = the indicated colon-separated field (used for groups)
func readPasswdLikeFile(path string, memberFieldIdx int) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		key := fields[0]
		var value string
		switch {
		case memberFieldIdx == -1:
			// Hash everything after the username — keeps the hash
			// out of memory. We only need to detect change.
			h := sha512.Sum384([]byte(strings.Join(fields[1:], ":")))
			value = hex.EncodeToString(h[:])
		case memberFieldIdx > 0 && memberFieldIdx < len(fields):
			value = line // keep full line for member diff
		default:
			value = line
		}
		out[key] = value
	}
	return out, sc.Err()
}

// splitGroupMembers parses the member field (4th colon-separated)
// of a /etc/group line into a set of usernames.
func splitGroupMembers(line string) map[string]struct{} {
	out := map[string]struct{}{}
	parts := strings.Split(line, ":")
	if len(parts) < 4 {
		return out
	}
	for _, m := range strings.Split(parts[3], ",") {
		m = strings.TrimSpace(m)
		if m != "" {
			out[m] = struct{}{}
		}
	}
	return out
}

func setKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// redactPasswdLine returns the line with the second colon-delimited
// field (the password slot, traditionally "x" but may be a literal
// hash on some legacy systems) replaced with "*". Defensive: a
// well-managed host puts hashes in /etc/shadow not /etc/passwd, but
// some embedded distros still inline them in /etc/passwd.
func redactPasswdLine(line string) string {
	fields := strings.SplitN(line, ":", 3)
	if len(fields) < 3 {
		return line
	}
	if fields[1] != "" && fields[1] != "x" && fields[1] != "*" {
		fields[1] = "*"
	}
	return strings.Join(fields, ":")
}
