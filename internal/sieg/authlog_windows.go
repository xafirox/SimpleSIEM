//go:build windows

package sieg

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// AuthLogCollector on Windows reads the Security event log via the
// built-in `wevtutil.exe qe Security` subprocess. Polls every
// auth_log_interval seconds for events with RecordId greater than
// the last one we've seen, filters to the logon + account-management
// EventIDs, and emits each one to the auth log type with a shape
// matching the Linux/macOS auth events.
//
// Logon-relevant EventIDs:
//
//	4624 — successful logon
//	4625 — failed logon
//	4634 — logoff
//	4672 — special privileges assigned (admin login signal)
//
// Account-management EventIDs (canonical names match the Linux
// authlog parser so a rule written for Linux works unchanged on
// Windows — the s2 manual-test fix):
//
//	4720 — user_added                (a user account was created)
//	4722 — user_enabled              (a user account was enabled)
//	4724 — password_changed          (password reset attempt)
//	4725 — user_disabled             (a user account was disabled)
//	4726 — user_deleted              (a user account was deleted)
//	4738 — user_modified             (a user account was changed)
//	4781 — user_renamed              (the name of an account was changed)
//	4732 — user_added_to_group       (member added to local group)
//	4733 — user_removed_from_group   (member removed from local group)
//	4727 — group_added               (security-enabled global group created)
//	4730 — group_deleted             (security-enabled global group deleted)
//	4731 — local_group_added         (security-enabled local group created)
//	4734 — local_group_deleted       (security-enabled local group deleted)
//
// Why wevtutil instead of a native EvtSubscribe call: wevtutil ships
// with every Windows version since Vista, doesn't need a DLL load,
// and the XML output is easy to parse with Go's stdlib. EvtSubscribe
// would be lower-latency and more efficient but requires winapi
// machinery not currently in the project's dependency graph. The
// poll approach matches the auth_log_interval the existing config
// already exposes (default 2s) so live latency is comparable to
// the Linux fsnotify path.
//
// Permissions: wevtutil reading Security requires the account to
// have "Manage auditing and security log" (SeSecurityPrivilege).
// SimpleSIEM's Windows service runs as LocalSystem by default which
// has this privilege; lower-privilege deployments need to add the
// service account explicitly via Group Policy or `secedit`.
type AuthLogCollector struct {
	storage  *Storage
	paths    []string // unused on Windows; kept for cross-platform struct compat
	interval time.Duration
	health   *HealthMonitor
	state    *stateStore
}

func (c *AuthLogCollector) Start(ctx context.Context, wg *sync.WaitGroup) {
	runCollector(ctx, wg, "authlog", c.storage, c.loop)
}

func (c *AuthLogCollector) loop(ctx context.Context) {
	const (
		stateName    = "authlog_windows"
		warnUnusable = "authlog_windows_unsupported"
	)
	// Probe wevtutil once at startup. If it isn't on PATH or it can't
	// read Security, log once and idle so the collector heartbeat
	// doesn't trip silent-collector alerts.
	if _, err := exec.LookPath("wevtutil.exe"); err != nil {
		c.storage.Write("meta", map[string]any{
			"event":  warnUnusable,
			"reason": "wevtutil.exe not on PATH",
		})
		idleHeartbeat(ctx, c.health)
		return
	}

	// Resume from the last recorded RecordId so a daemon restart
	// doesn't replay the entire Security log. On first run lastID
	// stays 0 — an unbounded first poll would be expensive, so we
	// initialise from "now" by asking wevtutil for the most recent
	// event's RecordId and seeding lastID from there.
	lastID := uint64(0)
	var resumed stateAuthLogWin
	if c.state != nil && c.state.Load(stateName, &resumed) == nil && resumed.LastRecordID > 0 {
		lastID = resumed.LastRecordID
	} else if id, err := wevtMostRecentID(); err == nil {
		lastID = id
	}

	interval := c.interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		c.health.Beat("authlog")
		newID, err := c.pollOnce(lastID)
		if err != nil {
			c.storage.Write("errors", map[string]any{
				"collector": "authlog",
				"error":     err.Error(),
			})
		} else if newID > lastID {
			lastID = newID
			if c.state != nil {
				_ = c.state.Save(stateName, stateAuthLogWin{LastRecordID: lastID})
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// idleHeartbeat keeps the collector marked alive when the runtime
// path isn't available (no wevtutil). Mirrors the previous stub.
func idleHeartbeat(ctx context.Context, h *HealthMonitor) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		h.Beat("authlog")
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pollOnce reads new Security events with RecordId > sinceID and
// emits them. Returns the highest RecordId seen so the caller can
// persist it. On any wevtutil failure returns the error and an
// unchanged sinceID; the caller logs once.
func (c *AuthLogCollector) pollOnce(sinceID uint64) (uint64, error) {
	// XPath query: Security channel, the four logon-relevant EventIDs,
	// RecordId greater than the watermark. /c limits the burst per
	// poll so a stale watermark on a chatty domain controller can't
	// flood a single pollOnce. /rd:false (chronological) so we emit
	// oldest-first.
	xpath := fmt.Sprintf(
		`*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4672`+
			` or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4725`+
			` or EventID=4726 or EventID=4738 or EventID=4781`+
			` or EventID=4732 or EventID=4733`+
			` or EventID=4727 or EventID=4730 or EventID=4731 or EventID=4734)`+
			` and (EventRecordID>%d)]]`,
		sinceID)
	cmd := exec.Command("wevtutil.exe", "qe", "Security",
		"/q:"+xpath,
		"/c:200",
		"/rd:false",
		"/f:RenderedXml")
	out, err := cmd.Output()
	if err != nil {
		return sinceID, fmt.Errorf("wevtutil: %w", err)
	}
	maxSeen := sinceID
	for _, blob := range splitWevtutilEvents(string(out)) {
		ev, recID, ok := parseWindowsAuthEvent(blob)
		if !ok {
			continue
		}
		c.storage.Write("auth", ev)
		if recID > maxSeen {
			maxSeen = recID
		}
	}
	return maxSeen, nil
}

// splitWevtutilEvents extracts complete <Event>...</Event> blobs from
// the wevtutil /f:RenderedXml byte stream. wevtutil mostly emits one
// Event per line, but some EventData fields (notably 4720's
// UserAccountControl) contain embedded newlines, which would split
// a single Event across multiple lines under a naive `strings.Split`.
// Scanning for the explicit `</Event>` close tag keeps each event
// intact regardless of internal whitespace.
func splitWevtutilEvents(raw string) []string {
	var out []string
	rest := raw
	for {
		startIdx := strings.Index(rest, "<Event")
		if startIdx < 0 {
			return out
		}
		endIdx := strings.Index(rest[startIdx:], "</Event>")
		if endIdx < 0 {
			return out
		}
		end := startIdx + endIdx + len("</Event>")
		out = append(out, rest[startIdx:end])
		rest = rest[end:]
	}
}

// wevtMostRecentID returns the RecordId of the newest Security
// event, used to seed the watermark on first daemon startup.
func wevtMostRecentID() (uint64, error) {
	cmd := exec.Command("wevtutil.exe", "qe", "Security",
		"/c:1", "/rd:true", "/f:RenderedXml")
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	for _, blob := range splitWevtutilEvents(string(out)) {
		_, recID, ok := parseWindowsAuthEvent(blob)
		if ok {
			return recID, nil
		}
	}
	return 0, nil
}

// windowsEventXML mirrors the subset of the wevtutil /f:RenderedXml
// output we care about. Schema reference:
// https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-elements
type windowsEventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID       int    `xml:"EventID"`
		EventRecordID uint64 `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name string `xml:"Name,attr"`
			Val  string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// parseWindowsAuthEvent decodes one <Event>…</Event> blob into the
// shape SimpleSIEM uses for auth events on Linux/macOS. Returns
// (event, recordID, ok). ok=false on malformed XML.
func parseWindowsAuthEvent(rawXML string) (map[string]any, uint64, bool) {
	var doc windowsEventXML
	if err := xml.Unmarshal([]byte(rawXML), &doc); err != nil {
		return nil, 0, false
	}
	// Map each EventID to a canonical event name that matches the
	// Linux/macOS auth-log shape. Normalising the name here means
	// rules written for the Linux schema work unchanged on Windows
	// AND triage's eventSummary cases (added in the s2 fix) light
	// up uniformly across platforms.
	var eventName string
	switch doc.System.EventID {
	// Logon lifecycle
	case 4624:
		eventName = "auth_success"
	case 4625:
		eventName = "auth_failed"
	case 4634:
		eventName = "auth_logout"
	case 4672:
		eventName = "auth_admin_assigned"
	// Account lifecycle (matches the Linux event-name vocabulary
	// from authlog_linux.go so triage's eventSummary cases render
	// `user_added alice uid=... ...` on Windows too).
	case 4720:
		eventName = "user_added"
	case 4722:
		eventName = "user_enabled"
	case 4724:
		eventName = "password_changed"
	case 4725:
		eventName = "user_disabled"
	case 4726:
		eventName = "user_deleted"
	case 4738:
		eventName = "user_modified"
	case 4781:
		eventName = "user_renamed"
	case 4732:
		eventName = "user_added_to_group"
	case 4733:
		eventName = "user_removed_from_group"
	case 4727, 4731:
		eventName = "group_added"
	case 4730, 4734:
		eventName = "group_deleted"
	default:
		return nil, doc.System.EventRecordID, false
	}
	// Pull the operator-relevant fields out of EventData. The full
	// EventData is verbose (15-25 named fields per logon); we keep
	// the same subset rules can match against on every platform:
	// user, source IP, mechanism.
	data := map[string]string{}
	for _, d := range doc.EventData.Data {
		data[strings.ToLower(d.Name)] = strings.TrimSpace(d.Val)
	}
	out := map[string]any{
		"event":          eventName,
		"event_id":       doc.System.EventID,
		"record_id":      doc.System.EventRecordID,
		"computer":       doc.System.Computer,
		"provider":       doc.System.Provider.Name,
		"user":           firstNonEmpty(data["targetusername"], data["subjectusername"]),
		"domain":         firstNonEmpty(data["targetdomainname"], data["subjectdomainname"]),
		"logon_type":     data["logontype"],
		"source_ip":      data["ipaddress"],
		"workstation":    data["workstationname"],
		"failure_reason": data["failurereason"],
	}
	// Account-management events carry the actor on SubjectUserName
	// (the admin who ran the change) and the target on
	// TargetUserName/MemberName. Surface both — the Linux parser
	// only knows the target, but Windows audit gives us the actor
	// for free, so we keep it as `actor` for richer triage rows.
	switch doc.System.EventID {
	case 4720, 4722, 4724, 4725, 4726, 4738, 4781:
		// User-account events: target is the user being changed.
		if v := data["targetusername"]; v != "" {
			out["user"] = v
		}
		if v := data["subjectusername"]; v != "" {
			out["actor"] = v
		}
	case 4732, 4733:
		// Group-membership: TargetUserName is the GROUP, MemberName
		// (or MemberSid resolved out-of-band) is the user being
		// added/removed. Map onto the Linux schema so eventSummary's
		// `user_added_to_group` case renders correctly.
		out["group"] = data["targetusername"]
		if mn := data["membername"]; mn != "" {
			out["user"] = mn
		} else if ms := data["membersid"]; ms != "" {
			out["user"] = ms
		}
		if v := data["subjectusername"]; v != "" {
			out["actor"] = v
		}
	case 4727, 4730, 4731, 4734:
		// Group lifecycle: TargetUserName carries the group name.
		out["group"] = data["targetusername"]
		if v := data["subjectusername"]; v != "" {
			out["actor"] = v
		}
	}
	if ts := doc.System.TimeCreated.SystemTime; ts != "" {
		// SystemTime is ISO-8601 with high-precision fraction; pass
		// through as-is. Storage stamps its own canonical ts at
		// write time if missing.
		out["windows_event_time"] = ts
	}
	return out, doc.System.EventRecordID, true
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
