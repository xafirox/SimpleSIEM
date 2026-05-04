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
// the last one we've seen, filters to the four logon-relevant
// EventIDs, and emits each one to the auth log type with a shape
// matching the Linux/macOS auth events.
//
// EventIDs:
//
//	4624 — successful logon
//	4625 — failed logon
//	4634 — logoff
//	4672 — special privileges assigned (admin login signal)
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
		`*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4672) and (EventRecordID>%d)]]`,
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
	// wevtutil returns one <Event>...</Event> per line for /f:RenderedXml.
	// We parse them one at a time so a single malformed entry doesn't
	// kill the whole batch.
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ev, recID, ok := parseWindowsAuthEvent(line)
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

// wevtMostRecentID returns the RecordId of the newest Security
// event, used to seed the watermark on first daemon startup.
func wevtMostRecentID() (uint64, error) {
	cmd := exec.Command("wevtutil.exe", "qe", "Security",
		"/c:1", "/rd:true", "/f:RenderedXml")
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_, recID, ok := parseWindowsAuthEvent(line)
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
	// Map the four EventIDs to canonical event names that match
	// the Linux auth-log shape. Normalising the name here means
	// rules written for the Linux schema work unchanged on Windows.
	var eventName string
	switch doc.System.EventID {
	case 4624:
		eventName = "auth_success"
	case 4625:
		eventName = "auth_failed"
	case 4634:
		eventName = "auth_logout"
	case 4672:
		eventName = "auth_admin_assigned"
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
		"event":         eventName,
		"event_id":      doc.System.EventID,
		"record_id":     doc.System.EventRecordID,
		"computer":      doc.System.Computer,
		"provider":      doc.System.Provider.Name,
		"user":          firstNonEmpty(data["targetusername"], data["subjectusername"]),
		"domain":        firstNonEmpty(data["targetdomainname"], data["subjectdomainname"]),
		"logon_type":    data["logontype"],
		"source_ip":     data["ipaddress"],
		"workstation":   data["workstationname"],
		"failure_reason": data["failurereason"],
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
