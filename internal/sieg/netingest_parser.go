package sieg

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Generic RFC 5424 + RFC 3164 syslog parser. Pass 1 only extracts
// envelope fields (priority, severity, facility, timestamp, host,
// app-name, msg). Per-vendor structured-field extraction is pass 2.

type syslogFrame struct {
	RawMessage string
	Priority   int
	Facility   int
	Severity   int
	Timestamp  string // RFC3339 if parseable
	Hostname   string
	AppName    string
	ProcID     string
	MsgID      string
	Message    string
	Vendor     string // resolved by detectVendorFromFrame()
}

// rfc5424Re matches: <PRI>VERSION TIMESTAMP HOSTNAME APP PROCID MSGID [STRUCTURED-DATA] MSG
// We accept an optional version digit + the leading `1 ` per RFC 5424.
var rfc5424Re = regexp.MustCompile(
	`^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$`)

// rfc3164Re matches: <PRI>MMM dd HH:MM:SS HOSTNAME [TAG] MSG (BSD style).
var rfc3164Re = regexp.MustCompile(
	`^<(\d{1,3})>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$`)

// parseSyslog returns a best-effort decoded frame. A parse failure
// still produces a syslogFrame with RawMessage populated and the
// minimum metadata extracted, so rules that match on regex still work.
func parseSyslog(raw string) syslogFrame {
	raw = strings.TrimRight(raw, "\r\n\x00")
	f := syslogFrame{RawMessage: raw, Message: raw}
	// Try RFC 5424 first.
	if m := rfc5424Re.FindStringSubmatch(raw); m != nil {
		pri, _ := strconv.Atoi(m[1])
		f.Priority = pri
		f.Facility = pri / 8
		f.Severity = pri % 8
		f.Timestamp = normaliseRFC5424Timestamp(m[2])
		f.Hostname = blankNil(m[3])
		f.AppName = blankNil(m[4])
		f.ProcID = blankNil(m[5])
		f.MsgID = blankNil(m[6])
		// m[7] = STRUCTURED-DATA + space + MSG. Strip [...] groups.
		rest := m[7]
		rest = stripStructuredData(rest)
		f.Message = strings.TrimSpace(rest)
		f.Vendor = detectVendorFromFrame(raw)
		return f
	}
	if m := rfc3164Re.FindStringSubmatch(raw); m != nil {
		pri, _ := strconv.Atoi(m[1])
		f.Priority = pri
		f.Facility = pri / 8
		f.Severity = pri % 8
		f.Timestamp = normaliseRFC3164Timestamp(m[2])
		f.Hostname = m[3]
		f.Message = strings.TrimSpace(m[4])
		// Try to split TAG from MSG by detecting "tag[pid]: " or "tag: "
		if idx := strings.Index(f.Message, ": "); idx > 0 && idx < 64 {
			f.AppName = stripBrackets(f.Message[:idx])
			f.Message = strings.TrimSpace(f.Message[idx+2:])
		}
		f.Vendor = detectVendorFromFrame(raw)
		return f
	}
	// Bare frames (no PRI prefix) are still ingested — the rule engine
	// can match on the raw message content.
	f.Vendor = detectVendorFromFrame(raw)
	return f
}

func blankNil(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// stripStructuredData removes RFC 5424 [SD-ELEMENT] groups from the
// front of the message component. Doesn't try to parse them — the
// generic parser leaves SD-PARAM extraction for vendor parsers.
func stripStructuredData(s string) string {
	s = strings.TrimLeft(s, " ")
	for strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			break
		}
		s = strings.TrimLeft(s[end+1:], " ")
	}
	return s
}

func stripBrackets(s string) string {
	if i := strings.Index(s, "["); i >= 0 {
		return s[:i]
	}
	return s
}

// normaliseRFC5424Timestamp accepts RFC 3339 or "-" and returns
// RFC3339Nano string (or empty).
func normaliseRFC5424Timestamp(s string) string {
	if s == "-" || s == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC().Format(time.RFC3339Nano)
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return s
}

func normaliseRFC3164Timestamp(s string) string {
	// "Jan  2 15:04:05" — no year. We back-fill with the current year
	// (BSD syslog always omits it).
	withYear := fmt.Sprintf("%d %s", time.Now().UTC().Year(), strings.ReplaceAll(s, "  ", " "))
	if t, err := time.Parse("2006 Jan 2 15:04:05", withYear); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return s
}

// severityWord maps RFC 5424 numeric severity to a word the rule
// engine and alerts pipeline expect. Mapped onto SimpleSIEM severity
// levels: critical (0..2), high (3), medium (4..5), low (6..7).
func severityWord(sev int) string {
	switch {
	case sev <= 2:
		return "critical"
	case sev == 3:
		return "high"
	case sev <= 5:
		return "medium"
	default:
		return "low"
	}
}

// frameToEvent converts a parsed frame plus envelope info into the
// SimpleSIEM event shape. The caller stamps `host` separately because
// it's the allowlist entry's label (NOT the syslog header host —
// devices lie about their hostname all the time).
func (f syslogFrame) toEventFields() map[string]any {
	return map[string]any{
		"event":            "syslog",
		"vendor":           f.Vendor,
		"severity":         severityWord(f.Severity),
		"syslog_priority":  f.Priority,
		"syslog_facility":  f.Facility,
		"syslog_severity":  f.Severity,
		"syslog_timestamp": f.Timestamp,
		"syslog_hostname":  f.Hostname,
		"app_name":         f.AppName,
		"proc_id":          f.ProcID,
		"msg_id":           f.MsgID,
		"message":          f.Message,
		"raw_message":      f.RawMessage,
	}
}
