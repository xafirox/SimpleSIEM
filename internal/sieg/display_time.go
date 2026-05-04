package sieg

import (
	"fmt"
	"time"
)

// displayTS returns t in the host's local time zone for human display.
// Storage, wire format, and on-disk filenames remain UTC; this is purely
// a formatting hop on the way to the operator's terminal.
//
// Cross-platform: time.Local is populated automatically by the Go
// runtime from the host OS — zoneinfo on macOS/Linux, the Windows
// registry on Windows — so this works on Mac, Windows, and Linux with
// no platform-specific code.
func displayTS(t time.Time) time.Time { return t.In(time.Local) }

// displayTZ returns the short zone abbreviation for the host's local
// time zone (e.g. "EDT", "PST", "UTC"). Used in CLI headers so the
// operator can tell at a glance which zone the rendered times belong
// to. Falls back to a numeric offset like "+05:30" when the runtime
// can't supply an abbreviation (rare on Windows for certain custom
// zones).
func displayTZ() string {
	name, off := time.Now().Zone()
	if name != "" {
		return name
	}
	sign := "+"
	if off < 0 {
		sign = "-"
		off = -off
	}
	h := off / 3600
	m := (off % 3600) / 60
	if m == 0 {
		return sign + itoa2(h)
	}
	return sign + itoa2(h) + ":" + itoa2(m)
}

func itoa2(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// formatLatest renders a freshness column for the `status` table. The
// caller passes the file mtime (UTC-stored, but compared against now)
// and the current wall clock; output uses the host's local time zone
// and a "(N ago)" tail so the operator can immediately tell whether
// logging is current or has stalled.
//
//	same calendar day     -> "15:42:11 (2m 14s ago)"
//	earlier calendar day  -> "2026-04-29 09:30:21 (2d 6h ago)"
//
// A zero mtime collapses to "-" so callers don't need a guard.
func formatLatest(mtime, now time.Time) string {
	if mtime.IsZero() {
		return "-"
	}
	local := mtime.In(time.Local)
	nowLocal := now.In(time.Local)
	ago := humanAgo(now.Sub(mtime))
	if local.Year() == nowLocal.Year() && local.YearDay() == nowLocal.YearDay() {
		return fmt.Sprintf("%s (%s ago)", local.Format("15:04:05"), ago)
	}
	return fmt.Sprintf("%s (%s ago)", local.Format("2006-01-02 15:04:05"), ago)
}

// humanAgo formats a positive duration with second-level granularity for
// short intervals, stepping up to coarser units as the duration grows.
// Designed for "freshness" indicators in `status` output where the
// operator needs to tell at a glance whether logging stalled an hour
// ago vs. five seconds ago.
//
//	< 1m  -> "12s"
//	< 1h  -> "5m 12s"  (or "5m" when seconds == 0)
//	< 1d  -> "3h 12m"  (or "3h")
//	>= 1d -> "2d 3h"   (or "2d")
//
// Negative durations (clock skew, future timestamps) collapse to "0s".
func humanAgo(d time.Duration) string {
	if d < 0 {
		return "0s"
	}
	secs := int(d.Seconds())
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	mins := secs / 60
	secs %= 60
	if mins < 60 {
		if secs == 0 {
			return fmt.Sprintf("%dm", mins)
		}
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	hours := mins / 60
	mins %= 60
	if hours < 24 {
		if mins == 0 {
			return fmt.Sprintf("%dh", hours)
		}
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	days := hours / 24
	hours %= 24
	if hours == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd %dh", days, hours)
}
