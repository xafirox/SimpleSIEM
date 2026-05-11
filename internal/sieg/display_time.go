package sieg

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// displayLocOnce caches the resolved display location across the life
// of the process. SIMPLESIEM_TZ is read once at first display call —
// changing it mid-process would require a restart, which matches how
// every other env var the daemon honours behaves.
var (
	displayLocOnce sync.Once
	displayLoc     *time.Location
)

// resolveDisplayLoc returns the location SimpleSIEM should use for
// human-facing time display. Priority:
//  1. SIMPLESIEM_TZ env var (operator override) — accepts any IANA
//     name like "America/New_York", "Europe/Berlin", or "UTC".
//  2. time.Local — Go's runtime resolution of the host's local zone
//     (zoneinfo on Mac/Linux, Windows registry on Windows).
//
// The override is the escape hatch for hosts whose system clock runs
// in UTC (containers, fresh Linux servers, CI). Without it those
// hosts would display every CLI timestamp in UTC even though the
// operator reads in their working zone — which is the s7 "alerts is
// not in local time" report.
func resolveDisplayLoc() *time.Location {
	displayLocOnce.Do(func() {
		if name := os.Getenv("SIMPLESIEM_TZ"); name != "" {
			if loc, err := time.LoadLocation(name); err == nil {
				displayLoc = loc
				return
			}
			// Bad SIMPLESIEM_TZ value: print a one-line warning to
			// stderr and fall back to time.Local. Done once per process
			// because of sync.Once, so we don't flood the terminal on
			// every CLI invocation that calls a display helper.
			fmt.Fprintf(os.Stderr, "warning: SIMPLESIEM_TZ=%q is not a valid IANA zone; falling back to host local time.\n", name)
		}
		displayLoc = time.Local
	})
	return displayLoc
}

// displayTS returns t in the configured display zone (SIMPLESIEM_TZ
// when set, host-local otherwise). Storage, wire format, and on-disk
// filenames remain UTC; this is purely a formatting hop on the way
// to the operator's terminal.
//
// Cross-platform: time.Local is populated automatically by the Go
// runtime from the host OS — zoneinfo on macOS/Linux, the Windows
// registry on Windows. Operators on UTC-clocked containers can set
// SIMPLESIEM_TZ to render everything in their preferred zone.
func displayTS(t time.Time) time.Time { return t.In(resolveDisplayLoc()) }

// displayTZ returns the short zone abbreviation for the configured
// display zone (e.g. "EDT", "PST", "UTC"). Used in CLI headers so
// the operator can tell at a glance which zone the rendered times
// belong to. Falls back to a numeric offset like "+05:30" when the
// runtime can't supply an abbreviation (rare on Windows for certain
// custom zones, common when SIMPLESIEM_TZ points at a fixed-offset
// zone).
func displayTZ() string {
	loc := resolveDisplayLoc()
	name, off := time.Now().In(loc).Zone()
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
	loc := resolveDisplayLoc()
	local := mtime.In(loc)
	nowLocal := now.In(loc)
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
