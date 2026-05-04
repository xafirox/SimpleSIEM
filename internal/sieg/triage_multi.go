package sieg

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// loadEventsInRangeMulti calls loadEventsInRange across each search root
// and merges the results, sorted by timestamp. Server-mode events already
// carry a "host" field (set at receive time); for any event from a root
// with a non-empty host that lacks the field, we backfill it so timeline
// rendering is consistent.
func loadEventsInRangeMulti(roots []searchRoot, start, end time.Time, typeFilter string) []Event {
	var out []Event
	for _, r := range roots {
		events := loadEventsInRange(r.base, start, end, typeFilter)
		if r.host != "" {
			for i := range events {
				if events[i].Data == nil {
					events[i].Data = map[string]any{}
				}
				if _, ok := events[i].Data["host"]; !ok {
					events[i].Data["host"] = r.host
				}
			}
		}
		out = append(out, events...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS.Before(out[j].TS) })
	return out
}

func findPivotsMulti(roots []searchRoot, fileMatch string, pidMatch int, grep, typ string, maxN, days int) []Event {
	var out []Event
	for _, r := range roots {
		ev := findPivots(r.base, fileMatch, pidMatch, grep, typ, maxN, days)
		if r.host != "" {
			for i := range ev {
				if ev[i].Data == nil {
					ev[i].Data = map[string]any{}
				}
				if _, ok := ev[i].Data["host"]; !ok {
					ev[i].Data["host"] = r.host
				}
			}
		}
		out = append(out, ev...)
		if len(out) >= maxN {
			out = out[:maxN]
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS.Before(out[j].TS) })
	return out
}

// printTriageMulti is the multi-root analogue of printTriage. When any
// event in the window carries a "host" field, an extra column is rendered
// so multi-host timelines stay readable.
func printTriageMulti(roots []searchRoot, pivot Event, window time.Duration, typeFilter string) {
	start := pivot.TS.Add(-window)
	end := pivot.TS.Add(window)
	events := loadEventsInRangeMulti(roots, start, end, typeFilter)

	pivotHost := strField(pivot.Data, "host")
	pivotHeader := fmt.Sprintf("%s  [%s]  %s",
		displayTS(pivot.TS).Format(time.RFC3339), pivot.Type, eventSummary(pivot))
	if pivotHost != "" {
		pivotHeader = fmt.Sprintf("%s  [%s on %s]  %s",
			displayTS(pivot.TS).Format(time.RFC3339), pivot.Type, pivotHost, eventSummary(pivot))
	}
	fmt.Println("Pivot:  " + pivotHeader)
	fmt.Printf("Window: %s -> %s  (±%s, %s)\n",
		displayTS(start).Format("15:04:05"), displayTS(end).Format("15:04:05"), window, displayTZ())
	fmt.Println(strings.Repeat("-", 78))

	showHost := false
	for _, e := range events {
		if strField(e.Data, "host") != "" {
			showHost = true
			break
		}
	}

	pivotMatched := false

	// Coalesce runs of consecutive identical (type, summary, host) rows
	// into a single line with a "(×N over D)" suffix. Pivot rows and
	// alerts are always emitted in full so they're never hidden inside
	// a count. Any non-matching event in the middle flushes the pending
	// run before being emitted, so a different event surrounded by
	// repeats stays visible — repeats become "(×3) ... different ... (×5)"
	// rather than getting lost in a count.
	emit := func(e Event, marker, suffix string) {
		delta := formatDelta(e.TS.Sub(pivot.TS))
		summary := eventSummary(e)
		if e.Type == "alerts" {
			if sev := strField(e.Data, "severity"); sev != "" {
				if code := severityColor(sev); code != "" {
					summary = colorize(summary, code)
				}
			}
		}
		if showHost {
			h := strField(e.Data, "host")
			fmt.Printf("%s %s %s  %-12s %-9s  %s%s\n",
				marker, displayTS(e.TS).Format("15:04:05.000"), delta, h, e.Type, summary, suffix)
		} else {
			fmt.Printf("%s %s %s  %-9s  %s%s\n",
				marker, displayTS(e.TS).Format("15:04:05.000"), delta, e.Type, summary, suffix)
		}
		if triageExplain && e.Type == "alerts" {
			if reason := explainAlert(e.Data); reason != "" {
				fmt.Printf("        matched: %s\n", colorize(reason, colDim))
			}
		}
	}

	var (
		pendFirst   Event
		pendCount   int
		pendLastTS  time.Time
		pendKey     string // type + "|" + summary + "|" + host
	)
	flushPending := func() {
		if pendCount == 0 {
			return
		}
		suffix := ""
		if pendCount > 1 {
			span := pendLastTS.Sub(pendFirst.TS)
			if span > 0 {
				suffix = fmt.Sprintf("  (×%d over %s)", pendCount, formatSpan(span))
			} else {
				suffix = fmt.Sprintf("  (×%d)", pendCount)
			}
		}
		emit(pendFirst, "  ", suffix)
		pendCount = 0
	}
	keyFor := func(e Event, summary string) string {
		return e.Type + "|" + summary + "|" + strField(e.Data, "host")
	}

	for _, e := range events {
		summary := eventSummary(e)
		isPivot := !pivotMatched && e.TS.Equal(pivot.TS) && (pivot.Raw == "" || e.Raw == pivot.Raw)

		// Pivot and alerts are always emitted in full.
		if isPivot {
			flushPending()
			pivotMatched = true
			emit(e, ">>", "")
			continue
		}
		if e.Type == "alerts" {
			flushPending()
			emit(e, "  ", "")
			continue
		}

		k := keyFor(e, summary)
		if pendCount > 0 && k == pendKey {
			pendLastTS = e.TS
			pendCount++
			continue
		}
		flushPending()
		pendFirst = e
		pendKey = k
		pendLastTS = e.TS
		pendCount = 1
	}
	flushPending()
	if !pivotMatched && pivot.Type == "marker" {
		fmt.Printf(">> %s %s  %-9s  (pivot time; no event recorded here)\n",
			displayTS(pivot.TS).Format("15:04:05.000"), formatDelta(0), pivot.Type)
	}
	if len(events) == 0 {
		fmt.Println("  (no events in window)")
	}
}

// emitTriageJSONMulti is the JSON-output counterpart to printTriageMulti.
// Each emitted line is the original event JSON augmented with _delta_ms,
// _pivot, and (when set) the "host" field.
func emitTriageJSONMulti(roots []searchRoot, pivot Event, window time.Duration, typeFilter string) {
	start := pivot.TS.Add(-window)
	end := pivot.TS.Add(window)
	events := loadEventsInRangeMulti(roots, start, end, typeFilter)
	enc := json.NewEncoder(os.Stdout)
	for _, e := range events {
		out := make(map[string]any, len(e.Data)+2)
		for k, v := range e.Data {
			out[k] = v
		}
		out["_delta_ms"] = e.TS.Sub(pivot.TS).Milliseconds()
		if pivot.Raw != "" && e.Raw == pivot.Raw {
			out["_pivot"] = true
		}
		_ = enc.Encode(out)
	}
}
