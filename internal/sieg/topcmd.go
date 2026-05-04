package sieg

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// runTopCmd is the `simplesiem top --by <field> --since <window>`
// aggregation tool. It groups events by a single field, counts them,
// and prints the top-N rows sorted descending. Use case: ad-hoc
// threat hunting — "which IPs are talking to my fleet most?",
// "what processes are spawning most often?", etc., without writing
// a rule.
//
// Stateless reader: walks the same on-disk corpus that `query` does,
// no daemon-side state.
func runTopCmd(args []string) {
	args = permuteArgs(args, map[string]bool{
		"config": true, "since": true, "type": true, "host": true,
		"by": true, "limit": true, "format": true,
	})
	fs := flag.NewFlagSet("top", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	since := fs.String("since", "1h", "time window (1h, 30m, 7d, RFC3339)")
	typeFilter := fs.String("type", "", "log type (default: all)")
	hostFilter := fs.String("host", "", "in server / master mode, restrict to one agent ID")
	by := fs.String("by", "", "field to group by (e.g. source_ip, process, remote, user)")
	limit := fs.Int("limit", 10, "show top N rows")
	format := fs.String("format", "table", "output format: table (default), csv, tsv")
	_ = fs.Parse(args)

	if strings.TrimSpace(*by) == "" {
		fatalf("--by <field> is required (e.g. --by source_ip)")
	}
	switch *format {
	case "table", "csv", "tsv":
	default:
		fatalf("--format must be one of: table, csv, tsv")
	}
	start, err := parseSince(*since)
	if err != nil {
		fatalf("--since: %v", err)
	}
	cfg := loadConfig(*cfgPath)
	if _, err := os.Stat(cfg.LogDir); err != nil {
		fmt.Fprintln(os.Stderr, "no logs at", cfg.LogDir)
		return
	}
	end := time.Now().UTC()
	roots := searchRoots(cfg, *hostFilter)
	events := loadEventsInRangeMulti(roots, start, end, *typeFilter)

	counts := map[string]int{}
	for _, e := range events {
		v := strField(e.Data, *by)
		if v == "" {
			continue
		}
		counts[v]++
	}

	type row struct {
		value string
		count int
	}
	rows := make([]row, 0, len(counts))
	totalGrouped := 0
	for v, c := range counts {
		rows = append(rows, row{v, c})
		totalGrouped += c
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].value < rows[j].value
	})
	if *limit > 0 && len(rows) > *limit {
		rows = rows[:*limit]
	}

	switch *format {
	case "csv", "tsv":
		sep := ","
		if *format == "tsv" {
			sep = "\t"
		}
		fmt.Printf("%s%scount\n", csvEscape(*by, *format), sep)
		for _, r := range rows {
			fmt.Printf("%s%s%d\n", csvEscape(r.value, *format), sep, r.count)
		}
	default:
		fmt.Printf("Top %s — %s -> %s   (%s; %d events scanned, %d distinct values)\n",
			*by,
			displayTS(start).Format("2006-01-02 15:04:05"),
			displayTS(end).Format("2006-01-02 15:04:05"),
			displayTZ(), len(events), len(counts))
		if len(rows) == 0 {
			fmt.Println("(no events with this field in the window)")
			return
		}
		// Right-justify counts; left-justify values.
		maxVal := 0
		for _, r := range rows {
			if len(r.value) > maxVal {
				maxVal = len(r.value)
			}
		}
		if maxVal > 60 {
			maxVal = 60
		}
		for _, r := range rows {
			val := r.value
			if len(val) > maxVal {
				val = val[:maxVal-1] + "…"
			}
			fmt.Printf("  %-*s  %d\n", maxVal, val, r.count)
		}
	}
}
