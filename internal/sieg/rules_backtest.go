package sieg

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// #5 — Rules backtest. Runs a draft rule against historical events
// in <log_dir>/<host>/<type>/*.jsonl[.gz], reports estimated fire
// rate. Performance: chunked walk, per-host parallelism, hard memory
// cap, progress on stderr every 5s.

type backtestResult struct {
	RuleName       string                  `json:"rule_name"`
	WindowSince    time.Time               `json:"window_since"`
	WindowUntil    time.Time               `json:"window_until"`
	EventsScanned  uint64                  `json:"events_scanned"`
	WalltimeSec    float64                 `json:"walltime_seconds"`
	Fires          int                     `json:"fires"`
	TopHosts       map[string]int          `json:"top_hosts"`
	SampleFires    []map[string]any        `json:"sample_fires"`
	ScanCapped     bool                    `json:"scan_capped,omitempty"`
}

// runRulesBacktestCmd dispatches `simplesiem rules backtest`.
func runRulesBacktestCmd(args []string) {
	args = permuteArgs(args, map[string]bool{
		"rule": true, "against": true, "max-events": true,
		"hosts": true, "max-memory-mb": true,
	})
	fs := flag.NewFlagSet("rules backtest", flag.ExitOnError)
	rulePath := fs.String("rule", "", "path to a single-rule JSON document to evaluate")
	against := fs.String("against", "30d", "history window: 30d, 24h, 5m, etc.")
	maxEvents := fs.Int64("max-events", 0, "soft cap on total events scanned (0 = unbounded)")
	hostsFilter := fs.String("hosts", "", "comma-separated host filter; default = all")
	maxMemMB := fs.Int("max-memory-mb", 256, "abort if memory exceeds this (default 256)")
	jsonOut := fs.Bool("json", false, "machine-readable output")
	_ = fs.Parse(args)
	if *rulePath == "" {
		fatalf("--rule is required (path to single-rule JSON)")
	}
	rule, err := loadSingleRule(*rulePath)
	if err != nil {
		fatalf("load rule: %v", err)
	}
	since, err := parseSince(*against)
	if err != nil {
		fatalf("--against %q: %v", *against, err)
	}
	cfg := loadConfig(defaultConfigPath())
	hosts := walkHostsForBacktest(cfg.LogDir, *hostsFilter)
	res := runBacktest(cfg.LogDir, hosts, rule, since, *maxEvents, *maxMemMB)
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(res)
		return
	}
	fmt.Printf("Rule:           %s\n", res.RuleName)
	fmt.Printf("Window:         %s → %s\n", res.WindowSince.Format(time.RFC3339), res.WindowUntil.Format(time.RFC3339))
	fmt.Printf("Events scanned: %d\n", res.EventsScanned)
	if res.ScanCapped {
		fmt.Println("                (--max-events cap reached)")
	}
	fmt.Printf("Walltime:       %.1fs\n", res.WalltimeSec)
	fmt.Printf("Fires:          %d\n", res.Fires)
	if len(res.TopHosts) > 0 {
		fmt.Println("Top hosts:")
		for h, n := range res.TopHosts {
			fmt.Printf("  %s    %d\n", h, n)
		}
	}
	if len(res.SampleFires) > 0 {
		fmt.Println("Sample fires (first 5):")
		for i, e := range res.SampleFires {
			if i >= 5 {
				break
			}
			b, _ := json.Marshal(e)
			fmt.Printf("  %s\n", b)
		}
	}
}

func loadSingleRule(path string) (*alertRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rules, err := parseRulesBytes(data)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules found in %s", path)
	}
	return rules[0], nil
}

func walkHostsForBacktest(logDir, filter string) []string {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil
	}
	var hosts []string
	wanted := map[string]bool{}
	if filter != "" {
		for _, h := range strings.Split(filter, ",") {
			wanted[strings.TrimSpace(h)] = true
		}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), "_") {
			continue
		}
		if filter != "" && !wanted[e.Name()] {
			continue
		}
		hosts = append(hosts, e.Name())
	}
	return hosts
}

func runBacktest(logDir string, hosts []string, rule *alertRule, since time.Time, maxEvents int64, maxMemMB int) backtestResult {
	start := time.Now()
	var scanned uint64
	var fires int
	var firesMu sync.Mutex
	topHosts := map[string]int{}
	var samples []map[string]any
	capped := atomic.Bool{}

	progress := time.NewTicker(5 * time.Second)
	defer progress.Stop()
	go func() {
		for range progress.C {
			fmt.Fprintf(os.Stderr, "  scanned %d events, %d fires so far\n", atomic.LoadUint64(&scanned), fires)
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if maxMemMB > 0 && ms.Alloc/(1024*1024) > uint64(maxMemMB) {
				fmt.Fprintf(os.Stderr, "  OOM cap reached (%d MB) — aborting\n", maxMemMB)
				capped.Store(true)
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for _, host := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			hostDir := filepath.Join(logDir, host)
			types, _ := os.ReadDir(hostDir)
			for _, t := range types {
				if !t.IsDir() || strings.HasPrefix(t.Name(), "_") {
					continue
				}
				typDir := filepath.Join(hostDir, t.Name())
				files, _ := os.ReadDir(typDir)
				for _, f := range files {
					if f.IsDir() {
						continue
					}
					if maxEvents > 0 && int64(atomic.LoadUint64(&scanned)) >= maxEvents {
						capped.Store(true)
						return
					}
					if capped.Load() {
						return
					}
					readBacktestFile(filepath.Join(typDir, f.Name()), t.Name(), host, rule, since, &scanned, &fires, &firesMu, topHosts, &samples)
				}
			}
		}(host)
	}
	wg.Wait()

	return backtestResult{
		RuleName: rule.Name, WindowSince: since, WindowUntil: time.Now().UTC(),
		EventsScanned: scanned, WalltimeSec: time.Since(start).Seconds(),
		Fires: fires, TopHosts: topHosts, SampleFires: samples,
		ScanCapped: capped.Load(),
	}
}

func readBacktestFile(path, logType, host string, rule *alertRule, since time.Time,
	scanned *uint64, fires *int, firesMu *sync.Mutex, topHosts map[string]int, samples *[]map[string]any) {

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return
		}
		defer gz.Close()
		r = gz
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		atomic.AddUint64(scanned, 1)
		var ev map[string]any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		// since-window cut: events before since are skipped
		if tsRaw, ok := ev["@timestamp"].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, tsRaw); err == nil && t.Before(since) {
				continue
			}
		}
		fire, _ := rule.shouldFire(logType, ev)
		if !fire {
			continue
		}
		firesMu.Lock()
		*fires++
		topHosts[host]++
		if len(*samples) < 5 {
			*samples = append(*samples, ev)
		}
		firesMu.Unlock()
	}
}
