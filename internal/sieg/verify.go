package sieg

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runVerify walks one or more daily log files and recomputes each event's
// _hash, comparing to the stored value. It also checks that _prev links
// each event to the previous one in the same file. Mismatches are reported
// per-line; the command exits non-zero if any are found, so cron/CI can
// surface tampering.
//
// The chain naturally resets at file boundaries (daily rotation, size
// rotation, daemon restart) — a verifier sees _prev go from a non-empty
// hash to "" and treats that as a new sub-chain start, not an error.
func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	typeFilter := fs.String("type", "", "verify only this log type (default: all)")
	dateStr := fs.String("date", "", "verify only this YYYY-MM-DD (default: yesterday + today)")
	all := fs.Bool("all", false, "verify every file under the log dir")
	verbose := fs.Bool("v", false, "print one line per file even when OK")
	hostFilter := fs.String("host", "", "in server mode, restrict to one agent ID")
	_ = fs.Parse(args)

	cfg := loadConfig(*cfgPath)
	base := cfg.LogDir
	if _, err := os.Stat(base); err != nil {
		fmt.Fprintln(os.Stderr, "no logs at", base)
		os.Exit(1)
	}

	types := defaultLogTypes
	if *typeFilter != "" {
		types = []string{*typeFilter}
	}

	var dateFilter time.Time
	if *dateStr != "" {
		t, err := time.Parse("2006-01-02", *dateStr)
		if err != nil {
			fatalf("--date: %v (use YYYY-MM-DD)", err)
		}
		dateFilter = t
	}

	totalFiles := 0
	totalEvents := 0
	totalMismatches := 0

	roots := searchRoots(cfg, *hostFilter)
	for _, t := range types {
		var paths []string
		for _, r := range roots {
			paths = append(paths, listLogFilesForType(r.base, t)...)
		}
		for _, p := range paths {
			d := dateFromLogName(filepath.Base(p))
			if !*all && !dateFilter.IsZero() && !d.Equal(dateFilter) {
				continue
			}
			if !*all && dateFilter.IsZero() {
				todayStr := time.Now().UTC().Format("2006-01-02")
				yStr := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
				ds := d.Format("2006-01-02")
				if ds != todayStr && ds != yStr {
					continue
				}
			}
			res := verifyFile(p)
			totalFiles++
			totalEvents += res.events
			totalMismatches += len(res.problems)
			if len(res.problems) == 0 {
				if *verbose {
					fmt.Printf("OK   %s (%d events)\n", relPath(base, p), res.events)
				}
				continue
			}
			fmt.Printf("FAIL %s (%d events, %d problems)\n", relPath(base, p), res.events, len(res.problems))
			for _, msg := range res.problems {
				fmt.Println("    ", msg)
			}
		}
	}

	fmt.Println()
	fmt.Printf("Verified %d files, %d events, %d problems.\n", totalFiles, totalEvents, totalMismatches)
	if totalMismatches > 0 {
		os.Exit(1)
	}
}

type verifyResult struct {
	events   int
	problems []string
}

func verifyFile(path string) verifyResult {
	res := verifyResult{}
	f, err := openLogReader(path)
	if err != nil {
		res.problems = append(res.problems, fmt.Sprintf("open: %v", err))
		return res
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	prevHash := ""
	expectedSeq := uint64(0)
	subChainStart := true
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			res.problems = append(res.problems, fmt.Sprintf("line %d: not JSON: %v", lineNo, err))
			continue
		}
		res.events++
		// _chain_skip lines are diagnostic events written by the
		// writer watchdog directly to disk (bypassing the chain) when
		// the writer goroutine is wedged. They have no _hash/_prev/
		// _seq because the watchdog can't safely race the writer for
		// the in-memory chain state. Skip without flagging — they're
		// non-events from the chain's perspective.
		if skip, _ := event["_chain_skip"].(bool); skip {
			continue
		}
		gotHash, _ := event["_hash"].(string)
		gotPrev, _ := event["_prev"].(string)
		gotSeq := uint64(0)
		if v, ok := event["_seq"].(float64); ok {
			gotSeq = uint64(v)
		}
		if gotHash == "" {
			res.problems = append(res.problems, fmt.Sprintf("line %d: missing _hash", lineNo))
			continue
		}
		// Recompute the chain hash. SimpleSIEM only writes SHA-384
		// chains; legacy SHA-256 was removed alongside the crypto
		// upgrade since the project has no production deployments
		// to preserve compatibility with.
		delete(event, "_hash")
		canon, err := json.Marshal(event)
		if err != nil {
			res.problems = append(res.problems, fmt.Sprintf("line %d: re-marshal: %v", lineNo, err))
			continue
		}
		if len(gotHash) != 96 {
			res.problems = append(res.problems, fmt.Sprintf("line %d: unrecognised _hash length %d (expected 96 — SHA-384 hex)", lineNo, len(gotHash)))
			continue
		}
		sum := sha512.Sum384(canon)
		want := hex.EncodeToString(sum[:])
		if want != gotHash {
			// Truncate for compactness, but defend against a hostile
			// tamperer who set _hash to a short string — without the
			// min-length cap, [:12] panics with index-out-of-range
			// on an attacker-controlled value.
			res.problems = append(res.problems, fmt.Sprintf("line %d: hash mismatch (have %s, want %s)", lineNo, shortHash(gotHash), shortHash(want)))
			continue
		}
		// Check _prev linkage. An empty _prev anywhere in the file
		// marks the start of a new sub-chain — file start, daemon
		// restart, or size rotation. We tolerate it and reset our
		// expectations to match the new chain. The hash recomputation
		// above already proved the line itself is intact; sub-chain
		// transitions move the chain forward, they don't invalidate it.
		if gotPrev == "" && !subChainStart {
			// Mid-file sub-chain reset (typically a daemon restart).
			// Reset our running expectations to the new sub-chain so
			// the rest of the file verifies against its own chain.
			prevHash = gotHash
			expectedSeq = gotSeq
			continue
		}
		if gotPrev != prevHash {
			res.problems = append(res.problems, fmt.Sprintf(
				"line %d: _prev mismatch (have %s, want %s)",
				lineNo, shortHash(gotPrev), shortHash(prevHash)))
		}
		// _seq should be monotonic within a sub-chain.
		if !subChainStart && gotSeq != expectedSeq+1 {
			res.problems = append(res.problems, fmt.Sprintf("line %d: _seq jumped (have %d, want %d)", lineNo, gotSeq, expectedSeq+1))
		}
		prevHash = gotHash
		expectedSeq = gotSeq
		subChainStart = false
	}
	if err := scanner.Err(); err != nil {
		res.problems = append(res.problems, fmt.Sprintf("scan: %v", err))
	}
	return res
}

func relPath(base, p string) string {
	if r, err := filepath.Rel(base, p); err == nil {
		return r
	}
	return p
}

func shortHash(h string) string {
	if h == "" {
		return "(empty)"
	}
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// fmtPercent kept here in case any later code wants it; suppresses
// "imported and not used" if other helpers shrink. Currently unused.
var _ = strings.HasPrefix
