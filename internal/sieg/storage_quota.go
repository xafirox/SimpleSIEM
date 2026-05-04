package sieg

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/disk"
)

// StorageConfig governs how aggressively SimpleSIEM monitors free space
// on the volume(s) holding event logs. WarnThreshold is the level at
// which `simplesiem status` starts displaying a yellow warning;
// HaltThreshold is the level at which the daemon stops accepting new
// writes (and tries to fail over to the next entry in
// FailoverLocations, if any).
//
// Both thresholds accept two formats:
//
//	"80%"        — used-space percentage. Triggered when a volume's
//	               used percentage meets or exceeds this value.
//	"1TB"        — free-space floor. Triggered when free space falls
//	               below this absolute size. Suffixes: B, KB, MB, GB,
//	               TB (decimal); KiB/MiB/GiB/TiB (binary). Whitespace
//	               between the number and the unit is allowed.
//
// FailoverLocations is an ordered list of secondary log directories
// the daemon will switch to (in order) when its currently-active
// location halts. Empty by default — single-location operation.
type StorageConfig struct {
	WarnThreshold     string   `json:"warn_threshold"`
	HaltThreshold     string   `json:"halt_threshold"`
	FailoverLocations []string `json:"failover_locations"`
}

// storageThreshold is the parsed form of a StorageConfig threshold
// string. Exactly one of UsedPercent or FreeBytes is non-zero.
type storageThreshold struct {
	UsedPercent float64
	FreeBytes   uint64
	Original    string
}

func (t storageThreshold) IsZero() bool {
	return t.UsedPercent == 0 && t.FreeBytes == 0
}

// parseStorageThreshold parses "80%", "1TB", "20 GB", "512MiB", etc.
// Empty input returns a zero-value threshold with no error so callers
// can treat it as "feature disabled" instead of having to track an
// extra error.
func parseStorageThreshold(s string) (storageThreshold, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return storageThreshold{}, nil
	}
	orig := s
	if strings.HasSuffix(s, "%") {
		num := strings.TrimSpace(strings.TrimSuffix(s, "%"))
		v, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return storageThreshold{}, fmt.Errorf("invalid percent threshold %q: %v", orig, err)
		}
		if v <= 0 || v > 100 {
			return storageThreshold{}, fmt.Errorf("percent threshold %q must be in (0, 100]", orig)
		}
		return storageThreshold{UsedPercent: v, Original: orig}, nil
	}
	bytes, err := parseByteSize(s)
	if err != nil {
		return storageThreshold{}, fmt.Errorf("invalid storage threshold %q: %v", orig, err)
	}
	if bytes == 0 {
		return storageThreshold{}, fmt.Errorf("storage threshold %q must be > 0", orig)
	}
	return storageThreshold{FreeBytes: bytes, Original: orig}, nil
}

// parseByteSize parses "1TB", "20GB", "512MiB", "1024" (raw bytes).
// Decimal units use base 1000, binary units (KiB/MiB/GiB/TiB) use base
// 1024 — matching how disk vendors and OSes label sizes respectively.
func parseByteSize(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	// Find the boundary between digits and unit.
	i := 0
	for i < len(s) && (s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	numPart := s[:i]
	unit := strings.TrimSpace(strings.ToLower(s[i:]))
	if numPart == "" {
		return 0, fmt.Errorf("no number in %q", s)
	}
	v, err := strconv.ParseFloat(numPart, 64)
	if err != nil {
		return 0, err
	}
	if v < 0 {
		return 0, fmt.Errorf("negative size %q", s)
	}
	var mul uint64
	switch unit {
	case "", "b", "byte", "bytes":
		mul = 1
	case "k", "kb":
		mul = 1000
	case "kib":
		mul = 1024
	case "m", "mb":
		mul = 1000 * 1000
	case "mib":
		mul = 1024 * 1024
	case "g", "gb":
		mul = 1000 * 1000 * 1000
	case "gib":
		mul = 1024 * 1024 * 1024
	case "t", "tb":
		mul = 1000 * 1000 * 1000 * 1000
	case "tib":
		mul = 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unknown size unit %q", unit)
	}
	return uint64(v * float64(mul)), nil
}

// volumeUsage is the snapshot returned by probeVolume.
type volumeUsage struct {
	Path        string
	Total       uint64
	Used        uint64
	Free        uint64
	UsedPercent float64
}

// probeVolume returns disk usage for the volume containing path. Wraps
// gopsutil's disk.Usage for cross-platform parity (statfs on macOS/Linux,
// GetDiskFreeSpaceEx on Windows). gopsutil takes care of resolving the
// path to its mount point.
//
// When path does not yet exist (a fresh install before the daemon has
// run), gopsutil returns ENOENT. The volume hosting it is the same as
// the deepest existing ancestor's volume, so we walk up the directory
// tree until disk.Usage succeeds. This lets `simplesiem status`
// report storage state even before the daemon has created log_dir.
func probeVolume(path string) (volumeUsage, error) {
	u, err := disk.Usage(path)
	for err != nil {
		parent := parentDir(path)
		if parent == path {
			return volumeUsage{}, err
		}
		path = parent
		u, err = disk.Usage(path)
	}
	return volumeUsage{
		Path:        path,
		Total:       u.Total,
		Used:        u.Used,
		Free:        u.Free,
		UsedPercent: u.UsedPercent,
	}, nil
}

// parentDir returns path's parent. Hand-rolled instead of filepath.Dir
// because Dir("/") returns "/" (good — terminates the walk) but
// Dir("C:\\") on Windows returns "C:\\" too — also good. The contract
// is "if there's no parent, return path unchanged so the caller's
// loop terminates."
func parentDir(path string) string {
	clean := filepath.Clean(path)
	parent := filepath.Dir(clean)
	if parent == clean {
		return path
	}
	return parent
}

// storageState is the high-level classification of a volume against the
// configured thresholds.
type storageState int

const (
	storageOK storageState = iota
	storageWarn
	storageHalt
)

// classifyVolume returns the worst state triggered by the volume's
// current usage. HaltThreshold takes precedence over WarnThreshold
// — a volume below the halt level is in HALT regardless of warn.
func classifyVolume(v volumeUsage, warn, halt storageThreshold) storageState {
	if matchesThreshold(v, halt) {
		return storageHalt
	}
	if matchesThreshold(v, warn) {
		return storageWarn
	}
	return storageOK
}

func matchesThreshold(v volumeUsage, t storageThreshold) bool {
	if t.IsZero() {
		return false
	}
	if t.UsedPercent > 0 {
		return v.UsedPercent >= t.UsedPercent
	}
	if t.FreeBytes > 0 {
		return v.Free <= t.FreeBytes
	}
	return false
}

// resolvedQuotas resolves the cfg's storage thresholds to parsed form,
// substituting defaults when missing.
type resolvedQuotas struct {
	Warn storageThreshold
	Halt storageThreshold
}

func resolveQuotas(cfg Config) resolvedQuotas {
	w := strings.TrimSpace(cfg.Storage.WarnThreshold)
	if w == "" {
		w = "80%"
	}
	h := strings.TrimSpace(cfg.Storage.HaltThreshold)
	if h == "" {
		h = "90%"
	}
	wp, _ := parseStorageThreshold(w)
	hp, _ := parseStorageThreshold(h)
	return resolvedQuotas{Warn: wp, Halt: hp}
}

// allStorageLocations returns every configured log directory: the
// primary log_dir followed by each FailoverLocations entry, in order.
// Used by read paths that need to union events across volumes and by
// the controller picking the next non-halted write target.
func allStorageLocations(cfg Config) []string {
	out := []string{cfg.LogDir}
	for _, loc := range cfg.Storage.FailoverLocations {
		loc = strings.TrimSpace(loc)
		if loc == "" || loc == cfg.LogDir {
			continue
		}
		out = append(out, loc)
	}
	return out
}

// pickInitialStorageLocation returns the first configured storage
// location that isn't already past the halt threshold at startup.
// Falls back to the primary log_dir if every configured location is
// halted (the daemon will start, emit a halt event, and refuse writes
// until space is freed). Errors probing a volume are treated as "this
// volume is unavailable, try next" rather than failing startup.
func pickInitialStorageLocation(cfg Config) string {
	q := resolveQuotas(cfg)
	for _, loc := range allStorageLocations(cfg) {
		v, err := probeVolume(loc)
		if err != nil {
			continue
		}
		if classifyVolume(v, q.Warn, q.Halt) != storageHalt {
			return loc
		}
	}
	return cfg.LogDir
}

// Cached snapshot to keep `simplesiem status` and the controller goroutine
// from hammering the disk on rapid back-to-back probes.
var (
	volumeCacheMu sync.Mutex
	volumeCache   = map[string]volumeCacheEntry{}
)

type volumeCacheEntry struct {
	usage     volumeUsage
	err       error
	expiresAt time.Time
}

// cachedProbeVolume probes once every 5s per path. A 5s window is short
// enough that an operator who runs `simplesiem status` after freeing
// space sees the recovery within one heartbeat, but long enough to
// avoid bursts of statfs calls when several status callers run in
// parallel.
func cachedProbeVolume(path string) (volumeUsage, error) {
	volumeCacheMu.Lock()
	now := time.Now()
	if e, ok := volumeCache[path]; ok && now.Before(e.expiresAt) {
		volumeCacheMu.Unlock()
		return e.usage, e.err
	}
	volumeCacheMu.Unlock()
	u, err := probeVolume(path)
	volumeCacheMu.Lock()
	volumeCache[path] = volumeCacheEntry{usage: u, err: err, expiresAt: now.Add(5 * time.Second)}
	volumeCacheMu.Unlock()
	return u, err
}

// formatBytesDecimal renders a byte count using base-1000 units (the
// convention disk vendors and most OS UIs use). Status output favours
// readability over technical precision here.
func formatBytesDecimal(b uint64) string {
	const (
		k = 1000
		m = k * 1000
		g = m * 1000
		t = g * 1000
	)
	switch {
	case b >= t:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(t))
	case b >= g:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(g))
	case b >= m:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(m))
	case b >= k:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(k))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
