package sieg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// c5 — when a collector's paired source is unreachable for a threshold
// AND the operator has pre-staged a "realm repair" PSK at
// `<state>/realm_repair.psk`, the collector tries to re-pair with a
// failover server in the same realm. The PSK is the one shown by
// `simplesiem certs psk show` on any server in the realm — every
// server in the realm shares the realm-PSK because realm sync
// propagates it.
//
// Why a PSK file instead of an automatic call? The collector's
// existing cert may be invalid (CA rotated past it, allowlist
// removed) — a fresh enrollment against the failover server is the
// only way back. That requires an authenticated PSK call. Pre-staging
// one PSK file gives the collector a way to repair itself without a
// human on the collector host during the outage.
//
// Pairs with `simplesiem collector queue-repair --key <PSK>` to drop
// the file in place.

// collectorAutoRepairPSKPath is where the operator drops the realm
// PSK to opt this collector into auto-repair on paired-source outage.
func collectorAutoRepairPSKPath() string {
	return filepath.Join(defaultStateDir(), "realm_repair.psk")
}

// readCollectorAutoRepairPSK loads the staged PSK if present.
func readCollectorAutoRepairPSK() (string, error) {
	data, err := os.ReadFile(collectorAutoRepairPSKPath())
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(data))
	if !strings.HasPrefix(s, enrollPSKPrefix) {
		return "", fmt.Errorf("staged PSK at %s is malformed (missing %q prefix)", collectorAutoRepairPSKPath(), enrollPSKPrefix)
	}
	return s, nil
}

// consumeCollectorAutoRepairPSK deletes the staged file after a
// successful repair. Best-effort.
func consumeCollectorAutoRepairPSK() {
	_ = os.Remove(collectorAutoRepairPSKPath())
}

// collectorRepairState tracks when the source first became
// unreachable so we can apply a threshold instead of re-enrolling on
// every transient blip.
type collectorRepairState struct {
	firstDownAt atomic.Int64 // unix nano of the first observed down state, 0 when up
	lastAttempt atomic.Int64 // unix nano of the last repair attempt
}

var globalCollectorRepairState collectorRepairState

// noteCollectorSourceUp resets the down-watermark when the source is
// reachable. Called from the pull loop on a successful pull.
func noteCollectorSourceUp() {
	globalCollectorRepairState.firstDownAt.Store(0)
}

// noteCollectorSourceDown records the first-failure timestamp. Idempotent
// — repeated calls during the same outage keep the original timestamp.
func noteCollectorSourceDown() {
	if globalCollectorRepairState.firstDownAt.Load() == 0 {
		globalCollectorRepairState.firstDownAt.Store(time.Now().UnixNano())
	}
}

// tryCollectorAutoRepair runs a single repair cycle when:
//   - cfg.Collector.AutoRepairOnOutage is true
//   - the primary source has been unreachable for at least
//     RepairAfterMinutes minutes (default 30)
//   - the PSK file is staged on disk
//   - cfg.Collector.FailoverServers has at least one URL we can try
//
// Returns (attempted, err): attempted=false means we skipped (PSK
// missing, threshold not met, auto-repair disabled, no failover URLs).
func tryCollectorAutoRepair(cfg Config, cfgPath string, storage *Storage) (bool, error) {
	if !cfg.Collector.AutoRepairOnOutage {
		return false, nil
	}
	threshold := time.Duration(cfg.Collector.RepairAfterMinutes) * time.Minute
	if threshold <= 0 {
		threshold = 30 * time.Minute
	}
	first := globalCollectorRepairState.firstDownAt.Load()
	if first == 0 {
		return false, nil
	}
	since := time.Duration(time.Now().UnixNano() - first)
	if since < threshold {
		return false, nil
	}
	// Cooldown between attempts to avoid hammering during a
	// permanently-rotated PSK scenario.
	last := globalCollectorRepairState.lastAttempt.Load()
	if last != 0 && time.Duration(time.Now().UnixNano()-last) < 5*time.Minute {
		return false, nil
	}
	psk, perr := readCollectorAutoRepairPSK()
	if perr != nil {
		return false, nil
	}
	if len(cfg.Collector.FailoverServers) == 0 {
		return false, nil
	}
	if !globalCollectorRepairState.lastAttempt.CompareAndSwap(last, time.Now().UnixNano()) {
		return false, nil
	}

	// Try each failover URL in turn until one accepts the enrollment.
	var lastErr error
	for _, peerURL := range cfg.Collector.FailoverServers {
		peerURL = strings.TrimRight(peerURL, "/")
		if peerURL == "" || peerURL == strings.TrimRight(cfg.Collector.SourceURL, "/") {
			continue
		}
		storage.Write("meta", map[string]any{
			"event":      "collector_auto_repair_attempt",
			"old_source": cfg.Collector.SourceURL,
			"new_source": peerURL,
			"down_for_s": int(since.Seconds()),
		})
		if err := doCollectorPromote(cfgPath, peerURL, psk); err != nil {
			lastErr = err
			storage.Write("errors", map[string]any{
				"collector":  "collector_auto_repair",
				"new_source": peerURL,
				"error":      err.Error(),
			})
			continue
		}
		consumeCollectorAutoRepairPSK()
		// Reset state so we don't immediately retry on the next pull
		// (the next successful pull will clear firstDownAt anyway).
		globalCollectorRepairState.firstDownAt.Store(0)
		storage.Write("meta", map[string]any{
			"event":      "collector_auto_repaired",
			"new_source": peerURL,
			"hint":       "primary source was unreachable past the configured threshold; collector re-paired with this peer",
		})
		return true, nil
	}
	if lastErr != nil {
		storage.Write("meta", map[string]any{
			"event": "collector_auto_repair_failed",
			"error": lastErr.Error(),
			"hint":  "every failover URL rejected the staged PSK; verify the realm PSK on a server with `simplesiem certs psk show`",
		})
		return true, lastErr
	}
	return true, nil
}

// runCollectorQueueRepair is the operator-facing CLI to drop the
// realm PSK in place for c5's auto-repair flow.
func runCollectorQueueRepair(args []string) {
	args = permuteArgs(args, map[string]bool{"key": true})
	for i := 0; i < len(args); i++ {
		if args[i] == "--key" || args[i] == "-k" {
			if i+1 >= len(args) {
				fatalf("--key requires a value (a realm-server PSK from `simplesiem certs psk show`)")
			}
			psk := args[i+1]
			if _, err := pskRawBytes(psk); err != nil {
				fatalf("--key is not a valid PSK: %v", err)
			}
			if !isAdmin() {
				fatalf("must run as admin")
			}
			path := collectorAutoRepairPSKPath()
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				fatalf("create state dir: %v", err)
			}
			// atomicWriteFile carries the cross-platform mode contract;
			// see the parallel comment in runCollectorQueuePromote.
			if err := atomicWriteFile(path, []byte(strings.TrimSpace(psk)+"\n"), 0o600); err != nil {
				fatalf("write PSK: %v", err)
			}
			fmt.Printf("Realm repair PSK staged at %s.\n", path)
			fmt.Println("If the primary source becomes unreachable for longer than")
			fmt.Println("collector.repair_after_minutes (default 30), the daemon will")
			fmt.Println("re-pair with one of cfg.collector.failover_servers using this PSK.")
			return
		}
	}
	fatalf("usage: simplesiem collector queue-repair --key <PSK from a realm server's `certs psk show`>")
}
