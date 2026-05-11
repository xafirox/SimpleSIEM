package sieg

import (
	"context"
	"os"
	"sync"
	"time"
)

// startRulesWatcher polls rulesPath's mtime once a second and re-loads
// rules into the running engine when it changes. Every per-mode `rules
// enable / disable / set / delete` writes the rules file via
// atomicWriteFile, so this watcher is what makes the CLI's promise
// "daemon will hot-reload within ~1s" actually true.
//
// The applyFn callback is what wires the loaded rule set into the
// running daemon's state holder — Storage.SetRules for standalone /
// agent / collector, serverState.setRules for server / master. Caller
// closes the loop by passing the right setter.
//
// On parse error we log to stderr and skip this tick so a broken
// rules.json edit doesn't wipe the in-memory rule set. The next clean
// edit lands as expected.
func startRulesWatcher(ctx context.Context, wg *sync.WaitGroup, rulesPath string, applyFn func([]*alertRule), logger *Storage) {
	if rulesPath == "" || applyFn == nil {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var lastSeen int64
		// Seed lastSeen so we don't double-apply at startup (the daemon
		// already loaded rules once before we started watching).
		if info, err := os.Stat(rulesPath); err == nil {
			lastSeen = info.ModTime().UnixNano()
		}
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			info, err := os.Stat(rulesPath)
			if err != nil {
				continue
			}
			mt := info.ModTime().UnixNano()
			if mt == lastSeen {
				continue
			}
			lastSeen = mt
			rules, err := loadRules(rulesPath)
			if err != nil {
				if logger != nil {
					logger.Write("errors", map[string]any{
						"collector": "rules_watcher",
						"error":     err.Error(),
						"path":      rulesPath,
						"hint":      "rules.json failed to parse; previous in-memory rule set is unchanged",
					})
				}
				continue
			}
			applyFn(rules)
			if logger != nil {
				names := make([]string, 0, len(rules))
				for _, r := range rules {
					names = append(names, r.Name)
				}
				logger.Write("meta", map[string]any{
					"event": "rules_hot_reloaded",
					"path":  rulesPath,
					"count": len(rules),
					"names": names,
				})
			}
		}
	}()
}
