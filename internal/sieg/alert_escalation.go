package sieg

import (
	"context"
	"sync"
	"time"
)

// alertEscalator watches the local alerts log + ack index and
// re-fires `meta:alert_escalated` for any alert at or above
// `minSeverity` that's still unacked after `escalateAfter`. The
// escalation event flows through the same alertHooks fanout as
// the original — operators wire a separate webhook / syslog with
// a high-severity-only filter to get the escalation as a louder
// alert (PagerDuty, SMS, etc.).
//
// Cross-platform: pure Go, walks log_dir like the existing
// alerts CLI. No syscall-level dependencies.
type alertEscalator struct {
	logDir         string
	mode           string // "server" / "master" / "standalone" — needed for searchRoots layout
	escalateAfter  time.Duration
	minSeverity    int
	scanInterval   time.Duration
	cooldown       time.Duration
	logger         *Storage
	dispatch       func(map[string]any)
	mu             sync.Mutex
	escalatedHash  map[string]time.Time
	// startOnce protects against double-Start() spawning two scanner
	// goroutines that would re-fire every escalation alert twice.
	startOnce sync.Once
}

func newAlertEscalator(cfg ServerConfig, logDir, mode string, logger *Storage, dispatch func(map[string]any)) *alertEscalator {
	if cfg.AlertEscalation.Address == "" && !cfg.AlertEscalation.Enabled {
		return nil
	}
	after := time.Duration(cfg.AlertEscalation.AfterSeconds) * time.Second
	if after <= 0 {
		after = 15 * time.Minute
	}
	scan := time.Duration(cfg.AlertEscalation.ScanIntervalSeconds) * time.Second
	if scan <= 0 {
		scan = time.Minute
	}
	minSev := severityRank(cfg.AlertEscalation.MinSeverity)
	if cfg.AlertEscalation.MinSeverity == "" {
		minSev = sevCritical
	}
	return &alertEscalator{
		logDir:        logDir,
		mode:          mode,
		escalateAfter: after,
		minSeverity:   minSev,
		scanInterval:  scan,
		cooldown:      24 * time.Hour,
		logger:        logger,
		dispatch:      dispatch,
		escalatedHash: map[string]time.Time{},
	}
}

// Start launches the periodic escalation scan. Idempotent in two
// senses: each alert hash escalates at most once per cooldown, and
// calling Start twice is a no-op (a second goroutine would re-fire
// every escalation twice).
func (e *alertEscalator) Start(ctx context.Context, wg *sync.WaitGroup) {
	if e == nil {
		return
	}
	e.startOnce.Do(func() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(e.scanInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					e.scan()
				}
			}
		}()
	})
}

// scan walks the alerts log for events older than escalateAfter,
// looks up each in the ack index, and re-fires for any unacked
// alert at the configured minSeverity or above.
func (e *alertEscalator) scan() {
	now := time.Now()
	end := now.Add(-e.escalateAfter)
	// Lookback wider than escalateAfter so we don't miss alerts
	// that age into the eligible window between scans.
	start := end.Add(-24 * time.Hour)
	cfg := Config{LogDir: e.logDir, Mode: e.mode}
	roots := searchRoots(cfg, "")
	events := loadEventsInRangeMulti(roots, start, end, "alerts")
	acked := loadAckIndex(e.logDir)
	e.mu.Lock()
	defer e.mu.Unlock()
	// Decay the per-hash cooldown so a long-running daemon doesn't
	// accumulate ghost entries.
	for h, t := range e.escalatedHash {
		if now.Sub(t) > 7*24*time.Hour {
			delete(e.escalatedHash, h)
		}
	}
	for _, ev := range events {
		evType, _ := ev.Data["event"].(string)
		if evType != "rule_match" {
			continue
		}
		hash := strField(ev.Data, "_hash")
		if hash == "" {
			continue
		}
		sevStr := strField(ev.Data, "severity")
		if severityRank(sevStr) < e.minSeverity {
			continue
		}
		if acked[hash] {
			continue
		}
		if last, ok := e.escalatedHash[hash]; ok && now.Sub(last) < e.cooldown {
			continue
		}
		e.escalatedHash[hash] = now
		ageMinutes := int(now.Sub(ev.TS).Minutes())
		escalation := map[string]any{
			"event":             "alert_escalated",
			"original_alert":    hash,
			"original_rule":     strField(ev.Data, "rule"),
			"original_severity": sevStr,
			"age_minutes":       ageMinutes,
			"hint":              "alert was unacked after the configured escalation window — re-firing through alert hooks",
			"severity":          sevStr,
		}
		// Pass-through MITRE / annotation context if present so the
		// escalation alert carries the same triage info.
		if t := strField(ev.Data, "technique"); t != "" {
			escalation["technique"] = t
		}
		if t := strField(ev.Data, "tactic"); t != "" {
			escalation["tactic"] = t
		}
		if n := strField(ev.Data, "notes"); n != "" {
			escalation["notes"] = n
		}
		if u := strField(ev.Data, "runbook_url"); u != "" {
			escalation["runbook_url"] = u
		}
		if e.logger != nil {
			e.logger.Write("meta", escalation)
		}
		if e.dispatch != nil {
			// Re-fire through the alert dispatcher fanout so the
			// existing webhook / syslog sinks pick this up. We
			// rebrand it as a rule_match-shaped event so the
			// downstream filtering logic (severity_min) still
			// applies; the `event` field lets receivers
			// distinguish the original alert from its escalation.
			fanout := map[string]any{
				"event":         "alert_escalated",
				"rule":          "ESCALATED:" + strField(ev.Data, "rule"),
				"severity":      sevStr,
				"matched_type":  "meta",
				"matched_event": "alert_escalated",
				"original":      ev.Data,
				"age_minutes":   ageMinutes,
			}
			e.dispatch(fanout)
		}
	}
}
