package sieg

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Attack-pattern detector for the network-ingest listener. Runs on
// every inbound frame BEFORE allowlist validation (so attacks from
// rogue sources are caught + alerted just like attacks from
// allowlisted devices). Hits emit:
//
//   meta:network_ingest_attack_detected{
//     reason, technique, tactic, severity:"high", source_ip, source_mac,
//     authenticated:bool, indicator, frame_excerpt
//   }
//
// AND push the same content through the alert pipeline at severity=high
// so webhooks / syslog forwarders / incidents see it.
//
// Pattern set:
//
//   1. Hardcoded core (this file's `coreAttackPatterns`) — covers OWASP
//      top patterns mapped to MITRE ATT&CK techniques.
//
//   2. Optional sidecar `<config>/attack-patterns.json` — operator
//      extensions, hot-reloadable.

// attackPattern is one detection rule.
type attackPattern struct {
	Name        string         `json:"name"`
	Regex       string         `json:"regex"`
	Tactic      string         `json:"tactic"`     // MITRE ATT&CK tactic ID (TA####)
	Technique   string         `json:"technique"`  // MITRE technique (T####[.###])
	Description string         `json:"description"`
	// Disabled keeps the pattern in the sidecar for an audit trail
	// but stops it from compiling into the active set. Operators
	// flip this with `simplesiem attack-patterns disable <name>`;
	// the loader silently skips disabled entries so they don't
	// cause false positives or false negatives.
	Disabled bool `json:"disabled,omitempty"`
	compiled *regexp.Regexp `json:"-"`
}

// coreAttackPatterns is the hardcoded baseline. Each pattern carries a
// MITRE ATT&CK tactic + technique mapping so alerts hit the existing
// `simplesiem alerts --technique <ID>` / `rules coverage` paths
// without operators needing to wire anything up.
var coreAttackPatterns = []attackPattern{
	// SQL injection — classic OR-tautology / UNION patterns.
	{
		Name:        "sql_injection_or_tautology",
		Regex:       `(?i)(\bor\b\s+['"]?\s*[\d'"]+\s*=\s*[\d'"]|'\s*OR\s*'1'\s*=\s*'1)`,
		Tactic:      "TA0008",
		Technique:   "T1190",
		Description: "SQL injection — OR-tautology pattern in syslog frame",
	},
	{
		Name:        "sql_injection_union",
		Regex:       `(?i)\bunion\b\s+(?:all\s+)?\bselect\b`,
		Tactic:      "TA0008",
		Technique:   "T1190",
		Description: "SQL injection — UNION SELECT pattern",
	},
	{
		Name:        "sql_injection_drop_truncate",
		Regex:       `(?i)\b(?:drop|truncate)\s+(?:table|database)\b`,
		Tactic:      "TA0040",
		Technique:   "T1485",
		Description: "SQL DROP/TRUNCATE — destructive injection",
	},
	{
		Name:        "sql_comment_terminator",
		Regex:       `(?:--\s|;\s*--|/\*!.*?\*/)`,
		Tactic:      "TA0008",
		Technique:   "T1190",
		Description: "SQL comment terminator used to truncate query",
	},
	// Command / shell injection — substitution syntax + metachars.
	{
		Name:        "command_injection_substitution",
		Regex:       "(?:\\$\\{[^}]{0,200}\\}|\\$\\([^)]{0,200}\\)|`[^`]{1,200}`)",
		Tactic:      "TA0002",
		Technique:   "T1059",
		Description: "Command-injection substitution syntax ($(...), ${...}, backticks)",
	},
	{
		Name:        "command_injection_chained",
		Regex:       `(?:\|\s*(?:nc|netcat|bash|sh|zsh|curl|wget)\b|;\s*(?:rm|cat|wget|curl|bash|sh)\s+)`,
		Tactic:      "TA0002",
		Technique:   "T1059",
		Description: "Command chain to data-exfil / shell tool",
	},
	{
		Name:        "command_injection_redirect",
		Regex:       `(?:>\s*/etc/(?:passwd|shadow|hosts|sudoers)|<\s*/etc/(?:passwd|shadow))`,
		Tactic:      "TA0006",
		Technique:   "T1003.008",
		Description: "Sensitive-file redirect attempt",
	},
	// Log4Shell / JNDI lookups — extreme-impact RCE class.
	{
		Name:        "log4shell_jndi",
		Regex:       `(?i)\$\{(?:jndi|env|sys|lower|upper|date)[:.]`,
		Tactic:      "TA0002",
		Technique:   "T1190",
		Description: "Log4Shell / JNDI lookup — known RCE primitive",
	},
	// Format-string attacks.
	{
		Name:        "format_string_attack",
		Regex:       `%(?:n|x{4,}|s{6,}|0?\d+\$[snx])`,
		Tactic:      "TA0002",
		Technique:   "T1499.004",
		Description: "Format-string attack pattern (%n, repeated %x, positional %)",
	},
	// Path traversal.
	{
		Name:        "path_traversal_dotdot",
		Regex:       `(?:\.\./){2,}|(?:\.\.\\){2,}|(?:%2e%2e[/\\]){2,}|(?:\.\.%2f){2,}`,
		Tactic:      "TA0007",
		Technique:   "T1083",
		Description: "Path traversal sequence (../ or URL-encoded equivalent, ≥2 levels)",
	},
	// XSS / HTML script injection.
	{
		Name:        "xss_script_tag",
		Regex:       `(?i)<\s*script[\s>]|on(?:error|load|click|mouseover)\s*=\s*['"]|javascript:`,
		Tactic:      "TA0002",
		Technique:   "T1059.007",
		Description: "XSS / script-tag injection (JavaScript-class RCE on viewer)",
	},
	// XML entity expansion / XXE.
	{
		Name:        "xxe_doctype_entity",
		Regex:       `(?i)<!ENTITY\s+\S+\s+(?:SYSTEM|PUBLIC)\s|<!DOCTYPE\s+[^>]+\bSYSTEM\b`,
		Tactic:      "TA0002",
		Technique:   "T1190",
		Description: "XML XXE entity declaration",
	},
	// Null bytes / control characters.
	{
		Name:        "null_byte_injection",
		Regex:       "\x00",
		Tactic:      "TA0005",
		Technique:   "T1027",
		Description: "Null byte in syslog frame (filename truncation / parser confusion)",
	},
	{
		Name:        "ansi_escape_injection",
		Regex:       "\x1b\\[",
		Tactic:      "TA0005",
		Technique:   "T1027",
		Description: "ANSI escape sequence in syslog frame (terminal-injection)",
	},
	// LDAP injection.
	{
		Name:        "ldap_injection",
		Regex:       `(?:\(\|\(\&|\)\(\!\(|\(uid=\*\)\(|\(\&\(objectClass=\*\)\()`,
		Tactic:      "TA0006",
		Technique:   "T1110.003",
		Description: "LDAP injection — common filter-bypass tautology",
	},
	// Buffer-overflow / payload-flood patterns. Go's RE2 has no
	// backreferences, so we cover the common fuzzer probes by
	// individual character classes rather than a generic
	// "([X])\1{N,}" backref.
	{
		Name:        "buffer_flood_a_pattern",
		Regex:       `A{200,}`,
		Tactic:      "TA0040",
		Technique:   "T1499",
		Description: "Long A-pattern (canonical buffer-overflow probe)",
	},
	{
		Name:        "buffer_flood_x_pattern",
		Regex:       `(?:x{500,}|X{500,}|0{500,}|9{500,}|\.{500,})`,
		Tactic:      "TA0040",
		Technique:   "T1499",
		Description: "Long single-character flood (≥500 repeats)",
	},
	// Protocol confusion — HTTP request to a syslog port.
	{
		Name:        "http_protocol_smuggling",
		Regex:       `^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+/[^\s]*\s+HTTP/`,
		Tactic:      "TA0011",
		Technique:   "T1071.001",
		Description: "HTTP request directed at the syslog listener (protocol confusion)",
	},
	// Overlong / invalid UTF-8 is detected at byte level — Go's RE2
	// regex requires valid-UTF-8 string mode, so we can't express
	// "byte 0xc0 followed by 0x80-0xbf" as a regex. See the structural
	// check in attackDetector.ScanAll().
}

// invalidUTF8Pattern is the synthetic pattern returned when the
// structural UTF-8 check trips. Lives outside the regex list because
// it's enforced via byte-level inspection.
var invalidUTF8Pattern = attackPattern{
	Name:        "overlong_utf8",
	Tactic:      "TA0005",
	Technique:   "T1027",
	Description: "Overlong / invalid UTF-8 (encoding trick to bypass filters)",
}

func init() {
	for i := range coreAttackPatterns {
		coreAttackPatterns[i].compiled = regexp.MustCompile(coreAttackPatterns[i].Regex)
	}
}

// attackDetector holds the active pattern set. Hot-reloadable via
// the sidecar watcher.
type attackDetector struct {
	mu       sync.RWMutex
	patterns []attackPattern // core + sidecar, all compiled
}

func newAttackDetector(sidecarPath string) *attackDetector {
	d := &attackDetector{}
	d.LoadSidecar(sidecarPath)
	return d
}

// LoadSidecar reads <config>/attack-patterns.json and merges its
// patterns with the hardcoded core. Errors leave the previous state
// in place (atomic-edit contract matches the rest of the system).
func (d *attackDetector) LoadSidecar(path string) error {
	merged := make([]attackPattern, 0, len(coreAttackPatterns)+8)
	for _, p := range coreAttackPatterns {
		merged = append(merged, p)
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			var sidecar struct {
				Patterns []attackPattern `json:"patterns"`
			}
			if err := json.Unmarshal(data, &sidecar); err != nil {
				return fmt.Errorf("parse: %w", err)
			}
			for _, p := range sidecar.Patterns {
				if p.Regex == "" || p.Disabled {
					continue
				}
				re, err := regexp.Compile(p.Regex)
				if err != nil {
					return fmt.Errorf("regex %q: %w", p.Name, err)
				}
				p.compiled = re
				merged = append(merged, p)
			}
		}
	}
	d.mu.Lock()
	d.patterns = merged
	d.mu.Unlock()
	return nil
}

// ScanAll returns every pattern that matched. Used by the alert
// payload so investigators see the full attack-vector set.
func (d *attackDetector) ScanAll(frame string) []attackPattern {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := []attackPattern{}
	for i := range d.patterns {
		if d.patterns[i].compiled == nil {
			continue
		}
		if d.patterns[i].compiled.MatchString(frame) {
			out = append(out, d.patterns[i])
		}
	}
	if !validUTF8(frame) {
		out = append(out, invalidUTF8Pattern)
	}
	return out
}

// validUTF8 walks the frame's bytes manually so we can detect
// overlong sequences (which utf8.ValidString also catches) and
// invalid leading bytes that operators sometimes use to confuse
// log-pipeline parsers.
func validUTF8(s string) bool {
	for i := 0; i < len(s); {
		b := s[i]
		if b < 0x80 {
			i++
			continue
		}
		// 0xc0/0xc1 are overlong-encoding leaders (would encode
		// ASCII-range chars in 2 bytes — disallowed). 0xf5-0xff are
		// invalid 4-byte leaders (codepoint > U+10FFFF).
		if b == 0xc0 || b == 0xc1 || b >= 0xf5 {
			return false
		}
		// Leader byte expects N continuation bytes (10xxxxxx).
		var need int
		switch {
		case b < 0xc0:
			return false // continuation byte appearing without a leader
		case b < 0xe0:
			need = 1
		case b < 0xf0:
			need = 2
		default:
			need = 3
		}
		if i+need >= len(s) {
			return false
		}
		for k := 1; k <= need; k++ {
			if s[i+k]&0xc0 != 0x80 {
				return false
			}
		}
		i += 1 + need
	}
	return true
}

// PatternCount returns the active pattern count (core + sidecar). Used
// by status output and tests.
func (d *attackDetector) PatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}

// attackPatternsPath returns the canonical sidecar location.
func attackPatternsPath() string {
	return filepath.Join(defaultConfigDir(), "attack-patterns.json")
}

// attackPatternsWatcher hot-reloads the sidecar on change.
type attackPatternsWatcher struct {
	det      *attackDetector
	path     string
	logger   *Storage
	lastSeen int64
}

func newAttackPatternsWatcher(det *attackDetector, path string, logger *Storage) *attackPatternsWatcher {
	w := &attackPatternsWatcher{det: det, path: path, logger: logger}
	if info, err := os.Stat(path); err == nil {
		w.lastSeen = info.ModTime().UnixNano()
	}
	return w
}

func (w *attackPatternsWatcher) run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		info, err := os.Stat(w.path)
		if err != nil {
			continue
		}
		mt := info.ModTime().UnixNano()
		if mt == w.lastSeen {
			continue
		}
		w.lastSeen = mt
		if err := w.det.LoadSidecar(w.path); err != nil {
			if w.logger != nil {
				w.logger.Write("meta", map[string]any{
					"event":  "attack_patterns_reload_rejected",
					"detail": err.Error(),
				})
			}
			continue
		}
		if w.logger != nil {
			w.logger.Write("meta", map[string]any{
				"event":          "attack_patterns_reloaded",
				"pattern_count":  w.det.PatternCount(),
			})
		}
	}
}

// frameExcerpt returns a safe-to-log slice of the frame, capped at
// 200 chars and stripped of control characters that could themselves
// inject ANSI sequences into operator terminals.
func frameExcerpt(s string) string {
	if len(s) > 200 {
		s = s[:200]
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' || c == '\r' || c == '\t' {
			out = append(out, ' ')
			continue
		}
		if c < 0x20 || c == 0x7f {
			out = append(out, '?')
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// indicatorString returns a short human-facing summary for the meta
// event. Includes the matched pattern name + a short excerpt.
func indicatorString(p *attackPattern, frame string) string {
	return fmt.Sprintf("%s: %s", p.Name, frameExcerpt(matchExcerpt(p.compiled, frame)))
}

// matchExcerpt returns the matched substring, capped at 80 chars.
func matchExcerpt(re *regexp.Regexp, frame string) string {
	if re == nil {
		return ""
	}
	loc := re.FindStringIndex(frame)
	if loc == nil {
		return ""
	}
	start := loc[0]
	end := loc[1]
	if end-start > 80 {
		end = start + 80
	}
	if start > 20 {
		start -= 20
	} else {
		start = 0
	}
	if end > len(frame) {
		end = len(frame)
	}
	return frame[start:end]
}

// helper for tests
var _ = strings.Builder{}
