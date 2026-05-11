package sieg

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Shared helpers for the typed config-edit CLIs (alerts-cfg, trust, tune,
// storage-cfg, watch, auth-log, network-ingest). They route every
// operator-driven mutation through configReadMap / configWriteMap so the
// edits are atomic + schema-validated + hot-reloaded by configWatcher.

// mustAdmin halts the command early when the caller doesn't have the
// privileges needed to write /etc/simplesiem/config.json. The runtime
// check itself is in isAdmin (platform-specific).
func mustAdmin() {
	if !isAdmin() {
		fatalf("must run as admin")
	}
}

// editServerStringList loads config.json, locates server.<key> as a
// []string, applies the operator's transform, and atomically writes the
// result. The transform receives the current list (or nil if absent) and
// returns the desired list — append/remove/rotate logic stays at the
// call site.
func editServerStringList(key string, transform func([]string) []string) {
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	srv := getOrCreateMap(m, "server")
	cur := stringSliceFromAny(srv[key])
	next := transform(cur)
	if len(next) == 0 {
		delete(srv, key)
	} else {
		// Re-encode through []any so the resulting JSON has the
		// right primitive shape — a typed []string would marshal
		// fine, but going through []any keeps the in-memory map
		// homogeneous with the read path.
		out := make([]any, len(next))
		for i, v := range next {
			out[i] = v
		}
		srv[key] = out
	}
	if err := configWriteMap(cfgPath, m); err != nil {
		fatalf("write config: %v", err)
	}
}

// editCollectorBool sets cfg.collector.<key> to v.
func editCollectorBool(key string, v bool) {
	editScalarUnder("collector", key, v)
}

// editServerBool sets cfg.server.<key> to v.
func editServerBool(key string, v bool) {
	editScalarUnder("server", key, v)
}

// setServerStringField sets cfg.server.<key> = v (string scalar). Empty
// string deletes the key so the daemon falls back to its default.
func setServerStringField(key, v string) {
	editScalarUnder("server", key, v)
}

func editScalarUnder(parent, key string, v any) {
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	pm := getOrCreateMap(m, parent)
	if s, ok := v.(string); ok && s == "" {
		delete(pm, key)
	} else {
		pm[key] = v
	}
	if err := configWriteMap(cfgPath, m); err != nil {
		fatalf("write config: %v", err)
	}
}

// editServerObject replaces cfg.server.<key> with a fresh map. When the
// new map is empty, the key is removed so the daemon falls back to its
// default-zero behaviour.
func editServerObject(key string, fresh map[string]any) {
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	srv := getOrCreateMap(m, "server")
	if len(fresh) == 0 {
		delete(srv, key)
	} else {
		srv[key] = fresh
	}
	if err := configWriteMap(cfgPath, m); err != nil {
		fatalf("write config: %v", err)
	}
}

// editServerNetworkIngestField writes cfg.server.network_ingest.<key>.
func editServerNetworkIngestField(key string, v any) {
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	srv := getOrCreateMap(m, "server")
	ni := getOrCreateMap(srv, "network_ingest")
	if s, ok := v.(string); ok && s == "" {
		delete(ni, key)
	} else {
		ni[key] = v
	}
	if err := configWriteMap(cfgPath, m); err != nil {
		fatalf("write config: %v", err)
	}
}

// editStorageField writes cfg.storage.<key>.
func editStorageField(key string, v any) {
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	st := getOrCreateMap(m, "storage")
	if s, ok := v.(string); ok && s == "" {
		delete(st, key)
	} else {
		st[key] = v
	}
	if err := configWriteMap(cfgPath, m); err != nil {
		fatalf("write config: %v", err)
	}
}

// editTopLevelField writes cfg.<key> for the top-level scalar keys
// (retention_days, write_queue_size, max_log_file_mb, etc.).
func editTopLevelField(key string, v any) {
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	if s, ok := v.(string); ok && s == "" {
		delete(m, key)
	} else {
		m[key] = v
	}
	if err := configWriteMap(cfgPath, m); err != nil {
		fatalf("write config: %v", err)
	}
}

// editTopLevelStringList is the top-level analogue of editServerStringList,
// used for cfg.file_watch_paths and cfg.auth_log_paths.
func editTopLevelStringList(key string, transform func([]string) []string) {
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	cur := stringSliceFromAny(m[key])
	next := transform(cur)
	if len(next) == 0 {
		delete(m, key)
	} else {
		out := make([]any, len(next))
		for i, v := range next {
			out[i] = v
		}
		m[key] = out
	}
	if err := configWriteMap(cfgPath, m); err != nil {
		fatalf("write config: %v", err)
	}
}

// getOrCreateMap returns m[key] as a map, creating an empty one if
// missing. Returns the parent map untouched if m[key] exists with a
// non-map type so the caller's later configWriteMap surface the schema
// violation, rather than silently clobbering the operator's data.
func getOrCreateMap(m map[string]any, key string) map[string]any {
	if v, ok := m[key]; ok {
		if mm, ok := v.(map[string]any); ok {
			return mm
		}
		fatalf("config field %s exists but is not an object", key)
	}
	fresh := map[string]any{}
	m[key] = fresh
	return fresh
}

func stringSliceFromAny(v any) []string {
	if v == nil {
		return nil
	}
	a, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(a))
	for _, e := range a {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func validSeverityLevel(s string) bool {
	switch strings.ToLower(s) {
	case "low", "medium", "high", "critical":
		return true
	}
	return false
}

// parseDurationSeconds accepts plain integer seconds (e.g. "900") or a
// Go duration string (e.g. "15m", "2h"). Returns the value in whole
// seconds; durations less than one second round down to zero, which the
// daemon treats as "use default".
func parseDurationSeconds(s string) (int, error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("not a duration: %s", s)
	}
	return int(d.Seconds()), nil
}

// parsePercentOrSize validates a storage-threshold input ("80%", "1TB",
// "20GB"). The daemon does the actual interpretation; this helper just
// rejects obvious typos before the operator's edit lands on disk.
func parsePercentOrSize(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("empty value")
	}
	if strings.HasSuffix(s, "%") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "%"))
		if err != nil || n < 1 || n > 100 {
			return fmt.Errorf("percent must be 1..100")
		}
		return nil
	}
	suffixes := []string{"KB", "MB", "GB", "TB", "PB", "K", "M", "G", "T", "P"}
	for _, suf := range suffixes {
		if strings.HasSuffix(strings.ToUpper(s), suf) {
			n, err := strconv.ParseFloat(strings.TrimSuffix(strings.ToUpper(s), suf), 64)
			if err != nil || n < 0 {
				return fmt.Errorf("size value must be a positive number with suffix")
			}
			return nil
		}
	}
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return nil
	}
	return fmt.Errorf("expected percent (80%%) or size (1TB / 500GB)")
}
