package sieg

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// runConfigCmd is the generic config get/set/list/edit/unset façade.
//
// Operators previously had to reach for `jq` to flip server.bearer_tokens,
// alert webhooks, master trust gates, etc. — every flow now has at least
// this generic surface, plus typed wrappers for the high-traffic flows.
//
// All writes are atomic (temp + rename) and round-tripped through the
// Config struct so an operator can't accidentally produce a config the
// daemon would reject. The on-disk file is the source of truth; the
// running daemon picks the change up via configWatcher within ~1 s.
func runConfigCmd(args []string) {
	if len(args) == 0 {
		configUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "get":
		runConfigGet(args[1:])
	case "set":
		runConfigSet(args[1:])
	case "unset":
		runConfigUnset(args[1:])
	case "list":
		runConfigList(args[1:])
	case "edit":
		runConfigEdit(args[1:])
	case "help", "-h", "--help":
		configUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown config subcommand: %s\n", args[0])
		configUsage()
		os.Exit(2)
	}
}

func configUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem config <subcommand> [args]

subcommands:
  get <key>                 print the JSON value at the dotted key
  set <key> <value>         set the dotted key; value parsed as JSON when
                            possible (so set foo.bar 42 stores the number 42,
                            set foo.bar '"text"' stores the string "text")
  unset <key>               remove the dotted key from config.json
  list [prefix]             show every operator-settable key with its value;
                            optional prefix filters (e.g. server.alert_)
  edit                      open config.json in $EDITOR (or $VISUAL); the file
                            is validated against the Config schema before
                            replacing the live config

examples:
  simplesiem config get server.bearer_tokens
  simplesiem config set server.alert_webhooks '["https://example.com/hook"]'
  simplesiem config set server.master_can_rotate_ca true
  simplesiem config set agent.batch_size 50
  simplesiem config unset server.bearer_tokens
  simplesiem config list server.alert_`)
}

// configReadMap reads config.json as a map (no schema constraints). Edits
// happen against the map and are validated by unmarshaling into Config
// before the atomic write.
func configReadMap(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("config.json is not valid JSON: %w", err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// configWriteMap validates the map against Config, then atomically replaces
// config.json. Validation rejects edits that would produce a config the
// daemon would refuse on next start, surfacing the operator's mistake here
// (where they can react) instead of in the next service restart.
func configWriteMap(path string, m map[string]any) error {
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	var probe Config
	if err := json.Unmarshal(body, &probe); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	body = append(body, '\n')
	return atomicWriteFile(path, body, 0o600)
}

// configWalk navigates a dotted key into the map, creating intermediate
// objects as needed when create==true. Returns the parent map and the
// final segment so the caller can read or write the leaf.
func configWalk(root map[string]any, key string, create bool) (map[string]any, string, error) {
	parts := strings.Split(key, ".")
	if len(parts) == 0 || parts[0] == "" {
		return nil, "", fmt.Errorf("empty key")
	}
	cur := root
	for i, p := range parts[:len(parts)-1] {
		nxt, ok := cur[p]
		if !ok {
			if !create {
				return nil, "", fmt.Errorf("key not found: %s", strings.Join(parts[:i+1], "."))
			}
			fresh := map[string]any{}
			cur[p] = fresh
			cur = fresh
			continue
		}
		m, ok := nxt.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("intermediate key %q is not an object", strings.Join(parts[:i+1], "."))
		}
		cur = m
	}
	return cur, parts[len(parts)-1], nil
}

func runConfigGet(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem config get <key>")
		os.Exit(2)
	}
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	parent, leaf, err := configWalk(m, args[0], false)
	if err != nil {
		fatalf("%v", err)
	}
	v, ok := parent[leaf]
	if !ok {
		fatalf("key not found: %s", args[0])
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

func runConfigSet(args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem config set <key> <value>")
		os.Exit(2)
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	parent, leaf, err := configWalk(m, args[0], true)
	if err != nil {
		fatalf("%v", err)
	}
	parent[leaf] = parseConfigValue(args[1])
	if err := configWriteMap(cfgPath, m); err != nil {
		fatalf("write config: %v", err)
	}
	fmt.Printf("set %s; daemon will hot-reload within ~1s\n", args[0])
}

func runConfigUnset(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem config unset <key>")
		os.Exit(2)
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	parent, leaf, err := configWalk(m, args[0], false)
	if err != nil {
		fatalf("%v", err)
	}
	if _, ok := parent[leaf]; !ok {
		fmt.Printf("key %s not present; nothing to do\n", args[0])
		return
	}
	delete(parent, leaf)
	if err := configWriteMap(cfgPath, m); err != nil {
		fatalf("write config: %v", err)
	}
	fmt.Printf("unset %s\n", args[0])
}

// parseConfigValue interprets the operator's argument. JSON-shaped strings
// (numbers, booleans, arrays, objects, quoted strings, null) are decoded
// as JSON; anything else lands as a plain string. This matches what an
// operator probably means: `set server.foo 42` stores 42, `set server.foo
// '["a","b"]'` stores an array, `set server.foo hello` stores "hello".
func parseConfigValue(raw string) any {
	trim := strings.TrimSpace(raw)
	if trim == "" {
		return ""
	}
	switch trim {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}
	// Numbers
	if n, err := strconv.ParseInt(trim, 10, 64); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(trim, 64); err == nil {
		return f
	}
	// JSON shapes
	if strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[") || strings.HasPrefix(trim, "\"") {
		var v any
		if err := json.Unmarshal([]byte(trim), &v); err == nil {
			return v
		}
	}
	return raw
}

func runConfigList(args []string) {
	prefix := ""
	if len(args) > 0 {
		prefix = args[0]
	}
	cfgPath := defaultConfigPath()
	m, err := configReadMap(cfgPath)
	if err != nil {
		fatalf("read config: %v", err)
	}
	rows := flattenConfigMap("", m)
	sort.Strings(rows)
	for _, r := range rows {
		if prefix == "" || strings.HasPrefix(r, prefix) {
			fmt.Println(r)
		}
	}
}

// flattenConfigMap walks the map and emits "key.subkey = value" rows for
// every leaf, suitable for grep / awk / piping.
func flattenConfigMap(prefix string, m map[string]any) []string {
	var out []string
	for k, v := range m {
		full := k
		if prefix != "" {
			full = prefix + "." + k
		}
		switch t := v.(type) {
		case map[string]any:
			out = append(out, flattenConfigMap(full, t)...)
		default:
			b, _ := json.Marshal(t)
			out = append(out, full+" = "+string(b))
		}
	}
	return out
}

func runConfigEdit(args []string) {
	_ = args
	if !isAdmin() {
		fatalf("must run as admin")
	}
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		fatalf("no $EDITOR or $VISUAL set; specify one and retry, or use `simplesiem config set <key> <value>`")
	}
	cfgPath := defaultConfigPath()
	tmp := cfgPath + ".edit"
	src, err := os.ReadFile(cfgPath)
	if err != nil && !os.IsNotExist(err) {
		fatalf("read config: %v", err)
	}
	if len(src) == 0 {
		src = []byte(defaultConfigJSON())
	}
	if err := os.WriteFile(tmp, src, 0o600); err != nil {
		fatalf("write tmp: %v", err)
	}
	defer os.Remove(tmp)
	cmd := exec.Command(editor, tmp)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatalf("editor exited non-zero: %v", err)
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		fatalf("read edited file: %v", err)
	}
	var probe Config
	if err := json.Unmarshal(data, &probe); err != nil {
		fatalf("edited config is invalid (NOT applied): %v", err)
	}
	// Route through saveConfig so the previous-known-good config gets
	// preserved as <path>.bak. Previously this used atomicWriteFile
	// directly, which skipped the .bak refresh — meaning a follow-up
	// hand-edit that breaks the JSON had no fresh rollback target
	// (the s10 user complaint).
	if err := saveConfig(cfgPath, probe); err != nil {
		fatalf("write config: %v", err)
	}
	fmt.Println("config updated; daemon will hot-reload within ~1s")
}
