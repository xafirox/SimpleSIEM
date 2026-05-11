package sieg

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// rules.json is a JSON array of rule objects. The CLI mutators below
// preserve the file's insertion order — operators rely on `rules list`
// matching the file shape so they can grep / diff after a change.
//
// Every mutation goes through atomicWriteFile so a crash mid-write
// can't leave a half-finished rules.json that the daemon would later
// refuse to load. parseRulesBytes runs on the new content before write
// so a malformed edit is rejected before the file is replaced.

func resolveRulesPath() string {
	cfg := loadConfig(defaultConfigPath())
	if cfg.RulesPath != "" {
		return cfg.RulesPath
	}
	return defaultConfigDir() + string(os.PathSeparator) + "rules.json"
}

func loadRulesArray(path string) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var arr []map[string]any
	if err := json.Unmarshal(data, &arr); err != nil {
		return nil, fmt.Errorf("rules.json is not a valid JSON array: %w", err)
	}
	return arr, nil
}

func writeRulesArray(path string, arr []map[string]any) error {
	body, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return err
	}
	if _, err := parseRulesBytes(body); err != nil {
		return fmt.Errorf("rules failed validation: %w", err)
	}
	body = append(body, '\n')
	return atomicWriteFile(path, body, 0o640)
}

func runRulesList(args []string) {
	_ = args
	path := resolveRulesPath()
	arr, err := loadRulesArray(path)
	if err != nil {
		fatalf("%v", err)
	}
	if len(arr) == 0 {
		fmt.Printf("(no rules at %s)\n", path)
		return
	}
	// Sort by name for stable output (use insertion order if names are
	// duplicated — preserves the file shape an operator would see in
	// `rules show`).
	type row struct {
		name      string
		severity  string
		matchKeys int
		disabled  bool
		notes     string
	}
	var rows []row
	for _, r := range arr {
		name, _ := r["name"].(string)
		sev, _ := r["severity"].(string)
		notes, _ := r["notes"].(string)
		dis, _ := r["disabled"].(bool)
		mk := 0
		if m, ok := r["match"].(map[string]any); ok {
			mk = len(m)
		}
		rows = append(rows, row{name, sev, mk, dis, notes})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	for _, r := range rows {
		state := "enabled"
		if r.disabled {
			state = "disabled"
		}
		fmt.Printf("  %-30s sev=%-7s match-keys=%d  %-8s  %s\n",
			r.name, r.severity, r.matchKeys, state, truncForList(r.notes))
	}
	fmt.Printf("\n%d rule(s) at %s\n", len(rows), path)
}

func truncForList(s string) string {
	if len(s) <= 60 {
		return s
	}
	return s[:57] + "..."
}

func runRulesShow(args []string) {
	if len(args) != 1 {
		fatalf("usage: rules show <name>")
	}
	path := resolveRulesPath()
	arr, err := loadRulesArray(path)
	if err != nil {
		fatalf("%v", err)
	}
	for _, r := range arr {
		if name, _ := r["name"].(string); name == args[0] {
			body, _ := json.MarshalIndent(r, "", "  ")
			fmt.Println(string(body))
			return
		}
	}
	fatalf("no rule named %q in %s", args[0], path)
}

func runRulesAdd(args []string) {
	if len(args) != 1 {
		fatalf("usage: rules add <file|->\n\nThe file is a JSON object (one rule) or array (many).\nUse - to read from stdin.")
	}
	mustAdmin()
	var raw []byte
	var err error
	if args[0] == "-" {
		raw, err = io.ReadAll(bufio.NewReader(os.Stdin))
	} else {
		raw, err = os.ReadFile(args[0])
	}
	if err != nil {
		fatalf("read input: %v", err)
	}
	// Accept either a single object or an array. Normalise to a slice.
	trim := strings.TrimSpace(string(raw))
	var incoming []map[string]any
	if strings.HasPrefix(trim, "[") {
		if err := json.Unmarshal(raw, &incoming); err != nil {
			fatalf("input is not a valid rules JSON array: %v", err)
		}
	} else if strings.HasPrefix(trim, "{") {
		var one map[string]any
		if err := json.Unmarshal(raw, &one); err != nil {
			fatalf("input is not a valid rule JSON object: %v", err)
		}
		incoming = []map[string]any{one}
	} else {
		fatalf("input must be a JSON object (one rule) or array (many)")
	}
	if len(incoming) == 0 {
		fatalf("no rules in input")
	}
	for i, r := range incoming {
		name, _ := r["name"].(string)
		if name == "" {
			fatalf("rule #%d in input has no name", i+1)
		}
	}
	path := resolveRulesPath()
	existing, err := loadRulesArray(path)
	if err != nil {
		fatalf("%v", err)
	}
	// Refuse to overwrite an existing name. Operators wanting to
	// edit a rule should `rules show <name> > /tmp/r.json`, edit it,
	// `rules delete <name>`, then `rules add /tmp/r.json`.
	have := map[string]bool{}
	for _, r := range existing {
		if name, _ := r["name"].(string); name != "" {
			have[name] = true
		}
	}
	for _, r := range incoming {
		name, _ := r["name"].(string)
		if have[name] {
			fatalf("rule named %q already exists; delete it first or rename the new rule", name)
		}
	}
	merged := append(existing, incoming...)
	if err := writeRulesArray(path, merged); err != nil {
		fatalf("write rules: %v", err)
	}
	fmt.Printf("added %d rule(s) to %s (now %d total)\n", len(incoming), path, len(merged))
}

func runRulesDelete(args []string) {
	if len(args) != 1 {
		fatalf("usage: rules delete <name>")
	}
	mustAdmin()
	path := resolveRulesPath()
	arr, err := loadRulesArray(path)
	if err != nil {
		fatalf("%v", err)
	}
	out := arr[:0]
	removed := 0
	for _, r := range arr {
		if name, _ := r["name"].(string); name == args[0] {
			removed++
			continue
		}
		out = append(out, r)
	}
	if removed == 0 {
		fatalf("no rule named %q in %s", args[0], path)
	}
	if err := writeRulesArray(path, out); err != nil {
		fatalf("write rules: %v", err)
	}
	fmt.Printf("deleted %d rule(s) named %q from %s\n", removed, args[0], path)
}

func runRulesEnableDisable(args []string, enable bool) {
	verb := "enable"
	if !enable {
		verb = "disable"
	}
	if len(args) != 1 {
		fatalf("usage: rules %s <name>", verb)
	}
	mustAdmin()
	path := resolveRulesPath()
	arr, err := loadRulesArray(path)
	if err != nil {
		fatalf("%v", err)
	}
	hit := 0
	for _, r := range arr {
		if name, _ := r["name"].(string); name == args[0] {
			if enable {
				delete(r, "disabled")
			} else {
				r["disabled"] = true
			}
			hit++
		}
	}
	if hit == 0 {
		fatalf("no rule named %q in %s", args[0], path)
	}
	if err := writeRulesArray(path, arr); err != nil {
		fatalf("write rules: %v", err)
	}
	fmt.Printf("%sd %d rule(s) named %q\n", verb, hit, args[0])
}
