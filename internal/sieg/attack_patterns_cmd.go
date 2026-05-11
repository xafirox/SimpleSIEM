package sieg

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// attack-patterns is an imperative builder for the operator-extensible
// regex set the network-ingest detector uses. Operators never edit
// attack-patterns.json by hand: every verb mutates one field of one
// pattern, and `enable` runs a regex-compile audit + MITRE ID checks
// before flipping a pattern live.
//
// The on-disk format is:
//
//   { "patterns": [
//       {"name": "...", "regex": "...", "tactic": "...",
//        "technique": "...", "description": "...", "disabled": true},
//       ...
//   ] }
//
// Drafts start with `disabled: true` and the regex is empty until the
// operator sets it. `enable` refuses to flip a pattern with no regex
// or one that fails to compile.

type attackPatternsFile struct {
	Patterns []attackPattern `json:"patterns"`
}

func loadAttackPatternsFile() (*attackPatternsFile, error) {
	path := attackPatternsPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &attackPatternsFile{Patterns: []attackPattern{}}, nil
		}
		return nil, err
	}
	var out attackPatternsFile
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("attack-patterns.json is not valid JSON: %w", err)
	}
	if out.Patterns == nil {
		out.Patterns = []attackPattern{}
	}
	return &out, nil
}

func writeAttackPatternsFile(f *attackPatternsFile) error {
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := os.MkdirAll(defaultConfigDir(), 0o750); err != nil {
		return err
	}
	return atomicWriteFile(attackPatternsPath(), body, 0o640)
}

func runAttackPatternsCmd(args []string) {
	if len(args) == 0 {
		attackPatternsUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "new":
		runAttackPatternsNew(args[1:])
	case "set":
		runAttackPatternsSet(args[1:])
	case "unset":
		runAttackPatternsUnset(args[1:])
	case "validate":
		runAttackPatternsValidate(args[1:])
	case "enable":
		runAttackPatternsEnable(args[1:])
	case "disable":
		runAttackPatternsDisable(args[1:])
	case "delete", "remove":
		runAttackPatternsDelete(args[1:])
	case "list":
		runAttackPatternsList(args[1:])
	case "show":
		runAttackPatternsShow(args[1:])
	case "test":
		runAttackPatternsTest(args[1:])
	case "help", "-h", "--help":
		attackPatternsUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown attack-patterns subcommand: %s\n", args[0])
		attackPatternsUsage()
		os.Exit(2)
	}
}

func attackPatternsUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem attack-patterns <subcommand> [args]

build a pattern (stepwise — never type JSON; new patterns start disabled):
  new <id>                              create a draft (disabled until enable)
  set <id> regex <pattern>              the regex to scan each frame against
                                        (validated at set time — RE2 syntax,
                                        rejects unclosed groups / lookahead /
                                        backrefs that Go's RE2 can't compile)
  set <id> tactic <ID>                  MITRE tactic (TA####)
  set <id> technique <ID>               MITRE technique (T####[.###])
  set <id> description "<text>"         one-line description carried into alerts
  unset <id> <field>                    remove a field

activate / deactivate / inspect:
  validate <id>                         dry-run audit (regex compiles, fields set)
  enable <id>                           validate then activate (refuses on error)
  disable <id>                          keep in file but stop matching
  delete <id>                           remove from attack-patterns.json
  list                                  one line per pattern (id, tactic, state)
  show <id>                             print the full pattern JSON
  test <id> "<frame>"                   match the pattern's regex against a literal frame
                                        (read-only — for tuning before enable)

example session:
  sudo simplesiem attack-patterns new internal-honeypot
  sudo simplesiem attack-patterns set internal-honeypot regex 'X-Honeytoken: [A-Z0-9]{16}'
  sudo simplesiem attack-patterns set internal-honeypot tactic TA0009
  sudo simplesiem attack-patterns set internal-honeypot technique T1056.001
  sudo simplesiem attack-patterns set internal-honeypot description "honeytoken header echoed back to attacker"
  sudo simplesiem attack-patterns enable internal-honeypot

The hot reload picks up the change within ~1 s. The hardcoded core pattern
set is unchanged — sidecar entries are MERGED with the core set at load
time. Disable a sidecar pattern (rather than deleting) to keep an audit
trail of the regex you used to run.`)
}

var attackPatternIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func runAttackPatternsNew(args []string) {
	if len(args) != 1 {
		fatalf("usage: attack-patterns new <id>")
	}
	if !attackPatternIDRe.MatchString(args[0]) {
		fatalf("pattern id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
	}
	mustAdmin()
	f, err := loadAttackPatternsFile()
	if err != nil {
		fatalf("%v", err)
	}
	for _, p := range f.Patterns {
		if p.Name == args[0] {
			fatalf("pattern %q already exists", args[0])
		}
	}
	f.Patterns = append(f.Patterns, attackPattern{Name: args[0], Disabled: true})
	if err := writeAttackPatternsFile(f); err != nil {
		fatalf("write attack-patterns.json: %v", err)
	}
	fmt.Printf("pattern %q created (disabled). Set its regex + MITRE tags, then `enable %s`.\n", args[0], args[0])
}

func withAttackPatternEdit(id string, mutate func(*attackPattern)) {
	mustAdmin()
	f, err := loadAttackPatternsFile()
	if err != nil {
		fatalf("%v", err)
	}
	for i := range f.Patterns {
		if f.Patterns[i].Name == id {
			mutate(&f.Patterns[i])
			if err := writeAttackPatternsFile(f); err != nil {
				fatalf("write attack-patterns.json: %v", err)
			}
			return
		}
	}
	fatalf("no pattern named %q (run `attack-patterns new %s` first)", id, id)
}

func runAttackPatternsSet(args []string) {
	if len(args) < 3 {
		fatalf("usage: attack-patterns set <id> <regex|tactic|technique|description> <value>")
	}
	id, field := args[0], args[1]
	value := strings.Join(args[2:], " ")
	switch field {
	case "regex":
		if _, err := regexp.Compile(value); err != nil {
			fatalf("regex does not compile: %v", err)
		}
		withAttackPatternEdit(id, func(p *attackPattern) { p.Regex = value })
		fmt.Printf("set %s.regex\n", id)
	case "tactic":
		if !regexp.MustCompile(`^TA[0-9]{4}$`).MatchString(value) {
			fatalf("tactic must be a MITRE ID like TA0006")
		}
		withAttackPatternEdit(id, func(p *attackPattern) { p.Tactic = value })
		fmt.Printf("set %s.tactic = %s\n", id, value)
	case "technique":
		if !regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`).MatchString(value) {
			fatalf("technique must be a MITRE ID like T1110 or T1110.001")
		}
		withAttackPatternEdit(id, func(p *attackPattern) { p.Technique = value })
		fmt.Printf("set %s.technique = %s\n", id, value)
	case "description":
		withAttackPatternEdit(id, func(p *attackPattern) { p.Description = value })
		fmt.Printf("set %s.description\n", id)
	default:
		fatalf("unknown field %q. valid: regex tactic technique description", field)
	}
}

func runAttackPatternsUnset(args []string) {
	if len(args) != 2 {
		fatalf("usage: attack-patterns unset <id> <field>")
	}
	id, field := args[0], args[1]
	withAttackPatternEdit(id, func(p *attackPattern) {
		switch field {
		case "regex":
			p.Regex = ""
		case "tactic":
			p.Tactic = ""
		case "technique":
			p.Technique = ""
		case "description":
			p.Description = ""
		default:
			fatalf("unknown field %q", field)
		}
	})
	fmt.Printf("unset %s.%s\n", id, field)
}

func auditAttackPattern(p *attackPattern) []string {
	var out []string
	if p.Name == "" {
		out = append(out, "name: missing")
	}
	if p.Regex == "" {
		out = append(out, "regex: not set (run `attack-patterns set "+p.Name+" regex <pattern>`)")
	} else if _, err := regexp.Compile(p.Regex); err != nil {
		out = append(out, "regex: does not compile ("+err.Error()+")")
	}
	if p.Tactic != "" && !regexp.MustCompile(`^TA[0-9]{4}$`).MatchString(p.Tactic) {
		out = append(out, "tactic: not a MITRE tactic ID")
	}
	if p.Technique != "" && !regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`).MatchString(p.Technique) {
		out = append(out, "technique: not a MITRE technique ID")
	}
	return out
}

func runAttackPatternsValidate(args []string) {
	if len(args) != 1 {
		fatalf("usage: attack-patterns validate <id>")
	}
	f, err := loadAttackPatternsFile()
	if err != nil {
		fatalf("%v", err)
	}
	for i := range f.Patterns {
		if f.Patterns[i].Name == args[0] {
			problems := auditAttackPattern(&f.Patterns[i])
			if len(problems) == 0 {
				fmt.Printf("pattern %q is complete and would enable cleanly.\n", args[0])
				return
			}
			fmt.Printf("pattern %q has %d problem(s):\n", args[0], len(problems))
			for _, p := range problems {
				fmt.Println("  -", p)
			}
			os.Exit(1)
		}
	}
	fatalf("no pattern named %q", args[0])
}

func runAttackPatternsEnable(args []string) {
	if len(args) != 1 {
		fatalf("usage: attack-patterns enable <id>")
	}
	mustAdmin()
	f, err := loadAttackPatternsFile()
	if err != nil {
		fatalf("%v", err)
	}
	for i := range f.Patterns {
		if f.Patterns[i].Name == args[0] {
			problems := auditAttackPattern(&f.Patterns[i])
			if len(problems) > 0 {
				fmt.Fprintf(os.Stderr, "cannot enable: pattern %q is not yet complete:\n", args[0])
				for _, p := range problems {
					fmt.Fprintln(os.Stderr, "  -", p)
				}
				fmt.Fprintln(os.Stderr, "\nfix the items above, then run `enable` again.")
				os.Exit(1)
			}
			f.Patterns[i].Disabled = false
			if err := writeAttackPatternsFile(f); err != nil {
				fatalf("write: %v", err)
			}
			fmt.Printf("pattern %q ENABLED — daemon hot-reloads within ~1s\n", args[0])
			return
		}
	}
	fatalf("no pattern named %q", args[0])
}

func runAttackPatternsDisable(args []string) {
	if len(args) != 1 {
		fatalf("usage: attack-patterns disable <id>")
	}
	withAttackPatternEdit(args[0], func(p *attackPattern) { p.Disabled = true })
	fmt.Printf("pattern %q disabled (kept in file)\n", args[0])
}

func runAttackPatternsDelete(args []string) {
	if len(args) != 1 {
		fatalf("usage: attack-patterns delete <id>")
	}
	mustAdmin()
	f, err := loadAttackPatternsFile()
	if err != nil {
		fatalf("%v", err)
	}
	out := f.Patterns[:0]
	removed := 0
	for _, p := range f.Patterns {
		if p.Name == args[0] {
			removed++
			continue
		}
		out = append(out, p)
	}
	if removed == 0 {
		fatalf("no pattern named %q", args[0])
	}
	f.Patterns = out
	if err := writeAttackPatternsFile(f); err != nil {
		fatalf("write: %v", err)
	}
	fmt.Printf("deleted %d pattern(s) named %q\n", removed, args[0])
}

func runAttackPatternsList(args []string) {
	_ = args
	f, err := loadAttackPatternsFile()
	if err != nil {
		fatalf("%v", err)
	}
	if len(f.Patterns) == 0 {
		fmt.Printf("(no operator patterns at %s — only the hardcoded core set is active)\n", attackPatternsPath())
		return
	}
	type row struct {
		name      string
		tactic    string
		technique string
		state     string
	}
	rows := make([]row, 0, len(f.Patterns))
	for _, p := range f.Patterns {
		state := "enabled"
		if p.Disabled {
			state = "disabled"
		}
		rows = append(rows, row{p.Name, p.Tactic, p.Technique, state})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	for _, r := range rows {
		fmt.Printf("  %-30s %-8s %-12s %s\n", r.name, r.tactic, r.technique, r.state)
	}
	fmt.Printf("\n%d pattern(s) at %s\n", len(rows), attackPatternsPath())
}

func runAttackPatternsShow(args []string) {
	if len(args) != 1 {
		fatalf("usage: attack-patterns show <id>")
	}
	f, err := loadAttackPatternsFile()
	if err != nil {
		fatalf("%v", err)
	}
	for _, p := range f.Patterns {
		if p.Name == args[0] {
			out, _ := json.MarshalIndent(p, "", "  ")
			fmt.Println(string(out))
			return
		}
	}
	fatalf("no pattern named %q", args[0])
}

// runAttackPatternsTest matches the pattern's regex against a literal
// frame the operator supplies. Read-only — useful for tuning a regex
// before flipping it live ("does this pattern match this benign log
// line I worry about?").
func runAttackPatternsTest(args []string) {
	if len(args) != 2 {
		fatalf("usage: attack-patterns test <id> \"<frame>\"")
	}
	f, err := loadAttackPatternsFile()
	if err != nil {
		fatalf("%v", err)
	}
	for _, p := range f.Patterns {
		if p.Name != args[0] {
			continue
		}
		if p.Regex == "" {
			fatalf("pattern %q has no regex — set it first", args[0])
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			fatalf("regex does not compile: %v", err)
		}
		if loc := re.FindStringIndex(args[1]); loc != nil {
			fmt.Printf("MATCH at bytes %d..%d: %q\n", loc[0], loc[1], args[1][loc[0]:loc[1]])
			return
		}
		fmt.Println("no match")
		return
	}
	fatalf("no pattern named %q", args[0])
}
