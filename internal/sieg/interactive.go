package sieg

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type menuOption struct {
	label  string
	action func()
}

// stdinReader is a process-lifetime reader so prompts don't drop buffered data
// between menu iterations.
var stdinReader = bufio.NewReader(os.Stdin)

func readLine(prompt string) string {
	fmt.Print(prompt)
	line, _ := stdinReader.ReadString('\n')
	return strings.TrimSpace(line)
}

// runInteractiveMenu is shown when the binary is launched without a subcommand
// (e.g., by double-clicking). It adapts to the current service state and
// exposes every operator-facing feature documented in the README.
func runInteractiveMenu() {
	for {
		installed := isInstalled()
		running := installed && isRunning()
		mode := normaliseMode(loadConfig(defaultConfigPath()).Mode)

		fmt.Println()
		fmt.Println("======================================")
		fmt.Println("  " + productName + " - on-box SIEM manager")
		fmt.Println("  " + versionString())
		fmt.Println("======================================")
		fmt.Println()
		switch {
		case !installed:
			fmt.Printf("  Status: NOT INSTALLED  (configured mode: %s)\n", mode)
		case running:
			fmt.Printf("  Status: INSTALLED, RUNNING  (mode: %s)\n", mode)
		default:
			fmt.Printf("  Status: INSTALLED, STOPPED  (mode: %s)\n", mode)
		}
		fmt.Println()

		opts := buildMenu(installed, running)
		printMenu(opts)
		fmt.Println()

		choice := readLine("Choice: ")
		if choice == "" || strings.EqualFold(choice, "q") {
			return
		}
		idx, err := strconv.Atoi(choice)
		if err != nil {
			fmt.Println("invalid choice")
			continue
		}
		// User-visible numbering counts only actionable options (skips
		// section headers, which carry action == nil). Walk opts and
		// pick the idx-th selectable entry. Without this skip, picking
		// "1" landed on the "-- Service --" header and the menu nil-
		// dereferenced its action.
		action := nthAction(opts, idx)
		if action == nil {
			fmt.Println("invalid choice")
			continue
		}
		action()
	}
}

// nthAction returns the action of the n-th selectable (non-header) entry
// in opts, 1-indexed to match the on-screen numbering. Returns nil when
// n is out of range.
func nthAction(opts []menuOption, n int) func() {
	if n < 1 {
		return nil
	}
	count := 0
	for _, o := range opts {
		if o.action == nil {
			continue
		}
		count++
		if count == n {
			return o.action
		}
	}
	return nil
}

// printMenu renders the option list with section headers — entries with
// label "" are treated as separators.
func printMenu(opts []menuOption) {
	displayIdx := 0
	for _, o := range opts {
		if o.action == nil {
			// header / separator
			fmt.Println()
			fmt.Println("  " + o.label)
			continue
		}
		displayIdx++
		fmt.Printf("  %2d) %s\n", displayIdx, o.label)
	}
}

func buildMenu(installed, running bool) []menuOption {
	var opts []menuOption
	header := func(s string) { opts = append(opts, menuOption{label: s, action: nil}) }
	add := func(label string, action func()) {
		opts = append(opts, menuOption{label: label, action: action})
	}

	header("-- Service --")
	switch {
	case !installed:
		add("Install (start now + at every boot)", func() { elevateAndRun([]string{"install"}) })
	case running:
		add("Stop the running service", func() { elevateAndRun([]string{"stop"}) })
		add("Fix / repair installation", func() { elevateAndRun([]string{"fix"}) })
		add("Uninstall", func() { elevateAndRun([]string{"uninstall"}) })
	default:
		add("Start the service", func() { elevateAndRun([]string{"start"}) })
		add("Fix / repair installation", func() { elevateAndRun([]string{"fix"}) })
		add("Uninstall", func() { elevateAndRun([]string{"uninstall"}) })
	}
	if installed {
		add("Convert mode (standalone / agent / server)", convertPrompt)
	}

	header("-- View --")
	add("Triage events (timeline reconstruction)", triagePrompt)
	add("Live tail (follow new events)", tailPrompt)
	add("Recent alerts", alertsPrompt)
	add("Verify log integrity (hash chain)", verifyPrompt)
	add("Raw query (JSONL filter)", queryPrompt)
	add("Show status (mode / volume / health)", func() { runStatus(nil) })

	header("-- Manage --")
	add("Rules: check or test rules.json", rulesPrompt)
	add("Certificates: init / sign / server (PKI)", certsPrompt)

	opts = append(opts, menuOption{label: "Quit", action: func() { os.Exit(0) }})
	return opts
}

// ---------- read-only command prompts ----------

// triagePrompt gathers the inputs runTriage needs and dispatches. The
// pivot type is chosen first; flags (window, type, explain, host) are
// collected afterwards as common options.
func triagePrompt() {
	for {
		fmt.Println()
		fmt.Println("Triage - show events around a pivot or in a time range:")
		fmt.Println("   1) A file path                        (--file)")
		fmt.Println("   2) A process ID                       (--pid)")
		fmt.Println("   3) Text / regex match                 (--grep)")
		fmt.Println("   4) A specific time                    (--at)")
		fmt.Println("   5) A structured field (key=value)     (--field)")
		fmt.Println("   6) Last N (range mode)                (--since)")
		fmt.Println("   7) Explicit start/end window          (--start/--end)")
		fmt.Println("   8) Back")
		fmt.Println()
		choice := readLine("Choice: ")
		var args []string
		switch choice {
		case "1":
			v := readLine("File path: ")
			if v == "" {
				continue
			}
			args = []string{"--file", v}
		case "2":
			v := readLine("PID: ")
			if v == "" {
				continue
			}
			args = []string{"--pid", v}
		case "3":
			v := readLine("Search text or regex: ")
			if v == "" {
				continue
			}
			args = []string{"--grep", v}
		case "4":
			v := readLine("Time (RFC3339, 'now', '2pm today', '14:30'): ")
			if v == "" {
				continue
			}
			args = []string{"--at", v}
		case "5":
			v := readLine("Field expression (e.g. path=*=authorized_keys): ")
			if v == "" {
				continue
			}
			args = []string{"--field", v}
		case "6":
			v := readLine("Range (30m, 2h, 7d): ")
			if v == "" {
				continue
			}
			args = []string{"--since", v}
		case "7":
			s := readLine("Start time: ")
			if s == "" {
				continue
			}
			e := readLine("End time (default: now): ")
			args = []string{"--start", s}
			if e != "" {
				args = append(args, "--end", e)
			}
		case "8", "b", "back", "":
			return
		default:
			fmt.Println("invalid choice")
			continue
		}
		// Common options for any pivot/range invocation.
		if t := readLine("Type filter (network/files/auth/processes/traffic/meta/errors/alerts; blank=all): "); t != "" {
			args = append(args, "--type", t)
		}
		if w := readLine("Window in seconds (default 30, blank to use chosen mode default): "); w != "" {
			args = append(args, "--window", w+"s")
		}
		if h := readLine("Host filter (server mode; blank=all): "); h != "" {
			args = append(args, "--host", h)
		}
		if strings.EqualFold(readLine("Show --explain for alerts? [y/N]: "), "y") {
			args = append(args, "--explain")
		}
		fmt.Println()
		runTriage(args)
		pause()
	}
}

func tailPrompt() {
	fmt.Println()
	fmt.Println("Live tail - follow new events as they're written.")
	args := []string{}
	if strings.EqualFold(readLine("Alerts only? [y/N]: "), "y") {
		args = append(args, "--alerts")
	} else if t := readLine("Type filter (comma-separated; blank=all): "); t != "" {
		args = append(args, "--type", t)
	}
	if g := readLine("Grep regex (blank=none): "); g != "" {
		args = append(args, "--grep", g)
	}
	if h := readLine("Host filter (server mode; blank=all): "); h != "" {
		args = append(args, "--host", h)
	}
	if strings.EqualFold(readLine("Raw JSON output? [y/N]: "), "y") {
		args = append(args, "--json")
	}
	fmt.Println("(Ctrl-C to stop)")
	fmt.Println()
	runTail(args)
}

func alertsPrompt() {
	fmt.Println()
	fmt.Println("Recent alerts:")
	args := []string{}
	since := readLine("Window (default 1h; e.g. 30m, 7d): ")
	if since == "" {
		since = "1h"
	}
	args = append(args, "--since", since)
	if sev := readLine("Severity filter (low/medium/high/critical; blank=all): "); sev != "" {
		args = append(args, "--severity", sev)
	}
	if h := readLine("Host filter (server mode; blank=all): "); h != "" {
		args = append(args, "--host", h)
	}
	fmt.Println()
	runAlertsCmd(args)
	pause()
}

func verifyPrompt() {
	fmt.Println()
	fmt.Println("Verify log integrity (hash chain):")
	fmt.Println("   1) Yesterday + today (default)")
	fmt.Println("   2) A specific date (YYYY-MM-DD)")
	fmt.Println("   3) Every file under the log dir (--all)")
	fmt.Println("   4) Back")
	fmt.Println()
	choice := readLine("Choice: ")
	var args []string
	switch choice {
	case "1", "":
		args = []string{}
	case "2":
		d := readLine("Date (YYYY-MM-DD): ")
		if d == "" {
			return
		}
		args = []string{"--date", d}
	case "3":
		args = []string{"--all"}
	case "4", "b", "back":
		return
	default:
		fmt.Println("invalid choice")
		return
	}
	if t := readLine("Type filter (blank=all): "); t != "" {
		args = append(args, "--type", t)
	}
	if h := readLine("Host filter (server mode; blank=all): "); h != "" {
		args = append(args, "--host", h)
	}
	if strings.EqualFold(readLine("Verbose (one OK line per file)? [y/N]: "), "y") {
		args = append(args, "-v")
	}
	fmt.Println()
	runVerify(args)
	pause()
}

func queryPrompt() {
	fmt.Println()
	fmt.Println("Raw JSONL query - emit raw lines for piping into jq, etc.")
	args := []string{}
	if t := readLine("Type filter (blank=all): "); t != "" {
		args = append(args, "--type", t)
	}
	if s := readLine("Since (e.g. 1h, 30m, 2026-04-25T00:00:00Z; blank=no lower bound): "); s != "" {
		args = append(args, "--since", s)
	}
	if u := readLine("Until (e.g. 'now', '2pm today'; blank=no upper bound): "); u != "" {
		args = append(args, "--until", u)
	}
	if g := readLine("Grep regex (blank=none): "); g != "" {
		args = append(args, "--grep", g)
	}
	if f := readLine("Field filter key=value (blank=none): "); f != "" {
		args = append(args, "--field", f)
	}
	if h := readLine("Host filter (server mode; blank=all): "); h != "" {
		args = append(args, "--host", h)
	}
	if l := readLine("Limit (blank=no limit): "); l != "" {
		args = append(args, "--limit", l)
	}
	fmt.Println()
	runQuery(args)
	pause()
}

func rulesPrompt() {
	fmt.Println()
	fmt.Println("Rules:")
	fmt.Println("   1) Check rules.json (parse + compile)")
	fmt.Println("   2) Test rules against a JSONL events file")
	fmt.Println("   3) Back")
	fmt.Println()
	switch readLine("Choice: ") {
	case "1":
		runRulesCmd([]string{"check"})
	case "2":
		path := readLine("Events file path (or '-' for stdin): ")
		if path == "" {
			return
		}
		args := []string{"test", path}
		if strings.EqualFold(readLine("Use threshold/dedup state across events? [y/N]: "), "y") {
			args = append(args, "--with-threshold")
		}
		runRulesCmd(args)
	case "3", "b", "back", "":
		return
	default:
		fmt.Println("invalid choice")
		return
	}
	pause()
}

// ---------- admin-required prompts ----------

func certsPrompt() {
	fmt.Println()
	fmt.Println("Certificates - bundled PKI for agent/server mTLS.")
	fmt.Println("   1) Initialize the CA (one-time, on the server)")
	fmt.Println("   2) Issue a server certificate")
	fmt.Println("   3) Show the enrollment PSK (paste into agents' --key)")
	fmt.Println("   4) Rotate the enrollment PSK (invalidates old; agents already enrolled keep working)")
	fmt.Println("   5) Back")
	fmt.Println()
	switch readLine("Choice: ") {
	case "1":
		fmt.Println()
		fmt.Println("This will generate ca.pem + ca.key under <config>/certs/.")
		fmt.Println("Keep ca.key on the server only — anyone with it can mint client certs.")
		if !confirmYes() {
			return
		}
		elevateAndRun([]string{"certs", "init"})
	case "2":
		host := readLine("Hostname (CN): ")
		if host == "" {
			return
		}
		extra := readLine("Extra hostnames or IPs (space-separated; blank=none): ")
		args := []string{"certs", "server", host}
		args = append(args, strings.Fields(extra)...)
		// If a server cert already exists, the underlying writePEM
		// would refuse to overwrite. That's correct as a safety net,
		// but a baffling failure inside the menu's "issue a server
		// certificate" option. Detect it, ask, and pass --force.
		// The running server hot-reloads its cert from disk, so the
		// new one takes effect within ~1s with no manual restart.
		serverPem := filepath.Join(certsDir(defaultConfigPath()), "server.pem")
		if _, err := os.Stat(serverPem); err == nil {
			fmt.Printf("\nA server certificate already exists at %s.\n", serverPem)
			fmt.Println("Replacing it is safe IF the CA is unchanged — agents trust the CA, not")
			fmt.Println("the specific server cert, and the running server will hot-reload the")
			fmt.Println("new one within a second (no manual restart needed).")
			if !confirmYes("Replace it? [y/N] ") {
				fmt.Println("kept existing cert; nothing changed.")
				return
			}
			args = append(args, "--force")
		}
		elevateAndRun(args)
	case "3":
		// Show the PSK. Reading the file requires root (mode 0600), so
		// this routes through elevateAndRun the same as everything else.
		elevateAndRun([]string{"certs", "psk", "show"})
	case "4":
		fmt.Println()
		fmt.Println("Rotating the PSK invalidates any old PSK value still in someone's clipboard.")
		fmt.Println("Agents that have already enrolled keep working — they use mTLS, not the PSK.")
		fmt.Println("Future agent installs / convert agent commands need the new PSK.")
		if !confirmYes() {
			return
		}
		elevateAndRun([]string{"certs", "psk", "rotate", "--force"})
	case "5", "b", "back", "":
		return
	default:
		fmt.Println("invalid choice")
	}
	pause()
}

func convertPrompt() {
	fmt.Println()
	fmt.Println("Convert mode - changes how this install collects and stores events.")
	fmt.Println("   1) standalone (collect locally, store on disk)")
	fmt.Println("   2) agent      (collect locally, ship to a server over mTLS)")
	fmt.Println("   3) server     (receive batches from agents)")
	fmt.Println("   4) Back")
	fmt.Println()
	choice := readLine("Choice: ")
	var target string
	switch choice {
	case "1":
		target = "standalone"
	case "2":
		target = "agent"
	case "3":
		target = "server"
	case "4", "b", "back", "":
		return
	default:
		fmt.Println("invalid choice")
		return
	}
	args := []string{"convert", target}

	// Preserve-old is the default now. Only opt-out if the operator
	// explicitly answers "n" — pass --keep-old=false to convert.
	if strings.EqualFold(readLine("Preserve existing standalone logs under _legacy/? [Y/n]: "), "n") {
		args = append(args, "--keep-old=false")
	}

	switch target {
	case "agent":
		if v := readLine("agent.id (blank = auto from hostname): "); v != "" {
			args = append(args, "--id", v)
		}
		if v := readLine("agent.server_url (e.g. https://siem.example.com:9443; blank = edit later): "); v != "" {
			args = append(args, "--server", v)
		}
	case "server":
		if v := readLine("server.listen (default :9443): "); v != "" {
			args = append(args, "--listen", v)
		}
	}

	// The elevated child shows the warning + asks for confirmation.
	// Don't pass -y so the user reads the impact in the privileged context.
	elevateAndRun(args)
	pause()
}

func pause() {
	fmt.Println()
	if runtime.GOOS == "windows" {
		fmt.Print("Press Enter to close this window...")
	} else {
		fmt.Print("Press Enter to continue...")
	}
	stdinReader.ReadString('\n')
}

// runSubcommand dispatches an already-parsed subcommand within the current
// process. Used by the elevation path: when this binary is re-execed as
// root or under UAC, it lands here with the explicit args list rather
// than going through main()'s argv parsing.
func runSubcommand(args []string) {
	if len(args) == 0 {
		return
	}
	name := args[0]
	rest := args[1:]
	switch name {
	case "install":
		installService(rest)
	case "uninstall":
		uninstallService(rest)
	case "start":
		startCommand(rest)
	case "stop":
		stopCommand(rest)
	case "fix":
		runFix(rest)
	case "convert":
		runConvertCmd(rest)
	case "certs":
		runCertsCmd(rest)
	case "rules":
		runRulesCmd(rest)
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", name)
	}
}
