package sieg

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// Alert delivery / escalation knobs. Distinct from `alerts` (triage/ack)
// so `simplesiem alerts` stays focused on incident response and
// `simplesiem alerts-cfg` covers the dispatcher posture.
//
// All flows write through the configReadMap / configWriteMap helpers so
// edits are atomic + schema-validated + hot-reloaded. The configWatcher
// in server.go picks up the change within ~1 s.
func runAlertsCfgCmd(args []string) {
	if len(args) == 0 {
		alertsCfgUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "webhook":
		runAlertsWebhookCmd(args[1:])
	case "syslog":
		runAlertsSyslogCmd(args[1:])
	case "escalation":
		runAlertsEscalationCmd(args[1:])
	case "bearer":
		runAlertsBearerCmd(args[1:])
	case "help", "-h", "--help":
		alertsCfgUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown alerts-cfg subcommand: %s\n", args[0])
		alertsCfgUsage()
		os.Exit(2)
	}
}

func alertsCfgUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem alerts-cfg <subcommand> [args]

subcommands:
  webhook list                              show configured webhook URLs + min-severity
  webhook add <url> [--min-severity X]      append a URL; X = low|medium|high|critical
  webhook remove <url>                      drop one URL by exact match
  webhook clear                             remove every configured webhook URL
  webhook min-severity <X>                  raise/lower the global webhook severity floor

  syslog show                               print the current alert_syslog block
  syslog set <network> <addr> [opts]        network = udp|tcp|udp6|tcp6
                                            opts: --facility N (default 16, local0)
                                                  --tag NAME   (default simplesiem)
                                                  --min-severity X
  syslog disable                            clear the alert_syslog block

  escalation show                           print the current escalation block
  escalation enable [opts]                  opts: --after Ns (default 900)
                                                  --min-severity X (default critical)
                                                  --scan-interval Ns (default 60)
  escalation disable                        turn off escalation re-fires

  bearer add <token>                        append a server bearer token
  bearer remove <token>                     drop one token by exact match
  bearer rotate <old> <new>                 atomic swap (no window with no token)
  bearer list                               show configured tokens (last 4 chars only)
  bearer clear                              remove every configured token

examples:
  simplesiem alerts-cfg webhook add https://alerts.example.com/hook --min-severity high
  simplesiem alerts-cfg syslog set udp syslog.example.com:514 --tag siem-prod
  simplesiem alerts-cfg escalation enable --after 600s --min-severity high
  simplesiem alerts-cfg bearer add 8d2a1c3e0f...`)
}

// --- webhook ----------------------------------------------------------

func runAlertsWebhookCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem alerts-cfg webhook <list|add|remove|clear|min-severity>")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		webhookList()
	case "add":
		webhookAdd(args[1:])
	case "remove":
		webhookRemove(args[1:])
	case "clear":
		webhookClear()
	case "min-severity":
		webhookMinSeverity(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown webhook subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func webhookList() {
	cfg := loadConfig(defaultConfigPath())
	if len(cfg.Server.AlertWebhooks) == 0 {
		fmt.Println("(no webhooks configured)")
		return
	}
	min := cfg.Server.AlertWebhookMinSeverity
	if min == "" {
		min = "low"
	}
	fmt.Printf("min_severity = %s\n", min)
	for _, u := range cfg.Server.AlertWebhooks {
		fmt.Println(u)
	}
}

func webhookAdd(args []string) {
	fs := flag.NewFlagSet("webhook add", flag.ExitOnError)
	min := fs.String("min-severity", "", "raise the floor below which alerts skip the webhook")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: webhook add <url> [--min-severity X]")
	}
	url := fs.Arg(0)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fatalf("webhook URL must start with http:// or https://")
	}
	mustAdmin()
	editServerStringList("alert_webhooks", func(list []string) []string {
		for _, u := range list {
			if u == url {
				return list
			}
		}
		return append(list, url)
	})
	if *min != "" {
		setServerStringField("alert_webhook_min_severity", strings.ToLower(*min))
	}
	fmt.Printf("added webhook %s\n", url)
}

func webhookRemove(args []string) {
	if len(args) != 1 {
		fatalf("usage: webhook remove <url>")
	}
	mustAdmin()
	editServerStringList("alert_webhooks", func(list []string) []string {
		out := list[:0]
		for _, u := range list {
			if u != args[0] {
				out = append(out, u)
			}
		}
		return out
	})
	fmt.Printf("removed webhook %s (if present)\n", args[0])
}

func webhookClear() {
	mustAdmin()
	editServerStringList("alert_webhooks", func(_ []string) []string { return nil })
	fmt.Println("cleared all webhooks")
}

func webhookMinSeverity(args []string) {
	if len(args) != 1 {
		fatalf("usage: webhook min-severity <low|medium|high|critical>")
	}
	if !validSeverityLevel(args[0]) {
		fatalf("severity must be one of: low, medium, high, critical")
	}
	mustAdmin()
	setServerStringField("alert_webhook_min_severity", strings.ToLower(args[0]))
	fmt.Printf("set webhook min_severity = %s\n", strings.ToLower(args[0]))
}

// --- syslog -----------------------------------------------------------

func runAlertsSyslogCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem alerts-cfg syslog <show|set|disable>")
		os.Exit(2)
	}
	switch args[0] {
	case "show":
		syslogShow()
	case "set":
		syslogSet(args[1:])
	case "disable":
		syslogDisable()
	default:
		fmt.Fprintf(os.Stderr, "unknown syslog subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func syslogShow() {
	cfg := loadConfig(defaultConfigPath())
	s := cfg.Server.AlertSyslog
	if s.Address == "" {
		fmt.Println("(alert_syslog not configured)")
		return
	}
	out, _ := json.MarshalIndent(s, "", "  ")
	fmt.Println(string(out))
}

func syslogSet(args []string) {
	fs := flag.NewFlagSet("syslog set", flag.ExitOnError)
	facility := fs.Int("facility", 16, "RFC 5424 facility 0..23 (default 16 = local0)")
	tag := fs.String("tag", "simplesiem", "appname / msgid prefix")
	min := fs.String("min-severity", "low", "low|medium|high|critical floor")
	args = permuteArgs(args, map[string]bool{"facility": true, "tag": true, "min-severity": true})
	_ = fs.Parse(args)
	if fs.NArg() != 2 {
		fatalf("usage: syslog set <network> <address> [--facility N] [--tag NAME] [--min-severity X]")
	}
	network := strings.ToLower(fs.Arg(0))
	switch network {
	case "udp", "tcp", "udp6", "tcp6":
	default:
		fatalf("network must be one of udp / tcp / udp6 / tcp6")
	}
	if !validSeverityLevel(*min) {
		fatalf("--min-severity must be one of: low, medium, high, critical")
	}
	if *facility < 0 || *facility > 23 {
		fatalf("--facility must be 0..23")
	}
	mustAdmin()
	editServerObject("alert_syslog", map[string]any{
		"network":      network,
		"address":      fs.Arg(1),
		"facility":     *facility,
		"tag":          *tag,
		"severity_min": strings.ToLower(*min),
	})
	fmt.Printf("alert_syslog set: %s://%s tag=%s min=%s facility=%d\n",
		network, fs.Arg(1), *tag, strings.ToLower(*min), *facility)
}

func syslogDisable() {
	mustAdmin()
	editServerObject("alert_syslog", map[string]any{})
	fmt.Println("alert_syslog disabled")
}

// --- escalation -------------------------------------------------------

func runAlertsEscalationCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem alerts-cfg escalation <show|enable|disable>")
		os.Exit(2)
	}
	switch args[0] {
	case "show":
		escalationShow()
	case "enable":
		escalationEnable(args[1:])
	case "disable":
		escalationDisable()
	default:
		fmt.Fprintf(os.Stderr, "unknown escalation subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func escalationShow() {
	cfg := loadConfig(defaultConfigPath())
	e := cfg.Server.AlertEscalation
	if !e.Enabled && e.AfterSeconds == 0 {
		fmt.Println("(alert_escalation not configured)")
		return
	}
	out, _ := json.MarshalIndent(e, "", "  ")
	fmt.Println(string(out))
}

func escalationEnable(args []string) {
	fs := flag.NewFlagSet("escalation enable", flag.ExitOnError)
	after := fs.String("after", "900s", "re-fire window (e.g. 900s, 15m)")
	min := fs.String("min-severity", "critical", "low|medium|high|critical floor")
	scan := fs.String("scan-interval", "60s", "alerts-log scan cadence")
	args = permuteArgs(args, map[string]bool{"after": true, "min-severity": true, "scan-interval": true})
	_ = fs.Parse(args)
	if !validSeverityLevel(*min) {
		fatalf("--min-severity must be one of: low, medium, high, critical")
	}
	afterSec, err := parseDurationSeconds(*after)
	if err != nil {
		fatalf("--after: %v", err)
	}
	scanSec, err := parseDurationSeconds(*scan)
	if err != nil {
		fatalf("--scan-interval: %v", err)
	}
	mustAdmin()
	editServerObject("alert_escalation", map[string]any{
		"enabled":               true,
		"after_seconds":         afterSec,
		"min_severity":          strings.ToLower(*min),
		"scan_interval_seconds": scanSec,
	})
	fmt.Printf("alert_escalation enabled: after %ds, min=%s, scan every %ds\n",
		afterSec, strings.ToLower(*min), scanSec)
}

func escalationDisable() {
	mustAdmin()
	editServerObject("alert_escalation", map[string]any{"enabled": false})
	fmt.Println("alert_escalation disabled")
}

// --- bearer tokens ----------------------------------------------------

func runAlertsBearerCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: simplesiem alerts-cfg bearer <list|add|remove|rotate|clear>")
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		bearerList()
	case "add":
		bearerAdd(args[1:])
	case "remove":
		bearerRemove(args[1:])
	case "rotate":
		bearerRotate(args[1:])
	case "clear":
		bearerClear()
	default:
		fmt.Fprintf(os.Stderr, "unknown bearer subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func bearerList() {
	cfg := loadConfig(defaultConfigPath())
	if len(cfg.Server.BearerTokens) == 0 {
		fmt.Println("(no bearer tokens configured)")
		return
	}
	for _, t := range cfg.Server.BearerTokens {
		// Only show suffix so an operator can confirm "yes, that
		// token is on the list" without leaking the secret.
		suffix := t
		if len(t) > 4 {
			suffix = t[len(t)-4:]
		}
		fmt.Printf("...%s\n", suffix)
	}
}

func bearerAdd(args []string) {
	if len(args) != 1 {
		fatalf("usage: bearer add <token>")
	}
	if len(args[0]) < 16 {
		fatalf("token must be at least 16 characters")
	}
	mustAdmin()
	editServerStringList("bearer_tokens", func(list []string) []string {
		for _, t := range list {
			if t == args[0] {
				return list
			}
		}
		return append(list, args[0])
	})
	fmt.Println("bearer token added")
}

func bearerRemove(args []string) {
	if len(args) != 1 {
		fatalf("usage: bearer remove <token>")
	}
	mustAdmin()
	editServerStringList("bearer_tokens", func(list []string) []string {
		out := list[:0]
		for _, t := range list {
			if t != args[0] {
				out = append(out, t)
			}
		}
		return out
	})
	fmt.Println("bearer token removed (if present)")
}

func bearerRotate(args []string) {
	if len(args) != 2 {
		fatalf("usage: bearer rotate <old> <new>")
	}
	if len(args[1]) < 16 {
		fatalf("new token must be at least 16 characters")
	}
	mustAdmin()
	editServerStringList("bearer_tokens", func(list []string) []string {
		// Add new BEFORE removing old so there's never a window
		// where neither is accepted.
		hasNew := false
		for _, t := range list {
			if t == args[1] {
				hasNew = true
			}
		}
		if !hasNew {
			list = append(list, args[1])
		}
		out := list[:0]
		for _, t := range list {
			if t != args[0] {
				out = append(out, t)
			}
		}
		return out
	})
	fmt.Println("bearer token rotated")
}

func bearerClear() {
	mustAdmin()
	editServerStringList("bearer_tokens", func(_ []string) []string { return nil })
	fmt.Println("all bearer tokens cleared")
}
