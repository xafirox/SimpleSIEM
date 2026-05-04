package sieg

import (
	"flag"
	"fmt"
	"time"
)

// quietServiceOutput, when true, suppresses the trailing "service
// stopped" / "service started" lines that stopCommand and startCommand
// print on success. Set only by restartCommand so a single restart
// reads as one operation in CLI output. Sequential within one
// goroutine — no concurrency.
var quietServiceOutput bool

// restartCommand is the cross-platform `simplesiem restart` operator
// command. It calls stopCommand + startCommand back-to-back, with a
// short pause between so the OS service manager (systemd / launchd /
// SCM) has time to reflect the stop before start asks for status.
//
// If the daemon isn't currently running, the stop step is skipped —
// restart on a stopped daemon is equivalent to start. This makes the
// command safe to run unconditionally, e.g. as the final step of any
// config-mutating workflow (realm rename, certs server, etc.).
//
// startCommand and stopCommand are defined per-platform in
// service_unix.go (linux + darwin) and service_windows.go, so this
// shared dispatcher works identically on every supported OS without
// platform-specific code.
//
// Output is intentionally one line: a `restarting daemon...` /
// `service restarted` pair. The inner stop/start prints are suppressed
// via quietServiceOutput so the operator doesn't see four lines that
// look like two separate operations.
func restartCommand(args []string) {
	fs := flag.NewFlagSet("restart", flag.ExitOnError)
	_ = fs.Parse(args)
	fmt.Println("restarting daemon...")
	quietServiceOutput = true
	defer func() { quietServiceOutput = false }()
	if isRunning() {
		stopCommand(nil)
		// Brief pause so the service manager has settled the stop
		// before start re-checks. 500ms is enough for systemd /
		// launchctl / SCM in every case we've seen.
		time.Sleep(500 * time.Millisecond)
	}
	startCommand(nil)
	fmt.Println("service restarted")
}
