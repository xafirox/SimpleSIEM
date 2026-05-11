//go:build windows

package sieg

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"time"

	"golang.org/x/sys/windows/svc"
)

// writeCrashLog appends a panic signature + stack trace to
// <ProgramData>/SimpleSIEM/crash.log so an operator faced with a
// silent "service terminated unexpectedly" SCM event can see exactly
// what went wrong. SCM swallows stderr; this is the only durable trail.
func writeCrashLog(rec any) {
	dir := defaultConfigDir()
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, "crash.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "===== %s panic =====\n%v\n%s\n",
		time.Now().UTC().Format(time.RFC3339Nano), rec, debug.Stack())
}

// winService bridges SCM control messages to our daemon lifecycle.
type winService struct {
	cfgPath string
}

func (s *winService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecific bool, exitCode uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Diagnostic shim: SCM swallows stderr, so a panic propagating to
	// svc.Run produces only a bare "service terminated unexpectedly"
	// event log entry. Capture the panic value + Go stack to
	// <ProgramData>/SimpleSIEM/crash.log BEFORE re-raising so SCM
	// still sees the crash and operators have something to triage
	// against. NOT a recovery — the daemon still exits abnormally.
	defer func() {
		if rec := recover(); rec != nil {
			writeCrashLog(rec)
			panic(rec)
		}
	}()

	d, err := startDaemon(s.cfgPath)
	if err != nil {
		reportStartupError(err)
		return true, 1
	}
	changes <- svc.Status{State: svc.Running, Accepts: accepts}

loop:
	for {
		req := <-r
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			break loop
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	d.Stop()
	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	supervise := fs.Bool("supervise", false, "respawn the daemon if it exits non-zero (useful for hosts without SCM auto-restart)")
	_ = fs.Parse(args)

	if *supervise {
		runSuperviseLoop(*cfgPath)
		return
	}

	isSvc, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("windows service check: %v", err)
	}
	if isSvc {
		if err := svc.Run(serviceName, &winService{cfgPath: *cfgPath}); err != nil {
			log.Fatalf("svc.Run: %v", err)
		}
		return
	}
	// Console mode: Ctrl+C to stop. Wrap in panic recover so a panic
	// during init produces a visible stderr message instead of a
	// silent exit (the SCM Restart= mirror, but for console runs).
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "fatal: daemon panic during startup: %v\n", r)
			os.Exit(1)
		}
	}()
	d, err := startDaemon(*cfgPath)
	if err != nil {
		reportStartupError(err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "simplesiem daemon started (pid %d, build %s)\n", os.Getpid(), buildNumber)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	<-sigs
	d.Stop()
}

// runSuperviseLoop runs `simplesiem run --config <cfg>` as a child
// and respawns on any non-zero exit. Exits cleanly when the child
// exits 0 or on Ctrl+C. Lets a Windows-without-SCM run survive a
// daemon panic without manual intervention.
func runSuperviseLoop(cfgPath string) {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: cannot resolve own executable: %v\n", err)
		os.Exit(1)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		started := time.Now()
		cmd := exec.Command(self, "run", "--config", cfgPath)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "supervise: child start failed: %v (sleeping %s)\n", err, backoff)
			select {
			case <-sigs:
				return
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-sigs:
			_ = cmd.Process.Kill()
			<-done
			return
		case werr := <-done:
			if werr == nil {
				return
			}
			alive := time.Since(started)
			fmt.Fprintf(os.Stderr, "supervise: child exited after %s with %v; respawning in %s\n",
				alive.Round(time.Second), werr, backoff)
			if alive > 60*time.Second {
				backoff = time.Second
			} else if backoff < maxBackoff {
				backoff *= 2
			}
			select {
			case <-sigs:
				return
			case <-time.After(backoff):
			}
		}
	}
}
