//go:build linux || darwin

package sieg

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func runDaemon(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	supervise := fs.Bool("supervise", false, "respawn the daemon if it exits non-zero (suitable for Docker CMD / non-systemd hosts)")
	_ = fs.Parse(args)

	if *supervise {
		runSuperviseLoop(*cfgPath)
		return
	}

	// Wrap the whole startup in a panic recover so a panic during init
	// produces a clear stderr message instead of a silent exit. The
	// stderr lands in `/var/log/simplesiem/daemon.log` (standalone
	// fork) or the journald unit log (systemd) so the operator can
	// see WHY the daemon refused to come up. systemd's Restart=on-
	// failure picks us back up after the non-zero exit.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "fatal: daemon panic during startup: %v\n", r)
			os.Exit(1)
		}
	}()

	d, err := startDaemon(*cfgPath)
	if err != nil {
		// Malformed config gets the loud banner; every other startup
		// failure (missing certs, port in use, etc.) falls through to
		// a regular log line.
		reportStartupError(err)
		os.Exit(1)
	}
	// Stamp our own PID into the standalone PID file so isRunning()
	// reflects reality. The PID file may be left over from a prior
	// run — most commonly, the operator invoked `simplesiem install`
	// at IMAGE BUILD time, which forked a daemon under buildkit's
	// transient PID namespace; the build then exited and committed
	// the resulting filesystem (including a now-stale PID file)
	// into the image layer. Every container started from that image
	// inherits that ghost PID, and `simplesiem status` reports
	// "not running" even when the daemon (us) is alive.
	//
	// Writing our PID here makes the file authoritative. Removing
	// it on clean exit keeps the file in sync with reality across
	// graceful stops. A panic-killed daemon may leave a stale file,
	// but isRunning's processExists check handles that path
	// (signal 0 to a missing PID returns ESRCH → ok=false).
	writeDaemonPIDFile()
	defer removeDaemonPIDFile()
	fmt.Fprintf(os.Stderr, "simplesiem daemon started (pid %d, build %s)\n", os.Getpid(), buildNumber)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	d.Stop()
}

// writeDaemonPIDFile records our PID at the canonical standalone
// location. Best-effort: a write failure (e.g. /var/run isn't writable
// in some containers) is swallowed — `simplesiem status` will fall
// back to the no-pid path, which is no worse than today.
func writeDaemonPIDFile() {
	_ = os.MkdirAll("/var/run", 0o755)
	_ = os.WriteFile(standalonePIDFile,
		[]byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
}

// removeDaemonPIDFile removes our PID file on clean shutdown. Best-
// effort; a leftover file is automatically detected as stale by
// processExists() on the next isRunning() call.
func removeDaemonPIDFile() {
	_ = os.Remove(standalonePIDFile)
}

// runSuperviseLoop runs `simplesiem run --config <cfg>` as a child
// and respawns on any non-zero exit. Exits cleanly when the child
// exits 0 (graceful stop) or on SIGINT/SIGTERM. Used as the Docker
// CMD on hosts without systemd: ensures a daemon panic / OS-OOM /
// transient cert issue doesn't leave the container without a
// running SIEM.
//
// Backoff: starts at 1 s, doubles per failed restart up to 30 s.
// Resets to 1 s after the child has been alive for 60+ s (so a
// chronically-failing config doesn't pin the loop at 30 s but a
// healthy daemon that's just been alive a while gets prompt
// recovery on its first crash).
func runSuperviseLoop(cfgPath string) {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "supervise: cannot resolve own executable: %v\n", err)
		os.Exit(1)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
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
		// Forward shutdown signals to the child.
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case sig := <-sigs:
			_ = cmd.Process.Signal(sig)
			<-done
			return
		case werr := <-done:
			if werr == nil {
				// Clean exit — operator-initiated stop. Don't respawn.
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
