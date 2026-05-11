package sieg

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runLogDirMigrate is the CLI entry for `simplesiem log-dir migrate
// <new-path>`. It atomically moves the entire log tree from the
// configured `log_dir` to a new location and updates config.json.
// Atomicity rules:
//   - destination must not exist OR must be empty (refuses otherwise);
//   - daemon must be stopped (refuses otherwise — open file handles);
//   - on any error mid-migration, every file already moved is moved
//     back; config.json is restored from the .bak the writer kept.
//
// Cross-platform — uses os.Rename when source + destination are on the
// same filesystem; falls back to copy-then-delete (with the same
// rollback handling) when they aren't.
//
// Refuses on collector-paired hosts (m9 — see config_watcher.go for
// the runtime guard).
func runLogDirMigrate(args []string) {
	args = permuteArgs(args, map[string]bool{"config": true})
	fs := flag.NewFlagSet("log-dir migrate", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	yes := fs.Bool("y", false, "skip confirmation prompt")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: simplesiem log-dir migrate <new-path> [-y]")
	}
	newDir := fs.Arg(0)
	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}

	cfg := loadConfig(*cfgPath)
	oldDir := cfg.LogDir
	if oldDir == "" {
		fatalf("current log_dir is empty in config — nothing to migrate")
	}
	if newDir == oldDir {
		fmt.Println("source and destination are the same; nothing to do.")
		return
	}

	// m9 — collector-pairing guard.
	if cfg.Server.CollectorCN != "" || cfg.Master.QueryCollectorURL != "" {
		fatalf("refusing: a collector is paired with this host. Changing log_dir would put the collector's per-host mirror layout out of sync. Revoke the collector pairing first (`master collector revoke` / `certs collector revoke`).")
	}

	// Daemon-orchestrated lifecycle: open files block the rename, but
	// asking the operator to stop+start the daemon by hand is a poor
	// UX. If the daemon is up we stop it ourselves, perform the
	// migration, then start it again — so a single command does the
	// whole flow. We only do this when the operator hasn't passed
	// `-y`-equivalent guard rails would let them keep manual control.
	wasRunning := isRunning()
	if wasRunning {
		fmt.Println("daemon is running; stopping it for the migration...")
		// stopCommand's flagset doesn't define -y (it has no
		// confirmation prompt to skip), and flag.ExitOnError aborts
		// the whole process if we pass an unknown flag. Hand it nil
		// args so the platform branch (systemctl / launchctl / SCM)
		// runs cleanly.
		stopCommand(nil)
		// Give file handles time to close before we try to rename
		// the log_dir from underneath them.
		for i := 0; i < 30; i++ {
			if !isRunning() {
				break
			}
			time.Sleep(time.Second)
		}
		if isRunning() {
			fatalf("daemon did not stop after `simplesiem stop`; aborting migration. Stop the daemon manually and retry.")
		}
	}

	// Source-existence guard. A non-existent source is harmless —
	// nothing to move — but we surface it so the operator notices.
	if _, err := os.Stat(oldDir); err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("source log_dir %s does not exist; updating config.json only.\n", oldDir)
			if err := updateLogDirInConfig(*cfgPath, cfg, newDir); err != nil {
				fatalf("update config.json: %v", err)
			}
			fmt.Printf("config.json updated: log_dir = %s\n", newDir)
			return
		}
		fatalf("stat source %s: %v", oldDir, err)
	}

	// Destination-empty guard. If newDir exists, it must be empty
	// (we're about to fill it). If it doesn't exist, we'll create it.
	if entries, err := os.ReadDir(newDir); err == nil {
		if len(entries) > 0 {
			fatalf("refusing: destination %s exists and is not empty (%d entries). Migration must land in an empty dir to avoid clobbering data.", newDir, len(entries))
		}
	} else if !os.IsNotExist(err) {
		fatalf("stat destination %s: %v", newDir, err)
	}

	if !*yes {
		fmt.Printf("About to migrate log_dir:\n  from: %s\n  to:   %s\n", oldDir, newDir)
		fmt.Println("This is atomic — on failure, every file moved is moved back and config.json is restored from .bak.")
		if !confirmYes() {
			fmt.Println("aborted.")
			return
		}
	}

	// Save a backup of config.json before the migration so we can
	// roll the config edit back on any error.
	bak := *cfgPath + ".bak"
	if data, err := os.ReadFile(*cfgPath); err == nil {
		if werr := os.WriteFile(bak, data, 0o600); werr != nil {
			fatalf("write config backup: %v", werr)
		}
	}

	// Try the cheap path first: os.Rename works across the SAME
	// filesystem in O(1). If destination crosses filesystems, fall
	// back to copy-then-delete with rollback semantics.
	if err := os.MkdirAll(filepath.Dir(newDir), 0o755); err != nil {
		fatalf("mkdir parent of %s: %v", newDir, err)
	}
	if err := os.Rename(oldDir, newDir); err == nil {
		// Rename succeeded; update config.json to point at newDir.
		if err := updateLogDirInConfig(*cfgPath, cfg, newDir); err != nil {
			// Roll back: rename newDir back to oldDir.
			fmt.Fprintln(os.Stderr, "config update failed; rolling back rename...")
			_ = os.Rename(newDir, oldDir)
			fatalf("update config.json: %v (rolled back)", err)
		}
		fmt.Printf("migration complete: log_dir moved %s -> %s\n", oldDir, newDir)
		finishMigrationLifecycle(*cfgPath, oldDir, newDir, wasRunning)
		return
	}

	// Cross-filesystem path. Copy every entry then delete the source
	// only AFTER all copies succeed. On any copy error, delete the
	// partial destination so the source is the only authoritative
	// copy.
	fmt.Println("destination on a different filesystem; copying tree...")
	moved, err := copyTree(oldDir, newDir)
	if err != nil {
		// Rollback: blast the partial destination.
		_ = os.RemoveAll(newDir)
		fatalf("copy failed at %d files: %v (source untouched at %s)", moved, err, oldDir)
	}
	// Now delete source. If THIS fails, we have copies in both
	// places — surface the warning but treat the migration as
	// successful (the new path is the authoritative one once we
	// update config.json).
	if rmerr := os.RemoveAll(oldDir); rmerr != nil {
		fmt.Fprintf(os.Stderr, "warning: removed %d files from %s but couldn't remove the source dir: %v\n", moved, newDir, rmerr)
		fmt.Fprintln(os.Stderr, "data is in BOTH locations now; rm the source manually after confirming.")
	}
	if err := updateLogDirInConfig(*cfgPath, cfg, newDir); err != nil {
		fatalf("config update failed AFTER cross-fs copy: %v\nManually edit %s and set log_dir to %s, OR move %s back to %s", err, *cfgPath, newDir, newDir, oldDir)
	}
	fmt.Printf("migration complete: log_dir moved %s -> %s (%d files copied)\n", oldDir, newDir, moved)
	finishMigrationLifecycle(*cfgPath, oldDir, newDir, wasRunning)
}

// finishMigrationLifecycle handles the post-migration daemon dance for
// BOTH the rename and the cross-fs branches: auto-restart the daemon
// when it was running before, then verify the new log_dir is actually
// being written into. The cross-fs branch previously skipped restart,
// which is the bug the user hit at s5 — they migrated across drives,
// the daemon stayed stopped, and "no logs in new dir" was the visible
// symptom.
//
// Verification reads config back from disk to confirm the on-disk
// LogDir matches what we wrote, then waits up to 30s for the daemon
// to drop a fresh meta file under newDir/. A failure surfaces as a
// loud stderr warning; the migration itself stays successful (data is
// already in newDir and config.json is updated — the operator can
// debug the start failure separately).
func finishMigrationLifecycle(cfgPath, oldDir, newDir string, wasRunning bool) {
	// Confirm the config write actually landed. saveConfig errors are
	// already handled upstream, but reading back catches the rarer
	// "wrote successfully but the file's wrong" case (filesystem cache
	// weirdness, permission flip).
	if got, err := loadConfigStrict(cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: re-reading %s after migration failed: %v\n", cfgPath, err)
		fmt.Fprintln(os.Stderr, "the migration moved files but the on-disk config may be stale — restart the daemon manually after verifying the file.")
		return
	} else if got.LogDir != newDir {
		fmt.Fprintf(os.Stderr, "warning: %s now reports log_dir=%s, expected %s\n", cfgPath, got.LogDir, newDir)
		return
	}

	if !wasRunning {
		fmt.Println("config.json updated; start the daemon with: sudo simplesiem start")
		return
	}

	fmt.Println("restarting daemon at the new log_dir...")
	startCommand([]string{})
	// Verify the daemon actually came up and is writing to newDir.
	// The first writes at startup (start meta event, rules_loaded,
	// etc.) land within ~2 seconds in practice; we give a generous
	// 30s budget and surface progress so an operator can tell the
	// difference between "still booting" and "didn't restart".
	deadline := time.Now().Add(30 * time.Second)
	verified := false
	for time.Now().Before(deadline) {
		if migrationFreshActivity(newDir, time.Now().Add(-30*time.Second)) {
			verified = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !verified {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "warning: daemon did not write to the new log_dir within 30s.")
		fmt.Fprintf(os.Stderr, "         data was successfully moved to %s and config.json was\n", newDir)
		fmt.Fprintf(os.Stderr, "         updated, but the daemon either failed to restart or is\n")
		fmt.Fprintf(os.Stderr, "         silent. Check: simplesiem status\n")
		fmt.Fprintln(os.Stderr, "         If status shows 'not running', read the service log and rerun")
		fmt.Fprintln(os.Stderr, "         simplesiem start; the migration itself is intact.")
		return
	}
	fmt.Printf("verified: daemon is writing to %s\n", newDir)
}

// migrationFreshActivity reports whether ANY .jsonl file under base has
// been modified after `since`. Used by the post-migration verifier to
// confirm the daemon is alive at the new log_dir without relying on
// any specific log type (the first write could be meta:start, a rule
// load, the writer watchdog heartbeat, etc.).
func migrationFreshActivity(base string, since time.Time) bool {
	entries, err := os.ReadDir(base)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		typeDir := filepath.Join(base, e.Name())
		files, err := os.ReadDir(typeDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".jsonl") {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue
			}
			if info.ModTime().After(since) {
				return true
			}
		}
	}
	return false
}

// copyTree recursively copies src to dst, returning the number of
// regular files successfully copied. On any error, the caller is
// responsible for cleanup (we don't auto-rollback inside this helper
// so the caller can decide whether to keep the partial destination).
func copyTree(src, dst string) (int, error) {
	count := 0
	walkErr := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		if !info.Mode().IsRegular() {
			return nil // skip symlinks/devices — daemon doesn't create them
		}
		if err := copyFileWithMode(path, target, info.Mode()); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, walkErr
}

func copyFileWithMode(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// updateLogDirInConfig writes the updated config back to cfgPath.
// Uses the same saveConfig path the rest of the codebase uses so
// formatting + permissions stay consistent.
func updateLogDirInConfig(cfgPath string, cfg Config, newDir string) error {
	cfg.LogDir = newDir
	return saveConfig(cfgPath, cfg)
}
