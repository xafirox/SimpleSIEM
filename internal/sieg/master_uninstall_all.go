package sieg

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// runMasterUninstallAll fans out a destructive uninstall across the
// entire master-managed surface — every enrolled server, the paired
// collector (if any), and finally the master itself. Per the spec:
// "master uninstall all removes processes and binary from all peers
// managed including self and collector. master uninstall all
// --purge removes all logs, files, certs, and configs as well."
//
// Order:
//
//  1. Confirm twice (first generic prompt, then a typed-yes prompt
//     because this destroys an entire fleet).
//  2. POST /v1/master/uninstall-self to every enrolled server (in
//     parallel; 30 s timeout per server). Each server's handler
//     fires a goroutine that runs its own local uninstall after
//     responding 200 OK so the master's HTTP call completes cleanly.
//  3. POST /v1/master/uninstall-collector to the paired collector
//     (when paired). Same async-after-200 pattern.
//  4. Wait briefly for remote daemons to start their teardown, then
//     uninstall this master locally. We pass --no-notify-peers
//     because every remote already received the cascade signal.
//
// --force bypasses the "server has no opt-in" refusal — the cascade
// proceeds even when servers without master_can_uninstall return
// 403, only logging a warning per such server. Without --force,
// any 403 aborts the cascade BEFORE the local uninstall fires so
// the operator can fix the config and retry without leaving the
// fleet half-uninstalled.
//
// --purge propagates to every remote AND to the local uninstall, so
// log_dir / state_dir / config_dir / certs are wiped fleet-wide in
// one command.
func runMasterUninstallAll(args []string) {
	fs := flag.NewFlagSet("master uninstall-all", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	yes := fs.Bool("y", false, "skip the two confirmation prompts")
	purge := fs.Bool("purge", false, "ALSO wipe logs/state/config/certs on every node")
	force := fs.Bool("force", false, "proceed past per-server opt-in refusals (logs a warning per refusing server)")
	timeoutSec := fs.Int("timeout", 30, "per-remote HTTP timeout in seconds")
	_ = fs.Parse(args)

	cfg := loadConfig(*cfgPath)
	if normaliseMode(cfg.Mode) != "master" {
		fatalf("master uninstall-all requires master mode (current: %s)", cfg.Mode)
	}

	if !*yes {
		fmt.Println()
		fmt.Println("================================================================")
		fmt.Println("  master uninstall-all — DESTROYS THE ENTIRE FLEET")
		fmt.Println("================================================================")
		fmt.Println()
		fmt.Printf("  enrolled servers:  %d\n", len(cfg.Master.Servers))
		for _, s := range cfg.Master.Servers {
			fmt.Printf("    - %s\n", s)
		}
		if cfg.Master.QueryCollectorURL != "" {
			fmt.Printf("  paired collector:  %s\n", cfg.Master.QueryCollectorURL)
		}
		if *purge {
			fmt.Println()
			fmt.Println("  --purge SET: every node's logs, state, certs, AND config will be wiped.")
		}
		fmt.Println()
		if !confirmYes("Proceed? [y/N] ") {
			fmt.Println("aborted")
			return
		}
		fmt.Println()
		fmt.Println("This is your last chance. Type yes to confirm.")
		if !confirmYes("Type yes: ") {
			fmt.Println("aborted")
			return
		}
	}

	// Phase 2: cascade to servers.
	timeout := time.Duration(*timeoutSec) * time.Second
	results := make(chan cascadeResult, len(cfg.Master.Servers)+1)
	var wg sync.WaitGroup
	for _, server := range cfg.Master.Servers {
		wg.Add(1)
		go func(srv string) {
			defer wg.Done()
			err := postCascadeUninstall(cfg, srv, "/v1/master/uninstall-self", *purge, *force, timeout, true)
			results <- cascadeResult{target: srv, kind: "server", err: err}
		}(server)
	}

	// Phase 3: cascade to collector (when paired).
	if cfg.Master.QueryCollectorURL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := postCascadeUninstall(cfg, cfg.Master.QueryCollectorURL, "/v1/master/uninstall-collector", *purge, *force, timeout, false)
			results <- cascadeResult{target: cfg.Master.QueryCollectorURL, kind: "collector", err: err}
		}()
	}
	wg.Wait()
	close(results)

	cascadeOK := true
	for r := range results {
		if r.err != nil {
			cascadeOK = false
			fmt.Fprintf(os.Stderr, "  cascade %s [%s]: %v\n", r.kind, r.target, r.err)
			continue
		}
		fmt.Printf("  cascade %s [%s]: queued\n", r.kind, r.target)
	}
	if !cascadeOK && !*force {
		fatalf("cascade had failures; not uninstalling local master. Re-run with --force to proceed anyway.")
	}

	// Phase 4: wait briefly so remote daemons start tearing down,
	// then uninstall the master locally with --no-notify-peers
	// (every remote was already told via the cascade).
	fmt.Println()
	fmt.Println("waiting 5 s for remote daemons to start their teardown...")
	time.Sleep(5 * time.Second)
	localArgs := []string{"-y"}
	if *purge {
		localArgs = append(localArgs, "--all")
	}
	localArgs = append(localArgs, "--no-notify-peers")
	runUninstall(localArgs)
}

type cascadeResult struct {
	target string
	kind   string
	err    error
}

// postCascadeUninstall is the per-target HTTP call. Uses the
// master's per-server client cert when calling a server, and the
// master's per-collector cert when calling a collector. Returns
// non-nil err on transport failure / 4xx-5xx response — the caller
// decides whether to abort the cascade.
//
// The endpoint accepts {"purge": bool, "force": bool} JSON. The
// remote handler runs its uninstall asynchronously AFTER returning
// 200, so the HTTP call completes cleanly even though the remote's
// daemon is about to disappear.
func postCascadeUninstall(cfg Config, peerURL, path string, purge, force bool, timeout time.Duration, isServer bool) error {
	peerID := peerIDFromURL(peerURL)
	if peerID == "" {
		return fmt.Errorf("could not parse host from %q", peerURL)
	}
	var tlsCfg *tls.Config
	var err error
	if isServer {
		tlsCfg, err = loadMasterClientTLS(filepath.Join(masterCertsDir(cfg), peerID))
	} else {
		tlsCfg, err = loadMasterClientTLS(filepath.Join(masterQueryCollectorRoot(), peerID))
	}
	if err != nil {
		return fmt.Errorf("client TLS: %w", err)
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   timeout,
	}
	body := map[string]any{"purge": purge, "force": force, "reason": "master uninstall-all"}
	bodyBytes, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost,
		strings.TrimRight(peerURL, "/")+path,
		strings.NewReader(string(bodyBytes)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := make([]byte, 1024)
		n, _ := resp.Body.Read(buf)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(buf[:n]))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
