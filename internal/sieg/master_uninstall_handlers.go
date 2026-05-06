package sieg

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// handleMasterUninstallSelf is the receiving side of `master
// uninstall-all` on a managed server. Authentication: the caller
// MUST be a recognised master (peerAuthorized) AND the server's
// master_can_uninstall opt-in MUST be true. Returns 200 immediately,
// then runs the local uninstall asynchronously so the master's HTTP
// call has a chance to complete cleanly before the daemon
// disappears.
//
// The remote uninstall passes --no-notify-peers (the master is the
// driver and already aware) and --force (the master is the
// authority — the last-server-with-master refusal doesn't apply
// when the master itself is asking).
func (s *serverState) handleMasterUninstallSelf(w http.ResponseWriter, r *http.Request) {
	addSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.peerAuthorized(r) {
		http.Error(w, "not a recognised peer", http.StatusForbidden)
		return
	}
	if !s.masterCanUninstall.Load() {
		http.Error(w, "server.master_can_uninstall is false; remote uninstall refused", http.StatusForbidden)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	var req struct {
		Purge  bool   `json:"purge"`
		Force  bool   `json:"force"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &req)

	// Log the request before responding so an operator chasing a
	// "what just happened?" mystery can see the trigger in
	// _server/meta even after the daemon is gone.
	if st, err := s.storageFor("_server"); err == nil && st != nil {
		st.Write("meta", map[string]any{
			"event":  "master_uninstall_received",
			"reason": req.Reason,
			"purge":  req.Purge,
			"hint":   "master uninstall-all cascade triggered local uninstall",
		})
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true,"queued":true}`))

	// Spawn the local uninstall in a detached child process so the
	// running daemon (which would be killed by its OWN uninstall)
	// doesn't take the cascade with it. The child re-execs the same
	// binary with the appropriate uninstall flags.
	go runDetachedSelfUninstall(req.Purge)
}

// runDetachedSelfUninstall fires the local uninstall as a separate
// process. Argv:
//
//	<self> uninstall -y --force --no-notify-peers [--all]
//
// We use --force to bypass the last-server-with-master refusal
// (the master is the authority asking us to leave) and
// --no-notify-peers because the master initiated this via a
// separate channel and a depart notification at this point would
// race the dying daemon's TLS shutdown.
func runDetachedSelfUninstall(purge bool) {
	// Brief delay so the HTTP 200 reaches the master before we
	// nuke ourselves. Without this, fast networks can race the
	// kernel's TCP teardown and the master sees a "connection
	// reset" error even though we executed cleanly.
	time.Sleep(2 * time.Second)
	self, err := os.Executable()
	if err != nil {
		return
	}
	args := []string{"uninstall", "-y", "--force", "--no-notify-peers"}
	if purge {
		args = append(args, "--all")
	}
	cmd := exec.Command(self, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	_ = cmd.Start()
	// We don't Wait — the cascade's uninstall command will kill
	// our parent process via the service teardown.
}
