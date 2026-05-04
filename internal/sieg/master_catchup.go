package sieg

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CA-rotation catchup: closes the gap created by a partial fan-out
// of `master rotate-ca-all`. When the operator runs that command,
// some servers may be unreachable; the master records a per-realm
// "rotation policy timestamp" in master.rotation_realms. Every
// subsequent pull cycle, the master queries each server's CA status
// (GET /v1/master/ca-status) and rotates any server whose CA is
// older than the realm's policy.
//
// The same idea applies to finalize-rotate: master records the
// finalize policy in master.finalize_realms, and the catchup loop
// triggers finalize on any server that has rotated past the policy
// timestamp but still has legacy CAs on disk.
//
// Catchup is silent — failures log to errors and retry on the next
// cycle. An operator who wants to disable it can clear the policy
// with `master rotate-ca-policy clear-all` (or per-realm).
//
// Security: catchup uses the same /v1/master/rotate-ca and
// /v1/master/finalize-rotate endpoints, gated by
// `server.master_can_rotate_ca`. A server that disables the opt-in
// while catchup is in progress simply starts returning 403 — the
// master logs and stops trying.

// caCatchupCheck is invoked once per pull cycle, after the events
// pull. Best-effort: any error logs and the next cycle retries.
func caCatchupCheck(server, masterID, certDir string, cfg Config, client *http.Client, storage *Storage) {
	if len(cfg.Master.RotationRealms) == 0 && len(cfg.Master.FinalizeRealms) == 0 {
		return // no policy = no catchup
	}
	status, err := fetchCAStatus(client, server)
	if err != nil {
		// CA-status endpoint may be unauthorized (master_can_rotate_ca
		// false) or unavailable (older server build). Both are normal
		// and we shouldn't churn errors every minute. Log once per
		// outage by writing to debug-level meta only on first failure.
		return
	}
	policyRotate := cfg.Master.RotationRealms[status.RealmName]
	policyFinalize := cfg.Master.FinalizeRealms[status.RealmName]

	// Rotation catchup: server is "behind" if it has never rotated
	// since the policy was set, OR its last rotation predates the
	// policy. last_rotated_at is the authoritative signal — it's
	// written by performCARotation with no backdating, so the
	// comparison is exact.
	if policyRotate != "" {
		policyT, err := time.Parse(time.RFC3339, policyRotate)
		behind := false
		if err == nil {
			if status.LastRotatedAt == "" {
				behind = true // never rotated
			} else if rotT, perr := time.Parse(time.RFC3339, status.LastRotatedAt); perr == nil && rotT.Before(policyT) {
				behind = true // rotated, but before this policy was set
			}
		}
		if behind {
			res, err := triggerRotateOnServer(client, server)
			if err != nil {
				if storage != nil {
					storage.Write("errors", map[string]any{
						"collector": "master_catchup",
						"server":    server,
						"phase":     "rotate",
						"error":     err.Error(),
						"hint":      "will retry next sync cycle. Possible causes: server.master_can_rotate_ca is false, master not in master_cns, network outage.",
					})
				}
				return
			}
			// Write the new CA into the master's per-server cert dir so
			// the next handshake validates the server's freshly
			// hot-reloaded server cert (signed by the new CA).
			if err := writeMasterPerServerCA(cfg, server, res.NewCAPem); err != nil && storage != nil {
				storage.Write("errors", map[string]any{
					"collector": "master_catchup",
					"server":    server,
					"phase":     "rotate-write-ca",
					"error":     err.Error(),
				})
			}
			if storage != nil {
				storage.Write("meta", map[string]any{
					"event":  "ca_catchup_rotated",
					"server": server,
					"realm":  status.RealmName,
					"hint":   "server was behind realm rotation policy; rotation triggered automatically",
				})
			}
			return // server just rotated; finalize won't apply this cycle
		}
	}

	// Finalize catchup: policy is set AND server has legacy CAs AND
	// the server is not behind on rotation. Same last_rotated_at
	// signal as the rotation check.
	if policyFinalize != "" && status.LegacyCount > 0 {
		if policyRotate != "" {
			if policyT, err := time.Parse(time.RFC3339, policyRotate); err == nil {
				if status.LastRotatedAt == "" {
					return // never rotated; rotate first
				}
				if rotT, perr := time.Parse(time.RFC3339, status.LastRotatedAt); perr == nil && rotT.Before(policyT) {
					return // rotation pending; finalize would be premature
				}
			}
		}
		if err := triggerFinalizeOnServer(client, server); err != nil {
			if storage != nil {
				storage.Write("errors", map[string]any{
					"collector": "master_catchup",
					"server":    server,
					"phase":     "finalize",
					"error":     err.Error(),
				})
			}
			return
		}
		if storage != nil {
			storage.Write("meta", map[string]any{
				"event":  "ca_catchup_finalized",
				"server": server,
				"realm":  status.RealmName,
			})
		}
	}
}

// fetchCAStatus calls GET /v1/master/ca-status on a server using the
// supplied http.Client (which already has the per-server mTLS config).
func fetchCAStatus(client *http.Client, serverURL string) (MasterCAStatusResponse, error) {
	var zero MasterCAStatusResponse
	url := strings.TrimRight(serverURL, "/") + "/v1/master/ca-status"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return zero, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var out MasterCAStatusResponse
	if err := json.Unmarshal(rb, &out); err != nil {
		return zero, err
	}
	return out, nil
}

// triggerRotateOnServer is the catchup-time analogue of
// callMasterRotateCA. Reuses the master's existing pull-side TLS
// transport (master's per-server cert is already loaded in client).
// Returns the parsed response so the caller can persist the new CA.
func triggerRotateOnServer(client *http.Client, serverURL string) (MasterRotateCAResponse, error) {
	var zero MasterRotateCAResponse
	url := strings.TrimRight(serverURL, "/") + "/v1/master/rotate-ca"
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader("{}"))
	if err != nil {
		return zero, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var out MasterRotateCAResponse
	if err := json.Unmarshal(rb, &out); err != nil {
		return zero, fmt.Errorf("decode: %w", err)
	}
	return out, nil
}

// triggerFinalizeOnServer is the symmetric finalize trigger for
// catchup. Same wire shape as triggerRotateOnServer.
func triggerFinalizeOnServer(client *http.Client, serverURL string) error {
	url := strings.TrimRight(serverURL, "/") + "/v1/master/finalize-rotate"
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader("{}"))
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
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

