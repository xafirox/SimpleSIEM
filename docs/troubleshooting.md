# Troubleshooting and caveats

Grouped by where the problem typically shows up. Cross-references go to the mode guide that explains the affected area in depth.

## First debugging steps

When something looks wrong, in order:

1. `simplesiem status` — daemon up? mode correct? hosts visible?
1. `<log_dir>/errors/YYYY-MM-DD.jsonl` (standalone) or `<log_dir>/_server/errors/...` (server) or `<log_dir>/_master/errors/...` (master) — collectors and pull/sync goroutines log every failure here.
1. `<log_dir>/meta/...` — `start`, `stop`, `rules_loaded`, `collector_silent` show daemon lifecycle.
1. The relevant `from-<peer>.jsonl` files — if realm sync or master pull was supposed to bring something in but didn't.
1. Service log — `journalctl -u simplesiem` (Linux), `/var/log/simplesiem/daemon.log` (init-less Linux), `Console.app` (macOS), Event Viewer (Windows).

## Platform-specific

- **Root / admin is required** to see all connections, all processes, and to read auth logs. The daemon runs as root/LocalSystem by design. The hardened systemd unit drops most ambient privileges anyway.
- **Auth-log on Windows uses `wevtutil.exe`.** The daemon polls the Security event log on `auth_log_interval` (default 2s) and emits events for EventIDs 4624 (success), 4625 (fail), 4634 (logoff), and 4672 (admin assigned). The service account needs the `SeSecurityPrivilege` (Manage auditing and security log) right — LocalSystem has it; lower-privilege accounts must be added via Group Policy or `secedit`. If `wevtutil.exe` isn't on `PATH` or the account can't read Security, a `meta:authlog_windows_unsupported` event is logged and the collector idles instead of erroring every poll. Resume after a daemon restart is checkpointed via `<state_dir>/authlog_windows.json` so the Security log isn't replayed from the beginning.
- **macOS auth-log gap on restart**: events between daemon stop and start are lost. The Linux tailer resumes from the saved file offset; the macOS subprocess starts from "now" each time it launches.
- **macOS unsigned binaries**: first-run Gatekeeper block — right-click → Open, or strip quarantine (`xattr -d com.apple.quarantine simplesiem-darwin-arm64.command`).
- **Windows Defender / EDR**: a small unsigned SIEM binary that polls process/connection APIs looks like malware to heuristic scanners. Whitelist the install path if you see it being quarantined.
- **JSON parse errors on Windows when writing fixtures**: PowerShell 5.1's `-Encoding UTF8` writes a BOM that Go's JSON decoder rejects. Use `[System.IO.File]::WriteAllText($path, $data, (New-Object System.Text.UTF8Encoding $false))` to write BOM-less UTF-8.

## Collection (standalone, server-local, master-local)

- **If a collector looks empty**, check `<log_dir>/errors/YYYY-MM-DD.jsonl` first. Permission errors, fsnotify exhaustion, and watch-path absences are logged there.
- **`file_watch_paths` must include what you want watched.** The default list covers system configs, common user/tmp dirs, and persistence locations, but a path like `/dist` or `/srv/myservice` won't be captured unless you add it. Paths that don't exist at startup are skipped with an entry in `errors/`; restart once the path is in place.
- **`watch add` / `watch remove` requires a daemon restart.** `file_watch_paths` is NOT in the hot-reload set — the CLI prints `note: file_watch_paths is not hot-reloaded; restart the daemon to start watching this path` after every add/remove, and the running FileCollector keeps the original path list in memory until the next start. If a `watch add` "succeeded" but the path doesn't appear in `meta:fsnotify_watch_status` after 60 s, you skipped the restart.
- **Windows downloads not appearing in queries:** the Windows defaults explicitly include per-user `Downloads`, `Desktop`, `Documents`, and the per-user `AppData\Roaming\...\Startup` folder for every real profile under `C:\Users\` at install time (system profiles `Default` / `Public` / `defaultuser*` are skipped). New user profiles created AFTER install are not auto-watched — add them with `simplesiem watch add C:\Users\<name>\Downloads` and restart. Edge sometimes leaves an in-flight download named `Unconfirmed NNNNNN.crdownload` (SmartScreen pending / cancelled mid-download); query with `--grep Downloads` or `--grep crdownload`, not `--grep .zip`.
- **inotify watch limit (Linux)**: `/proc/sys/fs/inotify/max_user_watches` defaults to ~8192 on many distros. A recursive `/etc + /home + /opt + persistence paths` can hit this; the FileCollector logs an error event with the kernel limit as a hint. Raise with `sysctl fs.inotify.max_user_watches=524288` and persist in `/etc/sysctl.d/`.
- **If `meta:writes_dropped` keeps appearing**, the async write queue is overflowing. Raise `write_queue_size`, raise the polling intervals, narrow `file_watch_paths`, or reduce traffic with rule-based filtering upstream.
- **If `meta:collector_silent` fires**, that collector hasn't beat for 5 minutes. Likely causes: the collector panicked and is in backoff (check `errors/` for a stack), the auth-log file rotated and reopen failed, or a system call is deadlocked. The daemon will keep trying.
- **Per-process byte accounting is not tracked.** `traffic` records host-wide byte counters plus per-`(user, process, remote)` flow rollups, but not "process X sent N bytes". True per-process bytes need eBPF on Linux or `nettop`-class APIs on macOS — out of scope for v0.x.
- **Reverse DNS often returns nothing.** Many public IPs have no PTR record. Display falls back to `ip:port (no PTR)`. When the owning process's cmdline contains a URL or `user@host`-style target, the daemon extracts it as `cmdline_hosts` and triage's summary surfaces it as `... (cmdline)`. Provider labelling (Google, AWS, Cloudflare, ...) catches well-known PTR suffixes for instant readability.

## Read commands (query / triage / verify / status)

- **Hash chain breaks on daemon restart by design.** Verifier sees `_prev` go from non-empty to empty inside one daily file and treats it as a sub-chain start — not a tampering alert. If you see breaks *between* events without a corresponding `meta:start` or `meta:log_rotated_by_size` nearby, that's a real integrity problem.
- **If triage returns nothing**, widen `--scan-days` and/or use a looser `--grep`. The scanner stops at `--max-pivots` (default 10) — raise it if you know there should be more.
- **`--host` is meaningful only in server / master mode.** Standalone and agent events don't carry a `host` field; `--host X` will silently match nothing in those modes.
- **Bulk export / shipping**: `simplesiem query --since 7d` streams raw JSONL to stdout. Pipe into a shipper, gzip + copy, or use the built-in `--pretty` / `--select` / `--get` flags for jq-equivalent transforms (no external `jq` dependency on Mac/Windows). The on-disk files are also standard JSONL and safe to tail/rotate externally — but if you mutate them, the hash chain will break and `verify` will flag every line after the change.
- **No external tools required for JSON manipulation.** `simplesiem query --pretty` produces multi-line indented JSON; `--select event,user,host` projects a subset of fields (jq's `'{a,b}'`); `--get .nested.field` extracts a single value with array-index support like `--get .members.0`. Same flags work on `simplesiem triage --json`. Built into the binary — no need to install jq on Windows.

## User-management capture

Creating, modifying, or deleting users / groups / passwords on a SimpleSIEM-monitored host produces `auth:user_added` / `auth:user_deleted` / `auth:user_modified` / `auth:user_added_to_group` / `auth:user_removed_from_group` / `auth:group_added` / `auth:group_deleted` / `auth:password_changed` events. **Three independent paths** all converge on the same event shape:

- **Native auth-log readers** (Linux `/var/log/auth.log` tail, macOS `log stream`, Windows `wevtutil.exe`) — the original sources. Fire when the host has `rsyslog`/`journald` (Linux), unified-log access (Mac), or audit policy enabled (Windows).
- **`source: "process_invocation"`** (cross-platform) — `ProcessCollector` synthesizes the same shape from `process_start` cmdlines for `useradd / adduser / userdel / deluser / usermod / passwd / chage / chpasswd / groupadd / groupmod / groupdel / gpasswd` (Linux), `sysadminctl / dscl / dseditgroup` (Mac), `net user / net localgroup / PowerShell New-LocalUser / Remove-LocalUser / Set-LocalUser / Add-LocalGroupMember / Remove-LocalGroupMember` (Windows). Closes the gap on minimal Linux containers (no `auth.log`), stripped Macs, and Windows workstations without audit policy.
- **`source: "passwd_diff"`** (Linux + Mac) — `FileCollector` diffs `/etc/passwd` / `/etc/group` / `/etc/shadow` (and `/private/etc/*` macOS variants) on every modify and emits the matching event. **Catches sub-poll-interval `useradd` AND direct edits like `vi /etc/passwd` AND image-baking changes** that no `useradd` process ever ran for. Password slots in emitted events are redacted to `*`; shadow-file content is hashed in memory so cleartext password hashes never enter logs.

If `simplesiem query --type auth --grep user_added` returns nothing after creating a user:

1. **Check process_interval coverage** — `simplesiem query --type processes --grep useradd` shows whether the `useradd` process_start was sighted at all. A sub-poll-interval invocation can be missed by polling on Docker Desktop kernels (which strip `CONFIG_PROC_EVENTS`); on real Linux hosts the daemon emits `meta:proc_events_listener_started` and catches every exec instantly.
2. **Check the file-diff path** — `simplesiem query --type files --grep /etc/passwd` shows whether the file modify was observed. If yes but no synthesized auth event followed, check `simplesiem query --type errors --since 5m` for parse failures.
3. **Direct-edit detection** — `echo 'eve:x:2000:2000::/home/eve:/bin/sh' >> /etc/passwd` produces `auth:user_added user=eve source=passwd_diff` reliably; if that test returns nothing, the FileCollector isn't watching `/etc/` (check `file_watch_paths` in config).

## Agent / server connectivity

See [agent-server.md](agent-server.md) for the auth/encryption flow this section refers to.

- **Agent/server CN mismatch**: if you change `agent.id` without also reissuing the client cert, the server will reject the upload with HTTP 403 ("agent ID does not match client cert CN"). Fix: re-enroll the agent — `simplesiem convert standalone -y && simplesiem convert agent --server <url> --key <PSK> --id <new-id>`.
- **CN-host mismatch returns HTTP 403.** When an agent presents a client cert with CN=`A` but sets `X-SimpleSIEM-Host: B`, the server refuses with `agent ID does not match client cert CN`. Fix by re-enrolling the agent with the right ID.
- **Unauthorized agent returns HTTP 403.** When `server.agent_allowlist` is non-empty and the agent's ID isn't on it, the server refuses with `agent not authorized` even if the cert chain is otherwise valid. An audit entry lands in `<log_dir>/_server/errors/<today>.jsonl`. Fix: re-enroll the agent via the PSK flow (the server's `/v1/enroll` adds the ID to the allowlist atomically), or manually add it to `server.agent_allowlist` in `config.json` and restart. To revoke: remove the ID, restart.
- **Path-traversal hostnames return HTTP 400.** `X-SimpleSIEM-Host` values like `..`, `.bashrc`, or `a/b` are rejected before any filesystem operation.
- **Agent timestamps are clamped at the server.** Events with a `ts` outside `±max_clock_skew_seconds` of the server's clock are stored with `ts = now()`; the original is preserved in `agent_ts` and `clock_skewed: true` flags the event. Fix the agent's clock (NTP) or raise the skew tolerance.
- **Agents cannot write to the `alerts` log type.** Posts with `type:"alerts"` are rejected with a server-side error event noting the agent ID. Only the server's rule engine produces alerts.
- **Rate-limited agents see HTTP 429 with `Retry-After: 1`.** Bursts up to `rate_burst` events are allowed; sustained traffic above `rate_per_second` per source IP is throttled. The shipper's spool absorbs short throttling without data loss; sustained throttling trips spool overflow (`meta:agent_drops`).
- **Server saturation surfaces as HTTP 503.** When more than `max_concurrent` uploads are in flight, new requests are refused immediately instead of queueing. Tune the cap based on your disk write throughput and agent count.
- **Gzip bombs return HTTP 413 (`decompressed body too large`).** The server caps decompressed bytes at `max_decompressed_bytes` (default 256 MiB) on top of the compressed `max_batch_bytes` cap.
- **Garbage bodies return HTTP 400 (`too many decode errors`).** A per-batch budget of 100 JSON-decode errors aborts the request fast rather than spinning the decoder on non-JSON content.
- **Authentication failures return HTTP 401 with rate-limited logging.** The server emits one `errors` entry per source IP per 30 seconds when bearer-token brute-force attempts arrive.

## Agent shipping

- **Agent shipping gap on restart**: events generated *between* daemon stop and start aren't captured (collectors aren't running). Events generated while the daemon is up but the *server* is unreachable are spooled to disk and replayed on reconnect.
- **Spool overflow drops the oldest batches first.** A `meta:agent_drops` event is written locally each minute when this happens, so an offline outage that exceeds `spool_max_mb` is visible on the agent host. Raise the spool ceiling, narrow the watch list, or improve connectivity.
- **Server bind without a cert fails fast** with a clear error in the errors log. Run `simplesiem certs init` (auto-issues the server cert) before starting in server mode, or point `server.cert` / `server.key` at externally-issued certs.

## Cert and PSK

- **No agent-cert revocation/rotation.** To rotate a single agent's cert: re-enroll it (`simplesiem convert standalone -y && simplesiem convert agent --server <url> --key <PSK>`) — that produces a fresh keypair + cert. Compromised CA keys require regenerating from `certs init` (delete `ca.pem` and `ca.key` first), which forces every agent to re-enroll — there is currently no CRL.
- **PSK rotation invalidates pending enrollments.** `simplesiem certs psk rotate --force` generates a new PSK; in-flight enrollments using the old one fail. Existing enrolled agents are unaffected (they use mTLS, not the PSK).

## Realms

See [realms.md](realms.md) for the realm sync mechanics.

- **Realm peers must share a CA.** Agents present the same client cert to every peer in the realm, so every peer needs the same `ca.pem` to verify it. The simplest provisioning path is to copy `ca.pem` + `ca.key` from the first server to each subsequent peer before running `simplesiem certs server` + `simplesiem convert server` on it. Without a shared CA, agent failover fails closed with HTTP 403 on the next peer.
- **Realm sync watermark is per-peer.** Each peer keeps its own pull watermark for every other peer at `<state>/realm/<peer>.watermark`. The first sync after adding a peer to `realm.peers` fetches that peer's full event history from retention onward — expect a brief catch-up burst on day one.
- **Realm config reconciliation is last-write-wins.** When two peers edit `realm.name` (or any field reconciled by `/v1/sync/config`) within the same sync interval, the higher `config_version` (unix-nanos) wins on convergence. Don't expect quorum semantics — if you need them, edit on a single peer and let the change propagate.
- **Per-peer enrollment PSKs are independent.** Rotating the PSK on peer A doesn't affect peer B; it only affects future enrollments through A.
- **Replicated alerts come from the originating server's rule engine.** Each server evaluates the events it ingested directly. If servers run different rule sets, alerts surface only on their origin and replicate from there. Push the same `rules.json` to every peer if you want symmetric detection.

## Master

See [master.md](master.md) for the master pull mechanics.

- **Master rules don't fire.** The master is a pure consumer; it does not run the rule engine. Configure rules on each server.
- **Master cert revocation requires a server restart.** Removing a CN from `server.master_cns` doesn't take effect until that server reloads config. The hot-reload watcher handles `agent_allowlist` but not `master_cns` in the current build.
- **Master sees duplicate events when realms replicate.** If realm peers A and B both have an event from agent X, the master pulling from both will store it twice (once per origin file). Triage and query don't deduplicate. If exact event counts matter, query a specific origin: `simplesiem query --host X --grep ...` reads every `from-*.jsonl` file under `<host>/` indiscriminately.
- **Master has no listener and no `/v1/health` endpoint.** Health checks must observe behaviour (process running, watermarks advancing, fresh `master_sync_pulled` meta events) rather than probe a port.

## Cert auto-rotation

- **Renewal threshold defaults to 30 days before `NotAfter`.** Agents and masters check on every heartbeat / pull cycle and renew when inside the window. No operator action.
- **`meta:agent_cert_rotated` is the success signal.** Look for it in the agent's `_agent/meta/` log. Failures land in `_agent/errors/` with `collector: "agent_rotate"` and retry on the next beat.
- **A renewal hits HTTP 403 if the identity has been revoked or the cert isn't in the allowlist.** That's terminal — the operator must re-enroll the agent via PSK.

## Revocation

- **Tombstones are additive across realm peers.** Revoking on one peer reaches every peer within `realm.sync_interval_seconds` (default 15s). Removing a tombstone does NOT propagate; an accidental revocation must be undone on every peer's `config.json` manually.
- **Revocation does not invalidate the cert cryptographically.** It blocks future requests via the allowlist-and-revoked gate. The cert remains technically valid until its natural `NotAfter`.
- **Symptom: previously-working agent suddenly gets 403 from every peer.** Check `simplesiem certs revoked` on any server in the realm. To restore, edit `server.agent_revoked` on every peer and remove the entry, then restart.

## Master-driven CA rotation

- **`master rotate-ca-all` returns 403 on every server.** Default is `server.master_can_rotate_ca: false`. Set to `true` on each target server and restart that server's daemon, then re-run.
- **A server is offline at the moment `rotate-ca-all` runs.** Don't re-run by hand. The master records the rotation policy in `master.rotation_realms` and auto-catches the offline server up on the first pull cycle after it comes back. Watch `meta:ca_catchup_rotated` events on the master, or run `simplesiem master rotate-ca-status` to see fleet state.
- **Master triggered rotation but immediately can't talk to the server.** Look at the master's `/_master/errors/` log. Most likely the rotation succeeded but the master failed to write the new CA to its per-server cert dir (rare). Recovery: `rm -rf /etc/simplesiem/master/<server>/` and `simplesiem master enroll <server-url> --key <PSK>` to re-establish trust.
- **`finalize-rotate-all` removed the legacy CA and now an agent can't authenticate.** That agent's cert was still chained to the old CA — it didn't rotate before finalize. Recovery: re-enroll that agent via PSK against any peer in the realm.
- **`master rotate-ca-status` shows a server as `UNREACHABLE` with `tls: failed to verify certificate: x509: certificate signed by unknown authority`.** Means the server was rotated by something the master didn't drive (manual `init-rotate` on that server). Recovery: re-enroll the master against that server.

## Uninstall ceremony

- **"refusing: this is the last server in realm … AND a master is enrolled"** — uninstalling the only server in a master-managed realm would leave the master with no chain of trust to its agents. Pass `--force` to proceed; the master will go offline until a fresh server is enrolled in the realm.
- **`master uninstall-all` cascade aborts with 403** — the target server or collector hasn't been opted into remote uninstall. Set `server.master_can_uninstall: true` (server) or `collector.master_can_uninstall: true` (collector) on every cascade target, or pass `--force` to ignore the refusing nodes (the cascade still skips them; only opted-in nodes get torn down).
- **Cascade leaves master daemon running on success path** — by design: the cascade only teardowns the master's local daemon AFTER every target has acknowledged. If any target's pre-flight failed (e.g., the collector is unreachable), the master STAYS RUNNING so an operator can re-run the cascade once the offline target recovers. Re-run with `--force` to bypass that gate when the operator genuinely wants to abandon a missing target.
- **Cascade went through but a target's daemon is still up** — the receiving handler returns 200 immediately and detaches a child process to perform the actual uninstall. Wait at least 15 s for the child to complete its `simplesiem stop` + service-removal before re-checking. If a target stays up beyond that, check its daemon log for a stuck pre-stop hook.
- **`uninstall --all` removed everything but a stale config dir remained** — the parent of `config_dir` (e.g. `/etc/`) is kept; only `config_dir` and its contents are removed. If you want to also remove the parent, do it manually after the uninstall.

## Backup & restore

- **"backup is encrypted; --passphrase or --passphrase-file required"** — the `.siembak` file's flags byte has the `encrypted` bit set, but no passphrase was supplied. Provide one (out-of-band; never in shell history) via `--passphrase-file` to a 0600 file.
- **"backup frame N auth failed (wrong passphrase or corrupt file)"** — AES-GCM rejected the frame at index N. Wrong passphrase fails the FIRST frame; corruption / tampering fails wherever the modified byte landed. Verify the passphrase against `simplesiem backup inspect` first; if inspect succeeds but a real restore fails on a later frame, the file was modified in transit (re-pull from source).
- **"backup is truncated (final-frame marker missing)"** — the file ends without the final-frame flag. Indicates an interrupted scp / rsync / pipe. Re-fetch the original; do not attempt to restore a partial backup.
- **"refusing to restore: destination is already running in <mode> mode"** — the existing-install guard fires when the destination has anything other than a standalone install. Stop and uninstall the existing daemon first, OR pass `--force` if you genuinely want to replace a server / agent / master / collector with the contents of this backup. Existing trees are renamed to `<dir>.pre-restore-<UTC>` regardless, so a wrong --force is recoverable.
- **Restored agent not shipping events; `errors` log shows HTTP 409 "duplicate identity"** — the server's identity guard is rejecting the second presenter of this client cert. The original agent's daemon is either still up or stopped less than 60 s ago. Stop the original cleanly and wait at least 60 s for the guard window to expire before bringing the restored host online.
- **"--out is on the same volume as log_dir"** (collector mode) — the collector refuses backup output paths that share a volume with `log_dir`. Pick a path on a different storage partition.

## Storage quota

- **Daemon up, listener bound, but nothing landing on disk (`meta:storage_write_failed`)** — the storage writer goroutine is hitting an open / write error and silently used to drop the event after returning HTTP 200 to the agent. As of the post-r4 build, every disk-write failure is now counted and surfaced: a multi-line stderr banner fires on the **first** failure (visible via `journalctl -u simplesiem`), and a `meta:storage_write_failed` event is emitted every 30 s with `count`, `cumulative_total`, `last_error`, `log_dir`, and a remediation `hint`. Common causes: filesystem permissions, full disk under a halt threshold (separate event), or — historically — a custom `log_dir` outside the systemd unit's `ReadWritePaths`. The latter no longer applies on Linux as of the same build (see "Changing log_dir" below).
- **Changing `log_dir` (Linux):** as of the post-r4 build, the systemd unit no longer sets `ProtectHome=read-only`, and `extraReadWritePaths()` injects the configured `log_dir` + `storage.failover_locations` into `ReadWritePaths` at install time. End result: `sudo simplesiem log-dir migrate <new-path>` is the single command needed for any path outside `/etc`, `/usr`, `/boot`, `/efi` (still locked by `ProtectSystem=full`) — no install rerun, no manual unit edit, daemon stop+migrate+restart is automatic. If you migrate to an unusual path INSIDE one of the locked subtrees, the `storage_write_failed` event will surface with the exact `simplesiem install --log-dir <path>` command in its `hint`.
- **Status shows `HALT — SimpleSIEM has stopped collecting events`** — the active log volume crossed `storage.halt_threshold`. Free disk space, OR set `storage.failover_locations` in `config.json` to give the controller somewhere to fail over to. Recovery is automatic once free space returns above `warn_threshold` (controller emits `meta:storage_recovered` and resumes writes).
- **`writes_dropped_storage_halt` count climbing in the meta log** — events are being shed because the storage layer is halted. The count is reset on each periodic flush; a non-zero value means the daemon is currently dropping events. Pair with `simplesiem status` to see the volume state.
- **Master shows `remote storage warnings`** — one or more nodes the master pulls from are warning or halted. The events come through the existing meta replication; check `simplesiem triage --type meta --grep storage_` for the full history per host.
- **Failover happened but read commands still target the primary** — read paths (`tail`, `triage`, `query`, `verify`) union across every configured location, so events on the failover volume are visible alongside the primary. If a query feels incomplete, run with `--since` widening to confirm events from the failover window are present.

## Detection rules

See [rules.md](rules.md) for rule format and operators.

- **Rules fire only on the server that ingested the event.** In a realm, an event ingested by server-A fires alerts on A; the replicated copy on server-B is *already an alert*. Push the same `rules.json` to every server if you want symmetric detection.
- **No state replication across daemon restarts.** Threshold windows and dedup counters reset on restart. A fresh "5 failed SSH in 60s" sequence after a restart will fire even if the previous daemon counted 4 of them already.
- **No state replication across servers in a realm.** Each peer runs its own threshold/dedup state machine. A brute-forcer hitting both peers in a load-balanced setup may evade thresholds that would have fired on a single server seeing all 5 attempts.
- **Threshold windows are sliding, not bucketed.** "5 in 60s" means 5 matches whose timestamps fall inside any 60s window — not 5 per minute on a wall-clock minute boundary.
- **Rules file is mode 0640 by default.** `rules.json` describes the detection posture; world-readable rules let an unprivileged local user plan evasions. Tighten to 0600 or move outside the standard config dir if you keep sensitive IOC lists.

## Where to look when…

| Symptom | First place to check |
|---|---|
| Daemon won't start | `journalctl -u simplesiem` / Event Viewer / `daemon.log` |
| Collector dir empty | `<log_dir>/errors/YYYY-MM-DD.jsonl` |
| Agent isn't shipping | Agent's `<log_dir>/_agent/errors/` and `<log_dir>/_agent/meta/` |
| Server rejects an agent | Server's `<log_dir>/_server/errors/` |
| Realm peer not replicating | Each peer's `<log_dir>/_server/errors/` (filter for `realm_sync`) |
| Master not pulling | `<log_dir>/_master/errors/` and `<log_dir>/_master/meta/` (filter for `master_sync_pulled`) |
| Cert auto-rotation failing | Agent: `_agent/errors/` with `collector: "agent_rotate"`. Master: `_master/errors/` with `collector: "master_rotate"`. |
| `master rotate-ca-all` returns 403 on a server | `server.master_can_rotate_ca` is false; flip to true on that server and restart |
| `master rotate-ca-status` shows `UNREACHABLE` after rotation | Master's per-server CA file is stale; recovery is `rm -rf /etc/simplesiem/master/<server>/ && simplesiem master enroll <url> --key <PSK>` |
| CA-rotation auto-catchup not firing | Server-side: confirm the server is reachable; master-side: confirm `master.rotation_realms[<realm>]` is set (`simplesiem master rotate-ca-status`) |
| Revoked agent still seems to work | Tombstone hasn't propagated yet (≤60s); or agent's connection predates the revoke (server-side check fires on next reconnect) |
| Triage returns no rows | Widen `--scan-days`, raise `--max-pivots`, loosen `--grep` |
| `verify` flags chain breaks | Check for nearby `meta:start` (restart) or `meta:log_rotated_by_size` (rotation) — both are normal |
| Alerts firing too often | Add `dedup_window` to the rule; or use `threshold` to require N matches |
| Alerts not firing at all | `simplesiem rules check` for syntax; `simplesiem rules test events.jsonl` to replay |
| Restore aborts with "auth failed" | Wrong passphrase OR corrupt file — `simplesiem backup inspect` to confirm; if inspect passes, file was tampered with in transit |
| Restored agent stuck in 409 loop | Identity guard hasn't aged out — wait ≥60 s after the original's last heartbeat |
| `simplesiem status` shows HALTED | Free disk space on the active volume OR add `storage.failover_locations` to give the daemon somewhere to fail over to |
| Restore aborts with `invalid cross-device link` | Docker overlayfs without `redirect_dir` returns EXDEV even within the same overlay; `safeRenameDir` falls back to copy+remove automatically. If you still see this, your destination is on a genuinely different mount point that's read-only or full — fix the destination and retry. |
| Cross-server backup returns HTTP 403 "not a recognised peer" | Older realm joins stored the operator-typed (often IP-based) URL; receiver compares against its cert's hostname-CN. Re-run `simplesiem realm join <peer> --key <psk>` after upgrade — the joiner now stores the responder's canonical URL. |
| `triage --type meta` doesn't show server/master/collector lifecycle events | Pre-fix the `_server`/`_master`/`_collector` pseudo-host dirs were excluded from `listHosts`. Upgrade the binary; `triage` now walks every `_<name>` reserved dir alongside per-agent dirs. |
| `simplesiem realm rename` requires daemon restart to take effect | Pre-fix only. `configWatcher` now hot-reloads `realm.name`, `realm.peers`, and `master_can_uninstall` within ~1 s of the config-write. |
| `meta:agent_silent_anomaly` fires constantly on a quiet host | The detector's minimum-baseline floor is 5 events/min; agents above that should be steady. False positives usually mean the agent is genuinely intermittent (laptop, batch host) — bump `dropRatio` or `consecutive` in `internal/sieg/volume_anomaly.go`, or move that host out of the volume-anomaly evaluation by giving it a dedicated, lower-traffic agent_id naming convention. |
| `meta:alert_webhook_drops` events keep appearing | Webhook receiver is slow or rate-limiting; the dispatcher's queue is 1024 entries deep and overflow drops with a 30 s summary. Check the receiver's logs for 5xx; if 5xx is the norm, scale or remove the URL. |
| `meta:authlog_windows_unsupported` on a Windows agent | `wevtutil.exe` not on `PATH`, OR the service account lacks `SeSecurityPrivilege`. LocalSystem has it by default. For a non-LocalSystem account, grant via `secedit` or Group Policy → Computer Configuration → Local Policies → User Rights Assignment → Manage auditing and security log. |
| `simplesiem backup verify` reports a chain break | Either the file was tampered with after creation, OR it was created mid-rotation and the on-disk state included a partial last frame. Re-create the backup; if the new one also fails verify, investigate the source filesystem (the chain-hash machinery is also what `simplesiem verify --all` exercises against live storage). |
| `rules replay` shows zero fires for a rule that fires in production | The `--since` window predates the rule's typical firing pattern, OR the historical events were ingested before the rule was added (so the rule's fields don't match the older event shape). Widen `--since`; cross-check the rule against `simplesiem query --type <T> --since <window>`. |
| `rules stats` shows a rule with 0 fires that I expect to fire | The rule never matched within the window — same diagnosis as `rules replay` zero. Pull a candidate event with `simplesiem query --type <T> --since 7d --grep <signal>` and feed it to `simplesiem rules test events.jsonl` to see exactly which match key fails. |
| Master-side rule didn't fire on a cross-host event | (1) `cfg.master.rules_path` empty? Confirm with `jq .master.rules_path /etc/simplesiem/config.json`. (2) Master pull lag — `simplesiem triage --type meta --since 5m \| grep master_sync_pulled` should show recent pulls. (3) The rule's `match` keys don't appear on the replicated event (replicated events have `host`, `origin_server`, plus the original payload — confirm via `simplesiem query --since 5m --type <T>` on the master). (4) Master fires land in `<log_dir>/_master/alerts/`, not under `<host>/alerts/`. |
| `meta:alert_syslog_drops` keeps appearing | Receiver unreachable / refusing connections (TCP) or simply absent (UDP — UDP loss is silent at the wire). Check `cfg.server.alert_syslog.address` reachability. UDP loss can happen mid-stream without ever reporting drops; switch to TCP if guaranteed delivery matters. |
| `/metrics` returns HTTP 401 for my Prometheus scraper | The endpoint requires either a valid client cert (mTLS) or a bearer token in `cfg.server.bearer_tokens`. Configure the scraper with one of those. The error event `meta:http_auth_failures` increments per attempt. |
| `/metrics` returns counters at zero after recent event activity | Counters reset on daemon restart — they're in-memory only. Recent events arrived AFTER the most recent restart? Check `simplesiem status \| grep started`. Prometheus rate aggregation handles restart resets correctly via the `rate()` PromQL function. |
| `simplesiem chainhead verify` reports failures | Either the file was tampered with after signing, OR the public key in the embedded record was rewritten. Compare the signing-key fingerprint shown by `chainhead show` against your trusted reference (export the fingerprint to immutable storage when standing up the host). |
| `simplesiem alerts ack <prefix>` says "ambiguous" | Hash prefix matched multiple alerts in the last 30 days. Add more characters to disambiguate (use the `id=` suffix shown in `simplesiem alerts --no-color`). |
| macOS auth log gap not backfilled after restart | (1) Outage > 24 h: backfill is bounded to `backfillMaxLookback` (24 h) to avoid pulling unbounded unified-log data. (2) `<state>/authlog_darwin.json` not writable. (3) `log show --start` failed (check `simplesiem triage --type errors --since 5m \| grep authlog`). (4) Daemon was running when you booted the laptop from sleep — the previous run's last-seen-ts was already current; nothing to backfill. |
