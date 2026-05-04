# Standalone mode

Standalone is the default mode. The daemon collects events from the local host, stores them on disk under `<log_dir>/<type>/`, and runs the rule engine locally to produce alerts. Fine for one host; no network exposure, no CA/PSK to manage.

→ For multi-host setups, see [agent-server.md](agent-server.md). For the rule engine itself (rule format, thresholds, dedup), see [rules.md](rules.md).

## What it records

| Type | Captures |
|---|---|
| `network` | TCP/UDP open/close, local + remote `ip:port`, reverse-DNS of remote (with public-resolver fallback), provider label (Google/AWS/Cloudflare/...), protocol, owning PID/process/user, process cmdline, connection duration on close |
| `files` | Created / modified / deleted / renamed / chmod events on watched paths. Includes file size, mode, UID/GID and the resolved username (Linux/macOS) |
| `auth` | Login / logout sessions plus parsed auth-log events: `ssh_login` (success/failed/invalid_user), `ssh_disconnect`, `sudo` (with command), `su` |
| `processes` | Process start / exit — pid, name, cmdline, starting user, create time, **ppid + parent_name** for ancestry |
| `traffic` | Host-wide byte + packet counters (sent/received) and per-`(user, process)` active-flow rollups, with `destinations` embedded in `host_io` for instant who-talked-to-whom |
| `meta` | Daemon lifecycle, rule loads, authlog start, collector silent/recovered, write-queue drops, size-based log rotations |
| `errors` | Internal collector errors (permission denied, path missing, panics), with stack traces on panic |
| `alerts` | One event per rule match — name, severity, the original event, plus threshold count/window/group when applicable |

All events are written to per-type JSONL files, one line per event, with a UTC `ts` field in RFC3339Nano format. Full schemas are in [reference.md](reference.md#event-schemas).

## Install

### Double-click (recommended for admins)

| OS | File | Notes |
|---|---|---|
| Windows | `simplesiem-windows-amd64.exe` (or `-arm64`) | Opens a console with the manager menu. UAC prompts on Install/Uninstall. |
| macOS | `simplesiem-darwin-arm64.command` (or `-amd64`) | Opens Terminal. First time: `chmod +x` the file (Windows filesystems drop the Unix exec bit). |
| Linux | `simplesiem-linux-amd64` (or `-arm64`) | Not usually double-clicked; run from a terminal with `sudo`. |

From the menu, pick **Install (start now + at every boot)**.

**macOS Gatekeeper:** the binary is unsigned, so the first time you open it you'll get "cannot be opened because Apple cannot check it for malicious software". Either right-click the `.command` file → **Open** (one-time bypass), or strip the quarantine flag: `xattr -d com.apple.quarantine simplesiem-darwin-arm64.command`.

### From the command line

```
# Linux/macOS
sudo ./simplesiem-linux-amd64 install

# Windows (elevated PowerShell)
.\simplesiem-windows-amd64.exe install
```

`install` drops the binary, a default `config.json`, and a default `rules.json` (only if missing — existing rules are preserved). It then registers and starts the service.

Use `simplesiem fix` to repair an existing install rather than re-running install from a clean tree.

### Uninstall

From the menu pick **Uninstall**, or:

```
sudo simplesiem uninstall          # Linux/macOS
simplesiem.exe uninstall           # Windows, elevated
```

Config (`config.json`, `rules.json`), state, and collected logs are preserved. Delete the config dir, log dir, and state dir manually if you want a full wipe.

## Log storage layout

```
<log_dir>/
├── network/      YYYY-MM-DD.jsonl  (today, open for append)
│                 YYYY-MM-DD.jsonl.1, .2, ...   (size-rotated chunks)
│                 YYYY-MM-DD.jsonl.gz           (compressed past days)
├── files/        ...
├── auth/         ...
├── processes/    ...
├── traffic/      ...
├── meta/         ...
├── errors/       ...
└── alerts/       ...
```

### Default `<log_dir>` per platform

| OS | Path |
|---|---|
| Windows | `C:\ProgramData\SimpleSIEM\logs\` |
| macOS | `/var/log/simplesiem/` |
| Linux | `/var/log/simplesiem/` |

Override in `config.json` (`log_dir`) or via the `SIMPLESIEM_LOG_DIR` env var.

### File permissions

On Linux/macOS, the log directory is created mode `0750` and files mode `0640`. When `log_owner_group` resolves (default `adm` on Linux, `admin` on macOS), files and dirs are chowned to `root:<group>` so members of that group can read auth-relevant data without becoming root. Set `log_owner_group: ""` in `config.json` to leave ownership alone. On Windows, file ACLs are unchanged — the daemon runs as LocalSystem and the log directory inherits ACLs from `C:\ProgramData`.

### Other install paths

| Purpose | Windows | macOS / Linux |
|---|---|---|
| Binary | `C:\Program Files\SimpleSIEM\simplesiem.exe` | `/usr/local/bin/simplesiem` |
| Config | `C:\ProgramData\SimpleSIEM\config.json` | `/etc/simplesiem/config.json` |
| Rules | `C:\ProgramData\SimpleSIEM\rules.json` | `/etc/simplesiem/rules.json` |
| State | `C:\ProgramData\SimpleSIEM\state\` | `/var/lib/simplesiem/state/` |
| Service def | SCM (`sc.exe query simplesiem`) | systemd: `/etc/systemd/system/simplesiem.service` · launchd: `/Library/LaunchDaemons/com.simplesiem.plist` |

## Retention and compression

- Default retention: **30 days**. Configurable via `retention_days` in `config.json`.
- A sweep runs once per hour:
  - Daily files older than the retention cutoff are deleted.
  - Daily files for any day that isn't today are gzipped (typically 8–15× smaller).
- Today's open file is never compressed. Readers (`triage`, `query`, `tail`, `verify`, `status`, `alerts`) decompress `.jsonl.gz` transparently.

## Daily ops

### `status` — quick health check

```
simplesiem status
```

Shows daemon up/down, mode, retention floor, rule count, and per-type log volume.

### `tail` — live event stream

```
simplesiem tail                              # all types
simplesiem tail --type network,files         # only these
simplesiem tail --alerts                     # alerts only
simplesiem tail --grep "10\\.0\\.0\\."       # raw-JSON regex filter
simplesiem tail --json                       # raw JSONL for piping
```

Polls the daily files every 250 ms, reopens at midnight rollover. Alert rows are coloured by severity; `errors` rows are red; `meta` rows are dim. Pass `--no-color` (or set `NO_COLOR=1`) to force plain.

### `triage` — timeline reconstruction

The feature that makes this actually useful: pick a pivot event, get every other event recorded within ±window, merged across all log types and sorted by time.

```
simplesiem triage --file /tmp/suspicious.exe  --window 60s
simplesiem triage --pid 1234                  --window 10s
simplesiem triage --grep evil.com             --window 30s
simplesiem triage --at "2pm today"            --window 30s
simplesiem triage --since 1h                              # last hour, no pivot
simplesiem triage --start "2pm today" --end "3pm today"   # explicit range
simplesiem triage --field path=*=authorized_keys --since 7d
```

Sample output:

```
Pivot:  2026-04-25T14:57:16Z  [files]  created /tmp/suspicious.exe by root
Window: 14:56:46 -> 14:57:46  (±30s)
------------------------------------------------------------------------------
   14:57:01.000   -15000ms  network    connection_open evil.com (1.2.3.4:443) by admin/curl
   14:57:13.000    -3000ms  processes  process_start pid=1234 curl user=admin parent=bash(987)
>> 14:57:16.000        0ms  files      created /tmp/suspicious.exe by root
   14:57:18.300    +2300ms  alerts     [HIGH ] rule=executable_dropped on files/created
   14:57:22.000    +6000ms  files      modified /tmp/suspicious.exe by root
```

`>>` marks the pivot. Numeric column = ms delta from pivot. Multiple pivots are separated by `===`. With `--explain`, each alert gets a `matched: ...` sub-line showing exactly which rule fields hit.

**Coalescing.** Runs of identical rows collapse into one line with a `(×N over D)` suffix, so a `dpkg` install touching the same temp file 60 times doesn't fill the screen. Pivot rows and `alerts` rows are never coalesced. `--json` output is never coalesced — every event is emitted in full for jq/log shippers.

Full flag list in [reference.md#triage-flags](reference.md#triage-flags).

### `alerts` — recent rule matches

```
simplesiem alerts --since 1h                # default window
simplesiem alerts --since 7d --severity high
simplesiem alerts --since 1h --no-color     # plain output for scripts
```

Each alert is rendered with timestamp, severity (coloured), rule name, matched type/event, and a dim sub-line with the original event's summary. Threshold rules also show `count=N window=... group=value` so brute-force detection is visible at a glance.

### `query` — raw JSONL filter

For scripted consumption. Emits raw JSON lines matching filters.

```
simplesiem query --type network --since 1h --grep github --limit 50
simplesiem query --type files   --since 7d --grep "/etc/cron"
simplesiem query --since 2h --until 1h
```

Pipe into `jq` for analytics:

```
simplesiem query --type network --since 1h | jq 'select(.remote_host != null)'
```

### `verify` — hash-chain integrity

```
simplesiem verify                              # yesterday + today (default)
simplesiem verify -v                           # also print OK lines
simplesiem verify --type network               # only one type
simplesiem verify --date 2026-04-20            # one specific day
simplesiem verify --all                        # every file under <log_dir>
```

Recomputes per-line `_hash`, checks `_prev` linkage and `_seq` monotonicity. Exit code is non-zero on any mismatch — wire into cron/CI for an integrity heartbeat. Sub-chain breaks at file boundaries (daily rotation, size rotation, daemon restart) are tolerated and labelled. See [reference.md#hash-chain-integrity](reference.md#hash-chain-integrity) for the chain mechanics.

## Interactive menu

Launching the binary with no arguments opens the manager menu. The status banner shows the current install state plus the configured mode:

```
======================================
  SimpleSIEM - on-box SIEM manager
  SimpleSIEM 0.1.0 (build 20260429152302)
======================================

  Status: INSTALLED, RUNNING  (mode: standalone)

  -- Service --
   1) Stop the running service
   2) Fix / repair installation
   3) Uninstall
   4) Convert mode (standalone / agent / server)

  -- View --
   5) Triage events (timeline reconstruction)
   6) Live tail (follow new events)
   7) Recent alerts
   8) Verify log integrity (hash chain)
   9) Raw query (JSONL filter)
  10) Show status (mode / volume / health)

  -- Manage --
  11) Rules: check or test rules.json
  12) Certificates: init / sign / server (PKI)

  13) Quit
```

Read commands run in-process without elevation; admin actions (`install`/`uninstall`/`start`/`stop`/`fix`/`convert`/`certs *`) auto-elevate — UAC prompt on Windows, GUI password prompt via `osascript` on macOS, `sudo` on Linux. The interactive menu only appears when stdin is a terminal — over `ssh host simplesiem` (no `-t`), through a pipe, or in CI it prints the usage block and exits cleanly.

## Switching modes later

```
sudo simplesiem convert agent --server https://siem.example.com:9443 --key simplesiem-psk:abc…
sudo simplesiem convert server
sudo simplesiem convert standalone
```

`convert` flips an existing install in place — no reinstall, no service re-registration. See [agent-server.md#convert-mode](agent-server.md#convert-mode) for the full behaviour and `--keep-old` (rehome pre-switch logs).

## Configuration

Common knobs in `config.json`:

| Key | Purpose |
|---|---|
| `log_dir` | where JSONL files are written |
| `retention_days` | rolling retention window (default 30) |
| `network_interval` | connection-table poll interval (default 2s) |
| `process_interval` | process-table diff interval (default 2s) |
| `traffic_interval` | host_io rollup interval (default 30s) |
| `file_watch_paths` | directories watched via fsnotify |
| `file_watch_recursive` | add subdirectories as they appear |
| `auth_log_paths` | candidate auth-log files (Linux only; first existing wins) |
| `rules_path` | rules.json location; missing file = no rules |
| `max_log_file_mb` | per-file size cap before rotating (default 256 MB) |
| `write_queue_size` | async-write buffer (drops oldest when full) |

Full config reference: [reference.md#configuration](reference.md#configuration).

The default `file_watch_paths` list covers system configs, common user/tmp dirs, and persistence locations (cron, systemd unit dirs). Any admin-specific working dir (e.g. `/dist`, `/srv/myservice`) needs to be added explicitly.

## Caveats

- **Root / admin is required** to see all connections, all processes, and to read auth logs. The daemon runs as root/LocalSystem by design.
- **Auth-log on Windows polls the Security event log via `wevtutil.exe`** every `auth_log_interval` seconds (default 2 s). It maps the four logon-relevant EventIDs (4624 success, 4625 fail, 4634 logoff, 4672 admin assigned) to the same `auth_*` event shape Linux and macOS emit, so detection rules port across platforms unchanged. The service account needs `SeSecurityPrivilege` (LocalSystem has it; lower-privilege accounts must be granted via Group Policy or `secedit`). When `wevtutil.exe` isn't on `PATH` the collector logs `meta:authlog_windows_unsupported` and idles instead of erroring every poll.
- **macOS auth-log gap on restart**: events between daemon stop and start are lost.
- **inotify watch limit (Linux)**: `/proc/sys/fs/inotify/max_user_watches` defaults to ~8192 on many distros. Raise with `sysctl fs.inotify.max_user_watches=524288` and persist in `/etc/sysctl.d/`.
- **Per-process byte accounting is not tracked.** `traffic` records host-wide counters plus per-`(user, process, remote)` flow rollups, but not "process X sent N bytes".

More in [troubleshooting.md](troubleshooting.md).
