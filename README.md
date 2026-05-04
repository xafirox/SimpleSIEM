# SimpleSIEM

A single-binary, on-box SIEM for Windows, macOS, and Linux. Runs in five modes from the same executable:

- **standalone** — collect locally, store on disk, alert from a local rule engine. The default; fine for one host.
- **agent** — collect locally, ship encrypted (mTLS) to a server. Logs leave the host so a compromised box can't trivially erase its tracks.
- **server** — accept batches from many agents and store per-host, with the same hash chain, rules, and triage tooling as standalone.
- **master** — pull events from one or more servers across realms. Optional aggregation tier for operators with multiple realms or who want a single management plane on top of redundant servers.
- **collector** — single-source backup replicator. Pulls a redundant copy of every event from one master (preferred) or one server. Single-slot rule on the authority side: only one collector ever pairs with any given master or server.

Pick the mode at `install` time (or edit `config.json`); the same binary serves all five. Inter-host traffic is mTLS-authenticated with **ECDSA P-384 client certs over TLS 1.3** (NIST Suite B Top Secret cert family, ~192-bit security level). Key exchange is **`X25519MLKEM768`** only (NIST FIPS 203 ML-KEM hybrid post-quantum KEM, draft-ietf-tls-mlkem) — no classical fallback. SimpleSIEM only talks to other SimpleSIEM nodes built from the same tree, so a downgrade attack to a weaker primitive is impossible by construction. Both ends verify the other.

A short feature highlight: single-file install, tamper-evident SHA-384 hash chain, mTLS-only inter-host traffic, hot-reloadable rules with sequence/CIDR/threshold matchers, MITRE ATT&CK Phase 1+2 (auto-catalog + generated rules), threat-intel-enriched alerts, behavioral baselining, honey tokens, and an end-to-end backup/restore flow. Full feature list and workflow enhancements at the [bottom of this README](#features).

---

## Documentation

Quick orientation by what you want to do:

- **Just need a one-liner?** → [docs/quickref.md](docs/quickref.md)
- **Just want to monitor one host?** → [docs/standalone.md](docs/standalone.md)
- **Centralise logs from many hosts?** → [docs/agent-server.md](docs/agent-server.md)
- **Want HA / redundancy with multiple servers?** → [docs/realms.md](docs/realms.md)
- **Aggregating across realms?** → [docs/master.md](docs/master.md)
- **Adding an off-node backup replicator (collector mode)?** → [docs/collector.md](docs/collector.md)
- **Writing detection rules?** → [docs/rules.md](docs/rules.md)
- **Backing up / migrating between hosts?** → [docs/backup.md](docs/backup.md)
- **Looking up a config key, CLI flag, or event field?** → [docs/reference.md](docs/reference.md)
- **Something's broken?** → [docs/troubleshooting.md](docs/troubleshooting.md)

---

## Quick start (single host)

This gets you a working standalone install in one minute.

**Linux / macOS:**

```
sudo ./simplesiem install
sudo simplesiem status            # daemon: running, mode: standalone
sudo simplesiem tail              # follow events live
```

**Windows (elevated PowerShell):**

```
.\simplesiem-windows-amd64.exe install
.\simplesiem-windows-amd64.exe status
.\simplesiem-windows-amd64.exe tail
```

That's it. The daemon starts collecting network/file/process/auth/traffic events to `/var/log/simplesiem/` (Linux/macOS) or `C:\ProgramData\SimpleSIEM\logs\` (Windows), and the default `rules.json` fires alerts on common suspicious patterns. See [docs/standalone.md](docs/standalone.md) for what's collected and how to query it.

For agent → server, realm, or master setups, follow the linked guides above — they each have their own walk-through.

## Platforms

- **Windows** — 10 / 11 / Server. amd64 or arm64. Uses SCM. Auth-log capture polls the Security event log via `wevtutil.exe` and maps the four logon-relevant EventIDs (4624 success, 4625 fail, 4634 logoff, 4672 admin assigned) to the same `auth_*` event shape Linux and macOS emit, so detection rules port across platforms unchanged. The service account needs `SeSecurityPrivilege` (LocalSystem has it; lower-privilege accounts must be granted via Group Policy or `secedit`).
- **macOS** — 11+. amd64 (Intel) or arm64 (Apple Silicon). Uses launchd in the system domain. Auth-log capture subprocesses `log stream --style ndjson` against the unified log.
- **Linux** — any distro. amd64 or arm64. Uses systemd when present; falls back to a PID-file standalone mode in Docker / init-less environments. Tails `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora).

Agent and server modes work on every supported OS — you can have a mixed fleet of Windows agents shipping to a Linux server, or any combination.

## Modes at a glance

| Mode | What runs | Where logs go |
|---|---|---|
| `standalone` (default) | Collectors + local rule engine | Local disk under `<log_dir>/<type>/` |
| `agent` | Collectors only | Shipped over mTLS to a server; `<log_dir>/_agent/` keeps shipping diagnostics |
| `server` | HTTPS receiver + the same collector set as standalone | `<log_dir>/<host>/<type>/` per agent and for the server itself; realm-replicated peer events as `<date>.from-<peer>.jsonl` |
| `master` | Pulls from each registered server, plus local collection. Optional collector listener for one paired collector. | `<log_dir>/<host>/<type>/<date>.from-<server>.jsonl` per origin; `<log_dir>/_master/` for lifecycle |
| `collector` | Pulls from one source (master preferred, server fallback) on a configurable cadence (default daily); also runs local collectors | `<log_dir>/<host>/<type>/<date>.from-<origin>.jsonl` mirroring the source's per-origin layout; `<log_dir>/_collector/` for lifecycle |

## Build from source

Prereq: Go 1.21+.

```
# Cross-build all six targets (Windows amd64/arm64, macOS amd64/arm64, Linux amd64/arm64)
.\build.ps1

# Or one target manually
go build -trimpath -ldflags "-s -w" -o simplesiem .
```

See [docs/reference.md#build-from-source](docs/reference.md#build-from-source) for the full build invocation and test commands.

## Help and feedback

- `simplesiem help` — print usage
- `simplesiem version` — print version + build number
- Interactive menu: launch the binary with no args (or double-click)

If something's broken, check [docs/troubleshooting.md](docs/troubleshooting.md) first.

---

## Features

- **Single file** per target (~10 MB). No Python, no shell wrappers, no runtime deps.
- **Self-installing** as a native service (Windows SCM / Linux systemd / macOS launchd).
- **Self-managing** — double-click the binary for an interactive menu that adapts to install state.
- **Self-repairing** — `fix` audits the installation and restores anything broken.
- **Tamper-evident** — every event carries a SHA-384 hash chained to the previous event in the same file (paired with P-384 certs for ~192-bit security throughout). `simplesiem verify` auto-detects the hash length so legacy SHA-256 chains keep validating.
- **Detection-ready** — JSON rules with substring/regex matching, dedup, and threshold/correlation.
- **Centralised when wanted** — agent/server mode ships logs over mTLS so they survive an attacker rooting the source host.
- **Redundant when wanted** — pair two or more servers into a **realm** via PSK-authenticated `simplesiem realm join` (no shared CA private key). Each server keeps its own CA; the join handshake exchanges *public* certs and builds a runtime trust bundle. A higher **master** tier aggregates across realms.
- **Cert rotation that's hands-off** — client certs auto-renew before expiry over mTLS (no PSK reuse). For CA rotation, `simplesiem master rotate-ca-all` fans out across the entire fleet without service interruption, and an auto-catchup loop rotates any server that was offline at trigger time as soon as it comes back.
- **Per-host revocation that propagates** — `simplesiem certs revoke <id>` adds a tombstone that reaches every realm peer within one sync cycle.
- **Mode-flippable** — `simplesiem convert <agent|server|standalone|master|collector>` switches an existing install in place. Master and collector conversions are interactive and prompt for every server URL + PSK.
- **One-shot install + realm join** — `sudo simplesiem install --mode server --realm https://peer:9443 --realm-key simplesiem-psk:...` brings up a server AND attaches it to an existing realm in a single command. Same `--realm`/`--realm-key` flags work on `convert server`. A name-collision guardrail blocks accidental merging when two unrelated realms share a name.
- **Storage-aware** — every mode probes its log volume(s); `simplesiem status` shows `OK` / `WARN` / `HALT` per volume with used %, free space, and freshness ("latest update" in local timezone, e.g. `15:42:11 (2m 14s ago)`). Configurable warn / halt thresholds (`"80%"`, `"90%"`, `"1TB"`, `"20GB"`); when the active volume halts AND `storage.failover_locations` is set, every Storage instance fails over in lockstep and emits a `meta:storage_failover` event that propagates to peers / masters / collectors.
- **Hierarchical encrypted backup** — `simplesiem backup --out` produces a single AES-256-GCM `.siembak` (key from PBKDF2-SHA384 600k iters + per-backup salt; 1 MiB chunked frames so multi-GB backups stream without buffering). A server can `backup --all` to capture itself, every agent, and every realm peer (via `/v1/backup/create`); a master can `backup --all-realms` to capture itself + the paired collector + every server organized by realm directory. Restore refuses over a non-standalone install (use `--force` to override) and renames any existing trees to `<dir>.pre-restore-<UTC>` for rollback. → [docs/backup.md](docs/backup.md)
- **Identity guard** — the server tracks per-cert `(IP, ts)` and rejects a second daemon presenting the same client cert from a different IP within 60 s with HTTP 409 + `meta:identity_conflict`, catching the canonical "I restored a backup while the original was still running" mistake.
- **Cascade uninstall** — `simplesiem master uninstall-all [--purge]` tears down the entire master-managed surface (every enrolled server, the paired collector, and finally the master itself) in one command. Per-node opt-in (`server.master_can_uninstall`, `collector.master_can_uninstall` — both default `false`) is required so a compromised master can't wipe a fleet without explicit operator authorisation per node. → [docs/master.md → Cascade uninstall](docs/master.md#cascade-uninstall)
- **Atomic graceful uninstall** — `simplesiem uninstall` notifies relevant peers (`/v1/agent/depart`, `/v1/master/depart`, `/v1/collector/depart`, `/v1/realm/leave`) before teardown so allowlists / master_cns / collector slots are cleaned up immediately. Refuses on the last server in a master-managed realm without `--force`. `--all`/`--purge` wipes config/state/logs/certs.
- **Hot-reloadable realm config** — `simplesiem realm rename`, `realm join`, and `master_can_uninstall` flips on disk are picked up by the running daemon within ~1 s via the config watcher; no daemon restart required.
- **Append-only sealing of closed daily log files** — Linux uses `chattr +a` (append-only inode flag), macOS uses `chflags sappnd` (BSD system append-only), Windows sets `FILE_ATTRIBUTE_READONLY`. Even root can't `rm` or rewrite a sealed file without first clearing the flag, which leaves an audit trail. Combined with the SHA-384 hash chain and remote replication, an attacker who roots an agent can't silently scrub history. Always-on; the retention loop strips the flag before legitimate deletion.
- **Optional aggressive-shipping mode for high-threat agents** — `agent.no_local_storage: true` (default `false`) drops batches that fail to ship rather than spooling them to disk, and skips the local-mirror write. Pairs with `batch_size: 1` + `batch_interval_seconds: 1` to make the agent a near-pass-through to the server. Dangerous by default (events are lost during a server outage); use only when "lose events" is preferable to "leave plaintext on the agent's disk." → [docs/agent-server.md → Maximum exfiltration resistance](docs/agent-server.md#maximum-exfiltration-resistance)
- **Volume-anomaly alerting** — server-side watchdog tracks per-agent event rate via EWMA (alpha 0.2, 1-min ticks) and fires `meta:agent_silent_anomaly` when an agent that was previously chatty drops to <5 % of its baseline for two consecutive minutes. Detects "agent went quiet" without false-firing on normally-quiet hosts (warmup window + minimum-baseline floor). Recovery emits `meta:agent_silent_recovered`. → [docs/agent-server.md → Volume anomaly](docs/agent-server.md#volume-anomaly-alerts)
- **Outbound webhooks for alerts** — `cfg.server.alert_webhooks: ["https://..."]` POSTs every fired alert as JSON to one or more endpoints. Severity-filterable (`alert_webhook_min_severity: "high"`), retries on 5xx with exponential backoff (1s/4s/16s), no retry on 4xx, drops on overflow with a periodic drop-count meta event. → [docs/reference.md → alert_webhooks](docs/reference.md#alert_webhooks)
- **Backup verification** — `simplesiem backup verify <path>` decrypts the envelope, walks every JSONL inside, recomputes the SHA-384 hash chain, and reports tampered or truncated chains without restoring anything. Useful for periodic offline integrity checks of cold backups.
- **Rules replay against history** — `simplesiem rules replay --since 7d` runs the *current* rule file against historical events on disk and reports per-rule fire counts. Lets an operator iterate on rule tuning in seconds without waiting for production traffic. Stateless by default; pass `--with-threshold` to evaluate threshold/dedup state over the replay window. → [docs/rules.md → Replay against history](docs/rules.md#replay-against-history)
- **Reference deployment recipes** — [deploy/systemd/](deploy/systemd/) (the same hardened unit `simplesiem install` writes), [deploy/ansible/](deploy/ansible/) (idempotent fleet rollout playbook), and [deploy/k8s/](deploy/k8s/) (privileged DaemonSet for per-node monitoring). For Mac and Windows, the `install` command is the recipe.
- **Master-side rule engine for cross-host correlation** — when `cfg.master.rules_path` is set, the master evaluates the configured rules on every event it pulls from each registered server. Detection rules that need a cross-host view (e.g. "5 different agents see failed logins for user X within 10 min") fire on the master alongside the per-server fires the origin emitted. → [docs/master.md → Master-side rules](docs/master.md#master-side-rules)
- **Per-rule hit-rate stats** — `simplesiem rules stats --since 7d` walks the alerts log and prints a table of fire counts per rule (zero-fire rows included so dead rules are obvious). Helps identify chronically-firing noise and rules that need tuning. → [docs/rules.md → Stats](docs/rules.md#per-rule-stats)
- **Prometheus `/metrics` endpoint** — auth-gated text-format exposition with counters for events ingested/rejected, alert fires by rule + severity, agents active, alert webhook/syslog drops, HTTP auth failures. Same TLS as the rest of the server (mTLS or bearer token). Plug straight into Grafana. → [docs/reference.md → /metrics](docs/reference.md#metrics)
- **Outbound RFC 5424 syslog forwarding for alerts** — `cfg.server.alert_syslog: { network: "udp", address: "syslog.example.com:514", facility: 16, tag: "simplesiem", severity_min: "high" }` ships every fired alert as a syslog frame, facility/severity properly mapped. Drops on overflow surface as `meta:alert_syslog_drops`. Bridges into Splunk / Elastic / rsyslog pipelines without a separate webhook receiver. → [docs/reference.md → alert_syslog](docs/reference.md#alert_syslog)
- **Signed chain heads** — every host signs the latest `_hash` of each `(host, type, day)` file hourly with a per-host ECDSA P-384 key (auto-generated at first run, kept in `<state_dir>/chainhead.key`). Records land in `<log_dir>/_chainhead/<date>.jsonl` for export off-box. `simplesiem chainhead verify` re-checks every signature; an attacker who roots a host AFTER signing can't forge new signed records without the private key. Closes the "rewrite the live chain" gap that pure on-disk hashes left open. → [docs/reference.md → chainhead](docs/reference.md#chainhead)
- **Alert acknowledgement workflow** — `simplesiem alerts ack <hash-prefix> [--note "investigated"]` records the ack to `<log_dir>/_acks/<date>.jsonl`. `simplesiem alerts --unacked-only` filters the alert list to outstanding items, turning the alert log into a triage queue.
- **macOS auth-log gap backfill** — on daemon restart the macOS authlog collector runs `log show --start <last-seen-ts>` to recover events that landed during the outage, then resumes `log stream`. Mirrors the Linux file-tailer's inode+offset resume; gaps up to 24h are backfilled (longer outages skip to avoid pulling weeks of unified-log data).
- **Cross-event sequence rules** — a rule's `sequence:` clause defines an ordered list of step matchers + a `within` window + `group_by` key; the rule fires only when every step matches in order, by the same group_by key, within the window. Catches "exploit-then-shell", "fail-then-success-from-same-IP", "process-spawn-then-network-callout" patterns that per-event rules can't see. → [docs/rules.md → Sequence rules](docs/rules.md#sequence-rules)
- **Rich rule matchers** — beyond the existing `=`/`*=`/`~=` matchers, rules now support CIDR (`source_ip: { cidr: "10.0.0.0/8" }`), set-file with hot-reload (`source_ip: { in_file: "blocklist.txt" }`), numeric comparators (`size: { gt: 10485760 }`), and time-of-day / weekday gates on the rule itself (`time_of_day: "22:00-06:00", weekdays: "sat,sun"`). Plus `not_cidr` / `not_in_file` for negation. → [docs/rules.md → Match operators](docs/rules.md#match-operators)
- **Rule annotations + MITRE ATT&CK tagging** — `notes`, `runbook_url`, `tactic`, `technique` fields on rules flow through to the fired alert payload (and webhooks/syslog) so the on-call has triage context without looking up the rule. `simplesiem alerts --technique T1110` filters by technique; `simplesiem rules coverage` groups rules by ATT&CK and shows fire-count per group. → [docs/rules.md → MITRE tagging](docs/rules.md#mitre-tagging)
- **Alert escalation for unacked criticals** — `cfg.server.alert_escalation: { enabled: true, after_seconds: 900, min_severity: "critical" }` re-fires unacked alerts at the configured severity through the same alert dispatcher fanout. Pair with a separate webhook receiver filtering `min_severity: "critical"` for an "after-15-min PagerDuty" pattern.
- **First-seen entity detection** — server-side detector emits `meta:first_seen_<field>` (user / source_ip / sha384 / remote_host / process / name) the first time a `(host, field, value)` tuple is observed. Persistent across restarts in `<state>/firstseen.json`, 30-day decay. Catches "first time alice logged in from a new IP", "first time this binary appeared on the box", etc.
- **Per-entity time-of-day baselines** — server-side hour-of-day histogram per `(host, field, value)`; emits `meta:unusual_time_anomaly` when an entity acts outside its typical window (after ≥50 samples). Captures off-hours activity without writing per-entity rules.
- **`simplesiem top --by <field>`** — top-N aggregation for ad-hoc threat hunting ("which IPs are talking most?", "which processes spawn most often?"). Stateless walker over the on-disk corpus.
- **`simplesiem hunt rare` / `pivot` / `firstseen`** — investigation primitives: long-tail rare-value events, single-entity timeline across log types, field values that first appeared in the window. Plus saved hunts (`hunt save`/`run`/`list`/`delete`) so investigators don't re-type flags. → [docs/quickref.md → Threat hunting](docs/quickref.md#threat-hunting)
- **`simplesiem tree --pid <PID>`** — process-tree reconstruction from on-disk process events. Walks pid → ppid edges to render the parent-chain + descendants of a given PID, or every captured root in the window.
- **CSV / TSV export from query and top** — `simplesiem query --format csv --csv-fields ts,event,host,user` and `simplesiem top --format csv` write RFC4180-style output for spreadsheet triage.
- **File-content hashing on file events** — files collector adds SHA-384 to `created` / `modified` events for regular files ≤ 16 MiB. Pairs with `match: { sha384: { in_file: "malware-hashes.txt" } }` for IOC feeds.
- **Process exec enrichment (auditd-equivalent, cross-platform)** — process_start events now carry `sha384`, `exe_path`, `parent_cmdline`, `parent_user` in addition to the existing `pid`, `ppid`, `parent_name`, `cmdline`, `user`, `created`. Most of auditd's `EXECVE` value via gopsutil's `Exe()` (Linux `/proc/PID/exe`, macOS `proc_pidpath`, Windows `NtQueryInformationProcess`) — no kernel hooks, no CGO.
- **DNS event type** — `NetworkCollector` synthesizes a `dns:lookup` event the first time a `(remote_host, process)` tuple is observed in a 1-hour dedupe window. Cross-platform via the existing reverse-DNS resolution; lets rules match on `remote_host` uniformly across log types.
- **Atomic `log_dir` migration** — `simplesiem log-dir migrate <new-path>` moves the entire log tree to a new location with config.json updates + on-failure rollback. Refuses non-empty destinations (no clobber) and refuses while a collector is paired (would put the collector's per-host mirror layout out of sync).
- **Convert-mode guards** — `convert master`/`server`/`standalone`/`collector` now refuses dangerous transitions: server → master without a peer (master would inherit zero ingest), master → collector (asks for an explicit two-step path), server → standalone with realm dependents (would orphan agents). Each refusal includes the operator action that resolves it.
- **Tunable volume-anomaly thresholds** — `cfg.server.volume_anomaly: { min_baseline, drop_ratio, consecutive_low_mins, cooldown_minutes }` is hot-reloaded by configWatcher. Operators with bursty fleets (laptops, batch hosts) tune `drop_ratio` up; steady-traffic ops teams tune it down — without a daemon restart.
- **Master pushes rules to its paired collector** — `simplesiem master push-rules` now also dispatches to `cfg.master.query_collector_url`. The collector stores the rules so the c7 failsafe-query path can replay against its own corpus when the master is offline.
- **Server-direct collector queries when no master** — `simplesiem server query-collector enroll/run/status` lets a server in a master-less realm query the paired collector's archive. Refused when a master is enrolled (the master is the canonical querier).
- **Multi-server collector queries when no master (c4)** — every realm server can query the same collector concurrently. Each server enrolls via `simplesiem server query-collector enroll` against the collector's `/v1/enroll-realm-server`, gated on the collector side by `simplesiem collector realm-servers accept-next` (per-CN slot — a leaked PSK alone can't enroll an unbounded list). When a master is later enrolled, realm-server enrollment is refused (the master takes over as canonical querier).

### SIEM workflow enhancements

- **Rule efficacy feedback** — `simplesiem rules tune` reads persistent stats and reports dead rules (no fires in 30d), runaway rules (>1000/day), and severity-vs-ack-rate mismatches. `--apply` rewrites severity edits.
- **One-shot suppressions** — `simplesiem rules suppress add --match host=X --match rule_id=Y --for 7d` writes an auto-expiring scoped allowlist (max 90d, no permanent). Stored in a sidecar (`rules-suppressions.json`) so it never disturbs the rule loader. Auto-prune watcher emits `meta:suppression_expired`.
- **Cross-tier sequence rules** — `cross_host: true` correlates events across hosts on the master tier. Hard caps (`sequence_max_window_seconds: 300`, `sequence_max_per_rule_kb: 64`, `sequence_max_total_kb: 1024`) prevent state explosion.
- **Threat intel (default-on)** — `cfg.threatintel.feeds[0]` ships ThreatFox (abuse.ch, CC0). Indicator sets exposed as rule predicate `in_threat_set`. Stale-cache fallback when the feed is unreachable. Disable with `cfg.threatintel.enabled: false`.
- **Backtest** — `simplesiem rules backtest --rule new.json --against 30d` runs a draft rule against historical events. Chunked walker, per-host parallelism, memory cap, progress reporting.
- **Incidents grouping** — fired alerts auto-group by `(host, time-window)` into incidents; webhooks gain `incident_id`. Default 60s window, configurable. Authority chain: master if enrolled, server otherwise, with collector receiving state during master outage; standalone always groups locally.
- **First-seen tuples** — `cfg.firstseen.tuples` defaults to `(user, geoip.country)`, `(process, path_dir)`, `(parent_proc, process)`. Each first occurrence emits `meta:first_seen_tuple`. Persistent across restarts; backup-included.
- **MITRE ATT&CK (Phase 1 + Phase 2)** — `simplesiem mitre catalog|coverage|fetch` auto-pulls the enterprise STIX bundle weekly. `simplesiem mitre generate-rules` instantiates the shipped curated template library (T1110, T1059, T1003, T1136, T1547.001, T1562.001, T1078, T1486, T1490, ...) into a `rules-mitre-generated.json` sidecar that merges into the live rule set. `--reject`/`--include` give per-technique opt-out without losing other generations.
- **Detection-as-code** — `simplesiem rules fixture-test` walks auto-captured fixtures (events ±60s around each fired alert). Operators never hand-write fixtures; rule edits trigger a "NEEDS-REVIEW" state until `--refresh`.
- **Triage timeline + pivot** — `simplesiem triage-pivot --pivot-from <alert-id>` walks five concrete edges (`same_host`, `same_pid_lineage`, `same_user`, `same_remote_host`, `same_filename`) at depth-1, capped at 24h window and 500 events.
- **Alert enrichment from threat intel** — when a fired alert's matched event has a `remote_host`/`sha256`/`hash` value present in any threat-intel indicator set, the alert payload gains a `threatintel: {feed, kind, confidence, threat_type, first_seen, reference}` block before fanout. SOC analysts see "this alert hit ThreatFox-tagged C2, confidence 95" inline.
- **Allowlist learning** — `simplesiem rules suggest-suppression` walks ack records (default 30 days), groups by `(rule_id, host)`, surfaces patterns acked ≥5 times. `--apply` lands them as 7-day auto-suppressions with the operator's ack reason text.
- **Behavioral baselining** — per `(host, hour-of-day, day-of-week)` event-rate baseline learned over 14 days. Activity exceeding `cfg.baseline.stddev_trigger`σ (default 3.0) emits `meta:baseline_anomaly`. Bounded by `cfg.baseline.max_hosts` (default 200) so the table stays small on large fleets.
- **Honey tokens** — `simplesiem honey add <path> --description "..."` registers a fake credential / config file. The built-in monitor stats every 30s and emits `meta:honey_touched` (severity=high) on size/mtime/SHA change. `honey list` shows last-touched timestamps so the deployed set stays inventoried.