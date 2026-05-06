# Reference

Lookup material for config keys, CLI commands, event schemas, hash chain mechanics, and build/test commands. Scan, don't read top-to-bottom.

For task-oriented walk-throughs see the mode guides: [standalone.md](standalone.md), [agent-server.md](agent-server.md), [realms.md](realms.md), [master.md](master.md), [rules.md](rules.md). For copy-pasteable one-liners, see [quickref.md](quickref.md).

## Contents

- [Command reference](#command-reference)
- [Triage flags](#triage-flags)
- [Configuration](#configuration)
  - [Top-level keys](#top-level-keys)
  - [Storage-quota keys](#storage-quota-keys)
  - [Agent-mode keys](#agent-mode-keys)
  - [Server-mode keys](#server-mode-keys)
  - [Master-mode keys](#master-mode-keys)
- [Backup &amp; restore](#backup--restore)
- [Status display &amp; timezones](#status-display--timezones)
- [Event schemas](#event-schemas)
- [Hash-chain integrity](#hash-chain-integrity)
- [HTTP endpoints](#http-endpoints)
- [Service control from the OS](#service-control-from-the-os)
- [Build from source](#build-from-source)
- [Smoke tests](#smoke-tests)

---

## Command reference

```
simplesiem <command> [flags]

  install                Install and start the service (drops default rules.json)
  uninstall              Stop and remove the service (keeps config + logs + rules)
  start                  Start the installed service
  stop                   Stop the running service
  restart                stop + start in one shot. Skips the stop step when the
                         daemon isn't running, so it's safe to run unconditionally
                         after any config change. Used internally by `realm rename`.
  fix [--dry-run]        Audit install integrity and repair issues

  run [--config PATH]    Run the daemon (invoked by the service)

  query  [flags]         Raw JSONL filter (--type, --since, --until, --grep, --field, --limit, --host).
                         --format json (default) | csv | tsv ; --csv-fields ts,event,host[,...]
  triage [flags]         Timeline reconstruction around a pivot
  tail   [flags]         Follow new events live (--type, --grep, --alerts, --json, --host)
  alerts [flags]         Pretty list of recent rule matches (--since, --severity, --host).
                         --unacked-only filters to alerts with no ack record.
                         --technique <ID> / --tactic <ID> filter by MITRE.
  alerts ack <hash>      Mark one or more alerts (by _hash or 8+ char prefix)
       [--note "..."]    as acknowledged. Writes <log_dir>/_acks/<date>.jsonl.
       [--by <name>]     Multiple ids per command supported.

  rules check            Parse + compile rules.json; nonzero exit on error
  rules test <file|->    Replay JSONL events through current rules and report fires
  rules replay [flags]   Replay current rules over historical events on disk.
       [--since 7d]      Defaults to the last hour. --type narrows to one log type;
       [--type T]        --host scopes to one agent in server/master mode.
       [--host H]        Stateless by default (every matching event counts as a fire);
       [--with-threshold] --with-threshold replays threshold/dedup state across the window
       [-v]              so only events that crossed the threshold count.
  rules stats [flags]    Aggregate alert fire counts per rule from on-disk alerts.
       [--since 7d]      Default 24h. Cross-references the configured rules so
       [--host H]        zero-fire rules show up too (dead-rule visibility).
  rules coverage         Group rules by MITRE ATT&CK tactic+technique and
       [--since 7d]      show fire-count per group. Identifies coverage
                         gaps (untagged rules) and fire-rate per technique.

  top --by <field>       Top-N aggregation across the corpus.
       [--since 1h]      --by source_ip / process / remote / etc.
       [--type T] [--host H] [--limit 10] [--format table|csv|tsv]

  tree                   Process tree reconstruction from process_start events.
       [--pid N]         --pid anchors on one PID; without it, every
       [--since 1h]      root-level process in the window plus its descendants.
       [--format table|json]

  hunt rare              Events whose --field value occurs ≤ --max-count times.
       --field <name>    Long-tail anomaly without writing a rule.
       [--since 24h] [--type T] [--host H] [--max-count 2]
  hunt pivot             Single-entity timeline across log types.
       --entity field:value
       [--since 1h] [--type T] [--host H]
  hunt firstseen         Field values that first appear in --since window
       --field <name>    (compared against --baseline window). "What's new?"
       [--since 24h] [--baseline 30d] [--type T] [--host H]
  hunt save <name>       Persist a hunt invocation by name.
       "<description>" -- <subcommand> [flags]
  hunt list              Print saved hunts.
  hunt run <name>        Re-run a saved hunt.
  hunt delete <name>     Remove a saved hunt.

  log-dir migrate <new>  Atomically move log_dir to <new>. Refuses if <new>
       [-y]              is non-empty, daemon is running, or a collector is
                         paired (m9). On any error mid-move (cross-fs copy
                         failure, config write failure), partial destination
                         is removed and source is left intact (rollback).

  server query-collector <enroll|run|status>
                         Server-side collector query path (mirrors `master
                         query-collector`). Only available when the realm has
                         no master enrolled. → [docs/realms.md](realms.md)
  verify [flags]         Walk hash chains in stored logs (--type, --date, --all, -v, --host)

  certs init             Generate CA + auto-issue server cert + create enrollment PSK
  certs server <host>    Issue (or re-issue) a server cert signed by the CA
  certs psk show|rotate  Show or regenerate the enrollment PSK
  certs revoke <id>      Add a revocation tombstone for an agent ID or master CN.
                         Propagates through realm sync within ~60s.
  certs revoked          List revoked agents/masters with revocation timestamps
  certs init-rotate      Generate a new CA, archive the old one to legacy_cas/,
       [--years N]       re-issue the server cert under the new CA. Existing
                         client certs continue to validate via the legacy CA in
                         the trust bundle until they auto-rotate.
  certs finalize-rotate  Remove every legacy CA from <state>/legacy_cas/. Run
                         after every client cert has rotated to the new CA.

  master enroll <url>    Enroll this master with a server (uses the server's enrollment PSK).
                         Generates a keypair locally, sends a CSR, receives a signed cert,
                         and adds the server URL to master.servers in config.json.

  master rotate-ca-all                 Trigger CA rotation on every server in master.servers.
       [--years N]                     Servers that are unreachable get caught up automatically
                                       on the next master pull cycle (rotation_realms policy).
  master rotate-ca-realm <realm>       Same, scoped to one realm.
       [--years N]
  master finalize-rotate-all           Remove legacy CAs from every server in master.servers.
                                       Same auto-catchup semantics as rotate-ca-all.
  master finalize-rotate-realm <r>     Same, scoped to one realm.
  master rotate-ca-status              Per-server CA timestamp + behind/caught-up state +
                                       active rotation/finalize policy on the master.
  master rotate-ca-policy clear-all    Stop the rotate/finalize auto-catchup across all realms.
  master rotate-ca-policy clear-realm <r>   Stop catchup for one realm.

  master collector enable --listen <addr>  Enable the master's TLS listener for a single
                                           collector. Auto-bootstraps PKI if missing.
  master collector accept-next             Open the slot for the next /v1/enroll-collector.
  master collector revoke                  Clear the currently-associated collector.
  master collector status                  Slot state + listen address + push interval.
  master collector show-psk                Print the master collector PSK.
  master collector rotate-psk [--force]    Generate a new master collector PSK.
  master collector push-interval <dur>     Set the master-pushed pull interval.

  collector enroll <url>   Enroll this collector with a server (or master).
       --key <PSK>         Generates a keypair locally, writes cert under
                           <config>/collector/<source>/.
  collector promote <url>  Switch a paired collector's source from a server to
       --key <PSK>         the realm's master, after the source surfaces a
                           master_url via /v1/sync/config.
  collector interval <dur> Set the pull cadence (CLI minimum 1m; daemon default daily).
  collector status         Source URL, authority hint, pull interval, failover list.

  collector master enable --listen <addr>
                              Enable the collector's TLS listener for a paired master
                              (master query-collector path). Auto-bootstraps PKI.
  collector master accept-next  Open the slot for the next master enrollment.
  collector master revoke       Clear the currently-paired master.
  collector master status       Slot state + listen address.
  collector master show-psk     Print the collector master PSK.
  collector master rotate-psk [--force]   New collector master PSK.

  collector realm-servers accept-next   (c4) Open the slot for the next realm-server
                              enrollment. When no master is paired, multiple realm
                              servers can each enroll concurrently to query this
                              collector — each `accept-next` admits one new CN.
  collector realm-servers list          Show realm-server CNs currently allowed,
                              the master-paired indicator, and accept-next state.
  collector realm-servers revoke <cn>   Remove a CN from realm_server_cns; that
                              server's mTLS calls are rejected on next handshake.

  rules tune [--apply] [--since 30d]    (#1) Classify rules by fire/ack stats and
                              report dead/runaway/severity-mismatch. --apply rewrites
                              rules.json (refused on a server with master enrolled).
  rules suppress add --match k=v ... --for <dur> --reason "..."   (#2) Auto-expiring
                              scoped allowlist; max 90d, no permanent.
  rules suppress list|remove|extend     Inspect / manage active suppressions.
  rules backtest --rule <file> --against <window> [--max-events N] [--max-memory-mb 256]
                              (#5) Replay a draft rule over historical events.
  rules fixture-test [--rule X] [--refresh]
                              (#9) Replay auto-captured fixtures; reports regressions.

  incidents list|show|config|status     (#6) Inspect grouped incidents; configure
                              the grouping window (refused on server with master).
  threatintel status                    (#4) Show feed configuration + cache age.
  firstseen status                      (#7) Show configured tuples + entry counts.
  mitre catalog|coverage|fetch|disable  (#8 Phase 1) MITRE ATT&CK auto-catalog + coverage.
  mitre generate-rules [--reject <id>] [--include <id>] [--list-templates]
                              (#8 Phase 2) Instantiate the curated
                              technique→rule template mapping into
                              <config>/rules-mitre-generated.json
                              (merged into the live rule set on load).
  triage-pivot --pivot-from <alert-id> [--window 5m] [--edges ...]
                              (#10) Bounded chronological timeline of related events.

  rules suggest-suppression [--since 30d] [--min-acks 5] [--apply [--for 7d]]
                              (ext2) Walk ack records and surface scoped suppression
                              candidates. --apply writes them with auto-expiry.
  baseline status [--top N]   (ext3) Show per-host event-rate baseline rollup.
  honey add <path> [--description "..."]
                              (ext4) Register a honey token; built-in monitor fires
                              meta:honey_touched on size/mtime/SHA change.
  honey list                  Show registered tokens with last-touched timestamp.
  honey remove <path>         Stop monitoring this token.

  network-source add --ip <ip> --vendor <id> [--mac <mac>]
       [--label "..."] [--no-tls]
                              (ni) Add a non-SimpleSIEM device (firewall, switch, IoT)
                              to the sticky-IP allowlist. --vendor is REQUIRED; use
                              `other` for unsupported vendors (no auto TLS posture).
                              ARP-resolves the MAC if --mac is omitted. Vendor with
                              required-TLS auto-sets tls_required=true (and refuses
                              --no-tls). Server/master mode only — refused on
                              agent / standalone / collector.
  network-source list [--stale-only]
                              Show the allowlist; --stale-only filters to rows whose
                              ARP-resolved MAC no longer matches.
  network-source remove --ip <ip> [--mac <mac>] [--force]
                              Delete an entry. --force needed for kind=gateway entries.
  network-source rename --ip <ip> [--mac <mac>] --label "<label>"
                              Update label only. rDNS-at-add-time is locked in;
                              rename is the only path to change a label.
  network-source revalidate   Re-ARP every entry; flag missing/changed MACs as stale.
  network-source resync       Pull the canonical allowlist from the authority
                              (master, or peer set if no master) and reconcile.
  network-source vendors      Print the bundled vendor catalog (TLS posture per vendor).

  net-send --host <h> --port <p> --transport udp|tcp|tls --message <frame>
       [--insecure] [--count N] [--interval-ms N]
                              Diagnostic helper: send a syslog frame to the listener.
                              Used by tests/uat to simulate firewalls + rogue devices.

  master query-collector enroll <url> --key <PSK>
                              Pair this master with a paired collector for archive
                              queries. Writes cert under <config>/master/query-collector/<host>/.
  master query-collector run [--host X --since 30d --type ... --grep ...]
                              Stream events from the collector matching filters.
                              Same flag set as `simplesiem query`. Output: NDJSON to stdout.
  master query-collector status  Show paired collector URL + cert dir + cert expiry.

  master migrate-server <server-url> <new-realm-peer-url> --key <PSK>
                              Master-driven server migration: target server clears its R1
                              state (peers, agent_allowlist, peer CAs, collector pairing —
                              master pairing PRESERVED), then queues the realm-join via the
                              pending-join watcher (~5s). Same `master_can_rotate_ca` opt-in.

  realm migrate <new-peer-url> --key <PSK> [--force]
                              Server-driven atomic migration. Authority gate refuses when
                              a master is enrolled (use `master migrate-server`); --force
                              double-prompts and breaks the master pairing locally.
                              Preflight: at least one OTHER R1 peer must be online + the
                              destination URL must be reachable. With --force, log files
                              are moved to <log_dir>/_legacy/migrated-from-<R1>/.

  certs collector accept-next   (server-side) Open the single-collector slot.
  certs collector revoke        (server-side) Clear the currently-associated collector.
  certs collector status        (server-side) Show slot state.

  realm join <peer-url>  Join an existing realm via PSK-authenticated handshake.
                         Sends this server's public CA to the peer, receives the peer
                         list + their CAs back, writes everything to the trust bundle.
                         No CA private key is ever copied between hosts.
                         Interactive when --key or <peer-url> are omitted.
                         Refuses to silently merge two unrelated realms that share
                         a name — prompts when local realm name == peer's realm name
                         AND the peer isn't already in this server's peer list.

  realm rename <new>     Rename this server's realm. Refused on agent/collector/
                         standalone (no realm) and on a server where a master is
                         present (use `master realm rename` instead). Bumps
                         server.realm.config_version; peers adopt within ~60s.

  master realm rename <realm> <new>
                         Push a realm rename across every server in master.servers
                         that currently reports realm=<realm>. Each server applies
                         via /v1/master/push/realm-rename (same `master_can_rotate_ca`
                         opt-in as `master push-rules`). Other peers in the renamed
                         realm adopt the new name via /v1/sync/config last-write-wins.

  convert <mode>         Switch this install's mode in-place. Master / collector
                         conversions are interactive (prompts for each URL + PSK).
                         For convert server: --realm <peer-url> + --realm-key <PSK>
                         joins a realm in the same command (skipping the prompt).
                         --keep-old defaults to true; pass --keep-old=false to
                         discard pre-conversion logs instead of moving them under
                         <log_dir>/_legacy/.
  install --mode <m>     Install with mode = standalone | agent | server | master.
                         For --mode server, --realm + --realm-key join a realm in
                         the same command. For --mode agent, --server + --key
                         enroll automatically.

  status                 Daemon up/down, mode, retention, rule count, hosts (server/master), collector health,
                         storage quota state for every configured volume, "latest update" freshness column
                         per log type (HH:MM:SS in host's local timezone + "(N ago)"), and any remote-host
                         storage warnings replicated through the meta stream.
  version                Print version + build number
  help                   Print usage

  backup --out <path>    Create a single encrypted .siembak file containing config_dir + state_dir +
       --passphrase-file log_dir + manifest. Daemon stays running during the backup; events written
       <file>            after the backup's UTC start are NOT included. Default: encrypted (--no-encrypt
                         to opt out, with a private-keys-in-plaintext warning). --no-compress skips gzip.
                         Refused on collector mode when --out is on the same volume as log_dir
                         (use a different storage partition).
  backup --agent <id>    (server / master mode) Compose a .siembak from the events the receiver already
       --out-dir <dir>   holds for one specific agent. No outbound call is needed — the server is already
                         the top of the agent → server hop, so it builds the file from on-disk material.
  backup --realm <name>  (server / master mode) Per-host backup of every host the receiver has events for
       --out-dir <dir>   in the named realm.
  backup --all           (server mode) Self + every agent + (with realm peers) fan out via /v1/backup/create
       --out-dir <dir>   to each peer server, unpack each peer's bundle, write everything flat in --out-dir.
  backup inspect --in <path>
       --passphrase-file Print the manifest of an encrypted/unencrypted backup without extracting bytes.
  backup verify --in <path>
       --passphrase-file Decrypt the envelope, walk every JSONL inside, and recompute the SHA-384
       [-v]              hash chain. Reports tampered, truncated, or out-of-order chains; does NOT
                         restore anything to disk. Use for periodic offline integrity checks of cold
                         backups (sometimes a tape comes back wrong; verify catches it before you need
                         to read from it).

  chainhead verify       Re-verify every signed record in <log_dir>/_chainhead/ against
       [--in <dir>]      its embedded public key. Exits non-zero on any failure.
                         Override --in for a backup of the chainhead stream restored
                         elsewhere.
  chainhead show         Print one human-readable line per signed record (signed_at,
       [--in <dir>]      head count, signing-key fingerprint).

  restore --in <path>    Restore from a .siembak. The header is parsed; on a wrong passphrase the FIRST
       --passphrase-file frame's GCM auth tag fails and restore aborts (no partial extract on disk). Bytes
       <file> [-y]       are streamed to a tempdir, then promoted: any existing config/state/log dirs at
                         the manifest's destinations are renamed to <dir>.pre-restore-<UTC> for rollback.
                         Refused over an existing non-standalone install (server / agent / master /
                         collector) unless --force is set. Pre-existing standalone logs are preserved as
                         <log_dir>.pre-restore-<UTC>. --dry-run prints the entry list.
                         Override paths with --config-dir / --state-dir / --log-dir.

  master backup --self <out>
                         Local backup of the master itself.
  master backup --collector <out>
                         Pull a single .siembak of the paired collector over its mTLS query channel.
  master backup --realm <name> --out-dir <dir>
                         Pull a per-host backup from every server in the named realm; layout
                         <out-dir>/<realm>/<host>.siembak.
  master backup --all-realms --out-dir <dir>
                         Umbrella: master self + paired collector + every server in every realm,
                         realm-grouped output (<out-dir>/<realm>/<host>.siembak,
                         <out-dir>/_self.siembak, <out-dir>/_collector.siembak). Servers whose realm
                         can't be resolved fall back to <out-dir>/by-server-<id>/.

  master uninstall-all   Cascade-uninstall every enrolled server, the paired collector (if any), and
       [--purge] [-y]    finally the master itself. Per-target opt-in: server.master_can_uninstall
       [--force]         AND collector.master_can_uninstall must be true on each receiving node;
                         without it the call returns 403. --purge propagates so log_dir + state_dir +
                         config_dir + certs are wiped fleet-wide. --force tolerates per-node 403s
                         (cascade proceeds past refusing nodes). Asks for two confirmations unless -y.

  uninstall              Stop and remove the local service. Prompts unless -y. Mode-aware: agent
       [-y] [--all]      notifies the server (allowlist cleanup); server notifies realm peers;
       [--purge]         master notifies enrolled servers; collector notifies its master / source.
       [--force]         Refuses on the last server in a realm with a master attached unless --force.
                         --all (or --purge) also removes log_dir, state_dir, config_dir, certs.
```

`--host <agent_id>` is meaningful in server and master modes. In standalone or agent mode it's accepted but has no effect (events don't carry a host field).

With **no arguments**, the interactive manager menu is shown — *unless* stdin isn't a terminal, in which case the usage text is printed and the process exits cleanly. Subcommands run non-interactively regardless of stdin, so `ssh host 'simplesiem triage --pid 1234 --json'` works.

`install`, `uninstall`, `start`, `stop`, `fix`, `convert`, the `certs *` subcommands (except `psk show` / `revoked`), `master enroll`, the `master rotate-*` / `finalize-*` / `policy *` subcommands, and `realm join` all require admin/root. The menu auto-elevates; from the CLI use `sudo` / Administrator. Read-only commands (`query`, `triage`, `tail`, `alerts`, `verify`, `rules`, `status`, `version`, `certs psk show`, `certs revoked`, `master rotate-ca-status`) work without elevation as long as the running user can read the log directory.

If you type a flag where a subcommand belongs (the most common beginner mistake — `simplesiem --at now --window 5m`), the binary prints a one-line "Did you mean: simplesiem triage ..." suggestion spliced from your argv before the usage block.

### `fix` — audit and repair

Walks the install and reports/repairs each of:

- install directory / binary presence (recopies current exe on fix)
- config directory / `config.json` presence + valid JSON (bad JSON is renamed to `.broken` and replaced)
- log directory presence
- service definition (systemd unit / launchd plist / SCM registration)
- service definition points at the installed binary path
- service is enabled for auto-start / loaded / StartType=Automatic

With `--dry-run`, only reports — doesn't change anything. Exit code is non-zero when issues remain after applying fixes (scriptable).

## Triage flags

| Flag | Purpose |
|---|---|
| `--file <str>` | Pivot on events whose JSON contains this path |
| `--pid <n>` | Pivot on events with `pid == n` |
| `--grep <regex>` | Pivot on events whose raw JSON matches the regex |
| `--field key=val` | Structured filter; repeatable; value supports `*=substring` and `~=regex` |
| `--at <ts>` | Pivot at this time. Accepts: `now`, RFC3339, `2pm today`, `2pm yesterday`, `14:30`, `2pm`, `2026-04-25 2pm` |
| `--since <dur>` | No-pivot mode: every event in `[now − dur, now]` (e.g. `30m`, `2h`, `7d`) |
| `--start <ts>` / `--end <ts>` | No-pivot mode: explicit range. `--end` defaults to `now`. Same time formats as `--at` |
| `--type <t>` | Restrict pivot search to one log type (`files`, `network`, ..., `alerts`) |
| `--window <dur>` | ± window around each pivot (default `30s`); used alone, implies `--at now` |
| `--max-pivots <n>` | Stop after this many pivots (default 10) |
| `--scan-days <n>` | How far back to scan for pivots (default 30) |
| `--explain` | For each `alerts` row in the timeline, print which rule fields matched |
| `--json` | Emit raw JSONL (pipe into `jq`) — adds `_delta_ms` and `_pivot` |
| `--no-color` | Disable ANSI colour even on a TTY |
| `--config <path>` | Config file |
| `--host <agent_id>` | Server/master mode: scope to one host's directory |

## Configuration

`config.json` lives in the config dir. Missing fields fall back to defaults; extra fields are ignored. Most changes take effect on service restart; `agent_allowlist` and `rules.json` hot-reload.

```json
{
  "mode": "standalone",
  "log_dir": "/var/log/simplesiem",
  "retention_days": 30,
  "network_interval": 2,
  "dns_cache_ttl": 600,
  "file_watch_paths": [
    "/etc", "/root", "/home", "/tmp", "/var/tmp",
    "/opt", "/srv", "/app", "/workspace",
    "/usr/local/bin", "/usr/local/sbin",
    "/var/spool/cron", "/var/spool/at",
    "/lib/systemd/system", "/usr/lib/systemd/system",
    "/usr/local/lib/systemd/system"
  ],
  "file_watch_recursive": true,
  "file_poll_interval": 30,
  "auth_interval": 5,
  "process_interval": 2,
  "traffic_interval": 30,
  "auth_log_paths": ["/var/log/auth.log", "/var/log/secure", "/var/log/messages"],
  "auth_log_interval": 2,
  "rules_path": "/etc/simplesiem/rules.json",
  "log_owner_group": "adm",
  "max_log_file_mb": 256,
  "write_queue_size": 4096,
  "state_dir": "/var/lib/simplesiem/state",
  "agent": {
    "id": "",
    "server_url": "",
    "client_cert": "/etc/simplesiem/certs/client.pem",
    "client_key": "/etc/simplesiem/certs/client.key",
    "ca_cert": "/etc/simplesiem/certs/ca.pem",
    "bearer_token": "",
    "spool_dir": "/var/lib/simplesiem/state/spool",
    "spool_max_mb": 512,
    "batch_size": 100,
    "batch_interval_seconds": 5,
    "insecure_skip_tls": false,
    "failover_servers": []
  },
  "server": {
    "listen": ":9443",
    "cert": "/etc/simplesiem/certs/server.pem",
    "key": "/etc/simplesiem/certs/server.key",
    "ca_cert": "/etc/simplesiem/certs/ca.pem",
    "require_client_cert": true,
    "bearer_tokens": [],
    "agent_allowlist": [],
    "master_cns": [],
    "agent_revoked": {},
    "master_revoked": {},
    "master_can_rotate_ca": false,
    "collect_locally": true,
    "local_id": "",
    "max_batch_bytes": 33554432,
    "max_decompressed_bytes": 268435456,
    "max_header_bytes": 32768,
    "max_concurrent": 256,
    "rate_per_second": 200,
    "rate_burst": 400,
    "max_clock_skew_seconds": 300,
    "agent_reauth_seconds": 60,
    "realm": {
      "name": "default",
      "peers": [],
      "sync_interval_seconds": 60,
      "master_url": "",
      "config_version": 0
    }
  },
  "master": {
    "servers": [],
    "sync_interval_seconds": 60,
    "certs_dir": "",
    "master_id": "",
    "rotation_realms": {},
    "finalize_realms": {}
  }
}
```

### Top-level keys

| Key | Units | Meaning |
|---|---|---|
| `mode` | enum | `standalone` (default), `agent`, `server`, or `master` |
| `log_dir` | path | where JSONL files are written |
| `retention_days` | days | rolling retention window; older daily files are deleted |
| `network_interval` | seconds | connection-table poll interval |
| `dns_cache_ttl` | seconds | reverse-DNS cache TTL |
| `file_watch_paths` | list of paths | directories watched via fsnotify |
| `file_watch_recursive` | bool | add subdirectories as they appear |
| `file_poll_interval` | seconds | (reserved for future polling-fallback) |
| `auth_interval` | seconds | login-session diff interval |
| `process_interval` | seconds | process-table diff interval |
| `traffic_interval` | seconds | host_io rollup interval |
| `auth_log_paths` | list of paths | candidate auth-log files (Linux only; first existing wins) |
| `auth_log_interval` | seconds | poll interval for tailing the auth log |
| `rules_path` | path | rules.json location; missing file = no rules |
| `log_owner_group` | group name | unix group given read access to log files; `""` to skip |
| `max_log_file_mb` | MB | per-file size cap before rotating to `.jsonl.N` |
| `write_queue_size` | events | async-write buffer; drops oldest when full |
| `state_dir` | path | per-collector restart-resume state files |

### Storage-quota keys

(Active in every mode. Defaults: warn at 80% used, halt at 90% used, no failover.)

| Key | Meaning |
|---|---|
| `storage.warn_threshold` | When to start showing a yellow `WARN` for the active log volume. Accepts `"80%"` (used-percent ceiling) or `"10GB"` (free-space floor — fires when free space drops below). Default `"80%"`. |
| `storage.halt_threshold` | When to refuse new event writes (and trigger failover, if configured). Same format as `warn_threshold`. Default `"90%"`. The daemon emits a `meta:storage_halt` event the first time the threshold is crossed; the event replicates to peers / masters / collectors via the existing event sync, so a master running `simplesiem status` sees every node's halt without polling. |
| `storage.failover_locations` | Ordered list of fallback log directories. When the active volume crosses `halt_threshold`, the storage controller swings every Storage instance (per-host, per-mode) to the first non-halted entry in this list and emits `meta:storage_failover`. When the primary recovers below `warn_threshold` the controller fails back to it (`meta:storage_failback`). All read paths union across every configured location so `tail`, `triage`, `query`, `verify` see events regardless of which volume they were written to. |

Threshold-format reminders:
- Percent values are USED-PERCENT (`"80%"` = trigger at 80% used).
- Absolute sizes are FREE-SPACE FLOOR (`"1TB"` = trigger when free space drops below 1 TB). Decimal units (KB, MB, GB, TB) are 1000-based; binary units (KiB, MiB, GiB, TiB) are 1024-based.
- Cross-platform: probes go through `gopsutil/disk` (statfs on Linux/macOS, `GetDiskFreeSpaceEx` on Windows).

The storage controller probes the active volume every 30 s with a 5 s shared cache so several `status` callers running concurrently never hammer the disk. Warning re-emission is rate-limited to once per hour so a sustained 80% volume doesn't spam meta. The collector mode adds one extra constraint that's enforced at the CLI rather than via config: `simplesiem backup --out` refuses paths on the same volume as `log_dir` so a backup can't itself fill the volume that's being backed up.

### Agent-mode keys

(Only consulted when `mode = "agent"`.)

| Key | Meaning |
|---|---|
| `agent.id` | stable identifier; defaults to hostname; must equal client-cert CN |
| `agent.server_url` | e.g. `https://siem.example.com:9443` |
| `agent.client_cert` / `client_key` / `ca_cert` | PEM files for mTLS |
| `agent.bearer_token` | optional `Authorization: Bearer ...` second factor |
| `agent.spool_dir` | local NDJSON spool when the server is unreachable |
| `agent.spool_max_mb` | spool ceiling; oldest batches drop when exceeded |
| `agent.batch_size` / `batch_interval_seconds` | flush triggers |
| `agent.insecure_skip_tls` | dev-only escape hatch; logs `meta:agent_insecure_tls` if set. **Belt-and-suspenders gate:** the daemon refuses to start unless the operator ALSO exports `SIMPLESIEM_ALLOW_INSECURE_TLS=1` in the daemon's environment, so a tampered config alone cannot disable cert validation. |
| `agent.failover_servers` | list of peer server URLs to fall back to when the primary is unreachable. Populated automatically by the server on enrollment when the server is part of a realm; refreshed on every heartbeat so peers added later become valid failover targets without re-enrolling. Sticky — the agent only rotates on failure. |
| `agent.ca_cert` | path to the multi-cert CA bundle. In a realm, this PEM file contains every peer's CA concatenated; the heartbeat response carries the live bundle and the agent atomically rewrites the file when it changes. |
| `agent.no_local_storage` | opt-in (default `false`). When `true`, the shipper drops batches that fail to ship instead of spooling them, skips the local-mirror write into `<log_dir>/_agent/` on ship failure, and refuses to create `agent.spool_dir`. Use case: hosts where "lose the in-flight events" is preferable to "leave plaintext on disk." Pairs with `batch_size: 1` + `batch_interval_seconds: 1` to minimise the in-memory drop window. **Dangerous by default — events are PERMANENTLY LOST during a server outage.** See [agent-server.md → Maximum exfiltration resistance](agent-server.md#maximum-exfiltration-resistance) for the full threat model. |

### Server-mode keys

(Only consulted when `mode = "server"`.)

| Key | Meaning |
|---|---|
| `server.listen` | bind address, e.g. `:9443` |
| `server.cert` / `server.key` | server's TLS cert + key (PEM) |
| `server.ca_cert` | CA used to verify agent client certs |
| `server.require_client_cert` | when true (default), mTLS is required |
| `server.bearer_tokens` | optional list of accepted bearer tokens |
| `server.agent_allowlist` | explicit list of agent IDs the server will accept. Empty = open mode (any valid cert). Non-empty = strict — every other agent gets HTTP 403 even with a perfectly valid CA-signed cert. Agents land here automatically when they enroll via PSK. |
| `server.master_cns` | list of master CNs allowed to call `/v1/sync/events` (in addition to realm peers). Populated automatically by `/v1/enroll-master`; manual entries are honoured. |
| `server.agent_revoked` | tombstone map: `agent_id → rfc3339_revocation_timestamp`. Effective acceptance is `id ∈ agent_allowlist AND id ∉ agent_revoked`. Set via `simplesiem certs revoke <id>`; propagates additively across realm peers via `/v1/sync/config`. |
| `server.master_revoked` | master-CN counterpart of `agent_revoked`. Same propagation. |
| `server.master_can_rotate_ca` | opt-in (default `false`). When `true`, masters in `master_cns` can trigger this server's `init-rotate` / `finalize-rotate` via `/v1/master/*` endpoints. Required for `master rotate-ca-all` to work against this server. |
| `server.master_can_uninstall` | opt-in (default `false`). When `true`, masters in `master_cns` can trigger this server's full local uninstall via `/v1/master/uninstall-self` (the `master uninstall-all` cascade). Same rationale as `master_can_rotate_ca`: a destructive cluster-wide operation must require an explicit per-node opt-in so a compromised master can't wipe the fleet by surprise. |
| `server.network_ingest.enabled` | enable the syslog listener for non-SimpleSIEM devices. **Default `true`.** Listener binds the configured ports; allowlist starts empty so no rogue frames can post until the operator adds devices. Refused on agent / standalone / collector modes (a `meta:network_ingest_refused` event is emitted instead). See [network-ingest.md](network-ingest.md). |
| `server.network_ingest.syslog_udp_listen` / `syslog_tcp_listen` / `syslog_tls_listen` | bind addresses for the three transports. Default: only TLS (`:6514` server / `:6515` master) is bound; UDP and cleartext-TCP are off. Empty disables a given transport. RFC 5425 TLS is the recommended posture for vendors that support it. |
| `server.network_ingest.tls_cert_mode` | `"server"` (reuse SimpleSIEM server cert; vendors must trust the SimpleSIEM CA), `"operator"` (operator-supplied `tls_cert` + `tls_key`), or `"selfsigned"` (auto-generated EC P-384 cert at `<state>/network_ingest/{cert,key}.pem`; SHA-256 fingerprint emitted via `meta:network_ingest_tls_cert` for vendor pinning). Default `"selfsigned"`. |
| Frame storage | Frames are persisted in two distinct paths based on validation outcome. **Authenticated** frames (passed sticky-IP + MAC + TLS-posture checks) → `<log_dir>/<entry.label>/syslog/<date>.jsonl` with `authenticated: true`. **Unauthenticated** frames (failed any check) → `<log_dir>/_unauthenticated/syslog/<date>.jsonl` with `authenticated: false` and `unauth_reason` ∈ {`unknown_source_ip`, `mac_mismatch`, `cleartext_refused`, `entry_stale`}. The rule engine fires only on authenticated frames. The only path that drops without storing is the per-source rate-limit overflow. |
| Attack-pattern detector | Built-in pattern set runs on every frame **before** allowlist validation. Hits emit `meta:network_ingest_attack_detected{reason, tactic, technique, severity:"high", indicator}` and fan an alert through the alert pipeline. Patterns are mapped to MITRE ATT&CK tactic + technique IDs so `simplesiem alerts --technique <ID>` and `simplesiem rules coverage` work without setup. Operator-extensible via `<config>/attack-patterns.json` (hot-reloaded; malformed JSON rejected with `meta:attack_patterns_reload_rejected`). Frame excerpts in alerts are sanitised — control characters become `?` so an attacker can't smuggle ANSI escapes into operator terminals viewing the alert. |
| `server.network_ingest.tls_cert` / `tls_key` | operator-supplied PEM paths; only consulted when `tls_cert_mode = "operator"`. |
| `server.network_ingest.bind_explicit` | required for any non-loopback bind. Default `true` (because network ingest is on by default; the operator opts in by leaving the default config). Set to `false` to refuse any non-loopback bind — useful as a guardrail in environments where the operator wants to disable accidental WAN exposure even on the default port. |
| `server.network_ingest.max_frame_bytes` | hard cap per frame (default 64 KiB). Oversize frames dropped at the boundary; `meta:network_ingest_oversize` emitted. |
| `server.network_ingest.max_frames_per_source_per_second` | per-source-IP rate limit (default 1000). Overflow emits `meta:network_ingest_rate_limited` (rate-limited so the meta log doesn't drown). |
| `server.network_ingest.master_can_push_allowlist` | per-server consent flag for `/v1/master/network-allowlist` push. Default `false`. Same posture as `master_can_uninstall` / `master_can_rotate_ca`. |
| `server.network_ingest.rdns_cache_ttl_seconds` | rDNS lookup cache TTL for unlabelled devices (default 300). The label-at-add-time stays locked in regardless. |
| `server.collect_locally` | when true (default), the server also runs collectors against its own host and stores the events under `<log_dir>/<local_id>/`. Disable for a pure receiver. |
| `server.local_id` | identifier for the server's own host events; defaults to `os.Hostname()`. Falls back to `_localhost` if the hostname isn't a valid agent ID. |
| `server.max_batch_bytes` | hard cap on POST body (compressed) |
| `server.max_decompressed_bytes` | hard cap after gzip decompression; defeats zip bombs (default 256 MiB; 0 = derive 8× max_batch_bytes, capped at 1 GiB) |
| `server.max_header_bytes` | hard cap on request headers (default 32 KiB) |
| `server.max_concurrent` | simultaneous in-flight uploads; over this returns 503 |
| `server.rate_per_second` | per-IP token-bucket fill rate (req/s); 0 disables |
| `server.rate_burst` | per-IP token-bucket capacity; bursts up to this size are allowed |
| `server.max_clock_skew_seconds` | accept agent timestamps within ±this many seconds; outside the window the ts is clamped to `now` and `clock_skewed:true` is recorded |
| `server.agent_reauth_seconds` | how often agents must hit `/v1/heartbeat` to renew their session. Default 60s. Changes propagate to agents via the heartbeat response. |
| `server.realm.name` | realm identifier; default `"default"`. Operators can rename from any peer; the rename propagates via `/v1/sync/config`. |
| `server.realm.peers` | list of peer server URLs in this realm. Each peer pulls events from every other peer on `sync_interval_seconds`. Empty = single-server realm. |
| `server.realm.sync_interval_seconds` | how often peers replicate logs and reconcile realm config; default 60. |
| `server.realm.master_url` | optional URL of a master that owns this realm. Reserved — master config push is not yet enforced. |
| `server.realm.config_version` | unix-nanos timestamp used by the last-write-wins reconciliation in `/v1/sync/config`. Set automatically. |
| `server.alert_webhooks` | list of HTTPS URLs that receive a POST per fired alert (JSON body). Empty (default) = no webhooks. Network failures and 5xx are retried with exponential backoff (1 s / 4 s / 16 s); 4xx is treated as a permanent reject and not retried. Drops on overflow are summarised in a `meta:alert_webhook_drops` event every 30 s rather than blocking the alert path. |
| `server.alert_webhook_min_severity` | filter applied before dispatch: only alerts at this severity or higher are POSTed. Accepted values: `low` / `medium` / `high` / `critical`. Default `low` (everything). |
| <a id="alert_syslog"></a>`server.alert_syslog` | optional RFC 5424 syslog forwarder. Object with `network` (`udp` / `tcp` / `udp6` / `tcp6`; default `udp`), `address` (`host:port`; empty disables), `facility` (0..23, default 16 = local0), `tag` (default `simplesiem`), and `severity_min` (default `low`). Severity mapping: critical→Critical(2), high→Error(3), medium→Warning(4), low→Notice(5). UDP is fire-and-forget; TCP retries once per send on connection drop. Drops on overflow surface as `meta:alert_syslog_drops` every 30 s. |
| `server.alert_escalation` | optional escalation watcher. Object with `enabled` (bool), `after_seconds` (default 900 = 15 min), `min_severity` ("high" / "critical"; default "critical"), and `scan_interval_seconds` (default 60). When set, the watcher walks `<log_dir>/<host>/alerts/` periodically and re-fires any unacked alert at or above `min_severity` that's older than `after_seconds`. Re-fires flow through the same alert-hook fanout as the original (webhooks + syslog), with the rule renamed `ESCALATED:<original-rule>` and event=`alert_escalated` so receivers can filter. Per-hash 24h cooldown prevents repeat re-fires. |
| `server.volume_anomaly` | tunable thresholds for the per-agent volume-drop detector. Object with `min_baseline` (events/min below which we never fire; default 5), `drop_ratio` (current/baseline ratio that counts as "quiet"; default 0.05), `consecutive_low_mins` (minutes-low in a row before firing; default 2), `cooldown_minutes` (per-agent re-fire suppression; default 30). Zero values keep the built-in default. Hot-reloaded by configWatcher — no daemon restart needed. |
| `server.query_collector_url` | URL of a paired collector this server can query. Set by `simplesiem server query-collector enroll`; per-collector cert lives under `<config>/server/query-collector/<peer-id>/`. Used only when the realm has no master (the master is the canonical querier when present). |
| `server.collector_cn` | cert CN of the single collector currently associated with this server (only relevant when the server is the highest-authority peer). When non-empty, log_dir changes are refused (m9 guard). |
| `collector.realm_server_cns` | (c4) list of realm-server CNs allowed to query this collector when no master is paired. Populated by `/v1/enroll-realm-server` after `collector realm-servers accept-next`; revocations via `collector realm-servers revoke <cn>`. Suppressed when `collector.master_cn` is non-empty (the paired master is the canonical querier). |
| `collector.realm_server_pending_enroll` | (c4) one-shot flag opened by `collector realm-servers accept-next` and consumed by the next successful `/v1/enroll-realm-server`. Prevents a leaked PSK from landing unbounded CNs in `realm_server_cns`. |

### Master-mode keys

(Only consulted when `mode = "master"`.)

| Key | Meaning |
|---|---|
| `master.servers` | list of server URLs to pull events from. Populated by `simplesiem master enroll <url> --key <PSK>`; can also be set manually for externally-issued certs. |
| `master.sync_interval_seconds` | how often the master pulls from each server; default 60. |
| `master.certs_dir` | per-server client cert root. Default `<config_dir>/master/`; expected layout is `<certs_dir>/<server-host>/{cert,key,ca}.pem`. |
| `master.master_id` | CN this master uses on its CSRs and enroll requests. Defaults to `master-<hostname>`. |
| `master.rotation_realms` | per-realm CA-rotation policy: `realm_name → rfc3339_timestamp`. Set by `master rotate-ca-all` / `rotate-ca-realm`. Auto-catchup loop reads it every pull cycle and rotates any server in the realm whose `last_rotated_at` is older than the policy. |
| `master.finalize_realms` | per-realm finalize-rotate policy, same shape as `rotation_realms`. Set by `master finalize-rotate-all` / `finalize-rotate-realm`. The catchup loop only triggers finalize once the server has caught up to the rotation policy. |
| `master.query_collector_url` | URL of the master's paired collector (set by `master query-collector enroll`). Used by `master backup --collector` and `master backup --all-realms` to pull a backup from the collector. |
| `master.rules_path` | rules file evaluated against every event the master pulls from a server. Empty (default) disables master-side correlation; falls back to `cfg.rules_path` when empty. Master fires land in `<log_dir>/_master/alerts/` and dispatch through `cfg.server.alert_webhooks` / `cfg.server.alert_syslog`. → [docs/master.md → Master-side rules](master.md#master-side-rules) |

### SIEM-enhancement keys (#1-10 + MITRE Phase 2)

| Key | Meaning |
|---|---|
| `threatintel.enabled` | (#4) Default `true`. Set false to disable all threat-intel feed fetches (zero outbound). |
| `threatintel.feeds` | List of feed specs. Default ships abuse.ch ThreatFox (CC0). Each feed has `name`, `kind`, `url`, `interval_hours`, `min_confidence`, `max_age_days`, `indicator_kinds`. |
| `incidents.enabled` | (#6) Default `true`. Disables alert→incident grouping when false. |
| `incidents.window_seconds` | (#6) Default 60. Operator-tunable via `simplesiem incidents config --window <dur>` (refused on a server with master enrolled). |
| `incidents.max_lifetime_seconds` | (#6) Default 86400 (24h). Hard cap on a single incident's duration; alerts past this start a new incident even if activity continues. |
| `incidents.is_authoritative` | (#6) Set by master broadcast / failover; servers turn this off when master signals authority. |
| `firstseen.enabled` | (#7) Default `true`. Tuple-based first-seen detection. |
| `firstseen.tuples` | (#7) List of tuple specs (`name`, `fields`). Default ships `(user, geoip.country)`, `(process, path_dir)`, `(parent_proc, process)`. |
| `firstseen.max_entries_per_tuple` | (#7) Default 1,000,000. Per-tuple capacity cap; LRU eviction emits `meta:firstseen_capacity_exhausted`. |
| `firstseen.ttl_days` | (#7) Default 90. Entries past TTL are pruned at daily rollover. |
| `mitre.enabled` | (#8) Default `true`. Auto-fetch MITRE ATT&CK STIX bundle. |
| `mitre.update_interval_days` | (#8) Default 7. How often the catalog is refreshed. |
| `mitre.bundle_url` | (#8) Default points at MITRE's official `attack-stix-data` GitHub raw URL. |
| `mitre.auto_generate_rules` | (#8 Phase 2) Default `true`. Auto-runs `mitre generate-rules` after each catalog fetch when set; false leaves operators in full manual control of the sidecar. |
| `rules_extras.fixtures.enabled` | (#9) Default `true`. Auto-capture fixtures around fired alerts for `rules fixture-test`. |
| `rules_extras.fixtures.keep_per_rule` | (#9) Default 5. Per-rule retention; oldest evicted on overflow. |
| `rules_extras.fixtures.max_total_mb` | (#9) Default 100. Hard cap on total fixture-tree size. |
| `master.rules.sequence_max_window_seconds` | (#3) Default 300. Cross-tier sequence rule window cap; loader rejects rules above this. |
| `master.rules.sequence_max_per_rule_kb` | (#3) Default 64. Per-rule memory budget; runtime overflow evicts oldest partials. |
| `master.rules.sequence_max_total_kb` | (#3) Default 1024. Sum-of-all-budgets cap. |
| `baseline.enabled` | (ext3) Default `true`. Per-host event-rate baseline + anomaly detection. |
| `baseline.window_days` | (ext3) Default 14. Rolling window over which (host, hour, dow) buckets accumulate samples. |
| `baseline.stddev_trigger` | (ext3) Default 3.0. Number of stddevs above the bucket mean that emits `meta:baseline_anomaly`. |
| `baseline.max_hosts` | (ext3) Default 200. Per-host table cap; further hosts are dropped silently. |
| `honey.enabled` | (ext4) Default `true`. Built-in honey-token monitor. |
| `honey.interval_seconds` | (ext4) Default 30. Stat cadence; lower = faster detection, higher load. |

## Backup &amp; restore

The backup feature exports every artifact SimpleSIEM owns on a host (config_dir + state_dir + log_dir + a UTC-stamped manifest) into a single `.siembak` file you can move between machines, store offline, or hand to a colleague. The same binary handles both `backup` and `restore` on every supported OS.

For the operational walk-through (when to back up, how to restore on a fresh box, hierarchical pulls from server / master), see [backup.md](backup.md). What's covered here is the on-wire format, the cryptographic primitives, the security guarantees against an attacker holding the file, and the safety guards on restore.

### File format

```
[ 6B  magic         "SBAK1\0" ]
[ 1B  flags         bit0 = encrypted, bit1 = compressed ]
[  when encrypted:
    [ 4B  PBKDF2 iterations (BE) ]
    [ 32B salt (random per backup) ]
    [ 12B AEAD nonce base (random per backup) ]
]
[ chunked frames... ]
```

Each frame:

```
[ 4B BE length, top bit = final-frame flag ]
[ length bytes of ciphertext+16B GCM tag (or plaintext when not encrypted) ]
```

Plaintext payload (after frame decryption + optional gzip decompression) is a tar containing:

```
manifest.json     — host_id, mode, realm, platform/arch, version+build,
                    created_at_utc, encrypted/compressed flags, the source
                    paths recorded for restore, and a `note` documenting
                    that events written after created_at_utc are NOT in
                    this backup.
config/...        — copy of <config_dir>
state/...         — copy of <state_dir> (certs, PSK, watermarks, ...)
logs/...          — copy of <log_dir>
loose/...         — any explicitly-named files (config_path / rules_path)
                    that lived outside the three directories above.
```

### Pure-Go tar/gzip — no external tooling required

The tar and gzip layers use Go's stdlib (`archive/tar`, `compress/gzip`), both pure-Go. `simplesiem backup` and `simplesiem restore` never invoke a system `tar` / `gzip` binary, which means a Windows host with no tar installed, a stripped Docker image, or a hardened Linux box without `/usr/bin/tar` all restore identically. The single SimpleSIEM binary carries everything the format needs.

### Cryptographic primitives

| Primitive | Value |
|---|---|
| Cipher | AES-256-GCM, 12-byte nonces, 16-byte authentication tag |
| Key derivation | PBKDF2-SHA384, 600,000 iterations, 32-byte random salt |
| Frame size | 1 MiB (chunked so multi-GB backups stream without holding ciphertext in memory) |
| Per-frame nonce | `nonce_base XOR counter` — counter increments per frame; no nonce reuse possible inside or across backups |
| Truncation detection | Final-frame flag in the length prefix; missing flag → `errBackupTruncated` at restore time |
| Compression | gzip (best-speed) inside the encryption envelope, so compression ratios don't leak over the wire |

The KDF uses the same SHA-384 family the rest of SimpleSIEM uses (certificate signature hash, HMAC, event chain hash) so the backup crypto matches the project's overall ~192-bit security level.

### What an attacker holding the backup file sees

Without the passphrase, an offline observer has access to:

- The 6-byte magic (a fixed string).
- The 1-byte format flags (encrypted/compressed yes/no).
- The 4-byte iteration count + 32-byte salt + 12-byte nonce base.
- A length-prefixed sequence of opaque ciphertext frames.

They do **not** see filenames, file sizes, host ID, realm, platform, the manifest, or any structure inside the tarball — those all live inside the encrypted frames. Each frame carries its own GCM tag, so single-byte tampering fails the verification of that frame; the final-frame bit prevents an attacker from quietly truncating to a clean cut.

To brute-force the passphrase the attacker must compute roughly 600k SHA-384 rounds per guess. A 12+ character passphrase from a decent word list makes that economically infeasible on commodity hardware.

### Restore process for a protected backup

```
simplesiem backup inspect --in /path/to/backup.siembak \
                          --passphrase-file /path/to/passphrase
   # Prints the manifest only; verifies the FIRST frame's GCM tag — a
   # wrong passphrase fails here without touching disk.

sudo simplesiem stop
   # Restore over a running daemon is rejected unless --force is set.

sudo simplesiem restore --in /path/to/backup.siembak \
                        --passphrase-file /path/to/passphrase \
                        --dry-run
   # Streams the full backup, decrypting/verifying every frame, and
   # prints the entry list without writing anything to disk.

sudo simplesiem restore --in /path/to/backup.siembak \
                        --passphrase-file /path/to/passphrase
   # Real restore. Internally:
   #   1. Header parsed; PBKDF2 re-derives the AES-256 key from the
   #      passphrase + salt + iter count.
   #   2. Each frame: AES-GCM Open verifies the per-frame tag. First
   #      frame failing = wrong passphrase OR file tampering = abort.
   #   3. Plaintext flows through gzip → tar.
   #   4. Manifest is read. If the destination already has a
   #      non-standalone install, restore refuses (use --force to
   #      override).
   #   5. Each tar entry is written into a unique tempdir
   #      (simplesiem-restore-XXXX) — no live install is touched until
   #      every entry has been verified.
   #   6. Promotion: any existing config/state/log dirs at the
   #      manifest's destinations are renamed to <dir>.pre-restore-<UTC>
   #      for rollback; staged dirs are renamed into place.

sudo simplesiem fix          # repair service registration if the OS changed
sudo simplesiem start
simplesiem status            # confirm mode, realm, storage state
```

### Atomicity

Both `simplesiem backup` and `simplesiem restore` are atomic: a failed run leaves the host exactly as it was before the command was issued. The implementation:

- **Backup**: ciphertext streams into `<outPath>.tmp` and only becomes visible at `<outPath>` via a single-syscall rename after every byte is written + closed. Any directories `MkdirAll`-ed by the backup itself are removed on failure if they end up empty, so a failed run on `--out /new/never/seen/file.siembak` leaves no trace. If `<outPath>` already existed, the previous file is preserved unchanged on any failure.
- **Restore**: per-tree SIBLING staging dirs (same-volume rename), three-tree commit phase with reverse-order rollback, removal of any directories created from scratch if the restore fails on a freshly-deployed (uninstalled) host.

### Restore safety guards

| Guard | Default behaviour | Override |
|---|---|---|
| Wrong passphrase | First frame fails AEAD verification, restore aborts before writing anything | n/a |
| Truncated file | Frame reader hits EOF without seeing the final-frame flag, returns `errBackupTruncated` | n/a |
| Tampered byte | The frame whose ciphertext was modified fails its 16-byte GCM tag; restore aborts at that frame | n/a |
| Existing non-standalone install at the destination | Restore refused with a message naming the existing mode | `--force` |
| Existing standalone install at the destination | Existing dirs renamed to `<dir>.pre-restore-<UTC>` for rollback | n/a (preserved by default) |
| Cross-platform restore (Linux backup → Mac restore) | Allowed; restore prints a one-line note recommending `simplesiem fix` to re-register the service for the new OS | n/a |
| Live original still active when a restored daemon comes up | Server's identity guard rejects requests from the second IP with HTTP 409 inside the guard window (60 s). Wait for the original to fully stop before bringing up the restored host. | n/a |

### Hierarchical / remote backup

A higher authority can request a backup from a lower authority over the existing mTLS channel:

```
master ─┐
        ├─ /v1/backup/create ─→ server (returns a multi-file bundle:
        │                       SBKB header + [name_len|name|size|body]
        │                       records, one .siembak per host)
        └─ /v1/backup/create ─→ collector

server ─── /v1/backup/create ─→ peer server (when this server is in a
                                realm and the operator runs
                                `backup --all`; called using THIS
                                server's own server-cert as a client
                                cert against the realm's cross-trust
                                bundle)
```

The handler authenticates via the existing `peerAuthorized` gate (client cert CN must match a recognised realm peer or registered master CN). The passphrase travels in the JSON request body inside the TLS 1.3 forward-secret session, never in the URL.

Constraints honoured by the master's pull paths:

- Master cannot use the collector machine as a *destination* for backups — the master writes only to its own `--out-dir` / `--out`.
- Collector mode refuses `simplesiem backup --out` on the same volume as `log_dir` (different storage partition required), so a backup cannot itself fill the volume being backed up.

## Status display &amp; timezones

`simplesiem status` renders timestamps in the host's local timezone (zoneinfo on Linux/macOS, registry on Windows — both via Go's `time.Local`, no platform-specific code). The timezone abbreviation is appended once per output section so an operator reviewing a remote `status` capture can tell at a glance which zone the wall clocks belong to:

```
entry         files    size       latest (EDT)
------------------------------------------------------------------------------
  network        3      1.4 MB    15:42:11 (2m 14s ago)
  files          3      482 KB    15:41:58 (2m 27s ago)
  meta           3       12 KB    14:08:03 (1h 36m ago)
```

The `latest` column is the mtime of the newest log file, formatted as:

- Same calendar day → `HH:MM:SS (Xm Ys ago)`
- Earlier day → `YYYY-MM-DD HH:MM:SS (Nd Xh ago)`

This makes it possible to spot a stalled collector ("auth: 1h 36m ago" while everything else is "2m" or fresher) without grepping the JSONL.

The same local-timezone rendering applies to `tail`, `triage`, `alerts`, and the `outage started` and `cert expires` lines in `status` and `master query-collector status`. **Storage** (event records on disk, file-naming, watermark exchange between peers) remains UTC end-to-end so cross-host correlation, hash chains, and realm replication stay timezone-independent.

## Event schemas

All events include common fields: `ts` (RFC3339Nano UTC), `type`, an `event` discriminator, plus `_seq`, `_prev`, `_hash`.

### Server-stamped fields

Events that arrive at a server from an agent get extra fields stamped at receive time, before the chain hash is computed:

| Field | Notes |
|---|---|
| `host` | Set to `X-SimpleSIEM-Host`, validated against the client cert CN. Used by `--host` filters. |
| `received_at` | RFC3339Nano UTC at the moment the server accepted the line. Useful when the agent's clock is off — `ts` is the agent's view, `received_at` is the server's. |
| `origin_server` | The receiving server's stable peer ID (host portion of `server.listen` if set, otherwise the OS hostname). Used by realm sync and master pull to filter for "events that originated at peer X" so replicated events never re-replicate. Always present in server mode. |
| `clock_skewed` | Only present when the agent's `ts` was outside `±max_clock_skew_seconds`. Set to `true`; the original timestamp is preserved as `agent_ts` and `ts` is rewritten to the server's `now()`. |
| `agent_ts` | Only present when `clock_skewed:true`. Holds the agent's original `ts` for forensics. |

A typical server-stored event:

```json
{"_hash":"…","_prev":"…","_seq":42,"ts":"2026-04-25T14:57:16Z","received_at":"2026-04-25T14:57:16.103Z","host":"laptop-01","origin_server":"siem-a","type":"network","event":"connection_open",...}
```

Agents writing to a standalone-mode local store don't get these extra fields.

### `network`

| Field | Example | Notes |
|---|---|---|
| `event` | `connection_open` / `connection_close` | |
| `status` | `ESTABLISHED` / `LISTEN` / `SYN_SENT` / `TIME_WAIT` | |
| `protocol` | `tcp` / `udp` | |
| `local` | `10.0.0.5:51234` | |
| `remote` | `140.82.114.4:443` | |
| `remote_host` | `github.com` | reverse-DNS, falls back to `1.1.1.1` resolver in containers |
| `pid`, `process`, `user`, `cmdline` | owning process | |
| `cmdline_hosts` | `["api.github.com"]` | hostnames extracted from cmdline when PTR fails |
| `duration_s` | `4.213` | close events only |

In display (`triage`, `tail`, `alerts`), known providers (Google, AWS, Cloudflare, GitHub, Canonical, ...) are labelled inline: `Google [ym-in-f113.1e100.net] (108.177.122.113:80)`.

### `dns`

| Field | Example | Notes |
|---|---|---|
| `event` | `lookup` | always `lookup` today |
| `remote_host` | `github.com` | the hostname `network` collector observed for a remote IP |
| `remote_ip` | `140.82.114.4` | resolved address |
| `process`, `user` | owning process | |

Synthesized by `NetworkCollector` when a previously-unseen `(remote_host, process)` tuple appears in the current 1-hour dedupe window. Captures the spirit of "DNS query logging" without per-platform resolver hooks (no NFLOG / ETW provider / Endpoint Security extension required) — works uniformly on Linux, macOS, and Windows. Use when writing detection rules on suspicious hostnames / TLDs without coupling to platform-specific DNS APIs.

### `files`

| Field | Notes |
|---|---|
| `event` | `created` / `modified` / `deleted` / `renamed` / `chmod` / `baseline` |
| `path` | absolute path |
| `dest` | destination for renames |
| `size`, `mode` | stat at time of event |
| `uid`, `gid`, `user` | unix only; `user` is the resolved username for `uid` |
| `sha384` | SHA-384 of file content on `created` / `modified` events for regular files ≤ 16 MiB. Not present on deletions / chmods / large files. Pairs with `match: { sha384: { in_file: "..." } }` for IOC feed integration. |

The `user` field is the file's owning user *after the change* — it's a proxy for the actor, not a guarantee. fsnotify can't name the actor; true exec-attribution would need fanotify or eBPF.

### `auth`

| Field | Notes |
|---|---|
| `event` | `login` / `logout` / `baseline_sessions` (session diff) |
|  | `ssh_login` (parsed sshd line — `result`: `success`/`failed`/`invalid_user`) |
|  | `ssh_disconnect` |
|  | `sudo` (`result`: `ok`/`failed`; includes `command`, `target` user, `terminal`, `pwd`) |
|  | `su` |
|  | `auth_success` / `auth_failed` / `auth_logout` / `auth_admin_assigned` (Windows; mapped from Security EventIDs 4624 / 4625 / 4634 / 4672) |
| `user`, `terminal`, `host`, `started` | session details |
| `remote`, `port`, `method` | for `ssh_login` |
| `event_id`, `record_id`, `computer`, `provider`, `domain`, `logon_type`, `source_ip`, `workstation`, `failure_reason`, `windows_event_time` | Windows-only fields lifted from `wevtutil`'s RenderedXml output; useful for cross-platform rules that key on `user` and `source_ip` |

`ssh_*` and `sudo`/`su` events come from the Linux file tail and macOS `log stream` collectors; the four `auth_*` events come from the Windows `wevtutil.exe` poller. The same `auth` log type holds all of them, so detection rules that match on `event:auth_failed` or `user:<name>` work uniformly across platforms. When `wevtutil.exe` isn't on PATH or the service account lacks `SeSecurityPrivilege`, the daemon writes a `meta:authlog_windows_unsupported` event and the collector idles.

### `processes`

| Field | Notes |
|---|---|
| `event` | `process_start` / `process_exit` |
| `pid`, `ppid`, `parent_name` | parent PID and (best-effort) parent process name |
| `user`, `name`, `cmdline`, `created` | starter, name, args, RFC3339 create time |
| `parent_cmdline`, `parent_user` | best-effort parent's full cmdline + user (subject to TTL-on-exit cache) |
| `exe_path`, `sha384` | resolved executable path + SHA-384 of executable content for regular files ≤ 32 MiB. The auditd / ETW / ESF "EXECVE-equivalent" enrichment without kernel hooks — works on Linux (`/proc/PID/exe`), macOS (`proc_pidpath`), and Windows (`NtQueryInformationProcess`). Permission errors (cross-uid processes) skip enrichment silently. |

### `traffic`

| Field | Notes |
|---|---|
| `event` | `host_io` (interval snapshot) or `active_connection` (one per unique flow at snapshot time) |
| `bytes_sent`, `bytes_recv`, `packets_sent`, `packets_recv` | host-wide, only on `host_io` |
| `destinations` | `[{user, process, remote, remote_host, protocol, count}]` — top flows during the interval; embedded in `host_io` |
| `user`, `process`, `remote`, `remote_host`, `protocol`, `count` | per-flow rollup, only on `active_connection` |

`active_connection` is emitted every `traffic_interval` seconds (default 30s). One event per unique `(user, process, remote_ip:port, remote_host)` tuple. The flow filter includes `ESTABLISHED`, `TIME_WAIT`, `CLOSE_WAIT`, `SYN_SENT`, `FIN_WAIT_*`, `LAST_ACK`, `CLOSING`, and UDP. Per-flow byte counters need eBPF and are not captured.

### `alerts`

| Field | Notes |
|---|---|
| `event` | `rule_match` |
| `rule`, `severity` | from the rule definition |
| `matched_type` | the log type of the event that matched (`auth`, `files`, ...) |
| `matched_event` | the original event's `event` field |
| `original` | the entire matched event, embedded |
| `count`, `window`, `group_by`, `group_value` | threshold rules only |

### `meta`

| `event` | When |
|---|---|
| `start` | Daemon startup; carries pid/platform/arch/version/intervals |
| `stop` | Clean shutdown |
| `rules_loaded` | Rules file parsed; carries `count` |
| `authlog_tail_started` | Auth-log collector attached; carries `path` (Linux) or `source: log stream` (macOS) |
| `authlog_windows_unsupported` | Windows: `wevtutil.exe` isn't on PATH or the service account lacks `SeSecurityPrivilege`; the collector idles instead of erroring every poll |
| `collector_silent` | Collector hasn't beat in `> 5 minutes`; carries `last_beat`, `silent_for_s` |
| `collector_recovered` | A previously-silent collector beats again |
| `writes_dropped` | Async write queue overflowed; carries `count` |
| `log_rotated_by_size` | A daily file rolled to `.jsonl.N`; carries `log_type`, `max_bytes` |
| `agent_tls_ping_ok` | Agent: connectivity preflight succeeded after enrollment |
| `agent_insecure_tls` | Agent: `insecure_skip_tls` is set (dev-only flag) |
| `agent_drops` | Agent: spool overflowed and dropped batches |
| `agent_ca_bundle_refreshed` | Agent: heartbeat reported a new realm CA bundle; trust set rebuilt |
| `agent_failover_list_refreshed` | Agent: heartbeat reported a new failover list; persisted to config |
| `agent_cert_rotated` | Agent: client cert auto-renewed before expiry |
| `agent_heartbeat_recovered` | Agent: /v1/heartbeat is responding again after a window of failures |
| `agent_reauth_interval_changed` | Agent: server pushed a new `agent_reauth_seconds` value via heartbeat |
| `server_unreachable_started` | Agent: shipper transitioned to degraded mode (no server is accepting batches) |
| `server_recovered` | Agent: spooled events are now being forwarded to a recovered server |
| `master_cert_rotated` | Master: per-server client cert auto-renewed before expiry |
| `realm_sync_pulled` | Server: pulled N events from a realm peer |
| `realm_revocations_merged` | Server: adopted one or more revocation tombstones from a realm peer |
| `realm_trust_bundle_refreshed` | Server: adopted a new peer CA from realm sync |
| `realm_join_accepted` | Server: a peer joined this realm via /v1/realm/join |
| `realm_allowlist_merged` | Server: adopted one or more agent IDs from a peer's allowlist |
| `realm_master_cns_merged` | Server: adopted one or more master CNs from a peer (auto-discovery propagation) |
| `realm_peers_grown` | Server: adopted one or more new peer URLs from realm sync |
| `realm_renamed` | Server: adopted a renamed `realm.name` from a peer with a higher `config_version` |
| `realm_unrevoke_quorum` | Server: enough peers voted to drop a revocation tombstone; tombstone removed |
| `master_sync_pulled` | Master: pulled N events from a registered server |
| `master_enrolled` | Server: a master successfully completed `/v1/enroll-master` |
| `master_health_listener_start` | Master: optional health listener bound on `master.listen` |
| `enroll_issued` | Server: signed a new client cert via `/v1/enroll` (audit trail) |
| `cert_rotated` | Server: signed a renewal cert for an agent or master |
| `cert_expiry_warning` | Any role: a tracked cert is approaching `NotAfter` (30d/14d/7d/1d/1h thresholds) |
| `ca_rotated_by_master` | Server: master triggered an init-rotate on this server |
| `ca_finalized_by_master` | Server: master triggered finalize-rotate on this server |
| `ca_catchup_rotated` | Master: auto-catchup rotated a server that was behind the policy |
| `ca_catchup_finalized` | Master: auto-catchup finalized a server that had pending legacy CAs |
| `rules_pushed_by_master` | Server: master delivered a new `rules.json` via `/v1/master/push/rules` |
| `config_hot_reloaded` | Server: config.json changed on disk and runtime state was refreshed |
| `tls_cert_reloaded` | Server: hot-reloaded the server cert from disk |
| `cert_san_drift` | Server: a host IP isn't in the cert SAN; agents dialing that IP fail TLS |
| `server_cert_san_extended` | Server: an agent's `/v1/enroll` SNI named a host not in the cert SAN; cert was re-signed and the listener hot-reloaded |
| `legacy_backship_queued` | Agent: pre-conversion `<log_dir>/_legacy/` events queued into the shipper's spool on first start |
| `collector_pull_complete` | Collector: pull cycle finished successfully; carries `events`, `source`, `watermark` |
| `collector_cert_rotated` | Collector: client cert auto-renewed against its source |
| `collector_enrolled` | Server: a collector completed `/v1/enroll-collector` and was admitted to the single slot |
| `collector_failover_list_refreshed` | Collector: source's `/v1/sync/config` reported a new realm peer set; persisted to local config |
| `collector_authority_promotion_available` | Collector: source surfaced a `master_url`; operator can promote the collector to pull from the master |
| `collector_interval_pushed` | Collector: source pushed a new `pull_interval_seconds` via `collector_push_config` |
| `collector_ca_bundle_refreshed` | Collector: source's CA bundle changed; on-disk `ca.pem` updated to keep handshakes valid |
| `master_collector_enrolled` | Master: a collector completed `/v1/enroll-collector` against the master listener |
| `master_collector_cert_rotated` | Master: signed a renewal cert for the paired collector |
| `master_collector_listener_start` | Master: TLS collector listener bound on `master.collector_listen` |
| `realm_renamed_by_master` | Server: master pushed a realm rename via `/v1/master/push/realm-rename`; persisted and will propagate to peers next sync |
| `master_pull_goroutine_spawned` | Master: started a pull goroutine for a server in `master.servers`. Fires both at startup (one per initially-registered server) and at runtime (one per server added by `master enroll` after the daemon started — picked up by the dynamic-server-watcher within ~60s, no restart needed). |
| `collector_master_listener_start` | Collector: TLS listener for a paired master-query bound on `collector.master_listen` (opt-in via `simplesiem collector master enable`) |
| `collector_master_enrolled` | Collector: a master completed `/v1/enroll-master` against the collector listener (single-master rule on the collector side) |
| `collector_realm_server_enrolled` | (c4) Collector: a realm server completed `/v1/enroll-realm-server` and was added to `realm_server_cns`. `newly_added=true` distinguishes a fresh CN from an idempotent re-enroll |
| `mitre_catalog_updated` | (#8 Phase 1) Catalog refreshed from MITRE STIX bundle. Carries `techniques_total` + `new_since_last` (delta vs prior cache) |
| `mitre_fetch_failed` | (#8) STIX bundle fetch failed; daemon falls back to cached catalog. Carries the underlying error |
| `mitre_rules_generated` | (#8 Phase 2) Sidecar `rules-mitre-generated.json` was rewritten. Carries `count` + `sidecar` path |
| `threatintel_updated` | (#4) ThreatFox feed pulled successfully; carries `feed` + `indicator_count` |
| `threatintel_fetch_failed` | (#4) Feed fetch failed; daemon reuses last cached set. Logged once per outage |
| `first_seen_tuple` | (#7) First time a tuple key was observed in the retention window. Carries `tuple`, `key`, `fields`, `first_seen` |
| `firstseen_capacity_exhausted` | (#7) Per-tuple cap reached; oldest 10% evicted (LRU on `first_seen_at`) |
| `suppression_expired` | (#2) Auto-prune watcher removed an entry past its `expires_at` |
| `sequence_budget_overflow` | (#3) Cross-tier sequence rule evicted oldest partials due to `sequence_max_per_rule_kb` cap |
| `incidents_authoritative_changed` | (#6) Tier transitioned authoritative state (master signal received / lost) |
| `baseline_anomaly` | (ext3) Per-host event rate exceeded `cfg.baseline.stddev_trigger`σ above the (hour, dow) bucket mean. Carries `host`, `observed`, `baseline_mean`, `baseline_sd`, `trigger_sd` |
| `honey_touched` | (ext4) Registered honey token had its size / mtime / SHA-256 change. Carries `path`, `change`, `description`, `severity=high`, before / after attributes |
| `collector_master_cert_rotated` | Collector: signed a renewal cert for the paired master |
| `realm_peer_left` | Server: a peer signalled departure via `/v1/realm/leave`; trust bundle and `realm.peers` updated, `realm.config_version` bumped so the rest of the realm picks up the change on next sync |
| `server_migrated_by_master` | Server: master pushed a realm migration via `/v1/master/migrate-server`; R1 state cleared, R2 join queued |
| `realm_pending_join_completed` | Server: the daemon's pending-join watcher completed the queued realm-join handshake (master-driven migration finalisation) |
| `agent_silent_anomaly` | Server: the per-agent volume-anomaly detector observed `current_per_min < dropRatio * baseline` for `consecutive` minutes after the warmup window; carries `agent`, `baseline_per_min`, `observed_per_min`, `drop_ratio`, `hint`. Written under both `<host>/meta/` and `_server/meta/`. |
| `first_seen_user` | Server: first time a `(host, user)` tuple has been observed in the retention window. Written under both `<host>/meta/` and `_server/meta/`. State persists in `<state>/firstseen.json`. |
| `first_seen_source_ip` | Same shape as `first_seen_user` but keyed on the `source_ip` field. |
| `first_seen_remote_host` | Same shape, keyed on `remote_host` (the reverse-DNS-resolved hostname `network` collector observed). |
| `first_seen_remote` | Same shape, keyed on `remote` (the raw `host:port` of a network-collector connection). |
| `first_seen_process` | Same shape, keyed on `process` (process name observed in `network` / `traffic` events). |
| `first_seen_name` | Same shape, keyed on `name` (process name on `processes` events). |
| `first_seen_sha256` | Same shape, keyed on `sha256` (legacy field name; today's events use `sha384`. Reserved for backward compatibility — no new fires today). |
| `unusual_time_anomaly` | Server: an entity (`user`/`source_ip`/`process`/`name`) that has been active in other hours (≥50 samples) is now active in an hour where it never has been. Carries `host`, `field`, `value`, `hour_local`, `baseline_total`. Per-entity 6h cooldown to avoid duplicate alerts. State in `<state>/tod_baselines.json`. |
| `alert_escalated` | Server: an unacked alert at or above `cfg.server.alert_escalation.min_severity` was re-fired through the alert-hook fanout. Carries `original_alert` (the original `_hash`), `original_rule`, `original_severity`, `age_minutes`, plus pass-through MITRE / runbook fields. The corresponding fanout event uses `rule: "ESCALATED:<original>"`. |
| `agent_silent_recovered` | Server: an agent that previously fired `agent_silent_anomaly` is back to ≥ 50 % of baseline; carries `agent`, `baseline_per_min`, `observed_per_min`. |
| `alert_webhook_drops` | Server: the webhook dispatcher's queue overflowed (typically because the receiver is slow or returning 5xx); summary written every 30 s with the dropped-alert count. |
| `alert_syslog_drops` | Server / master: the syslog dispatcher couldn't deliver to the configured collector (UDP fire-and-forget loss is silent; this fires on TCP retry-exhaustion or queue overflow). Same 30 s summary cadence. |
| `collector_query_failsafe_on` | Collector: paired source went unreachable; read-only commands (query/triage/tail/alerts) are now allowed locally on the collector. |
| `collector_query_failsafe_off` | Collector: paired source reachable again; read-only commands are gated again. |
| `chainhead_signed` | Any role: the periodic chainhead signer wrote one signed record into `<log_dir>/_chainhead/`. Carries `heads` count. Operators export this stream off-box for tamper-evident audit. |
| `chainhead_corrupt_tail` | Any role: the chainhead signer found a `<log_dir>/<host>/<type>/<date>.jsonl` file whose last line failed to JSON-parse (truncation, partial write, byte flip). The chainhead skipped that file but the meta event surfaces the gap so an operator can investigate via `simplesiem verify`. Carries `host`, `type`, `file`, `reason`. |
| `identity_conflict` (bearer) | Server: in bearer-only mode, a second daemon presented the same agent_id from a different IP within the 60 s identity-guard window; rejected with HTTP 409. Mirrors the cert-mode `identity_conflict` semantics. |
| `authlog_backfill_started` | macOS-only: on daemon start, the unified-log backfill is recovering events between the last seen timestamp and now. Carries `start` timestamp and `gap_seconds`. |
| `authlog_backfill_complete` | macOS-only: backfill finished. Carries `events` (count of auth events parsed) and `high_water` (the new resume timestamp). |
| `agent_departed` | Server: an agent called `/v1/agent/depart` (graceful uninstall hook) and was removed from `agent_allowlist`. |
| `master_departed` | Server: a master called `/v1/master/depart`; CN removed from `master_cns`. |
| `collector_departed` | Master / server: the paired collector called `/v1/collector/depart`; the single-collector slot was freed. |
| `master_uninstall_received` | Server: a master triggered `/v1/master/uninstall-self` and this server is starting its local teardown. |
| `identity_conflict` | Server: a second daemon presented the same client cert from a different IP within the 60 s identity-guard window; rejected with HTTP 409. Catches "I restored a backup while the original was still running." |

### `errors`

Written by collectors when they hit permission errors, missing paths, fsnotify watch exhaustion, etc. Panics from any collector are caught and written here with a full `stack` field before the collector restarts under exponential backoff (5s → 5min cap).

## Hash-chain integrity

Every event line carries three integrity fields:

- `_seq` — per-(type, day) sequence counter, starts at 1, monotonic.
- `_prev` — the previous event's `_hash` in this file. Empty at chain start.
- `_hash` — SHA-384, hex-encoded (96 chars), of `json.Marshal(event)` with `_hash` removed. Paired with the P-384 cert family for consistent ~192-bit security throughout. `simplesiem verify` auto-detects the hash length per line, so legacy 64-char SHA-256 chains continue to validate.

The chain resets when:

- The daily file rotates at UTC midnight (new file, new chain).
- A file hits `max_log_file_mb` and rotates to `.jsonl.N` (a meta event marks the boundary).
- The daemon restarts (verifier sees `_prev` go from non-empty to empty inside one file and treats it as a new sub-chain — a normal sign of an intentional restart, not tampering).

In server, master, and realm-replicated layouts, **each `from-<peer>.jsonl` file has its own independent chain** validated in isolation.

Run `simplesiem verify` to walk one or more files and recompute every hash; mismatches print per-line, exit code is non-zero if any are found. This is genuinely useful only if the chain heads are also exported off-box periodically (e.g. to immutable object storage). Without that, an attacker with write access can rewrite the entire chain. Future versions may sign chain heads with a per-host key; for now the property is "no silent in-place tampering."

## HTTP endpoints

All endpoints require mTLS unless noted. **TLS 1.3 only** with key exchange restricted to `X25519MLKEM768` (NIST FIPS 203 hybrid post-quantum KEM) — no classical fallback. Cert keys are ECDSA P-384; HMAC-SHA384 binds enroll responses; chain hash is SHA-384.

| Path | Used by | Purpose |
|---|---|---|
| `POST /v1/events` | agent → server | gzipped NDJSON event batch |
| `GET  /v1/health` | anyone | liveness probe; returns `{"ok":true}`. Unauthenticated for k8s/load-balancer probes. |
| `POST /v1/enroll` | agent → server | PSK-driven CSR signing; adds the agent ID to `server.agent_allowlist`. Response carries the multi-CA bundle + realm peer list. |
| `GET  /v1/heartbeat` | agent → server | session re-auth; response carries `agent_reauth_seconds`, the live realm CA bundle, and the current failover list (so agents pick up CA/peer changes within one beat). |
| `POST /v1/rotate` | agent / master → server | mTLS-only: the existing client cert is the proof of identity. Server signs a fresh CSR with the same CN under the current CA, returns new cert + CA bundle. Drives auto-rotation; no PSK needed. |
| `GET  /v1/sync/events` | realm peer / master → server | streams events with `origin_server == this server` since the caller's watermark |
| `GET  /v1/sync/config` | realm peer → server | returns realm name, peer list, every peer's public CA, the agent allowlist, and revocation tombstones (`agent_revoked`, `master_revoked`). Last-write-wins on `config_version` for the realm name. |
| `POST /v1/realm/join` | server → server | PSK-authenticated handshake. Joining server sends its public CA; receiving peer adds it to the trust bundle, returns the realm name + peer list + every existing peer's CA. Replaces the auditing-failure pattern of copying `ca.key` between hosts. |
| `POST /v1/enroll-master` | master → server | PSK-driven CSR signing for masters; adds the master CN to `server.master_cns` so it can call `/v1/sync/events` |
| `POST /v1/enroll-collector` | collector → server / master | PSK-driven CSR signing for collectors. Single-slot rule: refuses unless `accept-next` opened the slot (or the requesting CN already holds it). On a server, exposed at the same listener as `/v1/enroll`. On a master, exposed at the optional `master.collector_listen` TLS listener. Auto-extends the listener's cert SAN if the agent's SNI named a host not yet covered. |
| `POST /v1/master/rotate-ca` | master → server | Triggers `init-rotate` on the server. Default-deny: requires `server.master_can_rotate_ca: true` AND caller's CN in `master_cns` AND not revoked. Response carries the new CA cert PEM so the master can update its own per-server trust file. |
| `POST /v1/master/finalize-rotate` | master → server | Symmetric `finalize-rotate` trigger. Same authorization gate. |
| `GET  /v1/master/ca-status` | master → server | Returns current CA cert metadata + `last_rotated_at` timestamp + legacy CA count. Used by master auto-catchup and `master rotate-ca-status`. |
| `POST /v1/master/push/rules` | master → server | Master delivers a `rules.json` payload. Server validates with the same parser `simplesiem rules check` uses, writes the file, and hot-reloads the rule engine. Same opt-in gate as the rotation endpoints (`master_can_rotate_ca`). |
| `POST /v1/master/push/realm-rename` | master → server | Master renames the realm on this server. Body: `{"new_name": "..."}`. Same opt-in + auth as `master/push/rules`. Server bumps `realm.config_version` and propagates the rename to every peer via standard `/v1/sync/config` last-write-wins. |
| `POST /v1/master/migrate-server` | master → server | Master instructs this server to migrate from its current realm to a new one. Body: `{"new_realm_peer_url", "new_realm_psk"}`. Same `master_can_rotate_ca` opt-in + auth as the other master push endpoints. Server pings the destination, notifies its current peers via `/v1/realm/leave`, clears its R1 state (peers, agent_allowlist, peer CAs, collector pairing — but **not** the master pairing), and queues the realm-join handshake; the daemon's pending-join watcher completes it within ~5s without an operator restart. |
| `POST /v1/realm/leave` | server → server | A leaving server signals one of its current peers it's departing the realm. mTLS-authenticated; the request body's `leaver_id` must match the calling cert's CN, so a peer can't spoof a leave on another peer's behalf. Receiver removes the peer from `realm.peers`, deletes the per-peer CA, bumps `realm.config_version` so the rest of the realm learns about the departure on the next `/v1/sync/config` cycle. |
| `POST /v1/backup/create` | server / master → peer server | Privileged peer-to-peer call: instructs the receiver to compose a `.siembak` of itself and stream it back. Drives `simplesiem backup --all` (server fan-out across realm peers) and `simplesiem master backup --realm` / `--all-realms`. mTLS gated against the realm cross-trust bundle. |
| `POST /v1/agent/depart` | agent → server | Graceful uninstall hook. The agent calls this from `simplesiem uninstall` so the server removes it from `agent_allowlist` immediately rather than waiting for a heartbeat timeout. |
| `POST /v1/master/depart` | master → server | Graceful master-side uninstall hook. Server removes the master CN from `master_cns`. |
| `POST /v1/collector/depart` | collector → master / server | Graceful collector-side uninstall hook. Frees the single-collector slot on the authority. |
| `POST /v1/master/uninstall-self` | master → server | The `master uninstall-all` cascade entry point. Server tears down its own service registration and exits. Default-deny: requires `server.master_can_uninstall: true` AND caller's CN in `master_cns`. |
| `POST /v1/master/uninstall-collector` | master → collector | The `master uninstall-all` cascade hook for the paired collector. Exposed on the collector's master-query listener. Default-deny: requires `collector.master_can_uninstall: true`. |
| <a id="metrics"></a>`GET  /metrics` | scraper → server | Prometheus exposition format. Auth-gated: any valid client cert OR a bearer token in `cfg.server.bearer_tokens` is accepted. Unauthenticated callers get HTTP 401. Counter families: `simplesiem_events_ingested_total`, `simplesiem_events_rejected_total`, `simplesiem_alert_fires_total{rule,severity}`, `simplesiem_events_by_host_type_total{host,type}`, `simplesiem_alert_webhook_drops_total`, `simplesiem_alert_syslog_drops_total`, `simplesiem_http_auth_failures_total`. Gauges: `simplesiem_agents_active`. Counters survive across daemon restarts only via Prometheus rate aggregation — they're zeroed on restart. |
| `GET  /health` | k8s probe → master | Master-only plain-HTTP liveness probe, off by default. Bound when `cfg.master.listen` is non-empty. Returns `{"ok":true}`; no auth (a master has no inbound trust relationship to leak — the only fact this exposes is "the master process is alive"). |

Status codes:

| Code | Cause |
|---|---|
| `200` | Success |
| `400` | malformed body / too many decode errors / path-traversal hostname / CSR validation failure |
| `401` | bearer token missing or wrong / wrong PSK / no client cert on a cert-required endpoint; rate-limited logging |
| `403` | CN ↔ Host mismatch / agent not on allowlist / agent or master revoked / master not on `master_cns` / `master_can_rotate_ca` is false |
| `413` | body or decompressed body too large |
| `429` | rate limit exceeded; carries `Retry-After: 1` |
| `503` | server saturated (more than `max_concurrent` in flight) |

## Service control from the OS

Besides `simplesiem start` / `stop`, the services are standard OS citizens:

```
# Windows
sc.exe start simplesiem
sc.exe stop  simplesiem
sc.exe query simplesiem

# Linux (systemd)
systemctl start   simplesiem
systemctl stop    simplesiem
systemctl status  simplesiem
journalctl -u simplesiem -f        # mostly silent on a healthy daemon

# Linux standalone (no systemd, e.g. Docker)
simplesiem start                              # setsids, records /var/run/simplesiem.pid
simplesiem stop                               # SIGTERMs the PID and cleans the pid file
kill -TERM $(cat /var/run/simplesiem.pid)     # equivalent
tail -f /var/log/simplesiem/daemon.log        # daemon stdout/stderr

# macOS
sudo launchctl list com.simplesiem
sudo launchctl kickstart -k system/com.simplesiem
sudo launchctl unload /Library/LaunchDaemons/com.simplesiem.plist
```

The systemd unit ships with a hardened sandbox: `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome=read-only`, `ProtectKernelTunables`, `ProtectKernelLogs`, `ProtectKernelModules`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`, `LockPersonality`, `RestrictRealtime`, `RestrictSUIDSGID`, `RestrictNamespaces`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`, plus an allow-list `SystemCallFilter=@system-service @network-io @file-system`. `PrivateTmp` is intentionally **off** because `/tmp` is in the default watch list — enabling it would put the daemon in a private tmpfs and make the watcher useless.

On macOS `stop` = `launchctl unload`. `KeepAlive=true` in the plist means a plain SIGTERM would be auto-restarted, so `simplesiem stop` unloads to actually halt. `simplesiem start` handles both the "reload" and "kickstart" cases.

### Docker & init-less Linux

SimpleSIEM detects whether systemd is available at install time. If it isn't (Docker, LXC, minimal base images, some CI runners), it falls back to **standalone mode** — a PID-file + `setsid` background daemon — so `install`, `start`, `stop`, `uninstall`, `status`, and `fix` all keep working without `systemctl`.

| Path | Purpose |
|---|---|
| `/var/lib/simplesiem/.installed` | install marker |
| `/var/run/simplesiem.pid` | running daemon's PID |
| `/var/log/simplesiem/daemon.log` | daemon's stdout/stderr |

For immutable container images, the better pattern is to skip install and let the daemon be PID 1:

```dockerfile
FROM debian:12-slim
COPY simplesiem-linux-amd64 /usr/local/bin/simplesiem
RUN chmod +x /usr/local/bin/simplesiem
VOLUME ["/var/log/simplesiem"]
ENTRYPOINT ["/usr/local/bin/simplesiem", "run"]
```

## Build from source

Prereq: Go 1.21+. Deps: `gopsutil/v3`, `fsnotify`, `golang.org/x/sys`.

```
# On Windows (cross-builds all six targets)
.\build.ps1

# Or manually for one target:
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -trimpath -ldflags "-s -w -X main.buildNumber=$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))" -o dist/simplesiem-linux-amd64 .
```

`build.ps1` produces six binaries (Windows amd64/arm64, macOS amd64/arm64, Linux amd64/arm64), each with a fresh UTC `YYYYMMDDHHMMSS` build number baked in via `-ldflags -X main.buildNumber=...`. Check it with:

```
simplesiem version
# SimpleSIEM 0.1.0 (build 20260425230048)
```

### Tests

```
go test ./...
```

Covers `parseTimeRef` / `parseClock` / friendly time formats, the rule matcher and `shouldFire` (including dedup and threshold), the auth-log parsers (Linux file tail and macOS ndjson), `providerLabel`, and `renderTarget`. The Linux auth-log tests are guarded by a `//go:build linux` tag; macOS tests by `//go:build darwin`.

## Smoke tests

End-to-end scripts under `tests/` exercise install → wait → trigger events → tail/alerts/verify/status/rules → uninstall on each platform. Useful as a CI smoke check or after a breaking refactor.

```
sudo ./tests/smoke_linux.sh                    # Linux, requires root
sudo ./tests/smoke_darwin.sh                   # macOS, requires sudo
.\tests\smoke_windows.ps1                      # Windows, elevated PowerShell
```

Each script:

- Stops/uninstalls any leftover from a previous run.
- Installs the binary as a service.
- Waits ~10s for collectors to settle.
- Touches a watched file and (on unix) runs `sudo` to generate events.
- Runs `tail` for 3s and checks for output.
- Runs `alerts`, `verify`, `status`, `rules check`, and `query` and checks each succeeds.
- Exercises the cert pipeline (`certs init`/`server`/`psk`) against a temp config dir and verifies the produced PEM files load via Go's `tls.LoadX509KeyPair`.
- Pipes a synthetic event through `rules test -` (stdin) to confirm rule matching works.
- Cleans up via a `trap` (so a failure mid-run doesn't leave a service installed).

Output is per-step PASS/FAIL with colour. Exit code is non-zero on any failure.

The scripts deliberately don't bring up a full agent↔server pair — that's a multi-process test better done in CI than a one-shot script. The cert generation half is covered, and the runtime mTLS round-trip is exercised by ad-hoc tests during development.

There's also a docker compose rig under `tests/docker/` with four containers (siem-server, siem-server2, siem-master, siem-agent) useful for exercising agent + realm + master flows in one place.
