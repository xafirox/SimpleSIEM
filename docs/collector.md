# Collector mode

Collector mode is the **optional 5th node role** in SimpleSIEM — a single-source backup replicator that pairs with one master (preferred) or one server. It exists to give a realm or master tier a redundant, off-node archive of the entire event corpus without inviting a second active aggregator into the trust graph.

You don't need a collector. Most deployments don't have one. Add one when you want a redundant copy of every event held by your master / realm, on a different administrative domain that an attacker compromising the master can't easily reach.

> **Naming note.** "Collector" is overloaded. This doc is about
> the **node role** — a separate host running with `mode:
> "collector"`. The unrelated **in-process collectors**
> (`NetworkCollector`, `FileCollector`, `AuthLogCollector`,
> `ProcessCollector`) are goroutines inside every daemon; their
> behaviour is in [docs/reference.md → Event schemas](reference.md#event-schemas)
> alongside the schemas of the events they produce.

## What a collector does

| | |
|---|---|
| **Pairs with** | exactly ONE source — a master (preferred) or a server (fallback). Single-slot rule on the authority side: a master / server can only ever associate with one collector at a time. |
| **Pulls from** | the source's `/v1/sync/events` endpoint on a configurable cadence. Default is once per day. |
| **Stores** | every replicated event under `<log_dir>/<host>/<type>/<date>.from-<origin>.jsonl`, mirroring the master's per-origin layout. |
| **Also runs** | the same in-process collector goroutines as standalone (so the collector host is itself monitored alongside the replicated archive). |
| **Cannot** | run rules, change realm config, push rules, query (by default — see failsafe below), or accept inbound from anything but its paired master. |

## When to add a collector

Add a collector when **at least one** of these applies:

- You want a tamper-evident redundant copy of the realm's events that survives a master compromise. The collector pulls from the master; an attacker rooting the master can corrupt master-side state but the collector's pull is mTLS-authenticated and the events carry their own SHA-384 chain — corruption is detectable via `simplesiem verify`.
- You want longer-tail retention than the master / realm holds. The collector's `log_dir` is sized independently; an operator can keep months of events on the collector while the realm rotates at 30 days.
- You want a dedicated host the SOC can pull from for offline threat hunting (`simplesiem query`) without adding load to the production aggregation tier.

**Don't** add a collector if you just want HA — that's what realm peering is for. Two servers in a realm replicate events to each other; a collector adds one-way redundancy on top of an already-HA realm, not a substitute for it.

## Collector ↔ master XOR collector ↔ server

A collector pairs with a master when the realm has one (the common case in master-managed deployments). It pairs with a server when there's no master — useful for single-realm setups that want backup redundancy without the master tier's complexity.

```
+--------------+              +-----------+              +----------+
|  agents (N)  |  ─mTLS──→    |  servers  |  ─pull──→    |  master  |
+--------------+              +-----------+              +----------+
                                                              │
                                                              │ (single-slot pull)
                                                              ▼
                                                          +-----------+
                                                          | collector |
                                                          +-----------+
```

If you don't have a master, the collector can pair directly with a server:

```
+--------------+              +-----------+              +-----------+
|  agents (N)  |  ─mTLS──→    |  server   |  ←pull───    | collector |
+--------------+              +-----------+              +-----------+
```

The collector's source URL determines the relationship; nothing about its mode changes between the two configurations. When the realm later acquires a master, the collector can be **promoted** to pull from the master instead — see "Authority promotion" below.

## Single-slot rule

The authority side (master OR server) refuses any `/v1/enroll-collector` request unless either:

- the slot is empty AND `accept-next` was opened by an operator, OR
- the requesting cert's CN already matches the recorded `collector_cn` (re-enrolling the same collector is fine).

This prevents a leaked PSK from enrolling a second collector while the slot is filled. Free the slot to swap collectors:

```bash
# On the master (or server):
sudo simplesiem master collector revoke
sudo simplesiem master collector accept-next
```

## Setting up a collector

The recommended flow uses **PSK enrollment**: the master generates one short string the operator types into the collector host, the collector generates its own keypair locally, and the master signs the CSR remotely. Private keys never traverse the network.

### 1. On the master (preferred)

```bash
# Stand up the master collector listener.
sudo simplesiem master collector enable --listen :9445

# Open the single-collector slot for the next enrollment.
sudo simplesiem master collector accept-next

# Print the PSK to type into the collector host.
sudo simplesiem master collector show-psk
# → simplesiem-psk:<...>
```

### 2. On the collector host

```bash
sudo ./simplesiem install --mode collector \
  --master https://<master-host>:9445 \
  --master-key simplesiem-psk:<master-collector-PSK>
```

Both flags are required at install time — the install is atomic; either it lands paired and pulling, or it doesn't land at all. After install completes the daemon starts pulling on the next interval (default 24 h, but the first pull happens immediately).

### Server-paired (no master)

If your realm has no master, swap the master-side commands for the server-side equivalents:

```bash
# On the server:
sudo simplesiem certs collector accept-next
sudo simplesiem certs psk show

# On the collector:
sudo ./simplesiem install --mode collector \
  --master https://<server-host>:9443 \
  --master-key simplesiem-psk:<server-PSK>
```

(The flag is named `--master` for both because the same internal mechanism handles either source — the collector records the source's `authority_hint` so future operations treat it correctly.)

### Verify

```bash
simplesiem collector status
# source URL:    https://<master-host>:9445
# authority:     master
# pull interval: 24h
# watermark:     2026-05-02T18:42:00Z
# last pull:     2026-05-02T18:42:00Z (success, 1247 events)
# failover list: 0 fallbacks
```

The first pull cycle (the immediate one on startup) backfills every event the source holds since the source's retention floor. Expect a brief catch-up burst on day one.

## Authority promotion

The collector tracks an `authority_hint` field in `cfg.collector.authority_hint`. Values:

- `"server"` — currently pulling from a server (no master in the realm)
- `"master"` — currently pulling from a master

When a server-paired collector's source surfaces a `master_url` via `/v1/sync/config` (i.e., the realm has just acquired a master), the collector emits a meta event:

```
meta:collector_authority_promotion_available
```

The operator can then promote the collector to pull from the master:

```bash
sudo simplesiem collector promote https://<master-host>:9445 \
  --key simplesiem-psk:<master-collector-PSK>
```

Promote is essentially "re-enroll against a different source." The previous source's pairing is cleared; the new one is recorded. The collector keeps its existing `log_dir` so historical events aren't lost.

## Tuning the pull cadence

```bash
# Pull every hour instead of daily:
sudo simplesiem collector interval 1h

# Or 5-minute (the CLI accepts a 1m minimum; sub-minute would
# turn the collector into a near-real-time replica):
sudo simplesiem collector interval 5m
```

The master can also push the cadence to the paired collector via `master.collector_push_config.pull_interval_seconds`; the collector adopts the pushed value transparently (operators see a `meta:collector_interval_pushed` event).

## Failover

`cfg.collector.failover_servers` is populated automatically from the source's `/v1/sync/config` peer list. On primary-source unreachability the collector rotates through the list (sticky — it stays on the first reachable peer until it fails). Same model as `agent.failover_servers`.

A non-master, server-paired collector inherits the realm's peer list as fallbacks. A master-paired collector typically has no fallbacks (a single master, no master-master peering); if the master is down, the collector emits `meta:collector_silent` and idles.

## What a collector cannot do (by design)

- **Run rules.** The collector has no rule engine. Configure rules on the servers; replicated alerts come along with the events.
- **Change realm config.** `realm rename` / `realm join` / `realm migrate` all return `refused: collector mode does not allow ...`.
- **Push rules.** `master push-rules` is master-only — but the master DOES push to the paired collector as part of that fan-out (c8). The collector stores the rule set on disk so the c7 failsafe-query path can replay against the local corpus when the master is offline.
- **Run queries by default.** `query` / `triage` / `tail` / `alerts` / `verify` are gated when the collector is paired. This is intentional — the collector is a backup tier, not an active analyst surface.

### Failsafe: queries when the source is unreachable

If the collector's master / server has been unreachable for a configurable threshold, the read-side commands turn back ON as a failsafe. The intent is "if all aggregators are down, the collector is the only place left with the events; let the operator query it." When the source comes back, queries auto-disable again on the next pull cycle.

A `meta:collector_query_failsafe_on` / `..._off` event marks each transition.

## Master querying the collector's archive

The master can pull historical events from the collector's longer-tail retention without touching its own (smaller) tail. Pair via the collector's optional master-query listener:

```bash
# On the collector:
sudo simplesiem collector master enable --listen :9446
sudo simplesiem collector master accept-next
sudo simplesiem collector master show-psk

# On the master:
sudo simplesiem master query-collector enroll https://<collector>:9446 \
  --key simplesiem-psk:<collector-master-PSK>

# Run queries against the collector's archive:
sudo simplesiem master query-collector run \
  --host <agent-id> --since 30d --type files --grep '/etc/'
```

This pairing is **single-master**: only one master ever queries a collector. Same single-slot rule that governs the collector ↔ master pairing.

## Realm-servers querying the collector (no master)

When the realm has **no master**, every realm server can query the collector concurrently — the master's "canonical querier" role isn't held by anyone, so there's no rule to break. Each server enrolls itself with the collector via the multi-server endpoint `/v1/enroll-realm-server`, gated on the collector side by a per-enrollment `accept-next` flag so a leaked PSK can't land an unbounded number of CNs in the list.

```bash
# On the collector — same listener the master path uses:
sudo simplesiem collector master enable --listen :9446
sudo simplesiem restart   # bind the listener

# For each realm server you want to admit:
sudo simplesiem collector realm-servers accept-next   # opens slot for ONE
sudo simplesiem collector master show-psk              # copy this

# On that realm server:
sudo simplesiem server query-collector enroll \
  https://<collector-host>:9446 --key simplesiem-psk:<...>

# Repeat accept-next on the collector for every additional server.
# To inspect / revoke later:
sudo simplesiem collector realm-servers list
sudo simplesiem collector realm-servers revoke server-<hostname>

# Run queries from any enrolled server:
sudo simplesiem server query-collector run \
  --host <agent-id> --since 30d --type files --grep '/etc/'
```

If a master later enrolls with the collector, `realm-servers accept-next` refuses (the master is now the canonical querier). Revoke the master to switch back to multi-server mode.

## Backup of the collector

Collector mode has an extra constraint: `simplesiem backup --out` **refuses to write the backup file onto the same filesystem as the collector's `log_dir`**. The rationale:

> A collector exists to keep a redundant copy of the corpus on
> different storage. Writing a multi-GB backup of the collector
> onto the SAME volume that holds the corpus defeats the
> "different storage partition" guarantee operators want.

Use a separate volume (mounted at `/mnt/extra` for example) and pass `--out /mnt/extra/collector-2026-05-02.siembak`.

The master can pull a backup of the paired collector remotely via:

```bash
sudo simplesiem master backup --collector /backups/collector.siembak \
                              --passphrase-file /etc/simplesiem/backup-pp
```

This goes through the same `/v1/backup/create` peer-to-peer endpoint the master uses to back up servers; it doesn't require SSH or any non-mTLS access to the collector.

## Uninstall

```bash
# Direct uninstall (collector notifies its source on the way out
# so the master / server frees the slot immediately):
sudo simplesiem uninstall

# Master can also tear down the collector as part of its cascade
# uninstall — requires `collector.master_can_uninstall: true` on
# the collector (default false; explicit per-node opt-in).
sudo simplesiem master uninstall-all
```

The graceful uninstall path calls `/v1/collector/depart` on the master / server so the slot is freed atomically. Without that call the slot would stay occupied by the departed collector's CN until the operator runs `master collector revoke`.

## Caveats

- **One source at a time.** Collectors don't multi-source; a collector is single-source by design. If the realm has two masters (which itself is unsupported — masters don't peer), the collector pairs with one of them.
- **No back-pressure to the source.** A slow / down collector doesn't slow ingest at the master; the master keeps writing, and the collector catches up by reading from its watermark on the next successful pull.
- **First pull can be expensive** on a long-running source. Default `pull_interval_seconds` is 86400 (24 h) precisely because the collector is a redundancy tier, not a hot mirror. If you tune it down, consider the bandwidth + storage cost.
- **No master-master peering** so a collector paired with master A has no automatic relationship with master B even if both exist. SimpleSIEM treats masters as pure dialers; multi-master collector pairing isn't implemented.

## See also

- [docs/master.md](master.md) — master mode (the typical collector source).
- [docs/realms.md](realms.md) — how realms work; collectors are read-only with respect to realm config.
- [docs/backup.md](backup.md) — backup / restore (collector mode's same-volume guard is here).
