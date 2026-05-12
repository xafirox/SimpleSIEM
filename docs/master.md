# Master mode — cross-realm aggregation

A **master** sits above one or more realms and pulls events from each registered server. It runs no listener — it's a pure consumer over mTLS. Use it when you have multiple realms and want a single management plane to triage across all of them, or when you want a single read-only console on top of redundant servers without exposing the realm peers themselves.

→ Prerequisite: one or more working server installs (a single server or a full realm). See [agent-server.md](agent-server.md) and [realms.md](realms.md) first if needed.

## What master does

The master:

- **collects locally** so the master host is monitored too,
- **pulls events from each registered server** via `/v1/sync/events` using a per-server client cert (each server signs its own master cert),
- **writes per-origin replication files** at `<log_dir>/<host>/<type>/<date>.from-<server>.jsonl` (independent hash chain per origin), and
- **preserves a per-server watermark** at `<state>/master/<server>.watermark` so a daemon restart resumes pulling from the last successful point.

Master mode is **read-only with respect to alerts**. Rules don't fire on the master; if a server already alerted, the alert is replicated along with the rest of the events. If the master is the *only* place you want to evaluate rules, configure them on each server in the realm. The master IS a control plane for cross-fleet operations — `push-rules`, `realm rename`, `migrate-server`, `rotate-ca-all`, `finalize-rotate-all`, and `uninstall-all` — but each is gated by per-server opt-in (`master_can_rotate_ca`, `master_can_uninstall`, both default `false`) so a compromised master can't reach into servers that haven't authorised it.

## Setting up a master

The master is the same `simplesiem` binary as everything else — no separate download. Master mode is selected by setting `"mode": "master"` in `config.json`, but you don't edit that file by hand: `simplesiem convert master` is interactive and handles every step.

**One PSK per realm is enough.** When the master enrolls with one server, it automatically discovers and stages cert dirs for every other server in that realm via `/v1/sync/config`. So a 2-realm × 2-server fleet only needs the operator to type **two** URLs + PSKs (one per realm), not four. See [Realm peer auto-discovery](#realm-peer-auto-discovery) below.

The flow below walks through two realms × two servers each and one master; adapt for any number of servers.

### 1. Install simplesiem on the master host

Copy the binary for your platform onto the master host. Install as a standalone service first — this registers the system service, creates `/etc/simplesiem/config.json`, and gives you a working `simplesiem` command on `$PATH`:

```
# Linux/macOS
sudo ./simplesiem-linux-amd64 install

# Windows (elevated PowerShell)
.\simplesiem-windows-amd64.exe install
```

### 2. On one server per realm, look up the enrollment PSK

The master uses the same enrollment PSK that agents use. **You only need the PSK from one server per realm** — auto-discovery handles the rest. Pick whichever peer is most convenient and print its PSK:

```
sudo simplesiem certs psk show   # simplesiem-psk:abc…64hex…
```

**Treat the PSK like a password** — anyone with it can enroll a master or an agent against that server, and (because of auto-discovery) gain read access to every server in that realm.

### 3. Run `simplesiem convert master` on the master host

```
sudo simplesiem convert master
```

The command is interactive. It confirms the conversion, then loops once per realm:

```
Continue? [y/N] y
Server URL (e.g. https://siem-a.example.com:9443): https://r1-server-a:9443
PSK for https://r1-server-a:9443: simplesiem-psk:abc…
  enrolling...
  ✓ enrolled with https://r1-server-a:9443 (master_id=master-ops-01, realm=us-east)
    + auto-discovered realm peer: https://r1-server-b:9443
Server URL (blank to finish): https://r2-server-a:9443
PSK for https://r2-server-a:9443: simplesiem-psk:def…
  enrolling...
  ✓ enrolled with https://r2-server-a:9443 (master_id=master-ops-01, realm=us-west)
    + auto-discovered realm peer: https://r2-server-b:9443
Server URL (blank to finish):
config updated: /etc/simplesiem/config.json (mode=master, master.servers=4)
starting daemon...
service started

Conversion complete. Daemon is running in master mode.
```

Notice the master ended up with **four** entries in `master.servers` even though the operator only typed **two** URLs. The other two were auto-discovered.

What `convert master` does, end-to-end:

1. Confirms with the operator (suppress with `-y` for scripting).
1. Prompts for each server URL + its PSK; runs `master enroll` inline for each. The first round is mandatory (an empty URL on the first prompt aborts with "at least one server is required"); later rounds are optional ("blank to finish").
1. For each enrollment: generates an EC P-384 keypair locally, builds a CSR with CN = `master-<hostname>` (reused across calls so each server records the same master CN), POSTs to `/v1/enroll-master`, verifies the response HMAC against the PSK, writes `cert.pem`/`key.pem`/`ca.pem` under `/etc/simplesiem/master/<server-host>/`, and appends the URL to `master.servers`.
1. **Auto-discovery**: queries the just-enrolled server's `/v1/sync/config`, gets the realm peer list + every peer's public CA, and stages a per-peer cert dir for each — using the *same* client cert (signed by the realm's shared trust set, so every peer in the realm accepts it). Each discovered URL is appended to `master.servers`.
1. Stops the running daemon, flips `"mode": "master"` in `config.json`, starts the daemon back up.

A single fat-fingered PSK doesn't blow the whole flow — the loop prints `error: ...` and asks for the next server URL, so you can retry the failing one or move on.

### Realm peer auto-discovery

When the master enrolls with one server in a realm, the master automatically learns about every other peer in that same realm and stages a per-server cert dir for each. The operator never has to type those URLs. Mechanics:

- The just-enrolled master calls `GET /v1/sync/config` on its primary (the server it ran `master enroll` against). The response carries `peers`, `peer_cas`, and `master_cns`.
- For every peer URL the master doesn't yet have a cert dir for, it copies its A-signed cert + key into `<config>/master/<peer>/` and writes the peer's CA from `peer_cas` as `ca.pem`. The cert is valid against every realm peer because the realm's trust bundle on each peer includes every peer's CA (built by `realm join`).
- The just-enrolled server's `master_cns` already contains the new master. On the next `/v1/sync/config` cycle (≤ `realm.sync_interval_seconds`, default 15s), realm peers merge that CN into their own `master_cns` — so subsequent pulls from those peers succeed.
- Until that cycle completes, pulls from auto-discovered peers may fail with HTTP 403. The master pull goroutine retries on the next cycle and starts succeeding once propagation is done. This is silent — no operator action.

**When auto-discovery is skipped** for a particular peer:

- The master already has a cert dir for that peer (idempotent — won't overwrite operator-driven enrollments that may have used a different `master_id`).
- The peer's CA isn't in the primary's `peer_cas` yet (fresh realm whose sync hasn't propagated). Operator can re-run later or enroll directly.

**Security note**: auto-discovery widens the blast radius of a leaked PSK. With it, one PSK reaches every server in the realm via the propagated `master_cns`. For high-security environments where each server should only trust an explicitly-enrolled master, see [FutureImprovements.md](../FutureImprovements.md) — an opt-out flag (`server.master_auto_discover_peers`) is the planned mitigation.

### Collector arbitration on enroll

`master enroll` also probes whether the realm being joined already has its own paired collector (the server returns `collector_cn` in `/v1/sync/config`). Two outcomes:

| Master state before enroll | Realm has a collector? | What happens |
|---|---|---|
| `master.collector_cn` empty | Yes | **Auto-adopt.** The master auto-enables its collector listener (`master collector enable --listen :9445`), bootstraps its own CA + server cert + collector PSK, and POSTs the PSK to the server's `/v1/master/collector-directive` endpoint. The server stages the PSK in `realm.pending_master_collector_psk` and surfaces it once via `/v1/sync/config` to its paired collector. The collector writes the PSK to `<state>/master_promote.psk` and the existing `r21` auto-promote loop re-pairs it with the master on its next pull cycle (≤ 60 s by default; ≤ 5 s when push-interval is tuned down). |
| `master.collector_cn` set | Yes | **Demote prompt.** The master prompts `Continue? [y/N]` (or `-y` skips); on confirmation the master POSTs `demote_to_server: true` to the server, the server surfaces `collector_demote_to_server` once via `/v1/sync/config`, and the realm collector logs a `critical`-severity `collector_master_demote_directive` meta event with the exact follow-up command (`convert standalone -y && convert server -y --realm <peer> --realm-key <PSK>`). The single-collector-per-master rule is preserved — the master keeps its own collector and the realm collector yields. |
| Either | No | No action taken — master enroll exits with the standard "enrolled with <server-url>" summary. |

The collector listener PSK auto-created in the adopt case is stored at `<state>/master_collector_enroll.psk` mode `0600`; subsequent operator invocations of `master collector show-psk` read the same file.

### 4. Verify

```
sudo simplesiem status
```

Master-specific output:

```
mode:           master
master_id:      master-ops-01
hosts:          5 (laptop-01, prod-web-04, siem-a, siem-b, ops-01)
servers:        2 registered
                  https://siem-a.example.com:9443
                  https://siem-b.example.com:9443
sync_interval:  60s
```

`hosts:` lists everything visible — the master's own host plus every agent and server replicated from any registered server. After one sync interval, the count should reflect every host that any registered server knows about.

Triage cross-realm:

```
simplesiem triage --since 1h                       # all hosts
simplesiem triage --host laptop-01 --window 30s    # one host
simplesiem alerts --since 24h                      # alerts from any realm
```

## Storage layout

```
<log_dir>/
├── _master/                                       master daemon lifecycle, pull errors
├── ops-01/                                        master's own host events (always-on local collection)
│   ├── network/
│   │   └── 2026-04-30.jsonl
│   └── ...
├── laptop-01/                                     agent #1, replicated from a server
│   ├── network/
│   │   ├── 2026-04-30.from-siem-a.jsonl           # ingested at server-A
│   │   └── 2026-04-30.from-siem-b.jsonl           # also seen on server-B (replicated within realm)
│   └── ...
└── prod-web-04/                                   agent #2, ditto
    └── ...
```

The master never receives events directly from agents, so every event-bearing file under a `<host>/` dir on the master ends in `from-<server>.jsonl`. The master's *own* host (under `<master-hostname>/`) is the only exception — those events are collected locally and live in plain `<date>.jsonl` files.

If you have one realm with two peers, you'll see two `from-*.jsonl` files per `(host, type, date)` because both peers report the same agent's events independently. That's expected — each file is its own chain. Triage / query / tail walk all of them and de-duplicate by `_seq`/`_hash` is not currently performed (events appear once per peer-pull). For most workflows the duplication is benign, but be aware of it when counting.

## Master config

```json
"master": {
  "servers": [
    "https://siem-a.example.com:9443",
    "https://siem-b.example.com:9443"
  ],
  "sync_interval_seconds": 60,
  "certs_dir": "",
  "master_id": "master-ops-01",
  "rotation_realms": {},
  "finalize_realms": {}
}
```

| Key | Meaning |
|---|---|
| `master.servers` | list of server URLs to pull events from. Populated by `simplesiem master enroll`; can also be set manually for externally-issued certs. |
| `master.sync_interval_seconds` | how often the master pulls from each server; default 60. |
| `master.certs_dir` | per-server client cert root. Default `<config_dir>/master/`; expected layout is `<certs_dir>/<server-host>/{cert,key,ca}.pem`. |
| `master.master_id` | CN this master uses on its CSRs and enroll requests. Defaults to `master-<hostname>`; same value reused across enrollments so each server records the same CN. |
| `master.rotation_realms` | per-realm CA rotation policy (set by `rotate-ca-all` / `rotate-ca-realm`); the catchup loop reads this on every pull cycle. See [CA rotation across the fleet](#ca-rotation-across-the-fleet). |
| `master.finalize_realms` | per-realm finalize-rotate policy. Same auto-catchup semantics. |

## Pull mechanics

Each server gets its own pull goroutine. Every `master.sync_interval_seconds`, the goroutine:

1. Reads its watermark from `<state>/master/<server-host>.watermark`.
1. Calls `GET /v1/sync/events?since=<watermark>` on the server, authenticated with the per-server client cert.
1. Streams the response (newline-delimited JSON) and writes each event to `<log_dir>/<host>/<type>/<date>.from-<server>.jsonl`. Chain integrity per file is independent.
1. Advances the watermark to the highest `received_at` it just saw.
1. Logs a `meta:master_sync_pulled` event in `_master/meta/` when `count > 0`.

On error (network down, server down, HTTP 403), the watermark is left unchanged and an entry is written to `_master/errors/`. The next cycle retries the same point. A 403 specifically means the master's CN was removed from `server.master_cns` — re-enroll to recover.

## Operations

### Adding another server to the master

**Same realm as an existing one**: nothing to do. The auto-discovery loop in `reconcileRealmConfig` adopts the new peer's URL + CA on the next `/v1/sync/config` cycle. The new server learns the master's CN via the same sync. Within ≤60s the master's pull goroutine starts hitting the new server. No operator command on the master.

**New realm** (or a server in a realm the master doesn't yet know about): enroll with one server in that realm — auto-discovery picks up the rest:

```
sudo simplesiem master enroll https://siem-r3-a.example.com:9443 --key simplesiem-psk:ghi…
sudo simplesiem stop && sudo simplesiem start    # pick up new master.servers
```

The output will list the realm's auto-discovered peers, same as the initial `convert master` flow. The first sync after adding a server fetches its history from retention onward — expect a brief catch-up burst.

### Revoking the master

On each server, remove the master's CN from `server.master_cns` and restart. The master's pull goroutines will see HTTP 403 on the next cycle and log the rejection to `_master/errors/`. Existing replicated events on the master are unaffected.

To re-enroll: delete `<config>/master/<server-host>/` on the master and run `simplesiem master enroll` again.

### Rotating master certs

Same as revocation + re-enrollment:

```
sudo rm -rf /etc/simplesiem/master/siem-a
sudo simplesiem master enroll https://siem-a.example.com:9443 --key simplesiem-psk:abc…
sudo simplesiem stop && sudo simplesiem start
```

### Verifying replicated chains

```
sudo simplesiem verify -v --all
```

Each `<host>/<type>/<date>.from-<server>.jsonl` validates as its own chain. Cross-file mismatches are not flagged — different servers may have ingested different events.

## CA rotation across the fleet

The master can rotate the signing CA on every server it manages with a single command. Existing client certs continue to validate via the legacy CA (kept in each server's trust bundle) until they auto-rotate to the new CA. **Service stays up the entire time.**

### Opt in on each server first

Default-deny. Operators must explicitly authorize the master to drive CA rotation on each server they want included:

```json
"server": {
  ...,
  "master_can_rotate_ca": true
}
```

…then `simplesiem stop && simplesiem start` on that server. A compromised master can't destroy CA keys without this opt-in.

### Trigger rotation across the fleet

```
sudo simplesiem master rotate-ca-all
sudo simplesiem master rotate-ca-realm us-east       # scoped to one realm
```

Each server runs its own `init-rotate` locally. The output looks like:

```
✓ https://r1-server-a:9443 — new CA in place, server cert re-issued ...
✓ https://r1-server-b:9443 — new CA in place, server cert re-issued ...
✗ https://r2-server-a:9443: dial tcp: connection refused
✓ https://r2-server-b:9443 — new CA in place, server cert re-issued ...

Rotation: 3 ok, 1 failed.
```

A 403 means that server hasn't been opted in (`master_can_rotate_ca`). A connection error usually means the server is offline.

### Auto-catchup for offline servers

`rotate-ca-all` records the rotation timestamp in `master.rotation_realms[<realm>]`. Every subsequent master pull cycle, the master:

1. Queries `GET /v1/master/ca-status` on each server.
1. Compares the server's `last_rotated_at` against the policy.
1. If the server is behind (or has never rotated since install), triggers `init-rotate` automatically.

Result: when an offline server comes back, it auto-rotates within one master pull cycle (default 60 s). Operator does not need to re-run the command. A `meta:ca_catchup_rotated` event is logged on the master each time catchup fires.

### Inspect fleet state

```
sudo simplesiem master rotate-ca-status
```

```
Master rotation policy:
  rotation_realms[us-east] = 2026-05-01T01:32:41Z

server                        realm     ca_not_before          legacy   behind?
-------------------------------------------------------------------------------
https://r1-server-a:9443      us-east   2026-05-01T00:32:41Z   1
https://r1-server-b:9443      us-east   2026-05-01T00:32:41Z   1
https://r2-server-a:9443      us-east   2026-04-15T08:30:00Z   0        ROTATE
https://r2-server-b:9443      UNREACHABLE  (network error)
```

`ROTATE` = server's `last_rotated_at` is older than the policy. `UNREACHABLE` = the master can't reach the server right now.

### Finalize after clients have caught up

Once every agent and master has auto-rotated to the new-CA-signed client cert (default ~30 days before client cert expiry), remove the legacy CA across the fleet:

```
sudo simplesiem master finalize-rotate-all
sudo simplesiem master finalize-rotate-realm us-east
```

Same auto-catchup applies — late-joining servers get finalized once they're caught up to the rotation policy. After this, certs that still chain to the old CA stop validating.

### Stop catchup

If you want the auto-catchup loop to stop trying:

```
sudo simplesiem master rotate-ca-policy clear-all
sudo simplesiem master rotate-ca-policy clear-realm us-east
```

This only clears the master's policy; servers that have already rotated keep their new CAs.

### Why service stays up during rotation

1. Each server's listener hot-reloads the re-issued server cert within ~1 s — agents reconnecting after the restart see the new cert and validate via either the new CA (already known to them) or the old CA (still in their trust bundle).
1. Existing client certs (signed by the old CA) continue to authenticate at every server because the legacy CA is in each server's runtime trust bundle.
1. Agents pick up the new CA via the heartbeat refresh on the next beat (default 60 s) — `agent_ca_bundle_refreshed` meta event confirms.
1. Realm replication and master pulls keep flowing through the rotation; each peer's per-server CA file is updated automatically on first contact after rotation.

## Master-side rules

When `cfg.master.rules_path` (or the global `cfg.rules_path` as a fallback) is set, the master evaluates the configured rules on every event it pulls from each registered server. Use this for cross-host correlations the per-server rule engine can't see — for example:

- "5 different agents see failed SSH logins for user `root` within 10 minutes" (a single agent's threshold rule wouldn't fire if the attacker spread attempts across the fleet).
- "the same source IP appears in failed logins on agents in two different realms" (per-realm rules don't see each other).

Master fires land in `<log_dir>/_master/alerts/<date>.jsonl` and flow through the same alert webhook + syslog dispatchers the server uses (`cfg.server.alert_webhooks`, `cfg.server.alert_syslog` — the master shares the dispatcher config rather than introducing a parallel `master.alert_*` tree). Per-server rules continue to fire on each origin server independently; master-side rules are additive.

```json
// /etc/simplesiem/config.json on the master
{
  "mode": "master",
  "master": {
    "rules_path": "/etc/simplesiem/master-rules.json",
    "servers": ["https://siem-east.internal:9443", "https://siem-west.internal:9443"]
  }
}
```

To push a single rule set to every *server* in the fleet (per-server rules, NOT master-side), run `simplesiem master push-rules --file rules.json` (writes to every server in `master.servers`, gated by `server.master_can_rotate_ca`). When a paired collector is configured (`master.query_collector_url`), the same push also fans out to the collector — c8. The collector stores the rules so the c7 failsafe-query path can replay against its corpus when the master is offline.

## Caveats

- **Master is read-only by default for alerts.** Without a `master.rules_path`, the master does not run the rule engine on pulled events. Per-server rules continue to fire on each origin server, and replicated alerts arrive on the master alongside the events that triggered them, so cross-realm `simplesiem alerts` still works uniformly even with no master rules. Set `master.rules_path` only when you need cross-host correlation that per-server rules can't see.
- **Master sees duplicate events when realms replicate.** If realm peers A and B both have an event from agent X, the master pulling from both will store it twice (once per origin file). Run queries with `simplesiem query --dedupe` to drop duplicates by `_hash` at read time, or scope to a single origin (`simplesiem query --host X` reads every `from-*.jsonl` under `<host>/`).
- **Master has no listener by default.** Health checks must observe behaviour (process running, watermarks advancing, fresh `master_sync_pulled` meta events) rather than probe a port. When the master collector listener is enabled (`simplesiem master collector enable --listen :9445`), it does expose `/v1/health` on that port for k8s/load-balancer probes.

## Cascade uninstall

`simplesiem master uninstall-all [--purge] [--force] [-y]` tears down the entire master-managed surface in one command:

1. Master sends `/v1/master/uninstall-self` to every enrolled server.
1. Master sends `/v1/master/uninstall-collector` to the paired collector (when `master.query_collector_url` is set).
1. Master waits 5 s for remote daemons to begin their teardown.
1. Master uninstalls itself locally.

**Per-target opt-in is required.** The cascade only tears down nodes where the operator has explicitly authorised it:

- Server: `server.master_can_uninstall: true`
- Collector: `collector.master_can_uninstall: true`

Both default to `false`. A 403 from any target without `--force` aborts the cascade BEFORE the master uninstalls itself, so an opt-in mistake leaves the fleet unchanged. The opt-in mirrors `master_can_rotate_ca` — a destructive remote operation must require explicit per-node authorisation so a compromised master can't wipe the fleet by surprise.

`--purge` propagates fleet-wide: every cascaded node also wipes its `log_dir`, `state_dir`, `config_dir`, and certs. Without `--purge` operational data stays on disk for forensic recovery.

The CLI prompts twice unless `-y` is passed (high-blast-radius operation; the second prompt is a typed-yes confirmation).

More in [troubleshooting.md](troubleshooting.md).
