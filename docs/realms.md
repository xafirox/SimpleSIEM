# Realms — multi-server redundancy

A **realm** is a redundancy/replication group of servers that share a CA and an agent allowlist. Pair two or more servers into a realm when you want active-active log replication, automatic agent failover, or both.

→ Prerequisite: a working agent + server setup. See [agent-server.md](agent-server.md) first if you haven't done that. For an aggregation tier above realms (cross-realm triage on a single host), see [master.md](master.md).

## What a realm gives you

Two or more servers in the same realm:

- **tell agents about each other** — an agent enrolled with one server receives the realm's peer list as `agent.failover_servers` and rotates through it on connection failure (sticks with whichever one last succeeded; rotates only on failure).
- **replicate event logs amongst themselves** — each peer pulls `/v1/sync/events?since=<watermark>` from the others on a configurable interval. Pulled events are stored under `<log_dir>/<host>/<type>/<date>.from-<peer>.jsonl` so each origin keeps its own independent hash chain and `simplesiem verify` validates each file in isolation.
- **trust each other's CAs without copying private keys** — each server keeps its own CA, and the realm-join handshake exchanges *public* CA certs over a PSK-authenticated channel. The receiving server adds the joiner's CA to its trust bundle (a per-host pool built from `<state>/realm/peer_cas/*.pem`), so an agent enrolled with peer A is accepted by peer B because B trusts A's CA.
- **propagate trust transitively** — when a third server joins peer A, the next `/v1/sync/config` cycle distributes the new peer's CA to every other peer in the realm. No quadratic join handshake.
- **share a realm name** that operators can rename from any peer; the rename propagates via `/v1/sync/config` using last-write-wins on a `config_version` (unix-nanos) field.

## Loop avoidance

Each ingress server stamps `origin_server: <self>` on every event before chain-hashing. Sync requests filter to events with `origin_server == the queried peer`, so an event ingested by A and replicated to B is never replicated by B back to A. This keeps the chains finite and the storage bounded.

The server-side `origin_server` value is the host portion of `server.listen` if set (e.g. `siem-a:9443` → `siem-a`), otherwise the OS hostname.

## Setting up a realm

Each server keeps its own CA. Joining a realm is a PSK-authenticated handshake (`simplesiem realm join`) that exchanges *public* CA certs between peers. Private keys never leave the host that generated them.

### 1. Provision server-A normally

```
sudo simplesiem install --mode server     # creates CA + server cert + PSK; starts the daemon
```

`install --mode server` (or `convert server` from a standalone install) auto-issues a CA and server cert. Capture A's enrollment PSK — server-B will use it to authenticate the realm-join request, and agents will use it (or B's PSK; either works after the join) to enroll.

```
sudo simplesiem certs psk show
# simplesiem-psk:abc...64hex...
```

### 2. Provision server-B normally

Server-B installs the **same way** — it gets its own independent CA and its own enrollment PSK. No CA copy.

```
# on server-B
sudo simplesiem install --mode server
sudo simplesiem certs psk show         # B's PSK; useful when agents prefer to enroll with B
```

At this point A and B are two unrelated single-server installs. Neither trusts the other yet.

### 3. Join server-B to the realm

On server-B, run the join command pointing at A and using A's PSK:

```
# on server-B
sudo simplesiem realm join https://siem-a.example.com:9443 \
  --key simplesiem-psk:abc...64hex...
```

The join is interactive when args are missing — without `--key` it prompts for the PSK; without the URL it prompts for that too.

What `realm join` does:

1. Loads B's own CA cert from disk (public part only).
1. POSTs `{psk, joiner_url, joiner_id, joiner_ca_pem}` to A's `/v1/realm/join`.
1. A verifies the PSK, validates the cert is a real CA cert, writes B's CA to `<state>/realm/peer_cas/siem-b.pem`, adds B to its `realm.peers`, and rebuilds its trust bundle.
1. A returns `{realm_name, peers, peer_cas, hmac}` — the realm name, every existing peer URL, and every peer's CA cert (including A's own).
1. B verifies the HMAC (keyed by the PSK — defeats MITM without a pre-shared CA) and writes each returned CA to its own `<state>/realm/peer_cas/`.
1. B updates its `config.json`: realm name adopted, peers union'd.
1. Restart B to pick up the new trust bundle:

```
sudo simplesiem stop && sudo simplesiem start
```

After this, A and B mutually trust each other's agent and master certs.

### 4. One-shot install + join

Skip the install/join chain entirely with `--realm` + `--realm-key` on `install` or `convert server`:

```
# on server-B (fresh box)
sudo simplesiem install --mode server \
  --realm https://siem-a.example.com:9443 \
  --realm-key simplesiem-psk:abc...64hex...
```

```
# OR if server-B is already installed standalone
sudo simplesiem convert server -y \
  --realm https://siem-a.example.com:9443 \
  --realm-key simplesiem-psk:abc...64hex...
```

Either form bootstraps PKI (when needed), runs `realm join` against the supplied peer, and restarts the daemon with the new trust bundle in one command. Either flag without the other prints a clear "both required" error.

Without `--realm`, `convert server` still offers the realm-join prompt at the end of the conversion (skipped under `-y`):

```
Join an existing realm now? [y/N] y
Existing realm peer URL (e.g. https://siem-a.example.com:9443): https://siem-a:9443
PSK from https://siem-a:9443 (sudo simplesiem certs psk show on that host): simplesiem-psk:abc...
```

### Renaming a realm

Realm renames follow a strict authority hierarchy:

| Mode of host running the rename CLI | Allowed? |
|---|---|
| `standalone` | No (no realm) |
| `agent` | No (no realm) |
| `collector` | **No** — collectors are pure consumers of realm config |
| `server`, no master enrolled in this realm | **Yes** via `simplesiem realm rename` |
| `server`, master enrolled (`server.realm.master_url` set) | No — operator must use the master |
| `master` | Use `simplesiem master realm rename <realm> <new>`; the local `realm rename` redirects |

**Server-local rename (no master):**

```
sudo simplesiem realm rename prod-east       # on any server in the realm
```

The rename writes to `config.json` with a fresh `config_version` (unix-nanos) and the change propagates to every other peer in the realm via the existing `/v1/sync/config` last-write-wins on the next sync cycle (default 60s). Each peer logs `meta:realm_renamed` when it adopts the new name.

**Master-driven rename:**

```
sudo simplesiem master realm rename realm-1 prod-east
```

The master walks `master.servers`, queries each server's current realm via `/v1/sync/config`, and POSTs the rename to every server whose realm matches `<realm-name>`. Servers in other realms are silently skipped.

Each target server applies via `/v1/master/push/realm-rename`; the endpoint requires `server.master_can_rotate_ca: true` (same opt-in that gates rule pushes and CA rotations) and the master's CN must be in `master_cns` and not revoked. Servers that opted out fail individually — the rest of the fleet still applies. Once one server in a realm has the new name, the others adopt via the standard realm-sync within ~60s. The master logs `meta:realm_renamed_by_master` on each successful target.

### Atomic server migration between realms

Moves a single server from one realm to another in one operation. Same authority hierarchy as realm rename:

| Caller's mode + state | Allowed? |
|---|---|
| Server, no master enrolled | **Yes** via `simplesiem realm migrate <new-peer> --key <PSK>` |
| Server, master enrolled (no `--force`) | No — operator must use `master migrate-server` instead |
| Server, master enrolled, `--force` | Yes (double prompt + chain-of-trust break — clears `master_cns`) |
| Master | `simplesiem master migrate-server <server-url> <new-peer> --key <PSK>` |

**Server-driven flow:**

```
sudo simplesiem realm migrate https://siem-c.example.com:9443 \
  --key simplesiem-psk:abc...64hex...
```

Step-by-step on the migrating server:

1. **Authority gate** — refuses if a master is enrolled (`master_cns` non-empty). With `--force` the operator confirms twice and clears the master pairing locally; the master's per-server cert becomes orphaned and must be re-enrolled if the master should manage this server again post-migration.
1. **Preflight** — the destination URL must respond to `/v1/health`. The "≥1 other R1 peer alive" check is **agent-conditional**: when this server's agent allowlist is empty, the migration is safe even with no peers (nothing to strand) and the peer-count check is skipped (a `0 agents allowlisted` confirmation is printed). When the allowlist has at least one entry, the check is enforced so the agents' failover list has somewhere to land. Both are skipped under `--force` (with explicit warning).
1. **Optional log drain** — under `--force` only, moves local-ingress `.jsonl` files to `<log_dir>/_legacy/migrated-from-<R1>/` so the operator can recover them after migration. Without `--force`, relies on realm sync having continuously replicated to remaining R1 peers.
1. **Notify R1 peers** — `POST /v1/realm/leave` to each known peer. Each receiver removes the leaver from its peer list + trust bundle, bumps `realm.config_version`, and the change propagates to other peers via the standard `/v1/sync/config` cycle (~60s). Without `--force`, all peers must acknowledge or the migration aborts; with `--force`, unreachable peers are warned but accepted.
1. **Clear local R1 state** — `realm.peers`, `agent_allowlist`, `<state>/realm/peer_cas/`, `collector_cn`. Agents currently shipping to this server start failing fast (403) and switch to a peer in the original realm via their existing failover list. **No signal is sent from this server to the agents** — the remaining R1 server's heartbeat response cleans up their failover list.
1. **Join R2** — standard PSK realm-join handshake against the new peer. Adopts R2's name + peer list + CAs.
1. **Restart daemon** — automatic, via `realm join`'s built-in `restartCommand` integration.

**Master-driven flow** runs steps 2–6 server-side via `/v1/master/migrate-server`, but **preserves** `master_cns`. The daemon's `pending-join watcher` polls `realm.pending_join_peer` every 5s and runs the handshake automatically — no operator restart needed on the migrated server.

```
sudo simplesiem master migrate-server \
  https://siem-b.example.com:9443 \
  https://siem-c.example.com:9443 \
  --key simplesiem-psk:abc...
```

Same `master_can_rotate_ca: true` opt-in as the other master push endpoints. Server logs `meta:server_migrated_by_master` on accept and `meta:realm_pending_join_completed` once the queued join lands.

### Name-collision guardrail

Realm names are labels, not identities — two unrelated single-server installs both running with the default name `default` would silently merge into one realm without a guardrail. `realm join` detects the case where:

- the local realm name == the peer's realm name (case-insensitive), AND
- the peer URL is **not** already in this server's local peer list

…and prompts for explicit confirmation before persisting:

```
WARNING: realm name collision detected.
  this server's realm name: default
  peer's realm name:        default
  peer URL:                 https://siem-a.example.com:9443

  These names match but the peer isn't in this server's known peer list.
  Joining will MERGE the two realms — every event/agent/master that one
  side trusts becomes accessible to the other. There is no automatic
  unmerge: recovery requires manually editing each side's config.json
  and clearing peer_cas.

  If both sides happened to use the default name on independent installs,
  abort here and rename one (`server.realm.name` in config.json) before
  re-trying. If you genuinely meant to merge them, proceed.

Proceed with the merge? [y/N]
```

`--yes` (used by `install --realm` and `convert server -y --realm`) prints the warning to stderr but proceeds — automation flows opted in.

To prevent the collision in the first place, rename one side before joining: edit `server.realm.name` in `config.json` (e.g. `"prod-east"`, `"prod-west"`) and restart the daemon, then run `realm join`. The joiner adopts the peer's name, so the two realms end up consistently named.

### 5. Add a third server (or fourth, fifth, ...)

For server-C, run `realm join` against any existing peer (A *or* B — doesn't matter):

```
# on server-C
sudo simplesiem realm join https://siem-a.example.com:9443 \
  --key simplesiem-psk:abc...
sudo simplesiem stop && sudo simplesiem start
```

Whichever peer C joined with returns the full known-peer list and their CAs. The other peers learn about C automatically on the next `/v1/sync/config` cycle (default 60s) — they pull C's CA from the peer that already has it and add it to their own trust bundle.

### 6. Verify

On any peer:

```
sudo simplesiem status                   # realm: <name>, peers: N
ls /var/log/simplesiem/<some-agent>/network/
# expect: 2026-04-30.jsonl                       (events ingested locally)
#         2026-04-30.from-siem-b.jsonl            (events replicated from B)
ls /var/lib/simplesiem/state/realm/peer_cas/
# one .pem file per peer in the trust bundle
```

`simplesiem triage --host <agent-id>` and `simplesiem alerts --since 1h` walk the per-peer files transparently.

### 7. Enroll an agent (once)

Agents enroll with **any** peer in the realm — pick whichever one is most convenient. The enrollment response carries the realm peer list and the *bundled* CA (every peer's CA concatenated into one PEM), so the agent trusts every peer's server cert out of the box and can fail over without re-enrollment.

```
sudo simplesiem convert agent \
  --server https://siem-a.example.com:9443 \
  --key simplesiem-psk:abc...
```

The agent's `config.json` ends up with:

```json
"agent": {
  "id": "laptop-01",
  "server_url": "https://siem-a.example.com:9443",
  "failover_servers": [
    "https://siem-b.example.com:9443"
  ],
  ...
}
```

…and `agent.ca_cert` is the bundled multi-CA PEM. New peers that join the realm later are picked up automatically: the heartbeat response carries the refreshed bundle + failover list, and the agent overwrites its on-disk copies so a daemon restart isn't needed.

## Agent failover behaviour

The agent always attempts the URL in `agent.server_url` first. On connection failure (timeout, TLS error, 5xx), it walks `failover_servers` in order until one accepts the batch, and **sticks with that URL** for subsequent batches until *it* fails. So failover is sticky, not round-robin — log streams stay coherent on one server unless that server breaks.

The mTLS handshake works against either peer because the agent's `ca.pem` is the *bundled* multi-CA PEM (all peer CAs concatenated) issued at enrollment time. Each peer's server cert is signed by that peer's own CA, and the agent trusts all of them. The agent's client cert was signed by whichever peer it enrolled with; the receiving peer accepts it because that issuing CA is in its runtime trust bundle (loaded from `<state>/realm/peer_cas/`).

If every server is down, the agent spools to disk under `<spool_dir>/`. Spool replay always tries the current "sticky" URL first.

## Realm sync mechanics

Each peer runs one pull goroutine per other peer in `realm.peers`. Every `sync_interval_seconds` (default 15), the goroutine:

1. Reads its watermark from `<state>/realm/<peer-id>.watermark` (the most recent `received_at` it's seen from that peer).
1. Calls `GET /v1/sync/events?since=<watermark>` on the peer.
1. Streams the response (newline-delimited JSON) and writes each event to `<log_dir>/<host>/<type>/<date>.from-<peer>.jsonl`. The chain on each `from-<peer>.jsonl` file is independent — `simplesiem verify` validates each as its own sub-chain.
1. Advances the watermark to the highest `received_at` it just saw, atomically.
1. Logs a `meta:realm_sync_pulled` event when `count > 0`.

On error (network, TLS, server down), the watermark is left unchanged and an entry is written to `errors/`. The next cycle retries the same point.

The `/v1/sync/config` endpoint runs on the same cadence and:

- reconciles the realm name using last-write-wins on `config_version` (unix-nanos),
- unions the peer URL set across every peer's response into local `realm.peers`,
- writes any newly-learned peer CA into `<state>/realm/peer_cas/` and rebuilds the live trust bundle.

This is what makes the realm self-heal as new peers join: the next sync cycle propagates the new peer's URL + CA to every existing peer without an operator-driven re-broadcast.

## Configuring a realm

| Key | Meaning |
|---|---|
| `server.realm.name` | realm identifier; default `"default"`. Operators can rename from any peer; the rename propagates via `/v1/sync/config`. |
| `server.realm.peers` | list of peer server URLs in this realm. Each peer pulls events from every other peer on `sync_interval_seconds`. Empty = single-server realm. |
| `server.realm.sync_interval_seconds` | how often peers replicate logs and reconcile realm config; default 15. |
| `server.realm.master_url` | optional URL of a master that owns this realm. Set automatically by `master enroll`. When non-empty, the server refuses local `realm rename` and `realm migrate` (use `master realm rename` / `master migrate-server` instead). Surfaced via `/v1/sync/config` so collectors can promote their authority from the server to the master. |
| `server.realm.config_version` | unix-nanos timestamp used by the last-write-wins reconciliation. Set automatically; rarely edited by hand. |

`agent.failover_servers` on the agent side is populated automatically from the server's realm peer list at enrollment, but can also be set manually for static HA deployments where you don't want the realm to auto-populate it.

## Storage layout

```
<log_dir>/                                          # on EACH peer in the realm
├── _server/                                        # receiver lifecycle
├── siem-a/                                         # this peer's own host events
│   └── network/
│       └── 2026-04-30.jsonl
├── laptop-01/                                      # agent #1
│   └── network/
│       ├── 2026-04-30.jsonl                        # ingested directly here
│       └── 2026-04-30.from-siem-b.jsonl            # replicated from peer
└── prod-web-04/                                    # agent #2
    └── ...
```

After a steady-state period, both peers store the same set of agent events — the ingester writes to the bare `<date>.jsonl`, every other peer writes to `<date>.from-<ingester>.jsonl`. Triage / query / tail / alerts walk all of them by default.

## Operations

### Adding a peer to an existing realm

On the new server (which already has its own CA + server cert from `install --mode server`), run:

```
sudo simplesiem realm join https://<any-existing-peer>:9443 --key <PSK>
sudo simplesiem stop && sudo simplesiem start
```

That peer's response carries the full known-peer set + their CAs, which the joining server writes into its trust bundle. Other peers in the realm learn about the new server automatically on the next `/v1/sync/config` cycle — they pull its CA from whichever peer already has it.

### Removing a peer

Take the peer offline. On each remaining peer:

```
# remove the URL from realm.peers
sudo simplesiem ... edit config.json, remove URL ...

# remove the trust bundle entry
sudo rm /var/lib/simplesiem/state/realm/peer_cas/<peer-id>.pem
sudo simplesiem stop && sudo simplesiem start
```

Existing replicated files (`from-<removed-peer>.jsonl`) are kept for retention until they age out — historical triage still works against them.

### Rotating a peer's CA (single peer)

For a graceful CA rotation on one peer:

```
sudo simplesiem certs init-rotate         # archive old CA, install new one, re-issue server cert
sudo simplesiem stop && sudo simplesiem start
```

The legacy CA stays in `<state>/legacy_cas/` so existing client certs keep validating. Agents auto-rotate to new-CA-signed certs over time (default within 30 days of expiry; configurable). Other peers learn about the new CA via `/v1/sync/config` on the next cycle.

Once every client cert chains to the new CA:

```
sudo simplesiem certs finalize-rotate     # delete legacy CAs from disk
sudo simplesiem stop && sudo simplesiem start
```

For fleet-wide rotation across multiple peers, see [master.md → CA rotation across the fleet](master.md#ca-rotation-across-the-fleet) — the master can fan-out the rotation with one command and auto-catch up servers that were down at trigger time.

### Revoking an agent or master across the realm

`simplesiem certs revoke <agent-id>` writes a tombstone in `server.agent_revoked`. The next request from that identity returns HTTP 403 on this peer; the tombstone propagates via `/v1/sync/config` so every peer in the realm enforces the revocation within one sync cycle. See [agent-server.md → Revocation](agent-server.md#revocation) for the complete flow.

### Renaming the realm

Edit `realm.name` on any one peer and restart that peer. The rename syncs to the other peers via `/v1/sync/config` within `sync_interval_seconds`. If two peers race to rename, the higher `config_version` (unix-nanos) wins on convergence.

### Verifying replication

```
sudo simplesiem verify -v --all       # walks all hosts and all per-peer files
```

Each `from-<peer>.jsonl` validates as its own independent chain. Cross-file mismatches are not flagged — different peers may ingest different events.

## Caveats

- **Realm peers do NOT share a CA private key.** Each peer keeps its own CA. Trust between peers is established by the realm-join handshake exchanging *public* CA certs, then maintained at runtime via the per-host trust bundle (`<state>/realm/peer_cas/`). Copying `ca.key` between hosts is an auditing failure and is not part of any supported flow.
- **First sync after a peer joins fetches that peer's full event history from retention onward.** Expect a brief catch-up burst on day one — typically a few MB per active host.
- **Last-write-wins config reconciliation has no quorum semantics.** When two peers edit the realm name within the same sync interval, the higher `config_version` (unix-nanos) wins on convergence. If you need quorum, edit on a single peer and let the change propagate.
- **Per-peer enrollment PSKs are independent.** Rotating the PSK on peer A doesn't affect peer B; it only affects future enrollments *and realm joins* through A. To revoke one peer's ability to attest new joiners, rotate that peer's PSK; existing realm peers are unaffected.
- **A wrong PSK on `realm join` returns HTTP 401** with a rate- limited audit log on the target peer. Same per-IP token bucket agent enrollment uses (1 token/sec, burst 3).
- **Replicated alerts come from the originating server's rule engine.** Each server evaluates the events it ingested directly. If peers run different rule sets, alerts surface only on their origin and replicate from there. Push the same `rules.json` to every peer if you want symmetric detection.
- **Trust bundle changes apply on the next handshake**, not on in-flight connections. Existing TLS sessions continue with the trust set they were established under; new connections (next sync cycle, agent reconnect) pick up the refreshed bundle.

More in [troubleshooting.md](troubleshooting.md).
