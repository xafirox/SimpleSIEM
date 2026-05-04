# Agent and server modes

Agent + server splits collection from storage: each agent runs collectors locally, ships events over mTLS to a central server, and the server stores them per-host. Use this when you want logs off-box (so a compromised host can't trivially erase its tracks) or want a single place to triage across a fleet.

→ For HA across multiple servers, see [realms.md](realms.md). For an aggregation tier above realms, see [master.md](master.md).

## How they fit together

| Mode | What runs | Where logs go | Rules / alerts |
|---|---|---|---|
| `agent` | Collectors only | Shipped over mTLS to a configured server. A small `<log_dir>/_agent/` directory keeps meta + errors locally so shipping problems are visible | None on the agent — the server fires all alerts |
| `server` | HTTPS receiver **plus** the same collector set as standalone (so the SIEM server is also monitored) | Agent events → `<log_dir>/<agent_id>/<type>/`; the server's own events → `<log_dir>/<server-hostname>/<type>/` (or whatever `server.local_id` is set to). Set `server.collect_locally: false` to disable. | Server-side rule engine fires alerts into the corresponding `<host>/alerts/` directory |

Read commands (`triage`, `query`, `tail`, `alerts`, `verify`, `status`) are mode-aware:

- In **server** mode, they walk every agent's directory by default and merge timelines; `--host <agent_id>` scopes to a single agent.
- In **agent** mode, they only see the local `_agent` audit log (collected events live on the server).

## Setting up an agent/server pair

The recommended flow uses **PSK enrollment**: the server generates one short string the operator types into each agent host, and the agent generates its own keypair locally — no manual file copy of private key material. The server signs the agent's CSR remotely and adds the agent to the allowlist atomically. Private keys never touch the network or another disk.

### 1. On the server host: bootstrap

```
sudo simplesiem certs init                # CA + server cert + enrollment PSK
sudo simplesiem install --mode server     # writes config.json with mode=server
sudo simplesiem start
```

`certs init` prints the enrollment PSK — it looks like
`simplesiem-psk:abc123…64hex…`. Re-display it later with
`simplesiem certs psk show`; rotate it with `simplesiem certs psk rotate --force` (this invalidates pending enrollments). The PSK file is mode 0600 at `<state>/enroll.psk`.

**Treat this string like a password: anyone with it can enroll an agent.**

### 2. On each agent host: enroll

```
sudo simplesiem install --mode standalone     # default; gets the binary in place
sudo simplesiem convert agent \
  --server https://siem.example.com:9443 \
  --key simplesiem-psk:abc123…64hex…
```

What `convert agent --key` does, end-to-end:

1. Generates an EC P-384 keypair on the agent host (private key never leaves this machine; written to `<config>/certs/client.key` mode 0600).
1. Builds a CSR with CN = the agent's chosen ID (defaults to hostname, override with `--id`).
1. POSTs `{psk, agent_id, csr_pem}` to the server's `/v1/enroll`.
1. Verifies the response HMAC keyed by the PSK — proves the server knew the secret, defeating MITM without a pre-shared CA.
1. Writes the returned signed cert + CA to disk.
1. Runs the standard connectivity preflight (full mTLS handshake +zero-event POST through the server's CN+allowlist gates).
1. Only then commits the mode flip in `config.json`.

If any step fails, on-disk state is unchanged — the running install is not affected. The server adds the agent's ID to `agent_allowlist` atomically as part of the enrollment response.

### 3. Verify

```
sudo simplesiem status                  # shows mode: agent + meta:agent_tls_ping_ok event
# on the server:
sudo simplesiem tail --host laptop-01
sudo simplesiem alerts --since 1h
```

### Periodic re-authentication

Each agent runs a heartbeat goroutine that calls `GET /v1/heartbeat` every `server.agent_reauth_seconds` (default 60s). The response carries the current interval, so changing it on the server propagates to every agent on the next beat — no agent restart needed. A heartbeat that fails surfaces in the agent's local errors log within the interval, which is also the worst-case revocation latency: removing an ID from `agent_allowlist` rejects the next heartbeat.

## Storage layout

**Server:**

```
<log_dir>/
├── _server/             receiver lifecycle (start/stop, collector_silent, decode/auth errors)
├── siem-server-01/      THIS server's own host events (when collect_locally is true)
│   ├── network/
│   └── ...
├── laptop-01/           agent #1
│   └── ...
└── prod-web-04/         agent #2
    └── ...
```

The local-collection identifier defaults to the OS hostname; override with `server.local_id` in the config if your hostname clashes with a planned agent ID. Set `server.collect_locally: false` if you want a pure receiver with no host monitoring.

Each `<host>/` subdirectory has its own independent hash chain — chain breaks across hosts are expected, not a tampering alert.

**Agent:** events live on the server, not locally. The agent only writes a small `<log_dir>/_agent/{meta,errors}/YYYY-MM-DD.jsonl` for shipping diagnostics so an operator can triage *connection* problems on the source host without going to the server.

## Wire protocol

- HTTPS with **TLS 1.3 only**. Key exchange is `X25519MLKEM768` only (NIST FIPS 203 hybrid post-quantum KEM). No classical fallback — every SimpleSIEM node is built from the same source, so the handshake fails fast against any binary that doesn't support thehybrid PQ curve rather than silently downgrading.
- Mutual auth: server presents a server cert chained to the configured CA; agent presents a client cert chained to the same CA. The server **also** checks that the cert's CN equals the `X-SimpleSIEM-Host` header — an agent with one cert can't impersonate another.
- Bearer token (`Authorization: Bearer <token>`) optionally accepted in *addition* to mTLS, for layered defence.
- Body: gzip-compressed NDJSON, one event per line, POSTed to `/v1/events`. `/v1/health` returns `{"ok":true}` for liveness probes.
- Server bounds the body at `max_batch_bytes` (default 32 MiB compressed) and rejects oversize requests with HTTP 413.

**Endpoints used by agent → server:**

| Path | Purpose |
|---|---|
| `POST /v1/events` | gzipped NDJSON event batch |
| `GET  /v1/health` | liveness probe; returns `{"ok":true}` |
| `POST /v1/enroll` | PSK-driven CSR signing; adds the agent ID to `server.agent_allowlist`. Response carries the realm peer list as `failover_servers` |
| `GET  /v1/heartbeat` | session re-auth; response carries the current `agent_reauth_seconds` |

Other endpoints (`/v1/sync/events`, `/v1/sync/config`, `/v1/enroll-master`) are used by realm peers and masters; see [realms.md](realms.md) and [master.md](master.md).

## Authentication layers

The server applies these checks in order before accepting any event:

1. **TLS 1.3 handshake** with hybrid post-quantum key exchange (`X25519MLKEM768`, no classical fallback) — encrypts the wire and authenticates the server to the agent.
1. **Mutual TLS (`require_client_cert: true`, default)** — the agent must present a client cert chained to the server's configured CA. No CA-signed cert, no connection.
1. **CN ↔ Host binding** — the cert's Common Name must equal the `X-SimpleSIEM-Host` header. An agent holding cert CN=`A` cannot post events as host `B`.
1. **Agent allowlist (`server.agent_allowlist`)** — when non-empty, the agent ID must be on the explicit list. **A cert signed by a compromised CA is not enough on its own** — the operator has to have approved that 1pecific ID. Empty list preserves legacy behaviour (any valid cert is accepted).
1. **Optional bearer token** — if `server.bearer_tokens` is set, the request must also carry `Authorization: Bearer <token>`. Layered on top of mTLS by default.

To revoke an agent: remove its ID from `server.agent_allowlist` and restart. Future connections from that cert immediately get HTTP 403 with an audit entry in `_server/errors/`. The agent will see the revocation on its next heartbeat (within `agent_reauth_seconds`).

## Encryption posture

- ECDSA P-384 keys throughout (~192-bit security, NIST Suite B Top Secret family). Hash chain + HMAC-SHA384. Key exchange is `X25519MLKEM768` only — the hybrid post-quantum KEM (NIST FIPS 203) — so a future quantum-era adversary holding captured TLS sessions can't recover the symmetric key offline. No classical fallback (no production deployments to preserve compatibility with).
- Client and server private keys live on disk with mode 0600, owned by the user the daemon runs as.
- Without explicit `bearer_tokens` configured server-side, mTLS alone authenticates the request — no shared secret to leak.
- The agent `insecure_skip_tls` knob exists for first-boot debugging only; setting it emits a `meta:agent_insecure_tls` event so the lapse is visible in the audit trail.

## Resilience

- Agents buffer to disk when the server is unreachable (`spool_dir`, bounded by `spool_max_mb`). On reconnect, spooled batches are uploaded oldest-first and removed only after the server returns 2xx.
- The hash chain is computed **server-side** at receive time. If a network glitch costs you a batch, you don't get fake "tampering" alerts on the agent's side — there's nothing on disk to be tampered with there.
- Server mode survives an agent identity change (cert reissue with same CN) without operator action; only revocations require updating the CA bundle.

## Cert management (`certs`)

The bundled `simplesiem certs` subcommand generates a small ECDSA P-384 PKI plus the enrollment PSK. For production you can replace any of the resulting files with externally-issued certificates (same paths, same formats).

```
simplesiem certs init                          # one-time, on the server: CA + server cert + PSK
simplesiem certs psk show                      # print the PSK (paste into agent's --key)
simplesiem certs psk rotate --force            # regenerate the PSK; invalidates pending enrollments
simplesiem certs server <hostname> [more...]   # re-issue the server cert (e.g. new SAN)
```

- `init` writes `ca.pem` (mode 0644) and `ca.key` (mode 0600) under `<config_dir>/certs/`, auto-issues a server cert for the localhostname + non-loopback interface IPs + every reverse-DNS alias the resolver returns for those IPs, and creates a 256-bit enrollment PSK at `<state>/enroll.psk` (mode 0600).
- `psk show` prints the displayable PSK string. `psk rotate --force` generates a new one; in-flight enrollments using the old PSK fail. Existing enrolled agents are unaffected (they use mTLS, not the PSK).
- `server <hostname> [more...]` re-issues the server cert with the given hostnames and IPs as Subject Alternative Names. Pass `--force` to overwrite an existing cert; the running server hot-reloads from disk within ~1 s.

**SAN auto-extension on agent enroll.** The server doesn't always know what name the agent will dial it by — operators commonly use `/etc/hosts` aliases, docker network service names, or DNS records the server itself can't reverse-resolve. To cover that, `/v1/enroll` inspects the agent's TLS SNI value (the literal hostname after `https://` in `--server <url>`); if that name isn't already in the server's cert SAN, the server re-signs `server.pem` adding it (using the same CA), atomic-writes the file, and the hot-reloader picks up the new cert within ~1 second. The convert flow's preflight retries with backoff (0s / 1.5s / 3s) so it covers the reload window transparently. PSK auth gates the call (so a leaked PSK is the only way to drift the SAN), and there's a hard cap of 64 SAN entries to prevent unbounded growth. Each addition is logged as `meta:server_cert_san_extended` with the added name + remote address.

Agents are NOT issued certs by a separate `certs` subcommand. They generate their own keypair locally and the server signs the CSR over the wire when the operator runs `simplesiem convert agent --key <PSK>`. No private key ever traverses the network or another disk.

**Cert lifetime defaults:** CA = 10 years, server cert = 5 years, agent cert = 5 years. Override with `--years N` on `certs init` `certs server`. 

**Replacing the bundled PKI:** if you have an existing internal CA, just put your own `ca.pem` / `server.pem` / `server.key` / `client.pem` / `client.key` at the configured paths. SimpleSIEM doesn't care who issued them as long as the chain validates and the agent's client-cert CN matches its `agent.id`.

## Auto-rotation

Client certs (agent + master) renew themselves before expiry. Each agent's heartbeat goroutine inspects its own `client.pem`; once the cert is within `30 days` of `NotAfter`, it generates a fresh keypair locally, calls `POST /v1/rotate` over the existing mTLS connection (the existing cert is the proof of identity — no PSK needed), and atomically swaps the new keypair on disk. The next handshake reads from disk and uses the renewed cert. Master per-server certs follow the same flow on the master's pull goroutine.

A `meta:agent_cert_rotated` (or `meta:master_cert_rotated`) event records each successful renewal. Server-side, the corresponding `meta:cert_rotated` event in `_server/meta/` carries the role (`agent` / `master`), CN, and the new `not_after`.

The renewal endpoint refuses requests where:

- the existing cert isn't on the allowlist (or isn't in `master_cns`)
- the identity has been revoked via `simplesiem certs revoke`
- the CSR's CN doesn't match the calling cert's CN (no cross-identity rotation)

Operators don't need to do anything for a routine 5-year rotation — the daemon handles it. The original PSK path still works for re-enrollment when an agent's keypair is lost or compromised.

## Revocation

`simplesiem certs revoke <agent-id>` adds a tombstone in `server.agent_revoked`. The next request from that agent gets HTTP 403 — `/v1/events` is blocked, `/v1/heartbeat` is blocked, `/v1/rotate` is blocked. The cert remains cryptographically valid until its natural `NotAfter`, but operator policy says this identity is no longer welcome.

Revocations propagate across realm peers via the existing `/v1/sync/config` cycle (default 60s). One revocation on any peer reaches every peer in the realm without further operator action.

```
sudo simplesiem certs revoke laptop-old
sudo simplesiem certs revoked       # list current tombstones
```

The merge is **additive** — removing a tombstone on one peer doesn't propagate the removal. To "unrevoke", an operator must edit each peer's `config.json` directly. (A future feature may add quorum-based deletion.)

For master CNs, the same command works: `simplesiem certs revoke master-ops-01`.

## Convert mode

`simplesiem convert <agent|server|standalone>` flips an existing install between modes in place — no reinstall, no service re-registration. It edits `config.json`, optionally rehomes pre-switch logs so they remain triageable, and prints next-step instructions specific to the new mode. 

```
sudo simplesiem convert agent --keep-old --id laptop-99 --server https://siem.example.com:9443
sudo simplesiem convert server --keep-old --listen :9443
sudo simplesiem convert standalone
```

| Flag | Effect |
|---|---|
| `-y` | Skip the confirmation prompt (for scripting) |
| `--keep-old` | Move existing standalone-shape `network/`, `files/`, … dirs into `_legacy/` so `triage --host _legacy ...` keeps working post-switch. Without it, those directories become invisible to read commands in the new layout. |
| `--config <path>` | Pick a non-default config file |
| `--id <agent-id>` | (agent only) Pre-populate `agent.id` in the new config |
| `--server <url>` | (agent only) Pre-populate `agent.server_url` |
| `--key <PSK>` | (agent only) Run PSK enrollment as part of convert |
| `--force` | (agent only) Skip the connectivity preflight |
| `--listen <addr>` | (server only) Pre-populate `server.listen` (default `:9443`) |

**Agent connectivity preflight:** when the target is `agent`, convert refuses to mutate `config.json` unless it can prove the server is actually ready to accept this agent. The preflight checks, in order:

1. `agent.server_url`, `client_cert`, `client_key`, and `ca_cert` are set and the cert files exist on disk.
2. The client keypair loads and the CA bundle parses.
3. An mTLS handshake to `server_url` completes — proves the server is listening, the server cert chains to our CA, and our client cert is presentable.
4. A zero-event `POST /v1/events` runs through the server's CN-match and `agent_allowlist` gates and returns 2xx — proves the agent ID we are about to commit to is approved on the server.

Failures map to actionable fix instructions, e.g. *"server rejected agent ID 'laptop-99' (HTTP 403) — on the server, add 'laptop-99' to `server.agent_allowlist` and restart, OR re-enroll the agent with the current PSK"*. Pass `--force` only when you are deliberately standing up the agent ahead of the server.

**Visibility impact (what you risk losing):**

- **Standalone → agent or server:** the existing `<log_dir>/{network,files,...}` dirs sit at the top level of the log directory. Server mode walks `<log_dir>/<host>/...` and agent mode's read commands only see `<log_dir>/_agent/...`, so those pre-switch events become invisible to triage/query/verify after the switch. `--keep-old` rehomes them into `<log_dir>/_legacy/<type>/`.
- **Agent → standalone or server:** collected events lived on the server, not this host. Locally only the small `<log_dir>/_agent/` diagnostics dir was kept.
- **Server → standalone or agent:** per-host directories under `<log_dir>/<agent-id>/` keep the on-disk events but become orphaned to read commands in the new mode. Copy them out before the switch if the historical data matters.

The interactive menu's "Convert mode" entry walks through the same prompts and applies `--keep-old` by default.

## Server config keys

Common server-mode keys (full list in [reference.md#server-mode-keys](reference.md#server-mode-keys)):

| Key | Meaning |
|---|---|
| `server.listen` | bind address, e.g. `:9443` |
| `server.cert` / `server.key` | server's TLS cert + key (PEM) |
| `server.ca_cert` | CA used to verify agent client certs |
| `server.require_client_cert` | when true (default), mTLS is required |
| `server.bearer_tokens` | optional list of accepted bearer tokens |
| `server.agent_allowlist` | explicit list of agent IDs the server will accept. Empty = open mode (any valid cert). Non-empty = strict |
| `server.collect_locally` | when true (default), the server also runs collectors against its own host |
| `server.local_id` | identifier for the server's own host events (defaults to `os.Hostname()`) |
| `server.max_batch_bytes` | hard cap on POST body (compressed) |
| `server.max_concurrent` | simultaneous in-flight uploads; over this returns 503 |
| `server.rate_per_second` / `rate_burst` | per-IP token bucket |
| `server.max_clock_skew_seconds` | accept agent timestamps within ±this many seconds |
| `server.agent_reauth_seconds` | heartbeat interval (default 60s) |

## Agent config keys

| Key | Meaning |
|---|---|
| `agent.id` | stable identifier; defaults to hostname; must equal client-cert CN |
| `agent.server_url` | e.g. `https://siem.example.com:9443` |
| `agent.client_cert` / `client_key` / `ca_cert` | PEM files for mTLS |
| `agent.bearer_token` | optional `Authorization: Bearer ...` second factor |
| `agent.spool_dir` | local NDJSON spool when the server is unreachable |
| `agent.spool_max_mb` | spool ceiling; oldest batches drop when exceeded |
| `agent.batch_size` / `batch_interval_seconds` | flush triggers |
| `agent.insecure_skip_tls` | dev-only escape hatch; logs `meta:agent_insecure_tls` if set |
| `agent.failover_servers` | list of peer URLs to try when the primary is unreachable. Populated automatically on enrollment when the server is part of a realm. See [realms.md](realms.md) |

## Server-stamped fields

Events that arrive at a server from an agent get extra fields stamped
at receive time, before the chain hash is computed:

| Field | Notes |
|---|---|
| `host` | Set to `X-SimpleSIEM-Host`, validated against the client cert CN. Used by `--host` filters. |
| `received_at` | RFC3339Nano UTC at the moment the server accepted the line. Useful when the agent's clock is off. |
| `origin_server` | The receiving server's stable peer ID. Used by realm sync and master pull. |
| `clock_skewed` | Only present when the agent's `ts` was outside `±max_clock_skew_seconds`. Set to `true`; the original timestamp is preserved as `agent_ts` and `ts` is rewritten to the server's `now()`. |
| `agent_ts` | Only present when `clock_skewed:true`. Holds the agent's original `ts`. |

## Caveats

- **Agent/server CN mismatch**: if you change `agent.id` without also reissuing the client cert, the server will reject the upload with HTTP 403. Solution: re-enroll the agent via PSK with the new ID.
- **Agent shipping gap on restart**: events generated *between* daemon stop and start aren't captured. Events generated while the daemon is up but the *server* is unreachable are spooled to disk and replayed on reconnect.
- **Spool overflow drops the oldest batches first.** A `meta:agent_drops` event is written locally each minute when this happens, so an offline outage that exceeds `spool_max_mb` is visible on the agent host.
- **Server bind without a cert fails fast** with a clear error in the errors log. Run `simplesiem certs init` (which auto-issues the server cert) before starting in server mode.
- **Agents cannot write to the `alerts` log type.** Posts with `type:"alerts"` are rejected with a server-side error event noting the agent ID. Only the server's rule engine produces alerts.

## Maximum exfiltration resistance

The default agent posture **prefers preserving events over preventing exfiltration**. If a server outage happens, batches spool to disk and replay on reconnect, and operators can `simplesiem triage` the local mirror during the outage — at the cost of leaving a copy of the events on the agent's disk for as long as the outage lasts.

For threat models where "lose the in-flight events rather than leave plaintext on disk" is the right trade-off — typically agents deployed in environments where you assume an attacker may eventually get root on the box and want to exfiltrate the historical events — SimpleSIEM exposes three knobs that together approximate "stream to remote, keep nothing local."

**This is opt-in. The default is to preserve every event.**

### Knob 1: aggressive shipping

Shrink the in-memory window between event collection and successful upload to the smallest practical size. Edit the agent's `config.json`:

```json
{
  "agent": {
    "batch_size": 1,
    "batch_interval_seconds": 1
  },
  "retention_days": 0
}
```

- `batch_size: 1` ships every event in its own POST instead of accumulating up to `batch_size`.
- `batch_interval_seconds: 1` flushes the buffer every second regardless of size.
- `retention_days: 0` removes any historical events from the agent's slim diagnostic log (`<log_dir>/_agent/`) on the next retention sweep.

The compromise window for an event drops from "next batch interval" (default 5 s) to under one second.

### Knob 2: `agent.no_local_storage`

The default agent has TWO local-disk fallbacks the shipper applies when the server is unreachable:

1. **Spool to disk** (`agent.spool_dir`, default `<state_dir>/spool`): failed batches are written to disk and retried on reconnect.
2. **Local mirror** (`<log_dir>/_agent/`): every event in a failed batch is also written to the agent's local Storage so `simplesiem triage` works during the outage.

Both can be turned off in one knob:

```json
{
  "agent": {
    "no_local_storage": true
  }
}
```

When `no_local_storage` is true:

- Batches that fail to ship are **dropped** (counter increments, reported in the meta log) instead of spooled to disk.
- The local-mirror write is **skipped** so triage can't see the batch from local state.
- Graceful daemon shutdown drops in-flight batches instead of spooling them.
- The `agent.spool_dir` directory is **not created** at startup; if a spool directory already exists from a prior run with `no_local_storage: false`, the shipper will not read from it.

The trade-off is real: a server outage with `no_local_storage: true` results in **events permanently lost** for the duration of the outage. This is dangerous-by-default. The flag exists for operators who have explicitly chosen "lose events" as preferable to "leave events on disk."

To get the most out of this mode, combine it with knob 1 — that shrinks the in-memory drop set to the smallest possible window.

### Knob 3: trust the realm tier as the real archive

The strongest practical defense against agent-side exfiltration is to treat agents as ephemeral collectors and the realm / master tier as the real archive. With aggressive shipping and `no_local_storage: true`, everything an agent observes leaves the host within roughly one second; the agent has no historical events to leak even if it's compromised the next minute.

For this to provide real protection, the **server must be in a different administrative domain** than any monitored agent — a different operator team, a different network segment, ideally a different physical or cloud account. If the same root credential covers both the agent and its server, an attacker with that credential reads everything regardless of how aggressively events ship.

Recommended configuration on the server side:

```json
{
  "retention_days": 365,
  "server": {
    "collect_locally": true,
    "agent_reauth_seconds": 30
  }
}
```

- `retention_days: 365` keeps a year of history on the server, where retention is bounded by storage capacity rather than exfiltration concerns.
- `collect_locally: true` ensures the server is also monitoring itself (the receiver host's own activity is part of the corpus).
- `agent_reauth_seconds: 30` halves the default heartbeat interval so a server-side revocation reaches each agent within ~30 s.

Pair the realm tier with a master that lives in a third administrative domain (`master.sync_interval_seconds: 60`); the master's pull provides a second copy of every event.

### Append-only sealing (always-on)

Independent of the above knobs, SimpleSIEM **automatically seals closed daily log files** with the platform-appropriate "no further modification" attribute:

- Linux: `chattr +a` (append-only inode flag — even root can't truncate, rewrite, or `unlink` the file without first running `chattr -a`, which is observable via auditd).
- macOS: `chflags sappnd` (system append-only flag — same semantics; clearing logged via the unified-logging system).
- Windows: `FILE_ATTRIBUTE_READONLY` set via `SetFileAttributes` (logged in the Event Log under standard audit policy).

The sealing fires on date rollover (when a new daily file starts) and on daemon startup (any past-day file that wasn't sealed at shutdown gets sealed on warmup). The retention loop strips the seal before deletion, so retention still works.

This is "speed bump" rather than "wall" protection against root — an attacker with root can clear the flag and then tamper, but the flag-clearing operation:

- leaves an audit trail (auditd / Console / Event Log)
- cannot be combined with the modification in a single syscall
- becomes detectable via `simplesiem verify --all` and via comparison against the upstream master's replicated copy

Combined with the SHA-384 hash chain and remote replication, the realistic outcome of a root-compromised agent is "the upstream master detects tampering within one pull cycle" rather than "the attacker silently scrubs the local logs and gets away clean."

More in [troubleshooting.md](troubleshooting.md).

## Volume anomaly alerts

The server tracks the per-agent ingress rate and fires `meta:agent_silent_anomaly` when a previously-chatty agent goes quiet. The detector is independent of agent heartbeat / mTLS and catches the case where the agent process is still alive (heartbeat OK) but its collectors have been muzzled — typically by an attacker who killed the relevant subsystems but left the binary running so the absence isn't loud.

### How it works

- Per-agent EWMA of events-per-minute, alpha = 0.2 (so a baseline re-stabilises within roughly five minutes of a real workload shift; tune by editing the constant in `volume_anomaly.go` if your traffic is bursty).
- An agent is flagged when current minute < 5 % of the EWMA baseline AND that holds for two consecutive minutes (so a single quiet minute during normal operation never fires).
- Warmup window of three minutes after the agent first reports — the EWMA needs time to settle.
- Minimum-baseline floor of 5 events per minute. Genuinely quiet agents (e.g. file collector on a static box) never trigger because their baseline is below the floor.
- 30-minute cooldown per agent so flapping doesn't fan out a wall of alerts.

When the agent comes back to ≥ 50 % of baseline, the server emits `meta:agent_silent_recovered` to close the loop.

### Tuning false positives

The defaults are conservative. If you see anomalies on agents you expect to be intermittent (laptops, batch hosts), the relevant constants are at the top of `internal/sieg/volume_anomaly.go`:

- `dropRatio` (0.05) — fraction of baseline that counts as "quiet"
- `consecutive` (2) — minutes-low before firing
- `minBaseline` (5) — events/min below which we never fire
- `cooldown` (30 * time.Minute) — per-agent re-fire suppression

These are deliberately not exposed as config keys today; if your deployment needs them tunable per-realm, open an issue.

### What the alert looks like

```json
{
  "type": "meta",
  "event": "agent_silent_anomaly",
  "agent": "host-43",
  "baseline_per_min": 124.6,
  "observed_per_min": 0,
  "drop_ratio": 0.0,
  "hint": "agent's event rate dropped below 5% of its rolling baseline for 2+ consecutive minutes — possible compromise + daemon kill, network outage, or aggressive shutdown"
}
```

The same event is written to `<log_dir>/<host-43>/meta/` AND `<log_dir>/_server/meta/` so both per-host and global views see the anomaly. A configured `alert_webhooks` endpoint is also notified.
