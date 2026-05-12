# Quick reference — one-liners

Every common workflow as a single command. Copy, paste, fill in the two or three placeholders. For the why and how, follow the link at the end of each section.

> Convention: `<peer-host>` is whatever the operator types after
> `https://` — a DNS name, a docker service name, an IP literal, or
> any reverse-DNS alias. The server cert SAN auto-extends on the
> first agent enrollment that dials by a new name (PSK-gated), so
> operators rarely need to re-issue certs by hand.
>
> `simplesiem-psk:...` placeholders come from the *target* host:
> `sudo simplesiem certs psk show`.

---

## Install

```bash
# Standalone (default — collect locally, alert from local rules)
sudo ./simplesiem install

# Server only
sudo ./simplesiem install --mode server

# Server + join an existing realm in one shot
sudo ./simplesiem install --mode server \
  --realm https://<peer-host>:9443 \
  --realm-key simplesiem-psk:<peer-PSK>

# Agent (auto-enrolls; PSK from the server's `certs psk show`)
sudo ./simplesiem install --mode agent \
  --server https://<server-host>:9443 \
  --key simplesiem-psk:<server-PSK>

# Master — interactive (prompts for each server URL + PSK)
sudo ./simplesiem install --mode master
sudo simplesiem convert master      # then enroll, see Master section below

# Collector (atomic — both flags required)
sudo ./simplesiem install --mode collector \
  --master https://<master-host>:9445 \
  --master-key simplesiem-psk:<master-collector-PSK>
```

Windows: replace `sudo ./simplesiem` with `.\simplesiem-windows-amd64.exe` from an elevated PowerShell.

---

## Convert (already-installed host, change mode in place)

```bash
# Standalone -> server
sudo simplesiem convert server -y

# Standalone -> server + realm join, in one shot
sudo simplesiem convert server -y \
  --realm https://<peer-host>:9443 \
  --realm-key simplesiem-psk:<peer-PSK>

# Standalone -> agent (PSK from the server)
sudo simplesiem convert agent -y \
  --server https://<server-host>:9443 \
  --key simplesiem-psk:<server-PSK>

# Anything -> master (interactive: prompts for every server URL + PSK)
sudo simplesiem convert master

# Anything -> master, non-interactive one-liner (single server)
sudo simplesiem convert master -y \
  --server https://<server-host>:9443 \
  --key simplesiem-psk:<server-PSK>

# Anything -> collector (interactive: prompts for source URL + PSK)
sudo simplesiem convert collector

# Back to standalone (legacy logs preserved by default)
sudo simplesiem convert standalone -y
```

Pre-conversion logs are preserved under `<log_dir>/_legacy/` by default. Pass `--keep-old=false` only if you genuinely want them discarded. The agent daemon backships `_legacy/` to the server on its first start so the server ends up with the full pre-conversion history.

→ [docs/agent-server.md](agent-server.md), [docs/realms.md](realms.md)

---

## Realm — manage redundancy

```bash
# Show this server's PSK (paste into a peer's `realm join --key ...`)
sudo simplesiem certs psk show

# Join a realm from an already-running server
sudo simplesiem realm join https://<peer-host>:9443 \
  --key simplesiem-psk:<peer-PSK>
sudo simplesiem stop && sudo simplesiem start    # apply trust bundle

# Status (realm name + peers)
simplesiem status | grep -E '^(mode|realm|peers):'

# Rename a realm (no-master case — any server in the realm)
sudo simplesiem realm rename prod-east

# Rename a realm via a master (master-driven fan-out across the fleet)
# Requires server.master_can_rotate_ca: true on each target server.
sudo simplesiem master realm rename <old-name> prod-east

# Atomic server migration to a different realm — server-driven (no master).
# Preflight: when the agent allowlist is empty, the migration proceeds
# even with no other R1 peer alive (nothing to strand). When ≥1 agent is
# allowlisted, at least one other R1 peer must respond to /v1/health.
sudo simplesiem realm migrate https://<new-peer>:9443 \
  --key simplesiem-psk:<new-realm-PSK>

# Atomic server migration — master-driven (master pairing PRESERVED)
# Requires master_can_rotate_ca: true on the target server.
sudo simplesiem master migrate-server \
  https://<target-server>:9443 \
  https://<new-peer>:9443 \
  --key simplesiem-psk:<new-realm-PSK>

# Server-driven migration --force (master enrolled): double-warns,
# breaks master pairing locally, then migrates.
sudo simplesiem realm migrate https://<new-peer>:9443 \
  --key simplesiem-psk:<new-realm-PSK> --force
```

**Name-collision guardrail.** If your local realm is named `default` and the peer's realm is also named `default`, but the peer isn't already in your peer list, `realm join` warns and prompts before merging. Two unrelated `default`-named installs *will* merge if you proceed — recovery is manual on both sides. Rename one side (`server.realm.name` in `config.json`) before joining if that's not what you want.

→ [docs/realms.md](realms.md)

---

## Master — pull from servers across realms

```bash
# Enroll the master with one server (run for each server you want covered).
# After enroll the master probes whether the realm already has its own
# collector and arbitrates:
#   - master has no paired collector → auto-adopts (enables :9445 listener,
#     stages a one-shot PSK on the server, realm collector auto-promotes
#     within one pull cycle).
#   - master already has a paired collector → prompts to demote the realm
#     collector. -y bypasses the prompt; the realm collector logs a
#     `critical` meta event with the exact follow-up command.
sudo simplesiem master enroll https://<server-host>:9443 \
  --key simplesiem-psk:<server-PSK> [-y]

# Status of every registered server (CA timestamp, behind/caught-up)
simplesiem master rotate-ca-status

# CA rotation across the entire fleet (auto-catches up offline servers)
sudo simplesiem master rotate-ca-all
sudo simplesiem master finalize-rotate-all      # after clients have rotated
```

Master adds every server in a realm to its server list automatically once you enroll with one — auto-discovery via `/v1/sync/config`.

```bash
# Push rules to one realm (auto-picks an available server in that realm)
sudo simplesiem master push-rules --file /path/to/rules.json --realm prod-east -y

# Query the paired collector's archive (long-tail retention pattern)
# 1) Collector side: enable the master-query listener + open the slot
sudo simplesiem collector master enable --listen :9446
sudo simplesiem collector master accept-next
sudo simplesiem collector master show-psk
# 2) Master side: enroll once
sudo simplesiem master query-collector enroll https://<collector-host>:9446 \
  --key simplesiem-psk:<collector-master-PSK>
# 3) Run queries (same flag set as `simplesiem query`)
sudo simplesiem master query-collector run \
  --host <agent-id> --since 30d --type files --grep '/etc/'
```

→ [docs/master.md](master.md)

---

## Collector — single-source backup replicator

A collector pulls a redundant copy of the entire event corpus from exactly one master (preferred) or one server. Single-slot rule on the authority side — only ONE collector ever pairs with any given master or server.

```bash
# On the master: open the slot + show the master collector PSK
sudo simplesiem master collector enable --listen :9445
sudo simplesiem master collector accept-next
sudo simplesiem master collector show-psk

# On the collector host: pair with the master
sudo simplesiem convert collector
# (interactive — prompts for the source URL and the PSK from the line above)

# Direct (non-interactive) enroll
sudo simplesiem collector enroll https://<master-host>:9445 \
  --key simplesiem-psk:<master-collector-PSK>

# Tune the pull cadence (default daily; minimum 1m via CLI)
sudo simplesiem collector interval 1h

# Status
simplesiem collector status
```

Free the slot to swap collector hosts:

```bash
# On the master
sudo simplesiem master collector revoke
sudo simplesiem master collector accept-next
```

The collector itself runs the same local collectors as a server, so its own host stays monitored alongside the replicated corpus.

---

## Certificate management

```bash
# Initial bootstrap (server-side)
sudo simplesiem certs init                       # CA + server cert + PSK

# Re-issue server cert with extra hostnames in the SAN
sudo simplesiem certs server $(hostname) <alias-1> <alias-2> 127.0.0.1 localhost
sudo simplesiem stop && sudo simplesiem start

# PSK
sudo simplesiem certs psk show
sudo simplesiem certs psk rotate --force         # invalidates pending enrollments

# Revocation tombstones (propagate via realm sync within ~60s)
sudo simplesiem certs revoke <agent-id-or-master-cn>
simplesiem certs revoked

# CA rotation (manual single-host)
sudo simplesiem certs init-rotate                # new CA + new server cert
# wait for clients to auto-rotate (heartbeat-driven, ~30 days max)
sudo simplesiem certs finalize-rotate            # remove legacy CA
```

The server cert auto-extends its SAN on the first agent enrollment that dials by a new hostname — the agent's TLS SNI value is recorded, the cert is re-signed by the same CA, and the listener hot-reloads within ~1 second. PSK auth gates this, capped at 64 SAN entries.

### Crypto stack — what's actually negotiated

| Primitive | Value |
|---|---|
| Transport | TLS 1.3 only |
| KEX | `X25519MLKEM768` — NIST FIPS 203 hybrid post-quantum (X25519 ECDH + ML-KEM-768). **Sole curve** — no fallback. |
| Cert keys | ECDSA P-384 (~192-bit security, NIST Suite B Top Secret family) |
| Cert sig hash | SHA-384 |
| Enroll/realm-join HMAC | HMAC-SHA384 |
| Event chain hash | SHA-384 |
| AEAD | TLS 1.3 picks AES-256-GCM or ChaCha20-Poly1305 |

Strict-mode rationale: SimpleSIEM only talks to other SimpleSIEM nodes built from the same source. A handshake against a binary that doesn't support `X25519MLKEM768` (Go 1.22 or older) fails fast at curve negotiation, making downgrade attacks impossible by construction. Re-build all peers from current main and the handshake works; no operator action required.

---

## Backup & restore

```bash
# Local backup of this host (encrypted by default; passphrase out-of-band).
sudo simplesiem backup --out /backups/$(hostname).siembak \
                       --passphrase-file /etc/simplesiem/backup-pp

# Inspect a backup without extracting (verifies passphrase + manifest).
simplesiem backup inspect --in /backups/$(hostname).siembak \
                          --passphrase-file /etc/simplesiem/backup-pp

# Dry-run the restore (decrypts + verifies every frame, lists entries, no writes).
sudo simplesiem restore --in /backups/host.siembak \
                        --passphrase-file /etc/simplesiem/backup-pp \
                        --dry-run

# Real restore (refused over a non-standalone install unless --force).
sudo simplesiem stop
sudo simplesiem restore --in /backups/host.siembak \
                        --passphrase-file /etc/simplesiem/backup-pp
sudo simplesiem fix && sudo simplesiem start && simplesiem status

# Server: back up self + every agent it has events for, plus realm peers.
sudo simplesiem backup --all --out-dir /backups \
                       --passphrase-file /etc/simplesiem/backup-pp

# Server scoped to one realm.
sudo simplesiem backup --realm prod-east --all --out-dir /backups \
                       --passphrase-file /etc/simplesiem/backup-pp

# Master: snapshot the entire fleet (self + collector + every server, by realm).
sudo simplesiem master backup --all-realms --out-dir /backups \
                              --passphrase-file /etc/simplesiem/backup-pp

# Master: just one piece of the fleet.
sudo simplesiem master backup --self /backups/master.siembak \
                              --passphrase-file /etc/simplesiem/backup-pp
sudo simplesiem master backup --collector /backups/collector.siembak \
                              --passphrase-file /etc/simplesiem/backup-pp
sudo simplesiem master backup --realm prod-east --out-dir /backups \
                              --passphrase-file /etc/simplesiem/backup-pp
```

Encryption is on by default (AES-256-GCM, key from PBKDF2-SHA384 600k iters + 32-byte random salt; per-frame nonces; 1 MiB chunked frames). Wrong passphrase fails the FIRST frame at restore and aborts before anything is written.

```bash
# Verify a cold backup without restoring (decrypt + walk every JSONL +
# recompute SHA-384 chain hashes; reports tampered or truncated files).
simplesiem backup verify --in /backups/host.siembak \
                         --passphrase-file /etc/simplesiem/backup-pp
```

→ [docs/backup.md](backup.md)

---

## Uninstall

```bash
# Remove the service; preserve config/state/logs/certs (the default).
sudo simplesiem uninstall

# Remove EVERYTHING (config + state + logs + certs).
sudo simplesiem uninstall --all

# Skip confirmation prompts (for cron / orchestration). Master mode
# requires --y because the prompt is two-step and won't fall through.
sudo simplesiem uninstall -y

# Override the "last server in a master-managed realm" refusal.
# Master goes offline until a fresh server is enrolled.
sudo simplesiem uninstall --force -y

# Master cascade — tear down every enrolled server, the paired
# collector, and finally the master itself. Per-node opt-in
# (`server.master_can_uninstall: true`, `collector.master_can_uninstall: true`)
# is required on each cascade target; the master refuses to start
# without explicit operator authorisation per node.
sudo simplesiem master uninstall-all --purge
```

→ [docs/reference.md → Command reference](reference.md#command-reference)

---

## Daily ops

```bash
# Tail every event live
simplesiem tail                                  # local
simplesiem tail --host <agent-id>                # one agent (server/master mode)

# Triage a window around a pivot
simplesiem triage --pivot-ts 2026-04-30T14:32:00Z --window 5m

# Filter raw stored events
simplesiem query --type files --since 1h --grep '/etc/'

# Built-in jq replacement (no external dependency on Linux/Mac/Windows)
simplesiem query --type auth --since 1h --pretty                         # multi-line indented JSON
simplesiem query --type auth --since 1h --select event,user,host         # field allowlist
simplesiem query --type auth --since 1h --grep user_added --get .user    # extract one value (newline-delimited)
simplesiem query --type files --since 1h --get .path                     # raw value, jq -r '.path' equivalent

# Track everything (a useradd/usermod/passwd will hit one of these)
simplesiem query --type auth --since 1h --select ts,event,user,actor,source --pretty
simplesiem query --type files --since 1h --field security_critical=*=credential_store
simplesiem query --type network --since 1h --select ts,protocol,remote,process,user --grep tool_invocation

# Recent alerts
simplesiem alerts --since 24h --severity high
simplesiem alerts --since 24h --unacked-only         # only outstanding triage items
simplesiem alerts ack 450891d69b66 --note "false positive"

# Per-rule fire counts (find dead rules and chronic noise)
simplesiem rules stats --since 7d

# Replay rules over historical events (rule-tuning loop)
simplesiem rules replay --since 7d
simplesiem rules replay --since 24h --type auth --with-threshold

# Hash-chain integrity
simplesiem verify --all
simplesiem chainhead verify                          # signed chain heads (off-box export pairs nicely)

# Daemon control
sudo simplesiem start
sudo simplesiem stop
sudo simplesiem restart                          # stop + start; safe even if stopped
sudo simplesiem fix                              # audit + repair install
simplesiem status                                # daemon up, mode, retention, hosts

# Move log_dir (atomic — stops daemon, moves data, updates config, restarts, verifies)
sudo simplesiem log-dir migrate /new/path -y    # any path outside /etc /usr /boot /efi works
                                                 # no install rerun needed (Linux post-r4 build)

# Add / remove a watched directory (requires daemon restart to take effect)
sudo simplesiem watch add /srv/myservice
sudo simplesiem watch remove /srv/myservice
sudo simplesiem watch list                       # current file_watch_paths from config
sudo simplesiem restart                          # required: file_watch_paths is not hot-reloaded
```

→ [docs/reference.md](reference.md)

---

## Detection / observability integrations

```bash
# Master-side cross-host correlation rules
# (master only; pulls events from all servers in master.servers)
sudo simplesiem tune master rules-path /etc/simplesiem/master-rules.json
# Then build the rules with the stepwise CLI (no JSON to type):
sudo simplesiem rules new cross-host-failed-logins
sudo simplesiem rules set cross-host-failed-logins severity high
sudo simplesiem rules match cross-host-failed-logins type auth
sudo simplesiem rules match cross-host-failed-logins event ssh_login
sudo simplesiem rules match cross-host-failed-logins result --any failed,invalid_user
sudo simplesiem rules threshold cross-host-failed-logins 5 600s user
sudo simplesiem rules enable cross-host-failed-logins

# Webhook fan-out for alerts
sudo simplesiem alerts-cfg webhook add https://soc.example.com/hook --min-severity high
sudo simplesiem alerts-cfg webhook list

# RFC 5424 syslog forwarding (Splunk / Elastic / rsyslog pipelines)
sudo simplesiem alerts-cfg syslog set udp syslog.internal:514 \
     --tag simplesiem --min-severity high
sudo simplesiem alerts-cfg syslog show

# Prometheus scrape (auth-gated; uses any agent client cert OR a bearer token)
curl -sk --cert /etc/simplesiem/certs/client.pem \
         --key  /etc/simplesiem/certs/client.key \
         --cacert /etc/simplesiem/certs/ca.pem \
         https://<server>:9443/metrics

# MITRE ATT&CK — auto-catalog + generate curated rules
sudo simplesiem mitre fetch                        # refresh enterprise STIX bundle
simplesiem mitre catalog                           # show fetch timestamp + technique count
simplesiem mitre coverage                          # rules.json tags vs catalog
simplesiem mitre generate-rules --list-templates   # show curated technique → template mappings
sudo simplesiem mitre generate-rules               # write rules-mitre-generated.json sidecar
sudo simplesiem mitre generate-rules --reject T1059.001    # suppress one technique (sticky)
sudo simplesiem mitre generate-rules --include T1059.001   # un-reject
```

---

## Network device ingest (firewalls / switches / IoT)

ON BY DEFAULT on server / master modes — RFC 5425 TLS listener bound on `:6514` (server) / `:6515` (master) with an auto-generated self-signed cert. Frames that fail allowlist validation are STORED in `<log_dir>/_unauthenticated/syslog/` (not dropped) with `authenticated: false` so investigators see attack attempts. Built-in attack-pattern detector (SQL injection, command injection, Log4Shell, path traversal, XSS, XXE, LDAP, format-string, buffer flood, HTTP-in-syslog, etc.) runs on every frame and tags hits with MITRE ATT&CK technique IDs at `severity: high`. Operator-extensible via `<config>/attack-patterns.json` (hot-reloaded). Every named vendor requires TLS; use `--vendor other` for cleartext-only legacy gear. Full doc: [network-ingest.md](network-ingest.md).

```bash
# Print the TLS fingerprint to pin on each device. Built-in --get
# replaces `| jq -r .detail` (no jq required on Mac/Windows).
sudo simplesiem query --type meta --grep network_ingest_tls_cert --get .detail

# Add a device. --vendor is REQUIRED. Use 'other' for unsupported vendors.
sudo simplesiem network-source add --ip <device-ip> --vendor pfsense --label main-fw
sudo simplesiem network-source add --ip <device-ip> --vendor other --label generic-iot --no-tls
sudo simplesiem network-source list                      # show full allowlist
sudo simplesiem network-source list --stale-only         # ARP-disagrees rows
sudo simplesiem network-source revalidate                # re-ARP every entry
sudo simplesiem network-source rename --ip <ip> --label "boundary-fw"
sudo simplesiem network-source remove --ip <ip> [--mac <mac>] [--force]
sudo simplesiem network-source resync                    # pull canonical from authority
sudo simplesiem network-source vendors                   # supported vendor catalog (pfsense, fortigate, cisco_ios, cisco_meraki, sonicwall, ubiquiti, hpe_aruba, other)

# Operator-supplied TLS cert (Let's Encrypt / internal PKI).
sudo simplesiem network-ingest tls-cert-mode operator
sudo simplesiem network-ingest tls-cert /etc/letsencrypt/live/siem.example.com/fullchain.pem
sudo simplesiem network-ingest tls-key  /etc/letsencrypt/live/siem.example.com/privkey.pem

# Add UDP and/or cleartext TCP listeners alongside the default TLS.
sudo simplesiem network-ingest udp-listen :514
sudo simplesiem network-ingest tcp-listen :1514

# Disable network ingest entirely.
sudo simplesiem network-ingest disable

# Operator-extensible attack-pattern detector (no JSON to type).
sudo simplesiem attack-patterns new internal-honey
sudo simplesiem attack-patterns set internal-honey regex 'X-Honey: [A-Z0-9]{16}'
sudo simplesiem attack-patterns set internal-honey tactic TA0009
sudo simplesiem attack-patterns set internal-honey technique T1056.001
sudo simplesiem attack-patterns enable internal-honey
sudo simplesiem attack-patterns test internal-honey "log line: X-Honey: ABC123DEF4567890"
```

---

## Detection content (stepwise CLIs — no JSON to type)

The same stepwise pattern (`new` → `set` → `enable`) covers every multi-field
detection block. Drafts start disabled, every value is validated at the moment
of the `set`, `enable` audits required fields and refuses on incomplete drafts.
Atomic write + hot-reload: edits land within ~1 s, no daemon restart.

```bash
# Threat-intel feeds (cfg.threatintel.feeds[])
sudo simplesiem threatintel status                     # cache age + indicator counts per feed
sudo simplesiem threatintel feed list                  # name / kind / state per feed
sudo simplesiem threatintel feed new abuse-ch          # draft (disabled until enable)
sudo simplesiem threatintel feed set abuse-ch kind abuse.ch.threatfox
sudo simplesiem threatintel feed set abuse-ch url https://threatfox-api.abuse.ch/api/v1/
sudo simplesiem threatintel feed set abuse-ch interval-hours 6
sudo simplesiem threatintel feed set abuse-ch min-confidence 75
sudo simplesiem threatintel feed set abuse-ch max-age-days 30
sudo simplesiem threatintel feed kinds abuse-ch set ip:port,domain,sha256
sudo simplesiem threatintel feed kinds abuse-ch add url       # add one
sudo simplesiem threatintel feed kinds abuse-ch remove sha256 # drop one
sudo simplesiem threatintel feed validate abuse-ch     # dry-run audit
sudo simplesiem threatintel feed enable abuse-ch       # validate + activate
sudo simplesiem threatintel feed disable abuse-ch      # keep file entry, stop fetching
sudo simplesiem threatintel feed delete abuse-ch       # remove from config
sudo simplesiem tune threatintel max-set-size 100000   # scalar tuning
sudo simplesiem tune threatintel stale-after-days 7
sudo simplesiem tune threatintel enabled false         # turn the manager off

# First-seen tuples (cfg.firstseen.tuples[])
sudo simplesiem firstseen status                       # tuple inventory + entry counts
sudo simplesiem firstseen tuple list
sudo simplesiem firstseen tuple add user_country user,geoip.country
sudo simplesiem firstseen tuple add proc_dir process,path_dir
sudo simplesiem firstseen tuple fields user_country user,geoip.country,asn   # rewrite
sudo simplesiem firstseen tuple show user_country
sudo simplesiem firstseen tuple remove proc_dir
sudo simplesiem tune firstseen ttl-days 90             # retention cap
sudo simplesiem tune firstseen max-entries-per-tuple 1000000

# Attack-patterns sidecar (already shown under Network ingest, repeated for cross-reference)
sudo simplesiem attack-patterns list
sudo simplesiem attack-patterns disable internal-honey
sudo simplesiem attack-patterns delete internal-honey

# Cert revoke ↔ unrevoke (no per-peer config-file edits anymore)
sudo simplesiem certs revoke r1-agent-a                # tombstone propagates via realm sync
sudo simplesiem certs unrevoke r1-agent-a              # vote to drop the tombstone (this peer)
sudo simplesiem certs unrevoke list                    # pending intents on this peer
sudo simplesiem certs unrevoke clear r1-agent-a        # withdraw THIS peer's vote
# For the tombstone to actually drop, ⌈peers/2⌉+1 peers in the realm must
# each run `unrevoke <id>` AND the latest intent timestamp must be newer
# than the original revocation timestamp. Single-server realms quorum on 1 vote.

# Baseline / incidents knobs (scalar tuning)
sudo simplesiem tune baseline window-days 14
sudo simplesiem tune baseline stddev-trigger 3.0
sudo simplesiem tune baseline max-hosts 200
sudo simplesiem tune baseline reset                    # back to defaults
sudo simplesiem tune incidents window-seconds 60
sudo simplesiem tune incidents max-lifetime-seconds 3600
```

---

## Troubleshooting cheats

```bash
# "events aren't appearing on the server"
simplesiem status                                # OPEN MODE allowlist? cert SAN drift?
simplesiem triage --type meta --since 30m       # server boot events / errors
sudo simplesiem fix                              # repairs install issues

# "agent can't connect — TLS errors"
# server cert SAN auto-extends on enroll; if the agent is using a
# pre-enrollment cert bundle copied by hand, re-enroll with --key
sudo simplesiem convert agent --server https://<server-host>:9443 \
  --key simplesiem-psk:<server-PSK>

# "I joined the wrong realm"
# stop daemon, manually clear server.realm.peers in config.json and
# <state>/realm/peer_cas/, then restart. There is no auto-unmerge.
```

→ [docs/troubleshooting.md](troubleshooting.md)
