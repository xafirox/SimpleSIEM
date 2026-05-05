# Network device ingest (sticky-IP allowlist)

SimpleSIEM ingests syslog from non-SimpleSIEM devices (firewalls, switches, IoT) only on **server** and **master** modes, behind a sticky-IP allowlist that pairs every authorised device with both an IP address AND the MAC address resolved at trust-time. A frame whose `(IP, MAC)` tuple doesn't match the allowlist is dropped; a frame whose IP matches but whose MAC differs from the live ARP entry is dropped AND fires a high-severity `meta:network_ingest_rejected{reason: mac_mismatch}` alert through the existing alert pipeline.

→ For mode definitions see [agent-server.md](agent-server.md). For the rule engine that fires on syslog events see [rules.md](rules.md). For backup/restore handling of the allowlist sidecar see [backup.md](backup.md).

## Threat model

What this control buys: only devices on a known L2 segment, presenting both a known IP and the MAC bound to that IP at trust-time, can post logs into the *authenticated* corpus. Frames that fail validation are still stored (in a separate `_unauthenticated/` quarantine) so investigators have full context — but they're tagged `authenticated: false`, do NOT trigger the rule engine, and surface with a `[UNAUTH]` marker in the operator UI. A spoofed-source UDP packet from outside the LAN gets quarantined. A spoofed-source-IP packet from inside the LAN trips the MAC check, gets quarantined AND fires a high-severity alert. The bar for forging an *authenticated* event becomes "ARP-spoof a specific allowlisted device on its native VLAN" — detectable by managed-switch port-security but not by SimpleSIEM itself.

Independent of allowlist outcome, every frame is scanned by an attack-pattern detector. Hits emit a high-severity alert tagged with the matching MITRE ATT&CK technique and embed `attack_indicators[]` on the stored frame. This means: a rogue source attempting an exploitation pattern triggers an alert even though it's not allowlisted — exactly the visibility the user needs to detect attacks against their listener.

What this does NOT defend against:

- An attacker on the same L2 who can spoof both IP and MAC of an allowlisted device. Mitigation lives at L2: 802.1X, MAC-locking, DHCP snooping.
- Cleartext syslog being sniffed in-flight. Mitigation: every named vendor requires TLS; the `other` profile is the only catch-all that allows cleartext.
- Compromise of an allowlisted device itself — once trusted, trusted.
- Novel attack patterns not covered by the bundled detector set. Operators extend via `<config>/attack-patterns.json`; the sidecar hot-reloads.

## Quick start

Network ingest is **enabled by default** on `server` and `master` modes. A fresh install of either mode binds an RFC 5425 TLS listener on `:6514` (server) / `:6515` (master) with an auto-generated self-signed cert. Until the operator adds devices to the allowlist, every inbound frame is rejected — the listener is up, but the sticky-IP gate is closed.

```bash
# 1. Print the TLS fingerprint to pin on each device. Self-signed by default;
#    the cert is regenerated only when the file is missing.
sudo simplesiem query --type meta --grep network_ingest_tls_cert | tail -1

# 2. Add a device. --vendor is REQUIRED. Use 'other' for unsupported /
#    unknown vendors. The server ARP-resolves the IP to capture its MAC.
sudo simplesiem network-source add --ip 10.0.0.50 --vendor pfsense --label main-fw

# 3. Configure the device to ship syslog to https://<server>:6514 over TLS.

# 4. Watch frames land:
sudo simplesiem tail --type syslog
```

To use a different TLS posture (operator-supplied cert, or reuse the SimpleSIEM server cert) edit `cfg.server.network_ingest.tls_cert_mode`. To turn off ingest entirely, set `cfg.server.network_ingest.enabled: false` and restart.

## Mode matrix

Only **server** and **master** modes bind a syslog listener. Agent / standalone / collector modes silently ignore `cfg.server.network_ingest.enabled` and emit `meta:network_ingest_refused` once at startup so the misconfig (or default-on field) is visible. Agents AND collectors report their own default gateway up to their enrolled source (server or master) so the realm allowlist stays in sync with each peer's L2 view; neither agents nor collectors ever ingest device logs.

| Mode | Listener | CLI mutations | Auto gateway discovery |
|---|---|---|---|
| `server` | yes (default `:6514` TLS) | yes | self + each enrolled agent (via `/v1/agent/gateway`) + each enrolled collector (via `/v1/collector/gateway`) |
| `master` | yes (default `:6515` TLS) | yes | self + each enrolled server (via `/v1/sync/config`) + each enrolled collector (via `/v1/collector/gateway` on the master listener) |
| `agent` | refused | refused | reports OWN gateway up to server |
| `collector` | refused | refused | reports OWN gateway up to its source (master or server) |
| `standalone` | refused | refused | n/a (no upstream to report to) |

## TLS cert posture (three options)

The TLS-syslog listener (`syslog_tls_listen`, RFC 5425) supports three cert modes via `cfg.server.network_ingest.tls_cert_mode`:

- **`server`** — reuse the existing `cfg.server.cert` / `cfg.server.key`. Vendors must trust the SimpleSIEM CA (import `<config>/certs/ca.pem` on each device). Operationally simple; weakens the vendor's TLS posture if the device can't pin a custom CA.
- **`operator`** — operator provides `cfg.server.network_ingest.tls_cert` and `tls_key` paths. Use this with Let's Encrypt, internal PKI, or any CA the device already trusts. Most flexible.
- **`selfsigned`** (default) — auto-generated EC P-384 cert at first start, written to `<state>/network_ingest/{cert,key}.pem` (mode 0600). The SHA-256 fingerprint is emitted as `meta:network_ingest_tls_cert{detail: "mode=selfsigned fingerprint=..."}` so operators can pin it on each device.

```bash
# Selfsigned: print the fingerprint for vendor pinning.
sudo simplesiem query --type meta --grep network_ingest_tls_cert | jq -r .detail

# Operator-supplied: point at an existing cert + key.
sudo jq '.server.network_ingest.tls_cert_mode = "operator" |
         .server.network_ingest.tls_cert = "/etc/letsencrypt/live/siem.example.com/fullchain.pem" |
         .server.network_ingest.tls_key  = "/etc/letsencrypt/live/siem.example.com/privkey.pem"' \
  /etc/simplesiem/config.json > /tmp/c.json && sudo mv /tmp/c.json /etc/simplesiem/config.json
sudo simplesiem restart
```

## Vendor catalog

Seven named vendor profiles plus a generic `other` catch-all. **Every named vendor requires TLS** — operators with cleartext-only legacy gear must use `--vendor other`. This is a tightening from earlier versions: the rationale is "if a vendor supports TLS, require it." `other` is the only escape hatch.

| Vendor ID | Display name | TLS-syslog | Required | Default port |
|---|---|---|---|---|
| `other` | Other / unspecified | yes | optional | 514 |
| `pfsense` | pfSense | yes | required | 6514 |
| `fortigate` | FortiGate | yes | required | 6514 |
| `cisco_ios` | Cisco IOS / IOS-XE | yes | required | 6514 |
| `cisco_meraki` | Cisco Meraki | yes | required | 6514 |
| `sonicwall` | SonicWall | yes | required | 6514 |
| `ubiquiti` | Ubiquiti / UniFi | yes | required | 6514 |
| `hpe_aruba` | HPE Aruba | yes | required | 6514 |

`--vendor` is **required** on `network-source add`. The missing-vendor hint mentions `other` so the catch-all is always discoverable. For named vendors, `--no-tls` is refused; `tls_required: true` is set automatically and cannot be silently downgraded. For `--vendor other`, the operator chooses TLS posture via `--no-tls`.

## Allowlist mechanics

The allowlist lives in `<config>/network-allowlist.json` next to `config.json`. Schema is versioned, every entry carries a unix-nanos `version` field for last-write-wins reconciliation, and the file as a whole has a `config_version`. Mutations go through atomic `temp + fsync + rename` writes — readers never see a partial file. A malformed edit rejected by the hot-reload watcher emits `meta:network_allowlist_reload_rejected` and leaves the in-memory state untouched until the next valid edit.

Each entry is `(ip, mac, kind, vendor, label, tls_required, owners[])`:

- `kind: "gateway"` — auto-discovered. `owners` is a list of peer IDs that vouched for this gateway. When all owners depart, the entry is auto-pruned.
- `kind: "manual"` — operator-added. `owners: ["operator"]`.

```bash
sudo simplesiem network-source list                  # show all entries
sudo simplesiem network-source list --stale-only     # only flagged-stale rows
sudo simplesiem network-source add --ip X [...]      # ARP-resolve + add
sudo simplesiem network-source remove --ip X [--mac Y] [--force]
sudo simplesiem network-source rename --ip X --label "boundary-fw"
sudo simplesiem network-source revalidate            # re-ARP every entry
sudo simplesiem network-source resync                # pull canonical from authority
sudo simplesiem network-source vendors               # print catalog
```

`remove` refuses to delete a gateway entry without `--force` — they're auto-discovered and would just come back on the next peer report. Use `--force` only when the auto-discovery itself was wrong.

## Frame validation flow

Frames go through three layers: a hard rate-limit (the listener's only DoS gate), an attack-pattern detector (always-on, runs on every frame regardless of source), and the sticky-IP allowlist. Frames that pass the rate-limit are **always stored** — authenticated frames go to the per-device dir, unauthenticated frames are quarantined under `<log_dir>/_unauthenticated/syslog/<date>.jsonl` so investigators can see the attempt rather than discover an empty log.

Order of operations per frame:

- Source IP from the L4 connection (TCP) or UDP datagram source.
- Per-source-IP rate-limit exceeded? **Drop** (the only path that does — preserves the rate-limit's DoS-gate role), emit `meta:network_ingest_rate_limited`.
- Frame size > `max_frame_bytes` (default 64 KiB)? Truncate to the cap, set `truncated: true` on the stored frame. Extreme size is itself an attack indicator — the partial payload helps investigations, so we keep it.
- Run the attack-pattern detector on the raw frame. Hits emit `meta:network_ingest_attack_detected{reason, tactic, technique, severity:"high", ...}` AND fan the alert through the existing alert pipeline (webhooks, syslog, incidents, MITRE coverage). `attack_indicators[]` is set on the stored frame.
- Lookup `(IP, MAC-from-ARP)` in the allowlist. Authentication outcome:
  - `(IP, MAC)` match AND entry not stale AND TLS posture matches → `authenticated: true`. Frame written to `<log_dir>/<entry.label>/syslog/<date>.jsonl`. The rule engine runs against this event.
  - Any other outcome → `authenticated: false` with `unauth_reason` set to one of `unknown_source_ip` / `mac_mismatch` / `cleartext_refused` / `entry_stale`. Frame written to `<log_dir>/_unauthenticated/syslog/<date>.jsonl`. The rule engine does NOT run on unauthenticated frames (so a rogue source can't fabricate fake alerts by injecting rule-matching content).
- `meta:network_ingest_unauthenticated` event fires for every unauthenticated frame, with severity matching the reason: `mac_mismatch` and `cleartext_refused` are `high` (active spoof / TLS-downgrade signals); `entry_stale` is `medium`; `unknown_source_ip` is `low`.

Operator-facing visibility:

- `simplesiem tail --type syslog` renders unauthenticated rows with a `[UNAUTH]` prefix in yellow, attack-flagged rows with a `[ATTACK]` prefix in red. Rows can carry both markers.
- `simplesiem triage` and `simplesiem alerts` surface the same flags in their pretty output.
- The structured fields `authenticated: false`, `unauth_reason`, `truncated: true`, `attack_indicators[]`, `tactic`, `technique` are queryable via `simplesiem query --grep`.

## Attack-pattern detection

A built-in pattern set runs on every frame **before** allowlist validation, so attacks from rogue sources still alert at high severity. Patterns are mapped to MITRE ATT&CK tactic + technique IDs so the existing `simplesiem alerts --technique <ID>` and `simplesiem rules coverage` paths work without operator setup.

Hardcoded core patterns (extract):

| Name | Tactic | Technique | What it catches |
|---|---|---|---|
| `sql_injection_or_tautology` | TA0008 | T1190 | `' OR '1'='1`, OR-tautology |
| `sql_injection_union` | TA0008 | T1190 | `UNION SELECT` |
| `sql_injection_drop_truncate` | TA0040 | T1485 | Destructive injection (`DROP`, `TRUNCATE`) |
| `sql_comment_terminator` | TA0008 | T1190 | `--` / `;--` / `/*!*/` |
| `command_injection_substitution` | TA0002 | T1059 | `$(...)`, `${...}`, backticks |
| `command_injection_chained` | TA0002 | T1059 | `\|nc`, `;rm`, etc. |
| `command_injection_redirect` | TA0006 | T1003.008 | `> /etc/passwd`, sensitive-file redirects |
| `log4shell_jndi` | TA0002 | T1190 | `${jndi:` / `${env:` / `${sys:` lookups |
| `format_string_attack` | TA0002 | T1499.004 | `%n`, repeated `%x`, positional `%` |
| `path_traversal_dotdot` | TA0007 | T1083 | `../` and URL-encoded equivalents (≥2 levels) |
| `xss_script_tag` | TA0002 | T1059.007 | `<script>`, `onerror=`, `javascript:` |
| `xxe_doctype_entity` | TA0002 | T1190 | XXE / DOCTYPE SYSTEM declarations |
| `null_byte_injection` | TA0005 | T1027 | NUL byte in frame |
| `ansi_escape_injection` | TA0005 | T1027 | ESC `[` (terminal injection) |
| `ldap_injection` | TA0006 | T1110.003 | `(uid=*)(\|`, filter-bypass tautologies |
| `buffer_flood_a_pattern` | TA0040 | T1499 | `A{200,}` (canonical buffer-overflow probe) |
| `buffer_flood_x_pattern` | TA0040 | T1499 | Long single-character flood (≥500) |
| `http_protocol_smuggling` | TA0011 | T1071.001 | HTTP request directed at the syslog port |
| `overlong_utf8` | TA0005 | T1027 | Invalid / overlong UTF-8 sequences (byte-level check) |

Operator-tunable extensions go in `<config>/attack-patterns.json`:

```json
{
  "patterns": [
    {
      "name": "custom_org_signature",
      "regex": "INTERNAL_FLAG=([A-Z0-9]{16})",
      "tactic": "TA0010",
      "technique": "T1041",
      "description": "Internal data-exfil marker"
    }
  ]
}
```

The sidecar is hot-reloaded on change. Malformed JSON is rejected (`meta:attack_patterns_reload_rejected`) and the previous pattern set stays active.

Frame excerpts in the meta event are sanitised: control characters are replaced with `?` so an attacker can't smuggle ANSI escapes into operator terminals viewing the alert.

## Bidirectional master ↔ server authority

In master-managed realms either side can edit the allowlist. The edit must end up on every node; on outage it queues and reconciles when peers come back.

- **Edit on master**: master writes locally, then `POST /v1/master/network-allowlist` to every server in `master.servers` whose `cfg.server.network_ingest.master_can_push_allowlist: true` is set. Per-server consent is required; refused servers emit `meta:network_allowlist_push_refused` and the master logs failure.
- **Edit on server**: server writes locally, then `POST /v1/server/network-allowlist-changed` to its enrolled master. The master applies the update + fans out to every OTHER server (excluding the originator). If the master is offline, the change queues at `<state>/server/network_allowlist_pending.json` and the pending-push dispatcher retries every 60s.
- **Resync on startup / authority transition / manual `network-source resync`**: pulls the canonical allowlist from the authority and reconciles. Reconciliation rule: higher `config_version` wins; entries the snapshot has but we don't are added; entries we have whose `version` < snapshot's `config_version` are removed; same-key-different-content uses higher `version`.

`master_can_push_allowlist` is per-server (default `false`). Same security posture as `master_can_uninstall` and `master_can_rotate_ca` — destructive or fleet-wide config changes need explicit operator opt-in per node.

## Cross-platform support

All gateway-discovery and ARP-resolution primitives are implemented for Linux, macOS, and Windows. There is no Linux-only path.

- **Linux** — `/proc/net/route` for the default-gateway list; `/proc/net/arp` for ARP, with a UDP-touch fallback that triggers the kernel to populate the entry when missing.
- **macOS** — `route -n get default` for the gateway; `arp -n <ip>` for the MAC.
- **Windows** — `Get-NetRoute -DestinationPrefix 0.0.0.0/0` (with a `route print -4` fallback); `arp -a <ip>` for the MAC.

Inside container environments (`/.dockerenv` present, or analogous Windows marker) the auto-add is skipped and `meta:network_allowlist_skip_container` is emitted; the docker bridge gateway would produce nonsense entries.

## Atomic config edits

Three guarantees match `config.json`'s contract:

- **Write path is `temp + fsync + rename`.** No reader ever sees a partial write.
- **Last-working state in memory.** A malformed reload (parse error or semantic error like a `tls_required: false` on a `tls_syslog_required` vendor) is rejected; the running daemon keeps validating frames against the last-good state.
- **Hot-reloadable in <2s.** Every CLI mutation, master push, and on-disk edit applies via the configWatcher's polling loop with no daemon restart.

## Configuration reference

Defaults applied on every fresh server install:

```json
{
  "server": {
    "network_ingest": {
      "enabled": true,
      "syslog_udp_listen": "",
      "syslog_tcp_listen": "",
      "syslog_tls_listen": ":6514",
      "tls_cert_mode": "selfsigned",
      "tls_cert": "",
      "tls_key": "",
      "max_frame_bytes": 65536,
      "max_frames_per_source_per_second": 1000,
      "bind_explicit": true,
      "rdns_cache_ttl_seconds": 300,
      "master_can_push_allowlist": false
    }
  }
}
```

The same block lives at `cfg.master.network_ingest` for master-tier listeners (default TLS bind is `:6515` to avoid colliding with a co-located server). UDP and cleartext-TCP listeners are off by default — operators opt into those explicitly. The empty allowlist on a fresh install means every frame is rejected until the operator runs `network-source add`, so the listener being on by default does NOT widen the trust surface.

## Diagnostic helper

`simplesiem net-send` is a small UDP / TCP / TLS frame emitter shipped for testing the listener:

```bash
simplesiem net-send --host <server> --port 6514 --transport tls \
                    --message "<134>1 ... <syslog frame>" --insecure
```

Used by the docker UAT to simulate firewalls + rogue devices + MAC-spoof scenarios. Not part of the operator-facing surface — it's a test-only diagnostic.
