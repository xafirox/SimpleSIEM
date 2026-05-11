# Rules engine

Rules live in `<config_dir>/rules.json` and are loaded once at daemon startup. The rule engine fires on collected events and writes matches into the `alerts` log type. It runs in:

- **standalone** mode — local events fire local alerts.
- **server** mode — events ingested from agents (and the server's own local collection) fire alerts under each `<host>/alerts/` directory.

In **agent** and **master** modes the rule engine does NOT run. Agents have nothing to alert on locally (collected events go to the server); masters are read-only aggregators (alerts replicate from origin servers along with other events).

## Quick start — stepwise CLI (no JSON to type)

The recommended way to add a rule is the stepwise CLI: `rules new` creates a disabled draft, each subsequent verb sets one field, and `rules enable` runs a required-field audit + the daemon parser before flipping the rule live. Drafts are silently skipped by the runtime loader, so an in-progress build never fires.

```
sudo simplesiem rules new ssh-brute
sudo simplesiem rules set ssh-brute severity high
sudo simplesiem rules match ssh-brute type auth
sudo simplesiem rules match ssh-brute event ssh_login
sudo simplesiem rules match ssh-brute result --any failed,invalid_user
sudo simplesiem rules threshold ssh-brute 5 60s remote
sudo simplesiem rules set ssh-brute dedup-window 5m
sudo simplesiem rules set ssh-brute tactic TA0006
sudo simplesiem rules set ssh-brute technique T1110.001
sudo simplesiem rules enable ssh-brute
```

The match operators surface every form the engine supports — `--regex`, `--substr`, `--cidr`, `--not-cidr`, `--in-file`, `--not-in-file`, `--gt`, `--lt`, `--ge`, `--le`, `--any` — and each is validated at the moment of the `set` (the regex must compile, the CIDR must parse, the MITRE ID must match the format). If `enable` fails, it lists *every* missing field at once:

```
cannot enable: rule "ssh-brute" is not yet complete:
  - severity: not set (run `rules set <id> severity <low|medium|high|critical>`)
  - match: at least one match key OR a sequence is required (run `rules match <id> <key> <value>` or `rules sequence-step <id> key=value...`)
```

`rules validate <id>` runs the same audit without changing state. Power users wanting to drop a hand-authored rule (or import many at once) can still use `rules add <file|->`. Both paths land in the same `rules.json` and the daemon hot-reloads either within ~1 s.

## Rule format

Each rule is a JSON object:

```json
{
  "name": "ssh_brute_force",
  "severity": "high",
  "match": {
    "type": "auth",
    "event": "ssh_login",
    "result": ["failed", "invalid_user"]
  },
  "threshold": { "count": 5, "window": "60s", "group_by": "remote" },
  "dedup_window": "5m"
}
```

`rules.json` is a JSON array of rule objects. A starter file is dropped at `install` time only if it doesn't already exist (so your edits survive re-installs).

## Match operators

The `match` map is logical AND across all keys. The reserved key `type` matches the log type (`auth`, `network`, ...); other keys match against event fields. Each value can be:

| Form | Semantics |
|---|---|
| Plain string | Equality (`"event": "ssh_login"`) |
| `"*=foo"` | Substring (`"path": "*=authorized_keys"`) |
| `"~=regex"` | Go regex (`"path": "~=/(etc\|lib)/systemd/system/.*\\.service$"`) |
| `["a","b",...]` | Any-of; each element is itself parsed by the same rules |
| `{ "cidr": "10.0.0.0/8" }` or `{ "cidr": ["10.0.0.0/8","192.168.0.0/16"] }` | Field is an IPv4/IPv6 address inside any of the listed CIDRs |
| `{ "not_cidr": "10.0.0.0/8" }` | Negation of `cidr` |
| `{ "in_file": "blocklist.txt" }` | Field equals one of the lines in the file (one value per line; `#` comments allowed). Hot-reloaded — operators drop in IOC feeds without restarting the daemon. |
| `{ "not_in_file": "trusted.txt" }` | Negation of `in_file` |
| `{ "gt": 100 }` / `{ "lt": 60 }` / `{ "ge": ... }` / `{ "le": ... }` | Numeric comparison; accepts numbers and duration strings (`"5s"`) |
| `{ "all": [m1, m2] }` | Logical AND; every sub-matcher must pass (object form's default already AND's its top-level keys, so `all` is mainly for nesting) |
| `{ "not": m }` | Negation of one sub-matcher |

Examples:

```json
{ "match": { "type": "files", "path": "*=authorized_keys" } }

{ "match": { "type": "network", "remote_host": "~=\\.evil\\.com$" } }

{ "match": { "type": "auth", "event": ["ssh_login","sudo"], "result": "failed" } }

// Internal-network connections to a non-trusted IP (every tuple key in
// the same map AND's together — "source_ip in 10.0.0.0/8 AND remote_ip
// not in trusted-cidrs.txt"):
{ "match": {
    "type": "network",
    "source_ip": { "cidr": "10.0.0.0/8" },
    "remote_ip": { "not_in_file": "/etc/simplesiem/trusted-cidrs.txt" }
} }

// Block-listed file hashes (works with file_collector's sha384):
{ "match": { "type": "files", "sha384": { "in_file": "/etc/simplesiem/malware-hashes.txt" } } }

// Long-running connection (numeric duration):
{ "match": { "type": "network", "event": "connection_close", "duration_s": { "gt": 3600 } } }
```

### Time-of-day and weekday gates

Top-level rule fields (NOT inside `match`):

```json
{
  "name": "after-hours-prod-login",
  "severity": "high",
  "match": { "type": "auth", "event": "auth_success", "host": "prod-*" },
  "time_of_day": "22:00-06:00",
  "weekdays": "sat,sun,mon,tue,wed,thu,fri"
}
```

`time_of_day` is `"HH:MM-HH:MM"` in the daemon's local timezone; ranges that wrap midnight (`"22:00-06:00"`) are matched correctly. `weekdays` is a comma-separated list of three-letter day names (`mon`, `tue`, ...). Both clauses are evaluated against the daemon's wall clock at event ingest. Empty / omitted means "always matches".

### MITRE tagging

Annotate rules with ATT&CK tactic + technique IDs to enable `simplesiem alerts --technique <ID>` filtering and the `simplesiem rules coverage` heat-map view:

```json
{
  "name": "ssh_brute_force",
  "severity": "high",
  "match": { "type": "auth", "event": "ssh_login", "result": "failed" },
  "threshold": { "count": 5, "window": "60s", "group_by": "remote" },
  "notes": "5 failed SSH from same source in 60s — typical bruteforce",
  "runbook_url": "https://runbook.example.com/ssh-bf",
  "tactic": "TA0006",
  "technique": "T1110.001"
}
```

`notes` and `runbook_url` flow through to the fired alert payload — `alerts --no-color` renders both as sub-rows under each alert header, and webhook / syslog receivers see them in the JSON body.

### Generated rules from MITRE templates

`simplesiem mitre generate-rules` instantiates the shipped curated technique → rule template mapping into `<rules.json's dir>/rules-mitre-generated.json`. The sidecar is merged with `rules.json` at daemon load; operators never edit it by hand, but rule names and tags from it surface in `simplesiem rules stats` / `coverage` / `alerts` exactly like hand-written rules.

```bash
# Prereq: the MITRE catalog has been fetched at least once.
sudo simplesiem mitre fetch

# Generate the curated rule set (writes rules-mitre-generated.json next to rules.json).
sudo simplesiem mitre generate-rules

# See every curated technique → template mapping the binary ships.
simplesiem mitre generate-rules --list-templates

# Suppress one technique permanently — the rejected list survives regen.
sudo simplesiem mitre generate-rules --reject T1059.001

# Un-reject (restores on the next run).
sudo simplesiem mitre generate-rules --include T1059.001
```

The shipped curated set covers the highest-volume techniques: T1110, T1110.001, T1059.001/003/004, T1003, T1136, T1547.001, T1562.001, T1078, T1486, T1490. Each template carries `tactic`, `technique`, `severity`, and `notes` already populated, so generated rules surface in `simplesiem rules coverage` immediately. Rejected techniques persist in `<rules.json's dir>/mitre-rejected.json` so `--reject` is sticky across regeneration.

Refused on a server that has a master enrolled — run on the master so the generated sidecar can be `master push-rules`'d to the realm.

When `cfg.mitre.auto_generate_rules` is `true` (the default), the catalog refresh loop runs `generate-rules` automatically after each successful `fetch`. Set it to `false` to keep the operator in full manual control of the sidecar.

## Severity

Free-form, but `low` / `medium` / `high` / `critical` get severity colours in `tail` / `alerts` / `triage` output. Anything else is shown plain.

## Dedup

Optional. Suppresses repeat fires of the same rule within a time window:

```json
"dedup_window": "30s",
"dedup_key": "remote"
```

`dedup_key` selects the field used as the dedup grouping key (so failed SSH from many IPs each get their own dedup window). Omit `dedup_key` to dedup globally.

## Threshold (correlation)

Optional. Turns a per-event rule into "fire when N matches occur within `window` for the same `group_by`":

```json
"threshold": { "count": 5, "window": "60s", "group_by": "remote" }
```

When the threshold trips, the alert event includes `count`, `window`, and `group_value` so the alert message reads *"5 in 60s by remote=10.0.0.5"*. The matched-events window for that group resets after a fire so the next N events trigger another alert (combine with `dedup_window` to throttle repeats).

## Sequence rules

Threshold counts identical events. **Sequence rules** describe an ordered chain of *different* events that must occur in order, by the same `group_by` key, within the configured window. Use these for cross-event correlations the per-event matchers can't see — "failed login then successful login from the same IP" (credential stuffing breakthrough), "process spawn then network callout" (RCE
+ C2 beacon), "file write to /etc/cron.* then process spawn" (
persistence then payload).

A rule with `sequence:` set is mutually exclusive with `threshold:` and `match:` — the rule's behaviour is fully determined by the sequence steps.

```json
{
  "name": "fail-then-success-same-ip",
  "severity": "high",
  "tactic": "TA0006",
  "technique": "T1110.003",
  "notes": "credential-stuffing breakthrough — failed then successful from same source",
  "sequence": {
    "steps": [
      { "type": "auth", "event": "ssh_login", "result": "failed" },
      { "type": "auth", "event": "ssh_login", "result": "success" }
    ],
    "within": "5m",
    "group_by": "remote"
  }
}
```

Semantics:

- Each step is a `match`-shaped object (every key/value AND'd; same matcher syntax as the regular `match:` clause including CIDR / in_file / numeric).
- `within: "5m"` is the maximum time from step 0 to the final step.
- `group_by: "remote"` keys the per-key state machine — a fail on one IP and a success on another don't complete the sequence.
- When the final step matches, the rule fires and the per-key state is cleared. The alert payload includes `sequence_steps`, `sequence_within`, `sequence_elapsed_ms`, `group_by`, `group_value` so triage can see how the chain ran.

Three or more steps work the same way:

```json
{
  "name": "rce-then-c2-then-cron-persistence",
  "severity": "critical",
  "sequence": {
    "steps": [
      { "type": "processes", "event": "process_start", "name": "~=^(curl|wget|nc)$" },
      { "type": "network", "event": "connection_open", "process": "~=^(curl|wget|nc)$" },
      { "type": "files", "path": "*=cron." }
    ],
    "within": "5m",
    "group_by": "host"
  }
}
```

Sequence rules are stateful: each in-flight `(rule, group_by_value)` key occupies a small struct (current step index + start timestamp). A long `within` window with high-cardinality `group_by` will use proportional memory; the rule engine prunes stale state on every new event for the key.

## Validating and testing

```
simplesiem rules check                                # parse + compile
simplesiem rules test events.jsonl                    # replay events
simplesiem rules test events.jsonl --with-threshold   # with state
cat live.jsonl | simplesiem rules test -              # from stdin
```

`check` exits non-zero on any parse error, naming the rule and field. `test` runs match-only by default (no time semantics, just "does this event satisfy this rule?"); `--with-threshold` keeps full threshold/dedup state across the input so brute-force scenarios can be exercised.

Capture a small corpus to test against by piping `query` output:

```
simplesiem query --type auth --since 7d > test_events.jsonl
simplesiem rules test test_events.jsonl
```

## Replay against history

`rules replay` is `rules test` with the corpus pre-supplied: it runs the *current* rule file against every event already on disk inside a time window and reports per-rule fire counts.

```
simplesiem rules replay --since 7d                  # last week, all types
simplesiem rules replay --since 24h --type auth     # only auth events
simplesiem rules replay --since 7d --host host-43   # one agent (server/master)
simplesiem rules replay --since 7d --with-threshold # state across the window
simplesiem rules replay --since 7d -v               # one line per fire
```

The default output groups fires by rule name, sorted descending by count:

```
Replay window: 2026-04-25 00:00:00 -> 2026-05-02 00:00:00   (142,431 events, EDT, stateless)
Fires (141 total across 2 rule(s)):
  failed-ssh-bruteforce          sev=high    127
  unusual-process-spawn          sev=medium   14
```

**Use this when tuning rules.** The default is stateless — every matching event counts as a fire — so a rule with a `threshold` of "5 in 60s" reports every individual matching event, not just the events that actually crossed the threshold. Pass `--with-threshold` to evaluate threshold + dedup state across the replay window; that's slower but tells you what production would have actually fired.

`rules replay` operates on the local `log_dir` only. From a server or master, you replay against the central corpus the receiver has collected; from a standalone host, you replay against the host's own events.

## Per-rule stats

`rules stats` walks the alerts log (NOT the source events — alerts have already been written by the rule engine) and reports per-rule fire counts plus the first/last fire timestamps. It cross-references the configured rules file so dead rules show up as zero-fire rows.

```
simplesiem rules stats                  # default --since 24h
simplesiem rules stats --since 7d
simplesiem rules stats --since 7d --host host-43   # one agent
```

Sample output:

```
Alert window: 2026-04-25 00:00:00 -> 2026-05-02 00:00:00   (1,341 alerts across 9 rule(s), EDT)
  ssh-bruteforce                 sev=high    1241  first=2026-04-25 06:14:02 last=2026-05-01 23:55:11
  authorized_keys_modified       sev=high      62  first=2026-04-25 09:01:33 last=2026-05-01 17:22:08
  cron_modified                  sev=high      35  first=2026-04-26 14:11:58 last=2026-05-01 20:42:00
  systemd_unit_created           sev=high       3  first=2026-04-26 12:00:01 last=2026-04-29 08:32:11
  sudo_root_shell                sev=critical   0  (no fires in window)
  ...
```

**Use this to find dead rules and chronically-firing noise.** A rule that's never fired in a week is either too narrow or describes something that doesn't happen on this fleet — either way, worth a review. A rule firing thousands of times a day either needs a `threshold` to require correlation, or `dedup_window` to suppress re-fires.

`rules stats` is read-only and works without the daemon — just walks the on-disk alerts log. Same `log_dir` resolution as `rules replay`.

## Default rules shipped

The starter `rules.json` includes:

- `ssh_brute_force` — 5 failed/invalid SSH attempts from the same `remote` in 60s, dedup 5m
- `ssh_failed_login` — single failed/invalid SSH attempt, dedup 30s per remote
- `authorized_keys_modified` — any create/modify on a path containing `authorized_keys`
- `cron_modified` — create/modify/rename in `/etc/cron.*`, `/var/spool/cron/`, or `/etc/crontab`
- `systemd_unit_created` — new `.service`, `.timer`, or `.socket` under `/etc/`, `/lib/`, `/usr/lib/systemd/system/`
- `sudo_root_shell` — `sudo` invocation whose command starts with a shell

These are a starting point, not a security posture. Edit, add to, or delete them.

## Working with alerts

### View recent alerts

```
simplesiem alerts --since 1h
simplesiem alerts --since 7d --severity high
simplesiem alerts --since 1h --no-color     # plain output for scripts
```

Each alert is rendered with timestamp, severity (coloured), rule name, matched type/event, and a dim sub-line with the original event's summary. Threshold rules also show `count=N window=... group=value`.

### Triage an alert

The `--explain` flag on `triage` adds a `matched: ...` sub-line for each alert in the timeline showing exactly which rule fields hit:

```
simplesiem triage --grep "evil.com" --window 60s --explain
```

### Tail alerts live

```
simplesiem tail --alerts            # all alerts
simplesiem tail --alerts --grep ssh
```

### Acknowledge an alert

`simplesiem alerts --no-color` ends each header row with `id=<12-char-prefix>` of the alert's `_hash`. Use that prefix to write an acknowledgement record so the alert disappears from the unacked-only view:

```
simplesiem alerts ack 450891d69b66 --note "investigated, false positive"
simplesiem alerts ack 4508 --note "..."        # ≥8 chars; ambiguous prefixes are rejected
simplesiem alerts --since 7d --unacked-only    # show only outstanding alerts
```

Acks land in `<log_dir>/_acks/<date>.jsonl` as one JSON record per ack: `{alert_hash, ack_ts, by, note}`. The store is a flat append-only JSONL — operators can rsync, diff, or grep it like any other event log. No daemon coordination required; the next `alerts --unacked-only` invocation reads the directory.

`--by <name>` overrides the default operator name (`$USER`).

## File permissions and secrets

- `rules.json` is mode 0640 by default — readable by the `log_owner_group`, not world-readable. World-readable rules let an unprivileged local user plan evasions.
- If you keep highly sensitive rules (e.g. internal IOC lists), consider tightening to 0600 or moving them outside the standard config dir.

## Hot reload

The rule engine reloads `rules.json` on a SIGHUP / file-change watch. A `meta:rules_loaded` event with `count: <N>` confirms the new ruleset is active. Syntax errors fall back to the previous ruleset and log to `errors/` with the offending rule name.

`simplesiem rules check` is the safe pre-flight before reloading on a production server.

## Caveats

- **Rules fire only on the server that ingested the event.** In a realm, an event ingested by server-A fires alerts on A; the replicated copy on server-B is *already an alert*, not a fresh match against B's rules. If servers run different rule sets, you get the originating server's alerts. If you want symmetric detection, push the same `rules.json` to every server.
- **No state replication across daemon restarts.** Threshold windows and dedup counters reset on restart. A fresh "5 failed SSH in 60s" sequence after a restart will fire even if the previous daemon counted 4 of them already.
- **No state replication across servers in a realm.** Each peer runs its own threshold/dedup state machine. A brute-forcer hitting both peers in a load-balanced setup may evade thresholds that would have fired on a single server seeing all 5 attempts.
- **Threshold windows are sliding, not bucketed.** "5 in 60s" means 5 matches whose timestamps fall inside any 60s window — not 5 per minute on a wall-clock minute boundary.
