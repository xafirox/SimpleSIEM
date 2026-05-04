# Backup & restore

SimpleSIEM's backup feature exports every artifact a host owns — config, state (certs + PSK + watermarks), logs, plus a UTC-stamped manifest — into a single encrypted `.siembak` file you can move between machines, store offline, or hand to a colleague. Restore is symmetric: the same binary on any supported OS unpacks the file back into place.

This page is the operational walk-through. For the on-wire format, the cryptographic primitives, and config keys, see [reference.md → Backup & restore](reference.md#backup--restore).

## At a glance

| Scenario | Command |
|---|---|
| Local backup of the current host | `simplesiem backup --out <path> --passphrase-file <file>` |
| Inspect a backup without extracting | `simplesiem backup inspect --in <path> --passphrase-file <file>` |
| Verify a cold backup (decrypt + walk every chain) | `simplesiem backup verify --in <path> --passphrase-file <file>` |
| Restore a backup on a fresh box | `simplesiem restore --in <path> --passphrase-file <file>` |
| Server backs up self + every agent it sees | `simplesiem backup --all --out-dir <dir> --passphrase-file <file>` |
| Server backs up everyone in a realm (peers + their agents) | `simplesiem backup --realm <name> --all --out-dir <dir> --passphrase-file <file>` |
| Master backs up the whole fleet | `simplesiem master backup --all-realms --out-dir <dir> --passphrase-file <file>` |
| Master backs up just the paired collector | `simplesiem master backup --collector <out> --passphrase-file <file>` |
| Master backs up just itself | `simplesiem master backup --self <out> --passphrase-file <file>` |

Encryption is **on by default**. Passing `--no-encrypt` is opt-in and prints a warning that private keys and the enrollment PSK will land in plaintext inside the file.

---

## No external tooling required

The backup format uses Go's standard-library `archive/tar` and `compress/gzip` packages. Both are pure-Go implementations that run in-process — `simplesiem backup` and `simplesiem restore` do **not** shell out to a system `tar` or `gzip` binary, do not require GNU tar on Linux, BSD tar on macOS, or any tar at all on Windows. The same binary that creates the backup also restores it, on every supported OS, with no other tooling installed.

The only OS-level requirements at restore time are:

- Filesystem write permission for the destination paths (which is why `restore` is run with `sudo` / elevated PowerShell)
- Enough free space in the staging tempdir for the decompressed payload while frames are being verified.

## How encryption protects the file

Every backup is sealed with **AES-256-GCM** under a key derived from our passphrase via **PBKDF2-SHA384, 600,000 iterations, 32-byte andom salt** — generated fresh per backup so the same passphrase never produces identical files. The plaintext (a `tar.gz` containingmanifest.json`, `config/`, `state/`, `logs/`) is split into 1 MiB chunks; each chunk is independently AEAD-sealed with a per-frame once (`nonce_base XOR counter`) so no two frames ever reuse a nonce within or across backups, and any byte tampering fails that frame's6-byte authentication tag.

A `final-frame` bit in the length prefix detects truncation: if a file ends without ever seeing it, the restorer returns `errBackupTruncated` instead of silently using a partial backup.

### What an attacker holding the file actually sees

Without the passphrase, an offline observer has access to:

- 6-byte fixed magic (`SBAK1\0`).
- 1-byte format flags (encrypted yes/no, compressed yes/no).
- 4-byte iteration count + 32-byte salt + 12-byte nonce base.
- A length-prefixed sequence of opaque ciphertext frames.

They do **not** see filenames, file sizes, host ID, realm, platform, the manifest, or any structure inside the tarball — those all live inside the encrypted frames. To brute-force the passphrase the attacker has to compute roughly 600k SHA-384 rounds *per guess*; a 12+ character passphrase from a decent word list makes that economically infeasible on commodity hardware.

> Treat the passphrase as you would a CA private key: deliver it
> out-of-band, never in the same channel as the `.siembak` file
> itself, and never check it into version control.

---

## Local backup

```bash
# Default: encrypted + gzipped + UTC-stamped filename.
sudo simplesiem backup --out /backups/$(hostname).siembak \
                       --passphrase-file /etc/simplesiem/backup-pp

# Faster but much larger:
sudo simplesiem backup --out /backups/$(hostname).siembak \
                       --passphrase-file /etc/simplesiem/backup-pp \
                       --no-compress

# Auto-generated filename: simplesiem-backup-<host>-<UTC>.siembak in $PWD
sudo simplesiem backup --passphrase-file /etc/simplesiem/backup-pp -y
```

The daemon is **not stopped** during the backup — collection continues, and the operator is warned that events written after the backup's UTC start are NOT in the file. The manifest's `note` field records the same warning so a future restorer reading the manifest sees it inline.

`-y` skips the interactive "events collected during the backup will not be included" prompt; useful in cron / orchestration pipelines.

### Inspecting a backup

`simplesiem backup inspect` decrypts the manifest only — first tar entry, then stops. A wrong passphrase fails the FIRST frame's GCM tag and aborts before any tarball state is parsed. Useful for:

- Verifying you have the right passphrase before committing to a restore.
- Reviewing what host / mode / UTC timestamp / platform the backup was created on.

```bash
$ simplesiem backup inspect --in /backups/laptop-2026-05.siembak \
                            --passphrase-file /etc/simplesiem/backup-pp
magic:           simplesiem-backup
version:         1
host_id:         my-laptop
mode:            standalone
realm:           default
created (UTC):   2026-05-01 22:18:03
created (local): 2026-05-01 18:18:03 EDT
platform:        darwin/arm64
simplesiem:      0.1.0 (build 20260502024559)
encrypted:       true
compressed:      true
config_dir:      /etc/simplesiem
state_dir:       /var/lib/simplesiem
log_dir:         /var/log/simplesiem
note:            events written after created_at_utc are NOT included; daemon was running during backup creation
```

### Verifying a cold backup

`backup verify` is the next step up from `backup inspect`. Where inspect stops at the manifest (one frame), **verify decrypts the entire envelope, walks every JSONL inside, and recomputes the SHA-384 hash chain on each one**. It reports tampered, truncated, or out-of-order chains without writing anything to disk:

```bash
$ simplesiem backup verify --in /backups/host.siembak \
                           --passphrase-file /etc/simplesiem/backup-pp
verify: walking 87 JSONL files (24,118 events)…
verify: 0 problems found
```

A non-zero `problemFiles` count exits non-zero and prints which files failed and at what line, so periodic offline integrity checks can be wired into cron or CI:

```bash
# Nightly: alert if any backup in /backups/ fails verify
for f in /backups/*.siembak; do
    simplesiem backup verify --in "$f" --passphrase-file /etc/simplesiem/backup-pp \
        || mail -s "[siem] backup verify failed: $f" ops@example.com < /dev/null
done
```

Cost: linear in backup size; verification is read-only and runs without consulting the daemon, so you can verify older backups on any host that has the binary and the passphrase.

### Pairs with: signed chain heads

`backup verify` proves a backup is internally consistent. It does NOT prove the chains in the backup match what the live daemon attested to at signing time — for that, pair the backup with the chainhead stream from `<log_dir>/_chainhead/` and run `simplesiem chainhead verify` against the restored copy. An attacker who roots a host AFTER signing can rewrite the live chain and the AEAD-protected backup taken later will be self- consistent (the attacker's chain signs cleanly), but the signature check will fail because the embedded signing key proves who attested to what. Export the chainhead stream off-box on a schedule that's tighter than your backup retention so the audit trail extends past restore.

---

## Restoring on a fresh machine

```bash
# 1. Move the file + the passphrase across (separate channels).
scp laptop.siembak fresh-host:/tmp/
# (passphrase delivered out-of-band — Slack, password manager, etc.)

# 2. On the fresh host, install the binary but DO NOT install the daemon.
chmod +x ./simplesiem-linux-amd64
sudo mv ./simplesiem-linux-amd64 /usr/local/bin/simplesiem

# 3. Dry-run first.
sudo simplesiem restore --in /tmp/laptop.siembak \
                        --passphrase-file /tmp/pp \
                        --dry-run

# 4. Real restore.
sudo simplesiem restore --in /tmp/laptop.siembak \
                        --passphrase-file /tmp/pp

# 5. Re-register the service for this OS, start, verify.
sudo simplesiem fix
sudo simplesiem start
simplesiem status
```

### What happens during a restore

1. Header parsed: magic + flags + (when encrypted) iter count + salt +  nonce base.
1. `PBKDF2-SHA384(passphrase, salt, iters)` re-derives the 32-byte  AES key.
1. AES-GCM `Open` is called on each frame. **Wrong passphrase** = the  first frame's tag fails — restore aborts with a clear error  before any disk state is touched.
1. Decrypted bytes flow through gzip → tar.
1. First entry is `manifest.json`. Manifest parsed; if the destination  already has a non-standalone install (server / agent / master /  collector), the restore is **refused** unless `--force` is set  (see [Safety guards](#safety-guards)).
1. Every subsequent tar entry is written into a unique  `simplesiem-restore-XXXX` tempdir — no live install is touched  until every entry has been verified.
1. Promotion: any existing `config_dir` / `state_dir` / `log_dir` at  the manifest's destinations are renamed to `<dir>.pre-restore-<UTC>`  so the operator can roll back manually if needed. Staged dirs are  renamed into place.

If anything fails between steps 5 and 7 (disk full, permissions error, tarball corruption), the staged tempdir is cleaned up and the existing install is left untouched.

### Cross-platform restore

A backup taken on Linux can be restored onto macOS or Windows (and vice versa). The restore prints a one-line note when the platform differs and recommends running `simplesiem fix` afterwards to re-register the service for the new OS:

```
note: backup was created on linux/amd64; restoring onto darwin/arm64.
Verify config paths and service registration after restore.
```

`simplesiem fix` audits the install, recreates the service definition for the current OS (systemd / launchd / SCM), and repairs any path or permission issues.

---

## Atomicity

Both `simplesiem backup` and `simplesiem restore` are **atomic**: a failed run leaves the host exactly as it was before the command was issued. There are no half-written `.siembak` files, no half-extracted config trees, no orphaned `.staging-*` or `.tmp` directories.

### Backup atomicity

- Bytes stream into a sibling `<outPath>.tmp` file. The final `outPath` only appears at the end via a single-syscall atomic rename (POSIX `rename(2)` / Windows `MoveFileEx`).
- If the operator was overwriting a previous `.siembak` file with the same destination, that previous file is preserved unchanged on any failure — the rename only happens after every byte has been written and the file handle has been closed cleanly.
- If `--out` pointed inside a directory chain that didn't exist (`--out /new/never/seen/file.siembak`), and the backup fails, any directories the backup created are removed too. A failed backup on a fresh path leaves no trace.
- Cancellation (Ctrl+C / SIGTERM mid-write) leaves the `.tmp` file on disk; the next successful run cleanly overwrites it. To clean up by hand: `rm <outPath>.tmp`.

### Restore atomicity

- Each top-level destination tree (`config_dir`, `state_dir`, `log_dir`) gets a SIBLING staging directory on the same volume so the final rename is a single-syscall atomic operation on every supported OS — sidestepping Windows' "rename across volumes is actually a copy" caveat.
- If extraction fails (truncation, AEAD tag mismatch, corrupt tar entry), every staging dir is removed and the host's existing install is untouched. None of the destinations are even renamed out of the way until extraction has completed cleanly.
- After extraction, the per-tree atomic swap runs in deterministic order (config → state → logs). If a swap fails partway through, every completed swap is reversed in opposite order: the staged tree at the destination is removed and the prior tree (renamed to `<dir>.pre-restore-<UTC>`) is moved back. The restore returns an error and the operator's install is identical to the pre-restore state.
- **Restore on an uninstalled binary:** if the operator runs `simplesiem restore` BEFORE `simplesiem install` (no pre-existing `config_dir` / `state_dir` / `log_dir`), and the restore fails, every directory the restore created from scratch is removed. The host is left with nothing — no empty `/etc/simplesiem` waiting to confuse the next install attempt.
- **Restore on a live install:** the existing-install guard refuses non-standalone destinations *before* any disk state is modified, so a guard-rejected restore is trivially atomic.

In practice this means a restore can be retried freely: a failed attempt leaves nothing to clean up, and a successful attempt is idempotent in the sense that the prior tree remains under `<dir>.pre-restore-<UTC>` for manual rollback.

## Safety guards

| Guard | Default behaviour | Override |
|---|---|---|
| Wrong passphrase | First frame fails GCM tag, restore aborts before writing anything | n/a |
| Truncated file | Frame reader hits EOF without seeing the final-frame flag, returns `errBackupTruncated` | n/a |
| Tampered byte | Affected frame's 16-byte tag fails, restore aborts at that frame | n/a |
| Existing non-standalone install at the destination | Refused with a message naming the existing mode (`server`, `master`, `collector`, `agent`) | `--force` |
| Existing standalone install at the destination | Existing dirs renamed to `<dir>.pre-restore-<UTC>` for rollback | n/a (preserved by default) |
| Live original still up + restored daemon coming online | Server's identity guard rejects the second IP with HTTP 409 (`duplicate identity: another daemon is currently active with this cert`) for 60 s after the original's last heartbeat | wait for the original to fully stop |
| Cross-platform restore | One-line note printed; restore proceeds | n/a |
| Collector mode: backup `--out` on same volume as `log_dir` | Refused with "different storage partition" error | use a path on a different volume |

### The identity guard

The server tracks per-CN `(last_seen_ip, last_seen_ts)` for every authenticated request. When a second IP shows up holding the same client cert inside the **60 s guard window**, the server returns HTTP 409 and emits a `meta:identity_conflict` event into the offender's per-host log:

```bash
$ simplesiem triage --host my-laptop --type meta --since 10m
... identity_conflict cn=my-laptop new_ip=10.0.0.42 prior_ip=10.0.0.17 ...
```

Beyond the window the new IP takes over (the previous occupant has been silent for a full minute — assumed dead). This means a properly sequenced restore (stop the original, wait at least 60 s, start the restored host) reassociates seamlessly; a "clone the laptop while it's still running" mistake is loudly rejected.

If you must take over while the original is still up — a hard host loss where the daemon never had a chance to gracefully stop — wait out the 60 s window before starting the restored daemon.

---

## Server-mode backup

When invoked on a server, `simplesiem backup` can compose a `.siembak` for any agent the server has events for, without an outbound call — the server is already at the top of the agent → server hop, so it builds the file from on-disk material.

```bash
# Just one agent.
sudo simplesiem backup --agent my-laptop \
                       --out-dir /backups \
                       --passphrase-file /etc/simplesiem/backup-pp

# Server + every agent it has events for.
sudo simplesiem backup --all \
                       --out-dir /backups \
                       --passphrase-file /etc/simplesiem/backup-pp
```

### Realm fan-out

When `--all` is run on a server that's part of a realm, the server additionally calls `/v1/backup/create` on each peer (using its own server cert as a client cert against the realm's cross-trust bundle). Each peer composes its own server-self backup + per-agent backups, packages them into a multi-file bundle (`SBKB` header + length-prefixed records), and streams the bundle back. The invoker unpacks each bundle into the same `--out-dir`:

```
/backups/
  simplesiem-backup-realm-server-a-20260502T024559Z.siembak
  simplesiem-backup-r1-agent-a-20260502T024559Z.siembak
  simplesiem-backup-r1-agent-b-20260502T024559Z.siembak
  realm-server-b.siembak                  # pulled from peer b's bundle
  agent-c.siembak                         # peer b's agent
  agent-d.siembak                         # peer b's other agent
```

No extra credentials are required: realms already cross-trust every peer's CA at `realm join` time, so the inbound listener accepts the caller's cert and `peerAuthorized` greenlights the call (same gate as `/v1/sync/events`).

---

## Master-mode backup

A master can pull a backup from any node it has authority over plus back up itself. The umbrella command is `master backup --all-realms` which combines all of the below into one invocation.

```bash
# Just the master.
sudo simplesiem master backup --self /backups/master.siembak \
                              --passphrase-file /etc/simplesiem/backup-pp

# Just the paired collector.
sudo simplesiem master backup --collector /backups/collector.siembak \
                              --passphrase-file /etc/simplesiem/backup-pp

# Per-host backup of every server in one named realm.
sudo simplesiem master backup --realm prod-east \
                              --out-dir /backups \
                              --passphrase-file /etc/simplesiem/backup-pp

# Everything: master + collector + every realm, organized by realm.
sudo simplesiem master backup --all-realms \
                              --out-dir /backups \
                              --passphrase-file /etc/simplesiem/backup-pp
```

Layout produced by `--all-realms`:

```
/backups/
  _self.siembak                              # master itself
  _collector.siembak                         # paired collector
  prod-east/
    realm-server-a.siembak
    realm-server-b.siembak
    laptop-1.siembak                         # agent under server-a
    laptop-2.siembak                         # agent under server-b
  prod-west/
    westa.siembak
    westb.siembak
  by-server-foo/                             # fallback when realm name
    foo.siembak                              # is unreachable mid-pull
```

The master resolves each enrolled server's realm name on the fly via `/v1/sync/config`, so the layout reflects the live realm membership rather than a stale config snapshot. Servers whose realm can't be resolved (offline at backup time, cert problem, etc.) fall back to `by-server-<id>/` so a single broken peer doesn't dump everything into "unknown".

### Constraint: collector ≠ backup destination

The master's backup paths always write to its own filesystem (`--out-dir` / `--out` are local paths, never URLs). This honours the spec's rule that the master must not use the collector as a backup-storage target. If the operator wants backups archived to a collector-attached file share, that's an operator-side responsibility (rsync the master's `--out-dir` over later) — the master's CLI won't push to the collector directly.

### Constraint: collector backup partition

When the collector itself runs `simplesiem backup --out <path>`, SimpleSIEM checks that `<path>` is on a different volume than `log_dir` and refuses if not:

```
collector mode: --out (/var/log/simplesiem-backup.siembak) is on the
same volume as log_dir (/var/log/simplesiem); pick a different
storage partition for the backup
```

Volume detection works cross-platform via `gopsutil/disk` (statfs mountpoint resolution on Linux/macOS, `GetDiskFreeSpaceEx` on Windows). The error is atomic — no partial `.siembak` is left on disk.

---

## Operational tips

- **Backup before any destructive action.** `convert master`, `realm migrate --force`, `certs init-rotate` — every operation that rewrites config or trust material is a good moment to take a pre-change backup.
- **Test your restore at least once.** A backup you've never restored is a hope, not a recovery plan. The `--dry-run` mode lets you exercise the full decrypt path without committing.
- **Treat the passphrase like a CA key.** Never co-located with the backup file, never in shell history, never in a wiki. Use `--passphrase-file` everywhere, with the passphrase file owned by root mode 0600.
- **Encrypted is default; keep it that way.** `--no-encrypt` produces a file that has private keys + the enrollment PSK in plaintext; useful only for ephemeral debugging.
- **Hierarchical backups.** From the master's vantage point, one `master backup --all-realms` capture is the closest thing to a "fleet snapshot" SimpleSIEM offers. From a server in a realm, `backup --all` captures that realm's slice. A standalone host's own `backup` is the leaf case.
- **The daemon stays running.** Backups are streaming snapshots, not hot-pause operations. Events written after `created_at_utc` are not included; that's documented in the manifest's `note` field and in the warning printed at backup start.