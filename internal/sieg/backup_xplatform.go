package sieg

import (
	"archive/tar"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// peekManifest opens a backup file, decrypts/decompresses the header,
// reads ONLY the first tar entry (manifest.json), and returns the
// parsed manifest without consuming the rest of the archive. The
// caller can decide on overrides (e.g. crossPlatformPathOverrides)
// before re-opening the file via restoreBackup for the actual
// extraction. Cheaper than two full restores to make an informed
// decision.
func peekManifest(path, passphrase string) (backupManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return backupManifest{}, err
	}
	defer f.Close()
	r, _, err := readBackupHeader(f, passphrase)
	if err != nil {
		return backupManifest{}, err
	}
	tr := tar.NewReader(r)
	hdr, err := tr.Next()
	if err != nil {
		return backupManifest{}, err
	}
	if hdr.Name != "manifest.json" {
		return backupManifest{}, fmt.Errorf("first tar entry is %q, expected manifest.json", hdr.Name)
	}
	body, err := io.ReadAll(tr)
	if err != nil {
		return backupManifest{}, err
	}
	var m backupManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return backupManifest{}, err
	}
	return m, nil
}

// crossPlatformPathOverrides returns restoreOverrides pointing at the
// CURRENT platform's default paths whenever the backup was created on
// a different platform. Without this, restoring (say) a Windows backup
// onto Linux would extract into literal paths like "/home/jake/C:\...
// \SimpleSIEM" — Linux accepts colons and backslashes as filename bytes,
// so the restore "succeeds" but the daemon (which reads from
// /etc/simplesiem on Linux) never sees the new config and continues
// running its old setup. Same problem in the other direction.
//
// Operator-provided overrides (--config-dir / --state-dir / --log-dir)
// always win — only fields the operator left blank are filled here.
func crossPlatformPathOverrides(m backupManifest, operator restoreOverrides) restoreOverrides {
	if m.Platform == runtime.GOOS {
		return operator
	}
	out := operator
	if out.configDir == "" {
		out.configDir = defaultConfigDir()
	}
	if out.stateDir == "" {
		out.stateDir = defaultStateDir()
	}
	if out.logDir == "" {
		out.logDir = defaultLogDir()
	}
	return out
}

// applyPostRestoreRebind runs AFTER restoreBackup has successfully
// extracted the manifest and content onto disk. It makes the restored
// install actually usable by:
//
//  1. Rewriting path-shaped fields in config.json so they point at the
//     CURRENT platform's directories rather than the backup's source
//     paths. (Cross-platform restore: a Linux-backup config with
//     `client_cert: /etc/simplesiem/certs/client.pem` becomes
//     `client_cert: C:\ProgramData\SimpleSIEM\certs\client.pem` on
//     Windows.)
//
//  2. Re-issuing the server cert with the LOCAL machine's hostname.
//     The CA private key from the backup is still on disk (and is the
//     realm CA the other peers already trust), so re-signing produces
//     a cert any realm member can verify. Without this, the local
//     listener presents a cert whose SAN names the BACKUP's source
//     host, and any peer dialing by the local hostname gets a TLS
//     name-mismatch.
//
//  3. Normalising server.realm.peers. Drop any entry that resolves to
//     the local hostname (self-references created by cross-restore).
//     Add a peer pointing at the backup's source host_id (the source
//     IS the other realm member after a swap), so a cross-restored
//     pair re-peers automatically without operator action.
//
//  4. Clearing server.local_id so pickServerLocalID falls back to
//     os.Hostname() — the daemon stamps events with the real local
//     hostname rather than the backup's source identity.
//
//  5. Resetting platform-specific defaults that don't translate:
//     auth_log_paths (Linux-shaped) and file_watch_paths.
//
// Best-effort per step: a non-fatal error in cert reissue or peer
// normalisation prints a warning but does not abort the restore — the
// extraction itself already succeeded. Aborting at this point would
// leave the operator with a daemon that won't start AND no clear
// remediation, which is worse than "daemon comes up but you may need
// to re-realm-join manually."
func applyPostRestoreRebind(cfgPath string, m backupManifest, dest restoreTargets) {
	cfgFile := filepath.Join(dest.configDir, "config.json")
	raw, err := os.ReadFile(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "post-restore: read config %s: %v\n", cfgFile, err)
		return
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "post-restore: parse config: %v\n", err)
		return
	}

	// 1. Path rewrite (only when crossing platforms or when path fields
	//    don't match the now-current dest paths).
	rewriteConfigPaths(cfg, m, dest)

	// 4. Clear server.local_id so daemon falls back to os.Hostname() on
	//    next start (must happen before peer normalisation, since we use
	//    the actual hostname there).
	localHost, _ := os.Hostname()
	if srv, ok := cfg["server"].(map[string]any); ok {
		if existing, _ := srv["local_id"].(string); existing != "" && existing != localHost {
			srv["local_id"] = ""
		}
	}

	// 3. Realm peer normalisation.
	hostnameRebindReport := normaliseRealmPeers(cfg, m, localHost)

	// Persist the rewritten config before touching certs (so a cert
	// failure doesn't desync config from disk).
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "post-restore: marshal config: %v\n", err)
		return
	}
	if err := os.WriteFile(cfgFile, out, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "post-restore: write config: %v\n", err)
		return
	}

	// 2. Re-issue server cert with local hostname (server mode only).
	if mode, _ := cfg["mode"].(string); mode == "server" {
		if err := reissueServerCertWithLocalHostname(cfgFile, m, localHost); err != nil {
			fmt.Fprintf(os.Stderr, "post-restore: server cert re-issuance: %v\n", err)
		} else {
			fmt.Printf("post-restore: server cert re-issued with SAN for %s\n", localHost)
		}
	}

	if hostnameRebindReport != "" {
		fmt.Print(hostnameRebindReport)
	}
}

// rewriteConfigPaths replaces path-shaped fields in cfg with their
// equivalents under the new platform's dest layout. Approach: build a
// substring map { old_prefix → new_prefix } for config_dir / state_dir
// / log_dir, then walk every string value in the config and apply
// the longest-matching prefix. Path separators are normalised to the
// new platform's convention.
func rewriteConfigPaths(cfg map[string]any, m backupManifest, dest restoreTargets) {
	type pair struct{ old, new string }
	prefixes := []pair{
		{m.ConfigDir, dest.configDir},
		{m.StateDir, dest.stateDir},
		{m.LogDir, dest.logDir},
	}
	// Sort longest-old-prefix first so /etc/simplesiem/state takes
	// precedence over /etc/simplesiem when both are configured.
	for i := 0; i < len(prefixes); i++ {
		for j := i + 1; j < len(prefixes); j++ {
			if len(prefixes[j].old) > len(prefixes[i].old) {
				prefixes[i], prefixes[j] = prefixes[j], prefixes[i]
			}
		}
	}

	// normaliseSep converts both `\` and `/` to `/` so prefix matching
	// works regardless of which platform produced the string AND which
	// platform the runtime is running on. (filepath.ToSlash only flips
	// `\` to `/` on Windows; it's a no-op on Linux/macOS, which is
	// exactly the cross-platform case we care about most.)
	normaliseSep := func(s string) string {
		return strings.ReplaceAll(s, "\\", "/")
	}
	rewriteOne := func(s string) string {
		if s == "" {
			return s
		}
		sF := normaliseSep(s)
		for _, p := range prefixes {
			if p.old == "" {
				continue
			}
			oldF := normaliseSep(p.old)
			if strings.HasPrefix(sF, oldF+"/") {
				rest := strings.TrimPrefix(sF, oldF)
				return joinNative(p.new, rest)
			}
			if sF == oldF {
				return p.new
			}
		}
		return s
	}

	walk(cfg, rewriteOne)

	// Reset platform-specific list fields that don't translate at all.
	// auth_log_paths is Linux/macOS-shaped; on Windows the daemon uses
	// wevtutil instead of file paths, so an inherited list of /var/log
	// entries is just noise. file_watch_paths defaults are similarly
	// shaped per platform — restoring a Linux watch list onto Windows
	// would have the FileCollector silently skip every entry.
	if m.Platform != runtime.GOOS {
		fresh := defaultConfig()
		cfg["auth_log_paths"] = stringListToAnySlice(fresh.AuthLogPaths)
		cfg["file_watch_paths"] = stringListToAnySlice(fresh.FileWatchPaths)
	}
}

// joinNative rejoins a path under newBase, restoring the new
// platform's separator. rest is in forward-slash form.
func joinNative(newBase, rest string) string {
	rest = strings.TrimPrefix(rest, "/")
	parts := strings.Split(rest, "/")
	out := newBase
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = filepath.Join(out, p)
	}
	return out
}

// walk recursively visits every string value in v and rewrites it via
// f. Maps and slices descend; other types pass through.
func walk(v any, f func(string) string) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = walk(val, f)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = walk(val, f)
		}
		return t
	case string:
		return f(t)
	default:
		return v
	}
}

func stringListToAnySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

// normaliseRealmPeers drops self-pointing entries from server.realm.peers
// (created when a backup is restored on a different host whose hostname
// is one of the source's peers) and adds an entry pointing at the
// backup's source host. After a cross-restore, the source host IS the
// other realm member from the local POV, so peering with it restores
// the realm topology.
func normaliseRealmPeers(cfg map[string]any, m backupManifest, localHost string) string {
	srv, ok := cfg["server"].(map[string]any)
	if !ok {
		return ""
	}
	realm, ok := srv["realm"].(map[string]any)
	if !ok {
		return ""
	}
	rawPeers, _ := realm["peers"].([]any)
	var report strings.Builder
	port := serverListenPort(srv)
	kept := make([]any, 0, len(rawPeers))
	for _, p := range rawPeers {
		s, _ := p.(string)
		if s == "" {
			continue
		}
		if peerMatchesHost(s, localHost) {
			fmt.Fprintf(&report, "post-restore: dropped self-pointing realm peer %s\n", s)
			continue
		}
		kept = append(kept, s)
	}
	// Add the backup source as a peer if not already present.
	if m.HostID != "" && !strings.EqualFold(m.HostID, localHost) {
		sourceURL := fmt.Sprintf("https://%s:%s", m.HostID, port)
		already := false
		for _, p := range kept {
			if peerMatchesHost(p.(string), m.HostID) {
				already = true
				break
			}
		}
		if !already {
			kept = append(kept, sourceURL)
			fmt.Fprintf(&report, "post-restore: added realm peer %s (backup source — auto re-peering)\n", sourceURL)
		}
	}
	realm["peers"] = kept
	return report.String()
}

// peerMatchesHost reports whether a peer URL string resolves (by
// hostname literal) to the given hostname. Case-insensitive on the
// hostname component.
func peerMatchesHost(peer, host string) bool {
	if peer == "" || host == "" {
		return false
	}
	u, err := url.Parse(peer)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), host)
}

// serverListenPort extracts the port from server.listen, defaulting
// to 9443 if unset or unparseable.
func serverListenPort(srv map[string]any) string {
	listen, _ := srv["listen"].(string)
	if listen == "" {
		return "9443"
	}
	listen = strings.TrimPrefix(listen, ":")
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		listen = listen[i+1:]
	}
	if listen == "" {
		return "9443"
	}
	return listen
}

// reissueServerCertWithLocalHostname re-signs the server cert against
// the existing CA on disk so the SAN names the local hostname. Skipped
// when the existing cert already covers localHost (idempotent — a
// straight-line restore on the same host doesn't churn the cert).
func reissueServerCertWithLocalHostname(cfgPath string, m backupManifest, localHost string) error {
	if localHost == "" {
		return fmt.Errorf("os.Hostname() returned empty; cannot infer SAN")
	}
	dir := certsDir(cfgPath)
	srvPath := filepath.Join(dir, "server.pem")
	if _, err := os.Stat(srvPath); os.IsNotExist(err) {
		// No server cert yet (e.g. cross-restored agent backup). Nothing
		// to re-issue — server-mode startup will trip the existing
		// "missing cert" error and the operator runs `certs init`.
		return nil
	}
	pemBytes, err := os.ReadFile(srvPath)
	if err != nil {
		return fmt.Errorf("read server cert: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("server cert is not PEM")
	}
	existing, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse server cert: %w", err)
	}
	// Idempotency: if the existing SAN already covers localHost, skip.
	for _, dns := range existing.DNSNames {
		if strings.EqualFold(dns, localHost) {
			return nil
		}
	}
	caCert, caKey, err := loadCAFromDisk(dir)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	hosts := []string{localHost, "127.0.0.1"}
	if !strings.EqualFold(localHost, "localhost") {
		hosts = append(hosts, "localhost")
	}
	hosts = appendUniqueHosts(hosts, gatherLocalIPs())
	hosts = appendUniqueHosts(hosts, gatherDNSAliases(gatherLocalIPs()))
	// issueServerCert refuses to clobber existing files (the
	// operator-facing `certs init` semantic). For the restore-driven
	// re-issuance path we explicitly WANT to replace the existing
	// cert/key — they're the source backup's, not the local install's.
	// Move the old pair aside first so the audit trail keeps the
	// pre-rebind material accessible.
	srvKeyPath := filepath.Join(dir, "server.key")
	stamp := strings.ReplaceAll(strings.ReplaceAll(m.CreatedAtUTC.Format("20060102T150405Z"), ":", ""), "-", "")
	if stamp == "" {
		stamp = "rebind"
	}
	if err := os.Rename(srvPath, srvPath+".pre-rebind."+stamp); err != nil {
		return fmt.Errorf("move old server.pem aside: %w", err)
	}
	if err := os.Rename(srvKeyPath, srvKeyPath+".pre-rebind."+stamp); err != nil {
		// Try to roll back the cert rename so we don't leave the
		// install half-orphaned.
		_ = os.Rename(srvPath+".pre-rebind."+stamp, srvPath)
		return fmt.Errorf("move old server.key aside: %w", err)
	}
	if err := issueServerCert(dir, caCert, caKey, 5, hosts); err != nil {
		// Best-effort restore the prior pair so the install isn't
		// orphaned by a partial failure here.
		_ = os.Rename(srvPath+".pre-rebind."+stamp, srvPath)
		_ = os.Rename(srvKeyPath+".pre-rebind."+stamp, srvKeyPath)
		return fmt.Errorf("issue server cert: %w", err)
	}
	return nil
}
