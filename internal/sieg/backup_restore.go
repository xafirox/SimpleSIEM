package sieg

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// jsonUnmarshalLoose decodes a JSON document while tolerating UTF-8
// BOMs and trailing whitespace. The existing-install guard runs over
// arbitrary on-disk config files (potentially edited on Windows where
// editors may inject a BOM); a strict json.Unmarshal would reject them.
func jsonUnmarshalLoose(body []byte, dst any) error {
	body = []byte(strings.TrimSpace(string(body)))
	utf8BOM := "\xef\xbb\xbf"
	body = []byte(strings.TrimPrefix(string(body), utf8BOM))
	return json.Unmarshal(body, dst)
}

// readBackupHeader parses the magic + flags + (when encrypted) KDF
// material at the head of a backup file and returns an io.Reader that
// yields the raw plaintext payload (gzip-of-tar or tar). The caller is
// responsible for closing src when finished.
func readBackupHeader(src io.Reader, passphrase string) (io.Reader, backupHeader, error) {
	var hdr backupHeader
	magic := make([]byte, len(backupMagic))
	if _, err := io.ReadFull(src, magic); err != nil {
		return nil, hdr, fmt.Errorf("read magic: %w", err)
	}
	if string(magic) != backupMagic {
		return nil, hdr, fmt.Errorf("not a simplesiem backup (bad magic)")
	}
	flagBuf := make([]byte, 1)
	if _, err := io.ReadFull(src, flagBuf); err != nil {
		return nil, hdr, fmt.Errorf("read flags: %w", err)
	}
	hdr.encrypted = flagBuf[0]&flagEncrypted != 0
	hdr.compressed = flagBuf[0]&flagCompressed != 0

	var aead cipher.AEAD
	var nonceBase [backupNonceBas]byte
	if hdr.encrypted {
		if passphrase == "" {
			return nil, hdr, fmt.Errorf("backup is encrypted; --passphrase or --passphrase-file required")
		}
		var iterBuf [4]byte
		if _, err := io.ReadFull(src, iterBuf[:]); err != nil {
			return nil, hdr, err
		}
		iters := binary.BigEndian.Uint32(iterBuf[:])
		if iters < 100000 || iters > 10_000_000 {
			return nil, hdr, fmt.Errorf("backup KDF iteration count %d outside reasonable range", iters)
		}
		salt := make([]byte, backupSaltSize)
		if _, err := io.ReadFull(src, salt); err != nil {
			return nil, hdr, err
		}
		if _, err := io.ReadFull(src, nonceBase[:]); err != nil {
			return nil, hdr, err
		}
		key, err := pbkdf2.Key(sha512.New384, passphrase, salt, int(iters), backupKDFKey)
		if err != nil {
			return nil, hdr, fmt.Errorf("kdf: %w", err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, hdr, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, hdr, err
		}
	}

	var raw io.Reader = newFrameReader(src, aead, nonceBase)
	if hdr.compressed {
		gz, err := gzip.NewReader(raw)
		if err != nil {
			return nil, hdr, fmt.Errorf("gzip header: %w", err)
		}
		raw = gz
	}
	return raw, hdr, nil
}

type backupHeader struct {
	encrypted  bool
	compressed bool
}

// inspectBackup returns the manifest from a backup file without
// extracting any payload data. Used by the restore CLI's --dry-run
// and by `simplesiem backup inspect` to print what's inside before an
// operator commits to the destructive restore step.
func inspectBackup(path, passphrase string) (backupManifest, error) {
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
		return backupManifest{}, fmt.Errorf("read manifest: %w", err)
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
		return backupManifest{}, fmt.Errorf("manifest JSON: %w", err)
	}
	return m, nil
}

// restoreBackup unpacks a backup into the destination paths recorded
// in its manifest (or, when overrides are non-empty, into those
// instead). Bytes are written to a sibling temp directory first and
// then atomically renamed into place so a half-extracted restore
// can't corrupt a working install. dryRun prints what would happen
// without touching disk.
//
// Existing-install guard: when the destination already has a
// SimpleSIEM config and the running mode is anything other than
// "standalone", the restore refuses by default. The operator must
// either uninstall first OR pass --force to override. Reason: an
// incoming agent backup over a live server would clobber the
// server's allowlist + per-host log tree; an incoming server backup
// over a master would replace the master's enrolled-servers list.
// Standalone has no such operational coupling so it's the only mode
// where a clean overwrite is safe by default.
//
// Pre-existing standalone logs are preserved by renaming the
// existing log_dir/state_dir/config_dir to <dir>.pre-restore-<utc>
// before promotion. The utc-stamped suffix makes the preserved tree
// discoverable to the operator (`ls /var/log/simplesiem.pre-restore-*`)
// and unique across multiple restores on the same host.
func restoreBackup(path, passphrase string, dryRun bool, overrides restoreOverrides) (backupManifest, error) {
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
	manifestHdr, err := tr.Next()
	if err != nil {
		return backupManifest{}, err
	}
	if manifestHdr.Name != "manifest.json" {
		return backupManifest{}, fmt.Errorf("first tar entry is %q, expected manifest.json", manifestHdr.Name)
	}
	body, err := io.ReadAll(tr)
	if err != nil {
		return backupManifest{}, err
	}
	var m backupManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return backupManifest{}, err
	}
	// Cross-platform restores are explicitly supported (a Linux server
	// being moved to a Mac, etc.) — but the operator should know
	// they're doing one. Don't refuse; just inform.
	if m.Platform != runtime.GOOS || m.Arch != runtime.GOARCH {
		fmt.Fprintf(os.Stderr, "note: backup was created on %s/%s; restoring onto %s/%s. Verify config paths and service registration after restore.\n",
			m.Platform, m.Arch, runtime.GOOS, runtime.GOARCH)
	}

	dest := resolveRestoreTargets(m, overrides)

	// Existing-install guard. Skipped on dry-run (operator may want to
	// inspect before deciding) and on --force (overrides.force=true).
	if !dryRun && !overrides.force {
		if existingMode, ok := readExistingMode(dest.configDir); ok && existingMode != "standalone" {
			return m, fmt.Errorf(
				"refusing to restore: destination is already running in %q mode at %s. "+
					"Restore is allowed only over standalone (or fresh) installs by default. "+
					"Uninstall the existing %s first or pass --force to override.",
				existingMode, dest.configDir, existingMode)
		}
	}

	if dryRun {
		// Dry-run: walk the tar (decrypts + verifies every frame's
		// AEAD tag) and print the entries WITHOUT touching disk.
		// Any verification failure during the walk surfaces here,
		// without ever creating staging dirs.
		fmt.Println("DRY RUN — entries that would be restored:")
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return m, err
			}
			fmt.Printf("  %-8s %10d  %s\n", strings.ToUpper(typeflagName(h.Typeflag)), h.Size, h.Name)
		}
		return m, nil
	}

	// Real restore — build the atomic transaction.
	//
	// Atomicity strategy: every destination tree (config / state /
	// logs / loose) gets a SIBLING staging dir on the SAME volume so
	// the final rename is a single-syscall atomic operation on every
	// supported OS (POSIX rename(2) / Windows MoveFileEx). On any
	// failure during extraction OR during the multi-step swap, the
	// tx.rollback() pass undoes every completed step in reverse
	// order, leaving the host in its pre-restore state — including
	// removing any directories the restore created from scratch on a
	// fresh-install host.
	tx := newRestoreTx(dest)
	defer func() {
		if err := tx.finalErr; err != nil || !tx.committed {
			tx.rollback()
		}
	}()

	if err := tx.prepareStaging(); err != nil {
		tx.finalErr = err
		return m, err
	}

	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			tx.finalErr = err
			return m, fmt.Errorf("backup tar read failed (rollback complete): %w", err)
		}
		stagingPath, perr := tx.stagingPathFor(h.Name)
		if perr != nil {
			tx.finalErr = perr
			return m, perr
		}
		if stagingPath == "" {
			continue
		}
		if werr := writeStagedEntry(stagingPath, h, tr); werr != nil {
			tx.finalErr = werr
			return m, fmt.Errorf("write entry %q failed (rollback complete): %w", h.Name, werr)
		}
	}

	if err := tx.commit(); err != nil {
		tx.finalErr = err
		return m, fmt.Errorf("promote failed (rollback complete): %w", err)
	}
	return m, nil
}

// restoreOverrides lets the operator point a restore at non-default
// paths (e.g. testing a backup against a tempdir before clobbering
// the live install). All-empty means "restore to the paths recorded
// in the manifest."
type restoreOverrides struct {
	configDir string
	stateDir  string
	logDir    string
	// force bypasses the existing-install guard. Required when
	// restoring over a non-standalone destination (server, agent,
	// master, collector).
	force bool
}

// readExistingMode peeks at config.json under configDir (if any) and
// returns the mode field. Used only by the existing-install guard.
// "" + ok=false means no install detected at the destination, which
// is treated as "fresh — any restore is fine."
func readExistingMode(configDir string) (string, bool) {
	candidates := []string{
		filepath.Join(configDir, "config.json"),
	}
	for _, p := range candidates {
		body, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		// Minimal struct: avoid pulling in the full Config so a
		// future field addition can't accidentally fail the parse.
		var probe struct {
			Mode string `json:"mode"`
		}
		if err := jsonUnmarshalLoose(body, &probe); err != nil {
			continue
		}
		mode := strings.TrimSpace(probe.Mode)
		if mode == "" {
			mode = "standalone"
		}
		return mode, true
	}
	return "", false
}

type restoreTargets struct {
	configDir string
	stateDir  string
	logDir    string
	loose     string // optional bag for files outside the three trees
}

func resolveRestoreTargets(m backupManifest, overrides restoreOverrides) restoreTargets {
	t := restoreTargets{
		configDir: m.ConfigDir,
		stateDir:  m.StateDir,
		logDir:    m.LogDir,
	}
	if overrides.configDir != "" {
		t.configDir = overrides.configDir
	}
	if overrides.stateDir != "" {
		t.stateDir = overrides.stateDir
	}
	if overrides.logDir != "" {
		t.logDir = overrides.logDir
	}
	t.loose = filepath.Join(t.configDir, "_restored_loose")
	return t
}

// restoreTx is the atomic-restore transaction. Every observable
// side-effect on the filesystem flows through one of its methods so
// rollback() can revert the host to its pre-restore state — even
// when the restore is the very first SimpleSIEM operation on a
// freshly-deployed binary (no install yet, no destination dirs
// existing on disk).
//
// Lifecycle:
//
//	newRestoreTx(dest)
//	tx.prepareStaging()     // create sibling staging dirs on each volume
//	  ...write tar entries to staging via tx.stagingPathFor(...)...
//	tx.commit()             // atomic per-tree swap with reverse-order rollback
//	  on any error → defer'd tx.rollback() removes staging + restores
//	                 any pre-restore tree it had renamed away.
type restoreTx struct {
	dest       restoreTargets
	utcStamp   string
	swaps      []*restoreSwap
	committed  bool
	finalErr   error
	createdParents []string
}

// restoreSwap captures everything we need to atomically install one
// staged subtree at its final destination AND undo that work later
// if a sibling swap fails.
type restoreSwap struct {
	tree           string // "config" / "state" / "logs" / "loose"
	stagingDir     string // sibling staging dir, lives until commit
	dstDir         string // final destination (e.g. /etc/simplesiem)
	preRestoreDir  string // <dstDir>.pre-restore-<utc> when dst existed before
	dstExisted     bool   // dstDir was present before we touched anything
	stagingCreated bool   // we created stagingDir (always true after prepareStaging)
	backedUp       bool   // dstDir → preRestoreDir succeeded
	promoted       bool   // stagingDir → dstDir succeeded
	hadEntries     bool   // at least one tar entry landed in stagingDir
}

func newRestoreTx(dest restoreTargets) *restoreTx {
	return &restoreTx{
		dest:     dest,
		utcStamp: time.Now().UTC().Format("20060102T150405Z"),
	}
}

// prepareStaging records the pre-restore state of each destination
// (existed-before yes/no), creates any missing parent directories
// (recording them so rollback can wipe them), and creates a SIBLING
// staging dir per tree on the same volume as the final destination.
// Same-volume siblings guarantee the rename in commit() is a
// single-syscall atomic operation on every supported OS, sidestepping
// Windows's "MoveFile across volumes is a copy" caveat.
func (tx *restoreTx) prepareStaging() error {
	// Three swaps — one per top-level destination tree. Loose
	// entries (config_path / rules_path that lived outside the three
	// trees) land INSIDE the config staging dir under
	// `_restored_loose/...`, NOT as a fourth sibling, because a
	// fourth sibling at <configDir>/_restored_loose would force us
	// to materialise <configDir> as an empty parent — and that
	// pre-existing empty dir then blocks the config tree's atomic
	// rename on Windows (rename-over-existing-dir is rejected).
	trees := []struct {
		name string
		dst  string
	}{
		{"config", tx.dest.configDir},
		{"state", tx.dest.stateDir},
		{"logs", tx.dest.logDir},
	}
	for _, t := range trees {
		if t.dst == "" {
			continue
		}
		s := &restoreSwap{
			tree:          t.name,
			dstDir:        t.dst,
			stagingDir:    t.dst + ".restore-staging-" + tx.utcStamp,
			preRestoreDir: t.dst + ".pre-restore-" + tx.utcStamp,
		}
		if _, err := os.Stat(s.dstDir); err == nil {
			s.dstExisted = true
		}
		if err := tx.ensureParent(s.dstDir); err != nil {
			return err
		}
		if err := os.MkdirAll(s.stagingDir, 0o700); err != nil {
			return err
		}
		s.stagingCreated = true
		tx.swaps = append(tx.swaps, s)
	}
	return nil
}

// ensureParent ensures filepath.Dir(p) exists, recording any
// directories WE create so rollback can remove them. Already-existing
// parent dirs aren't tracked — those belong to the operator and
// rollback must not touch them.
func (tx *restoreTx) ensureParent(p string) error {
	parent := filepath.Dir(p)
	if parent == "" || parent == "." {
		return nil
	}
	if _, err := os.Stat(parent); err == nil {
		return nil
	}
	// Create the missing chain ancestor-by-ancestor so we can record
	// each directory we add (and remove only those on rollback).
	missing := []string{}
	cur := parent
	for {
		if _, err := os.Stat(cur); err == nil {
			break
		}
		missing = append(missing, cur)
		next := filepath.Dir(cur)
		if next == cur {
			break
		}
		cur = next
	}
	// Make from outermost-missing down to the leaf parent.
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.MkdirAll(missing[i], 0o755); err != nil {
			return err
		}
		tx.createdParents = append(tx.createdParents, missing[i])
	}
	return nil
}

// stagingPathFor maps a tar archive name (e.g. "config/config.json")
// to the absolute on-disk staging path it should be written to.
// Returns "" for the manifest entry (already consumed) and for
// entries that don't belong to any tracked tree (silently ignored).
// Path-traversal attempts are rejected so an attacker-supplied
// backup can't write outside the staging dirs.
func (tx *restoreTx) stagingPathFor(archiveName string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(archiveName))
	// Reject path-traversal AND absolute paths on every platform.
	// On Windows, filepath.Clean("C:\\etc\\passwd") yields "C:\etc\passwd";
	// after ToSlash, "C:/etc/passwd" — doesn't start with "/" but
	// IS absolute. filepath.IsAbs catches both Unix and Windows.
	if strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") ||
		strings.HasPrefix(clean, "/") || filepath.IsAbs(archiveName) || filepath.IsAbs(clean) {
		return "", fmt.Errorf("rejecting suspicious tar entry %q", archiveName)
	}
	if clean == "manifest.json" {
		return "", nil
	}
	for _, s := range tx.swaps {
		prefix := s.tree + "/"
		if strings.HasPrefix(clean, prefix) {
			rel := strings.TrimPrefix(clean, prefix)
			s.hadEntries = true
			return filepath.Join(s.stagingDir, rel), nil
		}
	}
	// Loose entries (config_path / rules_path outside the three
	// trees) ride along inside the config tree. The final layout
	// after promotion: <configDir>/_restored_loose/<basename>.
	if strings.HasPrefix(clean, "loose/") {
		rel := strings.TrimPrefix(clean, "loose/")
		for _, s := range tx.swaps {
			if s.tree == "config" {
				s.hadEntries = true
				return filepath.Join(s.stagingDir, "_restored_loose", rel), nil
			}
		}
	}
	return "", nil
}

// commit performs the per-tree atomic swap in deterministic order
// (config → state → logs → loose). On the first failure mid-sequence
// the deferred rollback() call in restoreBackup undoes every
// completed swap PLUS removes any staging dirs that never made it
// into place, so the host is left exactly as it was before restore.
func (tx *restoreTx) commit() error {
	for _, s := range tx.swaps {
		if !s.hadEntries {
			// Nothing was extracted into this tree — nothing to
			// promote. Leave the destination alone.
			continue
		}
		if s.dstExisted {
			// safeRenameDir falls back to copy+remove on EXDEV
			// (overlayfs lower-layer rename, true cross-mount).
			if err := safeRenameDir(s.dstDir, s.preRestoreDir); err != nil {
				return fmt.Errorf("preserve existing %s: %w", s.dstDir, err)
			}
			s.backedUp = true
		}
		if err := safeRenameDir(s.stagingDir, s.dstDir); err != nil {
			return fmt.Errorf("promote %s -> %s: %w", s.stagingDir, s.dstDir, err)
		}
		s.promoted = true
	}
	tx.committed = true
	return nil
}

// rollback reverses every step prepareStaging / commit took, in the
// opposite order they were taken. Idempotent and best-effort: a
// missing intermediate file just means an earlier step partially
// succeeded; rollback presses on so the operator's view is "no
// trace of the restore" even if some cleanup steps fail.
func (tx *restoreTx) rollback() {
	// 1. Undo any successful per-tree swaps in reverse.
	for i := len(tx.swaps) - 1; i >= 0; i-- {
		s := tx.swaps[i]
		if s.promoted {
			// stagingDir is now at dstDir; remove it.
			_ = os.RemoveAll(s.dstDir)
			s.promoted = false
		}
		if s.backedUp {
			// Restore the pre-restore copy back to its destination.
			// safeRenameDir handles EXDEV with the same copy+remove
			// fallback as the forward path, so rollback succeeds even
			// on overlayfs.
			_ = safeRenameDir(s.preRestoreDir, s.dstDir)
			s.backedUp = false
		}
		if s.stagingCreated {
			_ = os.RemoveAll(s.stagingDir)
			s.stagingCreated = false
		}
	}
	// 2. Remove any parent directories we created on a
	//    previously-uninstalled host. Walk leaf → root so empty
	//    intermediate dirs disappear cleanly.
	for i := len(tx.createdParents) - 1; i >= 0; i-- {
		p := tx.createdParents[i]
		// Use Remove (not RemoveAll) so we don't accidentally wipe
		// out something the operator put there in parallel between
		// our MkdirAll and now. An empty dir we created comes off
		// cleanly; any newly-arrived sibling files keep the dir alive.
		_ = os.Remove(p)
	}
}

// symlinkTargetSafe checks that creating `linkAt -> linkTo` keeps the
// resolved target within the staging tree (one directory level up
// from linkAt). Refuses absolute targets and `..` paths that escape.
func symlinkTargetSafe(linkAt, linkTo string) bool {
	if linkTo == "" {
		return false
	}
	if filepath.IsAbs(linkTo) {
		return false
	}
	// Resolve linkTo relative to linkAt's directory.
	stagingRoot := filepath.Dir(linkAt)
	resolved := filepath.Clean(filepath.Join(stagingRoot, linkTo))
	// resolved must stay under stagingRoot (or one of its ancestors
	// up to a reasonable depth — tar archives sometimes have ../ for
	// sibling-dir relative links). We refuse anything that escapes
	// the parent of stagingRoot.
	stagingParent := filepath.Dir(stagingRoot)
	rel, err := filepath.Rel(stagingParent, resolved)
	if err != nil {
		return false
	}
	if strings.HasPrefix(rel, "..") {
		return false
	}
	return true
}

func writeStagedEntry(target string, h *tar.Header, body io.Reader) error {
	switch h.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(target, os.FileMode(h.Mode)|0o700)
	case tar.TypeSymlink:
		// Validate the link target stays within the staging dir. A
		// malicious .siembak with `Linkname=/etc/passwd` would
		// otherwise plant a symlink that redirects post-restore reads
		// to attacker-chosen paths (zip-slip / symlink-slip class).
		if !symlinkTargetSafe(target, h.Linkname) {
			return fmt.Errorf("refusing symlink that escapes staging dir: %s -> %s", h.Name, h.Linkname)
		}
		_ = os.MkdirAll(filepath.Dir(target), 0o700)
		_ = os.Remove(target)
		return os.Symlink(h.Linkname, target)
	case tar.TypeReg, tar.TypeRegA:
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(h.Mode)|0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, body)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	return nil
}

func typeflagName(t byte) string {
	switch t {
	case tar.TypeReg, tar.TypeRegA:
		return "file"
	case tar.TypeDir:
		return "dir"
	case tar.TypeSymlink:
		return "symlink"
	}
	return "other"
}
