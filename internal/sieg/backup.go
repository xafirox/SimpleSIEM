package sieg

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// On-wire constants for the backup envelope. Bumping `backupVersion`
// is reserved for a format break; the manifest's own `version` field
// is bumped for compatible additions.
const (
	backupMagic    = "SBAK1\x00"
	backupVersion  = 1
	backupKDFIters = 600000 // PBKDF2-SHA384 — pinned high; restore is a one-shot human action
	backupKDFKey   = 32     // AES-256
	backupSaltSize = 32
	backupNonceBas = 12     // GCM standard nonce length

	// 1 MiB chunks keep memory bounded for multi-GB backups while
	// staying far under GCM's 64 GiB single-call ciphertext limit.
	// Each chunk is its own AEAD frame: counter-derived nonce binds
	// frame ordering, the per-frame tag detects truncation, and the
	// final-frame flag detects a streaming cut at the boundary.
	backupChunkSize = 1024 * 1024

	// Format flag bits in the envelope header.
	flagEncrypted  byte = 1 << 0
	flagCompressed byte = 1 << 1
)

// backupManifest is the JSON descriptor written as the first entry in
// every backup tarball. Serves three purposes:
//
//  1. Operator audit — what was backed up, where it came from, when.
//  2. Restore validation — the restorer cross-checks platform/arch
//     mismatches before clobbering local files.
//  3. Future-proofing — `version` lets a newer restorer detect old
//     formats and apply migrations.
//
// Only fields that matter to a future restorer or to an operator
// reading the manifest belong here. Don't dump cfg blobs — the cfg
// itself is in config/config.json inside the tarball.
type backupManifest struct {
	Magic        string    `json:"magic"`
	Version      int       `json:"version"`
	HostID       string    `json:"host_id"`
	Mode         string    `json:"mode"`
	Realm        string    `json:"realm,omitempty"`
	Platform     string    `json:"platform"`
	Arch         string    `json:"arch"`
	SIEMVersion  string    `json:"siem_version"`
	SIEMBuild    string    `json:"siem_build"`
	CreatedAtUTC time.Time `json:"created_at_utc"`
	Encrypted    bool      `json:"encrypted"`
	Compressed   bool      `json:"compressed"`
	ConfigPath   string    `json:"config_path"`
	ConfigDir    string    `json:"config_dir"`
	LogDir       string    `json:"log_dir"`
	StateDir     string    `json:"state_dir"`
	RulesPath    string    `json:"rules_path,omitempty"`
	Note         string    `json:"note,omitempty"`
}

// backupArtifact bundles the on-disk paths of the items the backup is
// gathering. Pre-computed once at backup-start so the streaming
// archiver never has to re-resolve paths or chase cfg state mid-run.
type backupArtifact struct {
	configPath string
	configDir  string
	logDir     string
	stateDir   string
	rulesPath  string
}

func resolveBackupArtifact(cfg Config, cfgPath string) backupArtifact {
	cfgDir := filepath.Dir(cfgPath)
	if cfgDir == "" || cfgDir == "." {
		cfgDir = defaultConfigDir()
	}
	return backupArtifact{
		configPath: cfgPath,
		configDir:  cfgDir,
		logDir:     cfg.LogDir,
		stateDir:   cfg.StateDir,
		rulesPath:  cfg.RulesPath,
	}
}

// createBackup is the local-mode entry point: read every artifact off
// the filesystem, optionally compress + encrypt, and write the result
// to outPath. The daemon (if running) is NOT stopped — collectors
// keep firing. The manifest's CreatedAtUTC is the cut-off after which
// events are NOT in the backup; this is documented to the operator at
// invocation time and surfaced in the manifest's Note field.
//
// Atomicity contract: all-or-nothing on the destination. The function
// streams ciphertext into a sibling .tmp file and only renames into
// place after every byte has been written and synced. On any failure
// the .tmp is removed; if outPath already existed before the call,
// the original file remains untouched (the rename is a single-syscall
// atomic operation, so a failed write never partially overwrites the
// previous backup). Any output-directory we created from scratch is
// removed if it ends up empty — so a failed backup on a freshly-typed
// destination path leaves no stray directories.
func createBackup(cfg Config, cfgPath, outPath, passphrase string, compress bool) (err error) {
	art := resolveBackupArtifact(cfg, cfgPath)
	parent := filepath.Dir(outPath)
	createdParents, mkErr := mkdirAllTracking(parent)
	if mkErr != nil {
		return fmt.Errorf("output dir: %w", mkErr)
	}
	defer func() {
		// On any failure, undo any directories WE created so a
		// failed run on `simplesiem backup --out /new/never/seen/file`
		// leaves no trace.
		if err != nil {
			for i := len(createdParents) - 1; i >= 0; i-- {
				_ = os.Remove(createdParents[i])
			}
		}
	}()

	tmp := outPath + ".tmp"
	out, oerr := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if oerr != nil {
		return oerr
	}
	defer func() {
		// On any error path: close + remove the .tmp file. Closing
		// twice is fine (the second close is a no-op on a closed
		// *os.File); Remove on a non-existent file is fine.
		if err != nil {
			_ = out.Close()
			_ = os.Remove(tmp)
		}
	}()

	manifest := backupManifest{
		Magic:        "simplesiem-backup",
		Version:      backupVersion,
		HostID:       backupHostID(cfg),
		Mode:         normaliseMode(cfg.Mode),
		Realm:        cfg.Server.Realm.Name,
		Platform:     runtime.GOOS,
		Arch:         runtime.GOARCH,
		SIEMVersion:  version,
		SIEMBuild:    buildNumber,
		CreatedAtUTC: time.Now().UTC(),
		Encrypted:    passphrase != "",
		Compressed:   compress,
		ConfigPath:   art.configPath,
		ConfigDir:    art.configDir,
		LogDir:       art.logDir,
		StateDir:     art.stateDir,
		RulesPath:    art.rulesPath,
		Note:         "events written after created_at_utc are NOT included; daemon was running during backup creation",
	}

	if werr := writeBackupEnvelope(out, manifest, art, passphrase, compress); werr != nil {
		return werr
	}
	if cerr := out.Close(); cerr != nil {
		return cerr
	}
	// Atomic rename. If outPath already exists, the rename overwrites
	// it in one syscall — so a previous backup file is never observed
	// in a partial state, and a rename failure here leaves the
	// previous file untouched.
	if rerr := os.Rename(tmp, outPath); rerr != nil {
		return rerr
	}
	// Success: defuse the cleanup defers by returning nil. The
	// `createdParents` rollback only runs when `err != nil`, so a
	// successful run keeps any directories we created.
	return nil
}

// mkdirAllTracking is os.MkdirAll plus a record of which directories
// it actually CREATED (vs which already existed). Used by the backup
// path so a failed run can roll back its own scaffolding without
// removing pre-existing operator-owned directories. Returns the list
// of newly-created paths in outermost-first order; rollback should
// reverse-iterate so leaves disappear before their parents.
func mkdirAllTracking(p string) ([]string, error) {
	if p == "" || p == "." {
		return nil, nil
	}
	created := []string{}
	chain := []string{}
	cur := p
	for {
		if _, err := os.Stat(cur); err == nil {
			break
		}
		chain = append(chain, cur)
		next := filepath.Dir(cur)
		if next == cur {
			break
		}
		cur = next
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if err := os.Mkdir(chain[i], 0o755); err != nil {
			if os.IsExist(err) {
				continue
			}
			return created, err
		}
		created = append(created, chain[i])
	}
	return created, nil
}

// writeBackupEnvelope writes the full file: header + (optional KDF
// material) + chunked AEAD-or-plain stream of (gzip-or-plain) tar.
//
// Layout of the envelope:
//
//	[ 6B magic       "SBAK1\0" ]
//	[ 1B flags       bit0=encrypted, bit1=compressed ]
//	[ when encrypted:
//	    [ 4B  KDF iterations BE ]
//	    [ 32B salt ]
//	    [ 12B nonce base ]
//	]
//	[ chunked frames... ]
//
// Each frame:
//
//	[ 4B BE length-with-final-bit ] (top bit = final frame)
//	[ length bytes ciphertext+tag (or plaintext when not encrypted) ]
//
// The "final" bit on the last frame's length detects truncation: a
// reader that runs out of frames without seeing the final bit knows
// the stream was cut short and refuses to decode the manifest.
func writeBackupEnvelope(w io.Writer, m backupManifest, art backupArtifact, passphrase string, compress bool) error {
	if _, err := io.WriteString(w, backupMagic); err != nil {
		return err
	}
	var flags byte
	if m.Encrypted {
		flags |= flagEncrypted
	}
	if compress {
		flags |= flagCompressed
	}
	if _, err := w.Write([]byte{flags}); err != nil {
		return err
	}

	var aead cipher.AEAD
	var nonceBase [backupNonceBas]byte
	if m.Encrypted {
		var salt [backupSaltSize]byte
		if _, err := rand.Read(salt[:]); err != nil {
			return err
		}
		if _, err := rand.Read(nonceBase[:]); err != nil {
			return err
		}
		var iterBuf [4]byte
		binary.BigEndian.PutUint32(iterBuf[:], backupKDFIters)
		if _, err := w.Write(iterBuf[:]); err != nil {
			return err
		}
		if _, err := w.Write(salt[:]); err != nil {
			return err
		}
		if _, err := w.Write(nonceBase[:]); err != nil {
			return err
		}
		key, err := pbkdf2.Key(sha512.New384, passphrase, salt[:], backupKDFIters, backupKDFKey)
		if err != nil {
			return fmt.Errorf("kdf: %w", err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return err
		}
	}

	// Build a writer chain that ends at the framing layer:
	//   tar -> [gzip] -> [aead frames] -> file
	// The frame writer is the OUTER layer (encrypts the gzip-of-tar).
	var frames *frameWriter
	if m.Encrypted {
		frames = newFrameWriter(w, aead, nonceBase)
	} else {
		frames = newFrameWriter(w, nil, [backupNonceBas]byte{})
	}

	var compressed io.WriteCloser
	if compress {
		gz, err := gzip.NewWriterLevel(frames, gzip.BestSpeed)
		if err != nil {
			return err
		}
		compressed = gz
	}

	tarSink := io.Writer(frames)
	if compressed != nil {
		tarSink = compressed
	}
	tw := tar.NewWriter(tarSink)

	if err := writeManifestEntry(tw, m); err != nil {
		return err
	}
	if err := writeArtifactEntries(tw, art); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if compressed != nil {
		if err := compressed.Close(); err != nil {
			return err
		}
	}
	return frames.Close()
}

func writeManifestEntry(tw *tar.Writer, m backupManifest) error {
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	hdr := &tar.Header{
		Name:    "manifest.json",
		Mode:    0o600,
		Size:    int64(len(body)),
		ModTime: m.CreatedAtUTC,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = tw.Write(body)
	return err
}

// writeArtifactEntries copies every relevant on-disk file into the
// tar. Tree mapping:
//
//	<configDir>      -> config/
//	<stateDir>       -> state/
//	<logDir>         -> logs/
//
// configPath and rulesPath are typically inside configDir but are
// included explicitly in case they live elsewhere (operator override).
// Duplicate entries are de-duped by relative path so a file inside
// configDir AND specifically named as configPath only appears once.
func writeArtifactEntries(tw *tar.Writer, art backupArtifact) error {
	seen := map[string]bool{}
	tasks := []struct {
		root   string
		prefix string
	}{
		{art.configDir, "config"},
		{art.stateDir, "state"},
		{art.logDir, "logs"},
	}
	for _, task := range tasks {
		if task.root == "" {
			continue
		}
		if err := walkIntoTar(tw, task.root, task.prefix, seen); err != nil {
			return err
		}
	}
	// Cover loose files that might live outside the directories above
	// (custom configPath, rulesPath at unusual locations).
	for _, p := range []string{art.configPath, art.rulesPath} {
		if p == "" {
			continue
		}
		// Only include if it's not already inside one of the trees walked above.
		if pathInsideAny(p, []string{art.configDir, art.stateDir, art.logDir}) {
			continue
		}
		archiveName := "loose/" + filepath.Base(p)
		if seen[archiveName] {
			continue
		}
		if err := writeFileEntry(tw, p, archiveName); err != nil && !os.IsNotExist(err) {
			return err
		}
		seen[archiveName] = true
	}
	return nil
}

func pathInsideAny(p string, roots []string) bool {
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	for _, r := range roots {
		if r == "" {
			continue
		}
		ar, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		if strings.HasPrefix(abs, ar+string(filepath.Separator)) || abs == ar {
			return true
		}
	}
	return false
}

func walkIntoTar(tw *tar.Writer, root, prefix string, seen map[string]bool) error {
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return writeFileEntry(tw, root, prefix+"/"+filepath.Base(root))
	}
	return filepath.Walk(root, func(path string, fi os.FileInfo, werr error) error {
		if werr != nil {
			// Tolerate transient read errors on individual files
			// (e.g. a log file rotated mid-walk). The backup still
			// completes; the missing file simply isn't included.
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		archiveName := prefix + "/" + filepath.ToSlash(rel)
		if seen[archiveName] {
			return nil
		}
		seen[archiveName] = true
		if fi.IsDir() {
			return tw.WriteHeader(&tar.Header{
				Name:    archiveName + "/",
				Mode:    0o700,
				ModTime: fi.ModTime(),
				Typeflag: tar.TypeDir,
			})
		}
		// Symlinks: archive the link target rather than chasing it.
		// Avoids loops and keeps the on-disk layout faithfully
		// reproducible on restore.
		if fi.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return nil
			}
			return tw.WriteHeader(&tar.Header{
				Name:     archiveName,
				Linkname: target,
				Mode:     int64(fi.Mode().Perm()),
				ModTime:  fi.ModTime(),
				Typeflag: tar.TypeSymlink,
			})
		}
		return writeFileEntry(tw, path, archiveName)
	})
}

func writeFileEntry(tw *tar.Writer, path, archiveName string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return nil
	}
	hdr := &tar.Header{
		Name:    archiveName,
		Mode:    int64(fi.Mode().Perm()),
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

// backupHostID picks the canonical identifier embedded in the manifest
// and used when naming auto-generated backup filenames. Mode-aware so
// a server's backup is named after its peer ID rather than just
// `os.Hostname` (which would collide when two servers in different
// realms happen to share a hostname).
func backupHostID(cfg Config) string {
	mode := normaliseMode(cfg.Mode)
	switch mode {
	case "agent":
		if cfg.Agent.ID != "" {
			return cfg.Agent.ID
		}
	case "server":
		if id := deriveSelfPeerID(cfg.Server.Listen); id != "" {
			return id
		}
	case "master":
		if cfg.Master.MasterID != "" {
			return cfg.Master.MasterID
		}
	case "collector":
		if cfg.Collector.CollectorID != "" {
			return cfg.Collector.CollectorID
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown-host"
}

// defaultBackupFilename returns a backup filename suitable for the
// `--out` default. Pattern: `simplesiem-backup-<host>-<utc>.siembak`.
// UTC is encoded as `20060102T150405Z` so the filename sorts
// chronologically and works on Windows (no colons).
func defaultBackupFilename(cfg Config) string {
	return fmt.Sprintf("simplesiem-backup-%s-%s.siembak",
		backupHostID(cfg),
		time.Now().UTC().Format("20060102T150405Z"))
}

// errBackupTruncated is returned by the frame reader when the stream
// ends without ever seeing a final-flagged frame. Surfaced to the
// operator so a partial backup never silently restores.
var errBackupTruncated = errors.New("backup is truncated (final-frame marker missing)")
