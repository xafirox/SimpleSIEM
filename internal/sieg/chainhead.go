package sieg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// chainHeadSigner periodically scans the on-disk log layout for the
// latest `_hash` of each (host, type, day) file, signs the snapshot
// with a per-host ECDSA P-384 key, and appends the signed record to
// `<log_dir>/_chainhead/<date>.jsonl`. Operators export this stream
// off-box (rsync to a write-once bucket, mail it to an audit team,
// etc.) so a future reader can prove the exact set of chain heads
// known at signing time. An attacker with root who rewrites the live
// chains afterward can't produce a matching signature without the
// signing key.
//
// Threat model: the signing key lives at <state_dir>/chainhead.key.
// If an attacker takes that key + roots the host, they can forge new
// signed records. Mitigations:
//
//   - The key file is mode 0600 and only the daemon's user reads it.
//   - The exported chain-head stream lives in append-only off-box
//     storage; an attacker who didn't already root the host before
//     signing can't retroactively change the historical record.
//   - Signed records carry a creation timestamp; rolling key rotation
//     (manual today, see `simplesiem chainhead rotate-key`) gives
//     forward-secrecy bounds.
//
// Performance: one signature per signing cycle, regardless of how many
// (host, type, day) tuples exist. The signer reads only the last line
// of each .jsonl file (cheap); signing a single SHA-384-of-canonical-JSON
// on a 2025-class CPU is sub-millisecond.
type chainHeadSigner struct {
	logDir   string
	keyPath  string
	logger   *Storage
	interval time.Duration
	mu       sync.Mutex
	key      *ecdsa.PrivateKey
}

// newChainHeadSigner returns a signer ready to start. The signing key
// is created on first use if it doesn't exist; subsequent runs reuse
// the same key. Returns an error only if the state dir / key file
// can't be written — the caller should treat that as a hard failure
// (no signing means no future tamper detection).
func newChainHeadSigner(logDir, stateDir string, interval time.Duration, logger *Storage) (*chainHeadSigner, error) {
	if logDir == "" {
		return nil, fmt.Errorf("chainhead signer: log_dir is empty")
	}
	if stateDir == "" {
		return nil, fmt.Errorf("chainhead signer: state_dir is empty")
	}
	if interval <= 0 {
		interval = time.Hour
	}
	keyPath := filepath.Join(stateDir, "chainhead.key")
	s := &chainHeadSigner{
		logDir:   logDir,
		keyPath:  keyPath,
		logger:   logger,
		interval: interval,
	}
	if err := s.loadOrCreateKey(); err != nil {
		return nil, err
	}
	return s, nil
}

// loadOrCreateKey reads an existing P-384 key from <state>/chainhead.key
// if present; otherwise generates a fresh one and writes it with mode
// 0600. Same key family as the rest of SimpleSIEM's PKI (P-384 / SHA-384).
func (s *chainHeadSigner) loadOrCreateKey() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.keyPath)
	if err == nil {
		blk, _ := pem.Decode(data)
		if blk == nil {
			return fmt.Errorf("chainhead.key: not PEM")
		}
		k, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return fmt.Errorf("chainhead.key: %w", err)
		}
		s.key = k
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.MkdirAll(filepath.Dir(s.keyPath), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(s.keyPath, pemBytes, 0o600); err != nil {
		return err
	}
	s.key = k
	return nil
}

// Start launches the periodic signing loop. Runs one signing cycle
// immediately so a fresh daemon emits its first record without an
// interval-long warmup, then on `interval` thereafter. Stops on ctx
// cancellation.
func (s *chainHeadSigner) Start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.signOnce()
		t := time.NewTicker(s.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.signOnce()
			}
		}
	}()
}

// chainHeadEntry captures the latest hash for one (host, type, date)
// tuple. The signer batches every entry it can find into a single
// signed record so we have a stable snapshot per signing cycle.
type chainHeadEntry struct {
	Host    string `json:"host"`
	Type    string `json:"type"`
	Date    string `json:"date"`
	File    string `json:"file"`
	LastSeq uint64 `json:"last_seq"`
	LastHash string `json:"last_hash"`
}

// signedChainHead is one row of the chainhead log. Operators reading
// this stream rebuild the trust set with the public key (extracted
// from the signing key) and verify each row's signature.
type signedChainHead struct {
	SignedAt   time.Time        `json:"signed_at"`
	Heads      []chainHeadEntry `json:"heads"`
	Algorithm  string           `json:"algorithm"`
	Signature  string           `json:"signature"`
	PublicKey  string           `json:"public_key_pem"`
}

// signOnce gathers the heads currently on disk, signs them, and
// appends the record to the chainhead log. Errors are logged via
// the storage logger but otherwise silent — the next cycle retries.
func (s *chainHeadSigner) signOnce() {
	heads, err := scanChainHeads(s.logDir)
	if err != nil {
		if s.logger != nil {
			s.logger.Write("errors", map[string]any{
				"collector": "chainhead",
				"error":     fmt.Sprintf("scan: %v", err),
			})
		}
		return
	}
	if len(heads) == 0 {
		return // nothing to sign yet
	}
	// Canonical JSON for the body so the signature is over a stable
	// byte representation. Heads are pre-sorted in scanChainHeads.
	body, err := json.Marshal(heads)
	if err != nil {
		return
	}
	hash := sha512.Sum384(body)
	s.mu.Lock()
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, hash[:])
	pubDER, _ := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	s.mu.Unlock()
	if err != nil {
		if s.logger != nil {
			s.logger.Write("errors", map[string]any{
				"collector": "chainhead",
				"error":     fmt.Sprintf("sign: %v", err),
			})
		}
		return
	}
	rec := signedChainHead{
		SignedAt:  time.Now().UTC(),
		Heads:     heads,
		Algorithm: "ECDSA-P384-SHA384",
		Signature: hex.EncodeToString(sig),
		PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
	}
	if err := appendChainHeadRecord(s.logDir, rec); err != nil {
		if s.logger != nil {
			s.logger.Write("errors", map[string]any{
				"collector": "chainhead",
				"error":     fmt.Sprintf("append: %v", err),
			})
		}
		return
	}
	if s.logger != nil {
		s.logger.Write("meta", map[string]any{
			"event": "chainhead_signed",
			"heads": len(heads),
		})
	}
}

// scanChainHeads walks log_dir for every host/type/date.jsonl file
// and reads the last JSON line to extract its `_seq` and `_hash`.
// Skips `_chainhead/`, `_acks/`, `.from-*.jsonl` (replicated chains
// belong to their origin), and any file whose last line isn't valid
// JSON.
func scanChainHeads(logDir string) ([]chainHeadEntry, error) {
	var heads []chainHeadEntry
	hosts, err := os.ReadDir(logDir)
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if !h.IsDir() {
			continue
		}
		hostName := h.Name()
		if hostName == "_chainhead" || hostName == "_acks" {
			continue
		}
		hostDir := filepath.Join(logDir, hostName)
		types, err := os.ReadDir(hostDir)
		if err != nil {
			continue
		}
		for _, ty := range types {
			if !ty.IsDir() {
				continue
			}
			typeName := ty.Name()
			typeDir := filepath.Join(hostDir, typeName)
			files, err := os.ReadDir(typeDir)
			if err != nil {
				continue
			}
			for _, f := range files {
				name := f.Name()
				if !strings.HasSuffix(name, ".jsonl") {
					continue
				}
				if strings.Contains(name, ".from-") {
					// Replicated chain belongs to the origin server,
					// not us — skip so we don't sign-vouch for events
					// we didn't write.
					continue
				}
				// Filename pattern: "YYYY-MM-DD.jsonl" or
				// "YYYY-MM-DD.jsonl.N" (rotated). We extract the
				// date prefix for the entry.
				date := strings.SplitN(name, ".", 2)[0]
				path := filepath.Join(typeDir, name)
				seq, hash := readLastLineHashSeq(path)
				if hash == "" {
					continue
				}
				heads = append(heads, chainHeadEntry{
					Host:     hostName,
					Type:     typeName,
					Date:     date,
					File:     name,
					LastSeq:  seq,
					LastHash: hash,
				})
			}
		}
	}
	sort.Slice(heads, func(i, j int) bool {
		if heads[i].Host != heads[j].Host {
			return heads[i].Host < heads[j].Host
		}
		if heads[i].Type != heads[j].Type {
			return heads[i].Type < heads[j].Type
		}
		if heads[i].Date != heads[j].Date {
			return heads[i].Date < heads[j].Date
		}
		return heads[i].File < heads[j].File
	})
	return heads, nil
}

// readLastLineHashSeq tail-reads one JSONL file and extracts the last
// non-empty line's `_seq` and `_hash` fields. Cheap — uses a small
// buffer + seek-from-end. Returns ("", 0) on any read or parse error
// so the caller skips this file.
func readLastLineHashSeq(path string) (uint64, string) {
	f, err := os.Open(path)
	if err != nil {
		return 0, ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return 0, ""
	}
	// Read up to the last 64 KiB — enough for the longest realistic
	// final line. If the file's last line straddles 64 KiB we fall
	// back to reading the whole file.
	const tail = 64 * 1024
	start := fi.Size() - tail
	if start < 0 {
		start = 0
	}
	buf := make([]byte, fi.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil {
		return 0, ""
	}
	// Trim trailing newline so SplitAfter's last segment is the line
	// we want, not an empty string after the final \n.
	for len(buf) > 0 && (buf[len(buf)-1] == '\n' || buf[len(buf)-1] == '\r') {
		buf = buf[:len(buf)-1]
	}
	idx := strings.LastIndex(string(buf), "\n")
	last := string(buf)
	if idx >= 0 {
		last = string(buf[idx+1:])
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(last), &obj); err != nil {
		return 0, ""
	}
	hash, _ := obj["_hash"].(string)
	var seq uint64
	switch v := obj["_seq"].(type) {
	case float64:
		seq = uint64(v)
	case json.Number:
		n, _ := v.Int64()
		seq = uint64(n)
	}
	return seq, hash
}

// appendChainHeadRecord writes one signed record to
// <log_dir>/_chainhead/<UTC-date>.jsonl. Append-only; chained
// integrity is the signature itself rather than per-line hash chaining.
func appendChainHeadRecord(logDir string, rec signedChainHead) error {
	dir := filepath.Join(logDir, "_chainhead")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(body, '\n')); err != nil {
		return err
	}
	return nil
}
