package sieg

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// runChainHeadCmd dispatches `simplesiem chainhead <verify|...>`.
// The signing loop runs inside the daemon (chainhead.go); this CLI
// is the operator-side reader for the published stream.
func runChainHeadCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem chainhead <verify|show> [flags]

  verify [--in <dir>]   Re-verify every signed record in
                        <log_dir>/_chainhead/ against its embedded
                        public key. Reports tampered or unsigned
                        records and exits non-zero on any failure.
                        Use to confirm a backup of the chainhead
                        stream is internally consistent.
  show [--in <dir>]     Print one human-readable line per signed
                        record (signed_at, head count, signing key
                        fingerprint).`)
		os.Exit(2)
	}
	switch args[0] {
	case "verify":
		runChainHeadVerify(args[1:])
	case "show":
		runChainHeadShow(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown chainhead subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func runChainHeadVerify(args []string) {
	fs := flag.NewFlagSet("chainhead verify", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	in := fs.String("in", "", "directory holding signed records (default: <log_dir>/_chainhead/)")
	_ = fs.Parse(args)
	dir := *in
	if dir == "" {
		cfg := loadConfig(*cfgPath)
		dir = filepath.Join(cfg.LogDir, "_chainhead")
	}
	files, err := chainHeadFiles(dir)
	if err != nil {
		fatalf("read chainhead dir: %v", err)
	}
	if len(files) == 0 {
		fmt.Println("No signed records found in", dir)
		return
	}
	totalRecords := 0
	totalHeads := 0
	failures := 0
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			fmt.Printf("FAIL  open %s: %v\n", path, err)
			failures++
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			totalRecords++
			var rec signedChainHead
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				fmt.Printf("FAIL  %s:%d invalid JSON\n", path, lineNo)
				failures++
				continue
			}
			pub, err := parsePublicKeyPEM(rec.PublicKey)
			if err != nil {
				fmt.Printf("FAIL  %s:%d public key: %v\n", path, lineNo, err)
				failures++
				continue
			}
			body, err := json.Marshal(rec.Heads)
			if err != nil {
				fmt.Printf("FAIL  %s:%d marshal heads: %v\n", path, lineNo, err)
				failures++
				continue
			}
			hash := sha512.Sum384(body)
			sigBytes, err := hex.DecodeString(rec.Signature)
			if err != nil {
				fmt.Printf("FAIL  %s:%d signature decode: %v\n", path, lineNo, err)
				failures++
				continue
			}
			if !ecdsa.VerifyASN1(pub, hash[:], sigBytes) {
				fmt.Printf("FAIL  %s:%d signature does NOT verify\n", path, lineNo)
				failures++
				continue
			}
			totalHeads += len(rec.Heads)
		}
		f.Close()
	}
	fmt.Printf("\nchainhead verify: %d records, %d total head entries, %d failures\n",
		totalRecords, totalHeads, failures)
	if failures > 0 {
		os.Exit(1)
	}
}

func runChainHeadShow(args []string) {
	fs := flag.NewFlagSet("chainhead show", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	in := fs.String("in", "", "directory holding signed records (default: <log_dir>/_chainhead/)")
	_ = fs.Parse(args)
	dir := *in
	if dir == "" {
		cfg := loadConfig(*cfgPath)
		dir = filepath.Join(cfg.LogDir, "_chainhead")
	}
	files, err := chainHeadFiles(dir)
	if err != nil {
		fatalf("read chainhead dir: %v", err)
	}
	if len(files) == 0 {
		fmt.Println("No signed records found in", dir)
		return
	}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			fmt.Printf("error opening %s: %v\n", path, err)
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for sc.Scan() {
			var rec signedChainHead
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				continue
			}
			pubFp := publicKeyFingerprint(rec.PublicKey)
			fmt.Printf("%s  heads=%-3d  alg=%s  pubkey=%s\n",
				rec.SignedAt.Format("2006-01-02 15:04:05Z"),
				len(rec.Heads), rec.Algorithm, pubFp)
		}
		f.Close()
	}
}

// chainHeadFiles returns a sorted list of *.jsonl files inside dir.
func chainHeadFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".jsonl") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// parsePublicKeyPEM decodes a PKIX-encoded ECDSA public key from PEM.
func parsePublicKeyPEM(s string) (*ecdsa.PublicKey, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return nil, fmt.Errorf("not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key")
	}
	return ec, nil
}

// publicKeyFingerprint returns a short SHA-384 hex of the PEM body
// for use as a human-readable signing key identifier in `show`.
func publicKeyFingerprint(pemStr string) string {
	blk, _ := pem.Decode([]byte(pemStr))
	if blk == nil {
		return "?"
	}
	sum := sha512.Sum384(blk.Bytes)
	return hex.EncodeToString(sum[:8])
}
