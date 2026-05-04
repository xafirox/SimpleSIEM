package sieg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CA rotation: replace the server's signing CA without "stop the
// world, re-enroll every agent". Three operator commands form the
// flow:
//
//   1. simplesiem certs init-rotate [--years N]
//
//      Generates a new CA, moves the existing ca.pem to
//      <state>/legacy_cas/<timestamp>.pem (cert only — the OLD CA's
//      private key is destroyed), installs the new CA at the
//      configured ca.pem path, re-issues the server cert under the
//      new CA, and propagates the legacy CA cert to realm peers via
//      the existing /v1/sync/config trust bundle. Agents pick up
//      both CAs in the heartbeat bundle so handshakes against either
//      old- or new-CA-signed peers continue to work.
//
//      All client certs in the field are still trusted (legacy CA in
//      the bundle), but newly-issued certs (auto-rotation, fresh
//      enrollment, master enroll) are signed by the new CA.
//
//   2. Wait. Auto-rotation gradually replaces every client cert
//      with a new-CA-signed one. The threshold defaults to 30 days,
//      so within ~5y the entire fleet has rotated naturally. To
//      force the migration, an operator can set
//      `agent.cert_rotation_days` very low temporarily so existing
//      certs hit the threshold and rotate on the next heartbeat.
//
//   3. simplesiem certs finalize-rotate
//
//      Once every client cert chains to the new CA, removes the
//      legacy CA from <state>/legacy_cas/. After this, certs that
//      still chain to the old CA stop validating — finalizing too
//      early kicks orphan agents off the cluster. The command lists
//      pending old-CA certs detected on disk before deleting and
//      asks for confirmation.

// runCertsInitRotate is `simplesiem certs init-rotate`. Thin operator
// wrapper around performCARotation — the latter is also called by the
// server-side handler for /v1/master/rotate-ca so a master can trigger
// the same flow remotely.
func runCertsInitRotate(args []string) {
	fs := flag.NewFlagSet("certs init-rotate", flag.ExitOnError)
	years := fs.Int("years", 10, "validity of the new CA in years")
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}

	cfg := loadConfig(*cfgPath)
	if cfg.Server.CACert == "" {
		fatalf("server.ca_cert is empty in %s — run `simplesiem certs init` first", *cfgPath)
	}
	caPath := cfg.Server.CACert
	if _, err := os.Stat(caPath); err != nil {
		fatalf("read existing CA %s: %v", caPath, err)
	}

	fmt.Println("CA rotation:")
	fmt.Printf("  current CA:    %s\n", caPath)
	fmt.Printf("  legacy archive: %s/<timestamp>.pem (cert only — key destroyed)\n", legacyCAsDir())
	fmt.Printf("  new CA:        %s (validity %d years)\n", caPath, *years)
	fmt.Println()
	fmt.Println("After this:")
	fmt.Println("  - existing client certs still validate via the legacy CA in the trust bundle")
	fmt.Println("  - new enrollments and rotations sign against the new CA")
	fmt.Println("  - legacy CA propagates to realm peers via the next /v1/sync/config cycle")
	fmt.Println("  - run `simplesiem certs finalize-rotate` after all clients have rotated to remove the legacy CA")
	fmt.Println()
	if !*yes {
		if !confirmYes() {
			fmt.Println("aborted.")
			return
		}
	}
	res, err := performCARotation(cfg, *years)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("archived old CA cert: %s\n", res.LegacyArchivedTo)
	fmt.Printf("installed new CA: %s\n", res.NewCAPath)
	fmt.Printf("re-issued server cert: %s (signed by new CA)\n", cfg.Server.Cert)
	fmt.Println()
	fmt.Println("CA rotation complete on this server.")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Restart the daemon to pick up the new CA + re-issued server cert:")
	fmt.Println("     sudo simplesiem stop && sudo simplesiem start")
	fmt.Println("  2. Realm peers learn about the legacy CA on the next /v1/sync/config cycle")
	fmt.Println("     (default 60s) and add it to their trust bundle automatically.")
	fmt.Println("  3. Wait for client certs to auto-rotate (default threshold 30 days before expiry)")
	fmt.Println("     OR force migration by lowering agent.cert_rotation_days temporarily.")
	fmt.Println("  4. Once every client has rotated, run:")
	fmt.Println("     sudo simplesiem certs finalize-rotate")
}

// CARotationResult is the structured return of performCARotation,
// surfaced both to the operator CLI and to the master-triggered
// HTTP handler.
type CARotationResult struct {
	NewCAPath        string `json:"new_ca_path"`
	LegacyArchivedTo string `json:"legacy_archived_to"`
	RotatedAt        string `json:"rotated_at"`
	ServerCertPath   string `json:"server_cert_path"`
}

// lastCARotationPath returns the on-disk file that records the most
// recent CA rotation timestamp. Master catchup reads this via
// /v1/master/ca-status to decide whether a server is behind the
// realm's rotation policy. Decoupled from the cert's NotBefore
// (which is backdated 1h for clock-skew tolerance) so policy
// comparison is exact.
func lastCARotationPath() string {
	return filepath.Join(defaultStateDir(), "last_ca_rotation")
}

// readLastCARotation returns the RFC3339 string written by the most
// recent rotation, or "" if the file is missing (server has never
// rotated since install).
func readLastCARotation() string {
	data, err := os.ReadFile(lastCARotationPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// performCARotation does the actual rotation work: archive the old
// CA cert, generate a new keypair, install it, re-issue the server
// cert. Returns paths so callers can render confirmation. Used by
// both the operator CLI (`certs init-rotate`) and the master-driven
// /v1/master/rotate-ca handler.
func performCARotation(cfg Config, years int) (CARotationResult, error) {
	var zero CARotationResult
	caPath := cfg.Server.CACert
	caKeyPath := caPathToKeyPath(caPath)
	oldCertPem, err := os.ReadFile(caPath)
	if err != nil {
		return zero, fmt.Errorf("read CA cert: %w", err)
	}
	if err := os.MkdirAll(legacyCAsDir(), 0o750); err != nil {
		return zero, fmt.Errorf("create legacy_cas dir: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	legacyPath := filepath.Join(legacyCAsDir(), "old-"+stamp+".pem")
	if err := os.WriteFile(legacyPath, oldCertPem, 0o644); err != nil {
		return zero, fmt.Errorf("write legacy cert: %w", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return zero, fmt.Errorf("generate CA key: %w", err)
	}
	if years <= 0 {
		years = 10
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "SimpleSIEM CA (rotated " + stamp + ")", Organization: []string{"SimpleSIEM"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(years, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return zero, fmt.Errorf("create new CA cert: %w", err)
	}
	newCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return zero, fmt.Errorf("marshal CA key: %w", err)
	}
	newKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := atomicWriteFile(caPath, newCertPem, 0o644); err != nil {
		return zero, fmt.Errorf("write new CA cert: %w", err)
	}
	if err := atomicWriteFile(caKeyPath, newKeyPem, 0o600); err != nil {
		return zero, fmt.Errorf("write new CA key: %w", err)
	}
	if err := reissueServerCertUnderCurrentCA(cfg); err != nil {
		return zero, fmt.Errorf("re-issue server cert: %w (the new CA is in place; recover with `simplesiem certs server <hostname> --force`)", err)
	}
	rotatedAt := time.Now().UTC().Format(time.RFC3339)
	// Persist the rotation timestamp so master catchup can compare
	// against its policy without depending on the cert's backdated
	// NotBefore field. Best-effort: a write failure here doesn't
	// abort the rotation (the rotation itself was successful), the
	// next rotation will write the file again.
	_ = os.MkdirAll(filepath.Dir(lastCARotationPath()), 0o750)
	_ = atomicWriteFile(lastCARotationPath(), []byte(rotatedAt), 0o644)
	return CARotationResult{
		NewCAPath:        caPath,
		LegacyArchivedTo: legacyPath,
		RotatedAt:        rotatedAt,
		ServerCertPath:   cfg.Server.Cert,
	}, nil
}

// performCAFinalize is the reusable core of finalize-rotate, used by
// both the operator CLI and the master-triggered handler. Removes
// every legacy CA file under <state>/legacy_cas/, returns the count
// removed.
func performCAFinalize() (int, error) {
	dir := legacyCAsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read legacy_cas dir: %w", err)
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
			removed++
		}
	}
	return removed, nil
}

// reissueServerCertUnderCurrentCA generates a new server cert from
// the (now-rotated) CA on disk, preserving the existing SAN list. It
// reuses runCertsServer's logic by invoking it with --force and the
// list of SANs derived from the current cert.
func reissueServerCertUnderCurrentCA(cfg Config) error {
	certPath := cfg.Server.Cert
	if certPath == "" {
		return fmt.Errorf("server.cert is empty in config")
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read existing server cert: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("server cert is not a PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse existing server cert: %w", err)
	}
	hosts := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	if cn := cert.Subject.CommonName; cn != "" {
		// CN as the first SAN entry — runCertsServer treats argv[0]
		// as the CN; the rest extend the SAN list.
		first := []string{cn}
		for _, h := range hosts {
			if h == cn {
				continue
			}
			first = append(first, h)
		}
		hosts = first
	}
	if len(hosts) == 0 {
		hostname, _ := os.Hostname()
		hosts = []string{hostname}
	}
	args := append([]string{}, hosts...)
	args = append(args, "--force")
	runCertsServer(args)
	return nil
}

// runCertsFinalizeRotate is `simplesiem certs finalize-rotate`. Removes
// every legacy CA from <state>/legacy_cas/ after operator confirmation.
// Refuses if there are no legacy CAs (nothing to do) or, optionally,
// if any client cert it sees would stop validating — that check is
// best-effort because the daemon doesn't keep a global cert registry.
func runCertsFinalizeRotate(args []string) {
	fs := flag.NewFlagSet("certs finalize-rotate", flag.ExitOnError)
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	_ = fs.Parse(args)
	if !isAdmin() {
		fatalf("must run as admin (sudo on unix; Administrator on Windows)")
	}
	dir := legacyCAsDir()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		fmt.Println("No legacy CAs to remove. Nothing to do.")
		return
	}
	fmt.Println("Legacy CAs scheduled for removal:")
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fmt.Printf("  %s\n", filepath.Join(dir, e.Name()))
	}
	fmt.Println()
	fmt.Println("Removing these means client certs that still chain to the old CA will")
	fmt.Println("stop validating. Verify with `simplesiem verify -v --all` and check the")
	fmt.Println("agent fleet's heartbeat health before proceeding.")
	fmt.Println()
	if !*yes {
		if !confirmYes() {
			fmt.Println("aborted.")
			return
		}
	}
	removed, err := performCAFinalize()
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("Removed %d legacy CA(s).\n", removed)
	fmt.Println()
	fmt.Println("Realm peers learn about the removal on the next /v1/sync/config cycle.")
	fmt.Println("Restart the daemon to drop the legacy CA from the live trust bundle:")
	fmt.Println("  sudo simplesiem stop && sudo simplesiem start")
}

// caPathToKeyPath returns the conventional sibling .key path for a
// given CA cert path (e.g. /etc/simplesiem/certs/ca.pem →
// /etc/simplesiem/certs/ca.key).
func caPathToKeyPath(certPath string) string {
	dir := filepath.Dir(certPath)
	base := filepath.Base(certPath)
	if len(base) >= 4 && base[len(base)-4:] == ".pem" {
		return filepath.Join(dir, base[:len(base)-4]+".key")
	}
	return certPath + ".key"
}
