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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// runCertsCmd dispatches the certs subcommands. The bundled PKI is meant
// for getting started; production deployments should use externally-issued
// certificates (replace the files at the configured paths).
//
//	simplesiem certs init               # one-time, on the server: CA + server cert + PSK
//	simplesiem certs server <hostname>  # re-issue the server cert
//	simplesiem certs psk <show|rotate>  # manage the enrollment PSK
//
// All certificates use ECDSA P-256 — small (~360 bytes per cert), fast,
// and well-supported by every TLS 1.2+ client. Agent enrollment is
// handled via PSK (`simplesiem convert agent --key <psk>` on the agent,
// or `--key` at install time); the agent generates its keypair locally
// and the server signs the CSR over the wire — no manual cert copy.
func runCertsCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `usage: simplesiem certs <init|server|psk|revoke|revoked|init-rotate|finalize-rotate|collector> [args]

  init                              Generate a new CA + auto-issue server cert + create enrollment PSK
  server <hostname> [more-hosts]    Issue or re-issue the server cert (SAN includes the hostnames + IPs)
  psk <show|rotate>                 Manage the enrollment PSK used by `+"`convert agent --key`"+`
  revoke <agent-id|master-cn>       Add a revocation tombstone (propagates via realm sync)
  revoked                           List currently revoked agents and masters
  init-rotate [--years N]           Generate a new CA, move the old one to legacy_cas, re-issue server cert
  finalize-rotate                   After all client certs have rotated to the new CA, remove the legacy CA
  collector <accept-next|revoke|status>
                                    Manage the single collector slot. accept-next opens the slot for the
                                    next /v1/enroll-collector request; revoke clears the current slot.

All commands write to the configured certs directory and refuse to clobber
existing files (delete them first if you really mean to regenerate).`)
		os.Exit(2)
	}
	switch args[0] {
	case "init":
		runCertsInit(args[1:])
	case "server":
		runCertsServer(args[1:])
	case "psk":
		runCertsPSK(args[1:])
	case "revoke":
		runCertsRevoke(args[1:])
	case "unrevoke":
		runCertsUnrevoke(args[1:])
	case "revoked":
		listRevoked(args[1:])
	case "init-rotate":
		runCertsInitRotate(args[1:])
	case "finalize-rotate":
		runCertsFinalizeRotate(args[1:])
	case "collector":
		runCertsCollectorCmd(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown certs subcommand: %s\n", args[0])
		os.Exit(2)
	}
}

func certsDir(cfgPath string) string {
	cfg := loadConfig(cfgPath)
	// Prefer the agent's CA path's directory if it's set; fall back to a
	// conventional <config_dir>/certs/.
	if cfg.Agent.CACert != "" {
		return filepath.Dir(cfg.Agent.CACert)
	}
	return filepath.Join(defaultConfigDir(), "certs")
}

// writePEM writes a PEM block to disk with mode 0600 for keys (which
// contain private material) and 0644 for certs. Refuses to overwrite.
func writePEM(path string, blockType string, der []byte, isKey bool) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; remove it first if you intend to regenerate", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if isKey {
		mode = 0o600
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func writeKeyPair(certPath, keyPath string, certDER []byte, key *ecdsa.PrivateKey) error {
	if err := writePEM(certPath, "CERTIFICATE", certDER, false); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		os.Remove(certPath)
		return err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, true); err != nil {
		os.Remove(certPath)
		return err
	}
	return nil
}

func newSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

// loadCAFromDisk reads ca.pem + ca.key. Used by certs server (manual
// re-issuance) and by /v1/enroll (agent CSR signing) to chain newly-issued
// certificates back to the bundled CA.
func loadCAFromDisk(certsDir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPath := filepath.Join(certsDir, "ca.pem")
	keyPath := filepath.Join(certsDir, "ca.key")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert (%s): %w — run `simplesiem certs init` first", certPath, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("CA cert is not PEM: %s", certPath)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key (%s): %w", keyPath, err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, fmt.Errorf("CA key is not PEM: %s", keyPath)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	caKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not ECDSA")
	}
	return caCert, caKey, nil
}

// certsValueFlags is the set of flag names that take a value. Used by
// permuteArgs so users can type flags after positionals ("certs server
// hostname --config X") and have the parser accept it.
var certsValueFlags = map[string]bool{"config": true, "years": true, "out": true}

func runCertsInit(args []string) {
	args = permuteArgs(args, certsValueFlags)
	fs := flag.NewFlagSet("certs init", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	years := fs.Int("years", 10, "CA validity in years")
	caOnly := fs.Bool("ca-only", false,
		"create only the CA; skip auto-issuing a server cert for this host")
	serverYears := fs.Int("server-years", 5, "validity of the auto-issued server cert (ignored with --ca-only)")
	_ = fs.Parse(args)

	if !*caOnly {
		// Full bootstrap path: ensureServerPKI generates whatever's
		// missing (CA, server cert, PSK) and leaves what's already in
		// place untouched. Operators get the same one-command setup
		// regardless of whether they're starting fresh or recovering
		// from a partial install.
		_, lines, err := ensureServerPKI(*cfgPath, *years, *serverYears)
		if err != nil {
			fatalf("bootstrap PKI: %v", err)
		}
		fmt.Println("Bootstrapped SimpleSIEM PKI:")
		for _, l := range lines {
			fmt.Println("  " + l)
		}
		fmt.Println()
		fmt.Println("Ready to start the daemon: sudo simplesiem start")
		fmt.Println()
		fmt.Println("On each agent host, run:")
		host := bestServerHostname()
		if psk, perr := readEnrollPSK(); perr == nil {
			fmt.Printf("  sudo simplesiem convert agent --server https://%s:9443 --key %s\n", host, psk)
		} else {
			fmt.Printf("  sudo simplesiem convert agent --server https://%s:9443 --key <PSK from above>\n", host)
		}
		fmt.Println()
		fmt.Println("Keep ca.key and the enrollment PSK on this host only.")
		return
	}

	// --ca-only: generate ONLY the CA (legacy behaviour for operators
	// with multi-host PKI plans who want to issue the server cert with
	// a custom hostname/IP set later).
	dir := certsDir(*cfgPath)
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fatalf("generate CA key: %v", err)
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "SimpleSIEM Root CA",
			Organization: []string{"SimpleSIEM"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(*years, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		fatalf("create CA cert: %v", err)
	}
	if err := writeKeyPair(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), der, caKey); err != nil {
		fatalf("write CA: %v", err)
	}
	fmt.Printf("CA generated:\n  cert: %s\n  key : %s (mode 0600 — keep secret)\n",
		filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))

	// Even in --ca-only mode the operator still needs the enrollment
	// PSK for agent association, so generate it here too.
	if psk, err := generateEnrollPSK(false); err == nil {
		fmt.Println()
		fmt.Printf("Enrollment PSK: %s\n", psk)
	}

	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  simplesiem certs server <hostname>     # before `simplesiem start`")
	fmt.Println("  simplesiem certs psk show              # paste this into agents' --key flag")
	fmt.Println()
	fmt.Println("Keep ca.key and the enrollment PSK on this host only — anyone with")
	fmt.Println("either can mint client certs / enroll new agents.")
}

func runCertsServer(args []string) {
	args = permuteArgs(args, certsValueFlags)
	fs := flag.NewFlagSet("certs server", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	years := fs.Int("years", 5, "cert validity in years")
	force := fs.Bool("force", false, "overwrite an existing server cert/key (replaces, doesn't merge SANs)")
	autoIPs := fs.Bool("auto-ips", true, "also include every non-loopback IP on this host's interfaces in the SAN; pass --auto-ips=false to issue only with the explicit args")
	_ = fs.Parse(args)

	if fs.NArg() == 0 {
		fatalf("usage: simplesiem certs server <hostname> [extra-hostname-or-ip ...]\n  pass --force to overwrite an existing cert\n  pass --auto-ips=false to omit auto-detected interface IPs")
	}
	hosts := fs.Args()
	if *autoIPs {
		// Include the loopback baseline (127.0.0.1 + localhost) too —
		// otherwise each refresh narrows the SAN list compared to what
		// `certs init` originally produced. Operators issuing `certs
		// server` to extend the SAN expect "add to" semantics, not
		// "shrink to whatever I typed."
		hosts = appendUniqueHosts(hosts, []string{"127.0.0.1", "localhost"})
		hosts = appendUniqueHosts(hosts, gatherLocalIPs())
	}
	dir := certsDir(*cfgPath)
	caCert, caKey, err := loadCAFromDisk(dir)
	if err != nil {
		fatalf("%v", err)
	}
	if *force {
		// User asked to overwrite. Remove existing files so the
		// no-clobber guard in writePEM doesn't fire.
		_ = os.Remove(filepath.Join(dir, "server.pem"))
		_ = os.Remove(filepath.Join(dir, "server.key"))
	}
	if err := issueServerCert(dir, caCert, caKey, *years, hosts); err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("Server cert issued for %s:\n  cert: %s\n  key : %s\n",
		strings.Join(hosts, ", "),
		filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
	fmt.Println()
	fmt.Println("The running server (if any) will hot-reload the new cert within ~1 second.")
	fmt.Println("Look for `tls_cert_reloaded` in <log_dir>/_server/meta to confirm.")
}

// ensureServerPKI generates the CA, the server cert, and the enrollment
// PSK if any are missing, in that order. Idempotent: missing pieces are
// created, existing pieces are left untouched. Used by `install --mode
// server` and `convert ... server` to make those one-shot commands
// instead of "install, then init, then start" rituals.
//
// Returns (createdAnything, displayLines, error). displayLines is what
// the caller should print to keep operator-facing output identical to
// the legacy `certs init`. Operators who prefer the staged flow can
// still run `certs init` directly.
func ensureServerPKI(cfgPath string, caYears, srvYears int) (bool, []string, error) {
	dir := certsDir(cfgPath)
	caPath := filepath.Join(dir, "ca.pem")
	caKeyPath := filepath.Join(dir, "ca.key")
	srvPath := filepath.Join(dir, "server.pem")
	srvKeyPath := filepath.Join(dir, "server.key")

	var lines []string
	createdAnything := false

	var caCert *x509.Certificate
	var caKey *ecdsa.PrivateKey

	// 1. CA: generate only when BOTH ca.pem and ca.key are absent.
	//    - Both present:   load existing — re-running into an in-use CA
	//      must NOT replace it; that would invalidate every agent cert
	//      in the field.
	//    - Both absent:    bootstrap fresh.
	//    - One without the other (PARTIAL state): orphaned. Move the
	//      lone file aside (preserved as <file>.orphaned.<UTC> for
	//      audit) and fall through to fresh bootstrap. Common after
	//      `convert agent -> server`: the agent's ca.pem is the OLD
	//      server's trust anchor, kept on disk after enrollment, but
	//      never had a matching ca.key on this host (agents don't own
	//      one). Without this branch, ensureServerPKI sees ca.pem and
	//      dies in `loadCAFromDisk` trying to read the absent ca.key,
	//      leaving the convert in the half-state the user reported.
	caCertErr := func() error { _, e := os.Stat(caPath); return e }()
	caKeyErr := func() error { _, e := os.Stat(caKeyPath); return e }()
	hasCert := caCertErr == nil
	hasKey := caKeyErr == nil
	if (hasCert && !os.IsNotExist(caKeyErr) && !hasKey) || (hasKey && !os.IsNotExist(caCertErr) && !hasCert) {
		// Real I/O error on the absent side (permission denied, etc.).
		// Don't paper over that.
		err := caKeyErr
		if hasKey {
			err = caCertErr
		}
		return false, nil, fmt.Errorf("stat CA: %w", err)
	}
	if hasCert != hasKey {
		// Partial state. Orphan one or the other.
		orphan := caPath
		if hasKey {
			orphan = caKeyPath
		}
		backup := orphan + ".orphaned." + time.Now().UTC().Format("20060102T150405Z")
		if err := os.Rename(orphan, backup); err != nil {
			return false, nil, fmt.Errorf("partial CA state (only %s present, no matching pair on disk); could not move orphan aside to %s: %w. Remove %s manually and retry, OR restore the missing matching file.", filepath.Base(orphan), backup, err, orphan)
		}
		lines = append(lines, fmt.Sprintf("orphan %s moved to %s (no matching key/cert pair — typically an agent->server conversion leftover; bootstrapping a fresh CA below)", filepath.Base(orphan), filepath.Base(backup)))
		hasCert, hasKey = false, false
	}

	if !hasCert {
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return false, nil, fmt.Errorf("generate CA key: %w", err)
		}
		serial, _ := newSerial()
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				CommonName:   "SimpleSIEM Root CA",
				Organization: []string{"SimpleSIEM"},
			},
			// 24h backdate (was -1h) so cross-platform deployments
			// where one host's clock is several hours off (typical in
			// a fleet that mixes hardware-clock-set-to-local-time
			// Windows VMs with UTC-based Linux VMs) don't trip "x509:
			// certificate has expired or is not yet valid" during
			// enrollment. Picks 24h because that's longer than any
			// realistic timezone skew without making the CA
			// retroactively trusted for a long pre-issuance window.
			NotBefore: time.Now().Add(-24 * time.Hour),
			NotAfter:  time.Now().AddDate(caYears, 0, 0),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			return false, nil, fmt.Errorf("create CA cert: %w", err)
		}
		if err := writeKeyPair(caPath, caKeyPath, der, k); err != nil {
			return false, nil, fmt.Errorf("write CA: %w", err)
		}
		caCert, _ = x509.ParseCertificate(der)
		caKey = k
		createdAnything = true
		lines = append(lines, fmt.Sprintf("CA generated: %s (key 0600)", caPath))
	} else {
		c, k, err := loadCAFromDisk(dir)
		if err != nil {
			return false, nil, fmt.Errorf("load existing CA: %w", err)
		}
		caCert, caKey = c, k
	}

	// 2. Server cert: generate if absent. Auto-include hostname +
	//    127.0.0.1 + localhost + every non-loopback interface IP so
	//    agents can dial by hostname OR IP without re-issuance.
	if _, err := os.Stat(srvPath); err != nil {
		if !os.IsNotExist(err) {
			return createdAnything, lines, fmt.Errorf("stat server cert: %w", err)
		}
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "localhost"
		}
		hosts := []string{hostname, "127.0.0.1"}
		if hostname != "localhost" {
			hosts = append(hosts, "localhost")
		}
		ips := gatherLocalIPs()
		hosts = appendUniqueHosts(hosts, ips)
		// Reverse-DNS any local IP that resolves back to a different
		// name. Catches the common case where an operator dials the
		// server by a DNS hostname different from `hostname` itself
		// (e.g. `servers1r1.lan` while `hostname` reports `s1r1`).
		// Without this, the agent's preflight rejects the convert
		// with a SAN-drift error and the operator has to manually
		// re-issue the cert. Best-effort: lookup failures are ignored.
		hosts = appendUniqueHosts(hosts, gatherDNSAliases(ips))
		if err := issueServerCert(dir, caCert, caKey, srvYears, hosts); err != nil {
			return createdAnything, lines, fmt.Errorf("issue server cert: %w", err)
		}
		createdAnything = true
		lines = append(lines, fmt.Sprintf("server cert auto-issued for: %s", strings.Join(hosts, ", ")))
	}
	_ = srvKeyPath // kept for symmetry / future stat checks

	// 3. PSK: generate only if absent. Existing PSK is preserved
	//    across re-runs so a partially-completed install doesn't
	//    silently invalidate the value an operator already pasted
	//    into agent commands.
	psk, err := readEnrollPSK()
	if err != nil {
		newPSK, gerr := generateEnrollPSK(false)
		if gerr != nil {
			return createdAnything, lines, fmt.Errorf("generate PSK: %w", gerr)
		}
		psk = newPSK
		createdAnything = true
		lines = append(lines, fmt.Sprintf("enrollment PSK generated: %s", psk))
	} else {
		lines = append(lines, fmt.Sprintf("enrollment PSK (existing): %s", psk))
	}

	return createdAnything, lines, nil
}

// gatherLocalIPs returns every IP address on this host's interfaces that
// makes sense to put in a server cert's SAN: skips loopback (already
// covered explicitly), link-local (fe80::/10, 169.254.0.0/16), and
// any address on a down interface. Both IPv4 and IPv6 are included.
//
// Without this, an operator running `certs init` on a multi-homed
// host gets a cert that only covers the local hostname. Agents
// dialing the server by its LAN IP / Docker bridge IP / VPC IP all
// fail TLS with a confusing SAN-mismatch error. Auto-including local
// IPs trades a slightly larger SAN list for a workflow that "just
// works" in the most common deployment shapes.
func gatherLocalIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out
}

// bestServerHostname returns the most operator-friendly name for this
// host to print in "convert agent --server https://<host>:9443" hints.
// Prefers a non-loopback IPv4 address (works without DNS), then a
// non-loopback IPv6 wrapped in brackets, then os.Hostname(), then
// the literal "this-server" placeholder.
//
// Cross-platform: uses only net.Interfaces() and os.Hostname() from
// the Go standard library — no platform-specific dependencies.
func bestServerHostname() string {
	ips := gatherLocalIPs()
	// Prefer IPv4 — operators paste these into commands more often
	// and they're shorter / fit in terminal output without wrapping.
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			return ip
		}
	}
	// IPv6 fallback: bracket per RFC 3986 so the URL parses correctly.
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil {
			return "[" + ip + "]"
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "this-server"
}

// extendServerCertSAN re-issues the server cert with addedHost added
// to its SAN list, preserving every existing entry. Returns true when
// the cert was actually re-issued (false when addedHost was already
// covered or invalid). The hot-reloader's poll loop picks up the new
// file within ~1 second, so the listener accepts the new SAN without
// a daemon restart.
//
// Key + cert are atomically swapped (key first, then cert) — same
// ordering as rotateClientCert — so a crash mid-write never leaves
// a new cert paired with the old key.
//
// Used by handleEnroll's SNI-driven SAN auto-extension: when an
// operator dials the server by a hostname not yet in the cert (e.g.
// a docker service name or DNS alias), the agent's enrollment alone
// is enough to teach the server about the new name. The PSK gates
// the request, so only authorised callers can drift the SAN.
func extendServerCertSAN(certsDir, addedHost string) (bool, error) {
	addedHost = strings.TrimSpace(addedHost)
	if addedHost == "" {
		return false, nil
	}
	// Reject anything that doesn't look like a hostname / IP literal.
	// Hostnames go through validHostName; IPs are passed straight to
	// net.ParseIP. This blocks a compromised PSK from injecting paths,
	// query strings, or wildcards.
	isIP := net.ParseIP(addedHost) != nil
	if !isIP && !validHostName.MatchString(addedHost) {
		return false, fmt.Errorf("invalid SAN entry %q", addedHost)
	}
	srvPath := filepath.Join(certsDir, "server.pem")
	srvKeyPath := filepath.Join(certsDir, "server.key")
	pemData, err := os.ReadFile(srvPath)
	if err != nil {
		return false, fmt.Errorf("read server cert: %w", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return false, fmt.Errorf("server cert is not PEM")
	}
	cur, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse server cert: %w", err)
	}
	// Already covered? No-op.
	if isIP {
		newIP := net.ParseIP(addedHost)
		for _, ip := range cur.IPAddresses {
			if ip.Equal(newIP) {
				return false, nil
			}
		}
	} else {
		for _, dns := range cur.DNSNames {
			if strings.EqualFold(dns, addedHost) {
				return false, nil
			}
		}
	}
	// Build the new SAN list = current ∪ {addedHost}. Cap at 64 entries
	// so a leaked PSK can't grow the cert without bound.
	hosts := make([]string, 0, len(cur.DNSNames)+len(cur.IPAddresses)+1)
	hosts = append(hosts, cur.DNSNames...)
	for _, ip := range cur.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	hosts = append(hosts, addedHost)
	if len(hosts) > 64 {
		return false, fmt.Errorf("server cert SAN already at the 64-entry limit; refusing to grow further")
	}
	caCert, caKey, err := loadCAFromDisk(certsDir)
	if err != nil {
		return false, fmt.Errorf("load CA: %w", err)
	}
	srvKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return false, fmt.Errorf("generate key: %w", err)
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"SimpleSIEM"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		// Match the original cert's NotAfter so SAN extension doesn't
		// reset the validity window unexpectedly.
		NotAfter:    cur.NotAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return false, fmt.Errorf("sign cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(srvKey)
	if err != nil {
		return false, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	// Key first so a crash never pairs new cert with old key.
	if err := atomicWriteFile(srvKeyPath, keyPEM, 0o600); err != nil {
		return false, fmt.Errorf("write key: %w", err)
	}
	if err := atomicWriteFile(srvPath, certPEM, 0o644); err != nil {
		return false, fmt.Errorf("write cert: %w", err)
	}
	return true, nil
}

// gatherDNSAliases reverse-resolves each interface IP and returns
// every distinct DNS name the OS reports. Skips the trailing dot
// from FQDNs (`host.example.com.` → `host.example.com`) and rejects
// anything that doesn't look like a hostname (numeric IPs, empty
// strings).
//
// Best-effort: a lookup failure on any IP is silently skipped. The
// result is appended to the cert's SAN so an agent dialing the
// server by any of its DNS names completes TLS without operator
// intervention.
func gatherDNSAliases(ips []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, ip := range ips {
		names, err := net.LookupAddr(ip)
		if err != nil {
			continue
		}
		for _, n := range names {
			n = strings.TrimRight(n, ".")
			if n == "" {
				continue
			}
			// Skip the IP literal itself (LookupAddr can echo it on some platforms).
			if net.ParseIP(n) != nil {
				continue
			}
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	return out
}

// appendUniqueHosts merges add into base, skipping any value already
// present (case-sensitive — IP literals are case-sensitive anyway, and
// hostnames in our config land cased exactly as the operator typed).
func appendUniqueHosts(base, add []string) []string {
	seen := map[string]struct{}{}
	for _, h := range base {
		seen[h] = struct{}{}
	}
	for _, h := range add {
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		base = append(base, h)
	}
	return base
}

// issueServerCert mints a server cert for the listed hostnames+IPs and
// writes server.{pem,key} into dir. Refuses to clobber an existing
// server.pem so a re-run of `certs init` doesn't silently invalidate
// the operator's current cert. Used by both `certs server` (operator-
// driven) and `certs init` (auto-issue for the local host).
func issueServerCert(dir string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, years int, hosts []string) error {
	if len(hosts) == 0 {
		return fmt.Errorf("at least one hostname required")
	}
	srvKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serial, _ := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"SimpleSIEM"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(years, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		// Both ServerAuth and ClientAuth: this cert is used as the
		// listener's TLS server cert AND, in realm mode, as the
		// client cert when this server pulls events from peer servers
		// via /v1/sync/events. Without ClientAuth a peer's mTLS
		// handshake rejects the connection with "tls: bad certificate".
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("sign server cert: %w", err)
	}
	return writeKeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"), der, srvKey)
}


// allowlistEditMu serialises read-modify-write cycles on config.json's
// agent_allowlist. /v1/enroll can be hit by multiple agents at once;
// without this, two concurrent enrollments race the load/append/save
// and one wins, dropping the other's ID. Process-local is sufficient
// because there's only ever one server process editing the file.
var allowlistEditMu sync.Mutex

// addAgentToAllowlist atomically appends id to server.agent_allowlist
// in config.json, preserving the previous file as .bak. Returns true if
// the ID was newly added, false if it was already present. Uses
// loadConfig + saveConfig (defined in convert.go) so the round-trip is
// the same logic as `simplesiem convert`.
func addAgentToAllowlist(cfgPath, id string) (bool, error) {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	for _, x := range cfg.Server.AgentAllowlist {
		if x == id {
			return false, nil
		}
	}
	cfg.Server.AgentAllowlist = append(cfg.Server.AgentAllowlist, id)
	if err := saveConfig(cfgPath, cfg); err != nil {
		return false, err
	}
	return true, nil
}

// mergeAllowlistInConfig is the bulk variant used by realm sync. It
// unions the inbound id list with the existing allowlist atomically.
// Same global mutex other allowlist edits use, so concurrent updates
// don't lose entries.
func mergeAllowlistInConfig(cfgPath string, ids []string) error {
	allowlistEditMu.Lock()
	defer allowlistEditMu.Unlock()
	cfg := loadConfig(cfgPath)
	have := map[string]bool{}
	for _, x := range cfg.Server.AgentAllowlist {
		have[x] = true
	}
	added := false
	for _, id := range ids {
		if id == "" || have[id] {
			continue
		}
		cfg.Server.AgentAllowlist = append(cfg.Server.AgentAllowlist, id)
		have[id] = true
		added = true
	}
	if !added {
		return nil
	}
	return saveConfig(cfgPath, cfg)
}
