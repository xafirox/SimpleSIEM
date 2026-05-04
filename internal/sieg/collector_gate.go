package sieg

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// refuseInCollectorMode is the spec-mandated gate that prevents a
// collector from issuing realm / rule / config-change commands. The
// collector is supposed to be a passive replica — those operations
// flow from the associated master.
//
// Behaviour matrix:
//
//	cmd kind          collector + master reachable    collector + master DOWN
//	─────────────     ─────────────────────────────   ─────────────────────────
//	realm/rules/cfg   REFUSE always                   REFUSE always
//	read (query/tail) REFUSE                          ALLOW (failsafe)
//
// "Master DOWN" is a 2s TLS dial to the configured source URL —
// good enough for a CLI-time check; the operator runs the command
// in steady state, not during a flap. The failsafe applies only to
// READ commands so an operator chasing an outage on the collector
// has a way to pull recent events.
func refuseInCollectorMode(cfg Config, cmdKind string) {
	if normaliseMode(cfg.Mode) != "collector" {
		return
	}
	if cmdKind == "read" && !collectorSourceReachable(cfg) {
		// Failsafe path: emit a one-line note so the operator knows
		// they're running in degraded mode, then return without
		// refusing. The cmd proceeds.
		fmt.Fprintln(os.Stderr,
			"note: collector source unreachable; running this read-only command as failsafe.")
		return
	}
	what := "this command"
	switch cmdKind {
	case "realm":
		what = "realm changes"
	case "rules":
		what = "rule changes"
	case "config":
		what = "configuration changes"
	case "read":
		what = "queries"
	}
	fmt.Fprintf(os.Stderr, "refused: collector mode does not allow %s. "+
		"Run this command on the associated master / source server instead. "+
		"(Read-only commands are re-enabled automatically when the source is unreachable.)\n", what)
	os.Exit(2)
}

// collectorSourceReachable does a 2s TLS handshake against the
// collector's source URL using the per-source client cert. Returns
// true on a clean handshake; any error (timeout, TLS, network) is
// treated as "unreachable."
func collectorSourceReachable(cfg Config) bool {
	source := cfg.Collector.SourceURL
	if source == "" {
		return false
	}
	u, err := url.Parse(source)
	if err != nil {
		return false
	}
	host := u.Host
	if host == "" {
		return false
	}
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	certDir := filepath.Join(collectorCertsDir(cfg), peerIDFromURL(source))
	tlsCfg, err := loadMasterClientTLS(certDir)
	if err != nil {
		// No cert = can't dial = effectively unreachable.
		return false
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", host, tlsCfg)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
