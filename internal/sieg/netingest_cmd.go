package sieg

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// stdLookupAddr indirection so tests can stub it cleanly.
var stdLookupAddr = net.LookupAddr

// CLI surface for the network-ingest allowlist:
//
//   simplesiem network-source add --ip <ip> [--vendor <id>] [--label X] [--no-tls]
//   simplesiem network-source list [--stale-only]
//   simplesiem network-source remove --ip <ip> [--mac <mac>] [--force]
//   simplesiem network-source rename --ip <ip> [--mac <mac>] --label <label>
//   simplesiem network-source revalidate
//   simplesiem network-source resync
//   simplesiem network-source vendors
//
// All mutating commands refuse on agent / standalone / collector
// modes. On a server with a master enrolled (cfg.Server.MasterCNs
// populated), edits are accepted locally AND queued for the master
// to fan out. On a master, edits push to every server in
// cfg.Master.Servers that has master_can_push_allowlist=true.

func runNetworkSourceCmd(args []string) {
	if len(args) == 0 {
		networkSourceUsage()
		os.Exit(2)
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "add":
		runNetworkSourceAdd(rest)
	case "list":
		runNetworkSourceList(rest)
	case "remove":
		runNetworkSourceRemove(rest)
	case "rename":
		runNetworkSourceRename(rest)
	case "revalidate":
		runNetworkSourceRevalidate(rest)
	case "resync":
		runNetworkSourceResync(rest)
	case "vendors":
		runNetworkSourceVendors(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown network-source subcommand: %s\n", sub)
		networkSourceUsage()
		os.Exit(2)
	}
}

func networkSourceUsage() {
	fmt.Fprintln(os.Stderr, `usage: simplesiem network-source <subcommand>

  add --ip <ip> [--vendor <id>] [--label "..."] [--no-tls]
       Add a manual entry. ARP-resolves the IP to capture its MAC.
  list [--stale-only]
       Show the allowlist (entry per row).
  remove --ip <ip> [--mac <mac>] [--force]
       Delete an entry. --force needed for gateway entries.
  rename --ip <ip> [--mac <mac>] --label "<label>"
       Update an entry's human-facing label.
  revalidate
       Re-ARP every entry; flag missing/changed MACs as stale.
  resync
       Pull the canonical allowlist from the authority (master or
       realm peer set) and reconcile to the higher version.
  vendors
       Print the bundled vendor catalog (TLS posture per vendor).`)
}

func runNetworkSourceAdd(args []string) {
	args = permuteArgs(args, map[string]bool{"ip": true, "mac": true, "vendor": true, "label": true})
	fs := flag.NewFlagSet("network-source add", flag.ExitOnError)
	ip := fs.String("ip", "", "IPv4 address of the device")
	macFlag := fs.String("mac", "", "(optional) MAC address; if absent we ARP-resolve")
	vendor := fs.String("vendor", "", "vendor ID; see `network-source vendors`")
	label := fs.String("label", "", "human-facing label (default: rDNS)")
	noTLS := fs.Bool("no-tls", false, "skip auto-setting tls_required (refused for vendors that mandate it)")
	_ = fs.Parse(args)
	if *ip == "" {
		fatalf("--ip is required")
	}
	if *vendor == "" {
		fmt.Fprintln(os.Stderr, "--vendor is required. Use one of:")
		for _, id := range vendorIDs() {
			fmt.Fprintf(os.Stderr, "  %s\n", id)
		}
		fmt.Fprintln(os.Stderr, "\nUse --vendor other for unsupported / unknown vendors "+
			"(no auto TLS posture; operator decides via --no-tls).")
		os.Exit(2)
	}
	cfg := loadConfig(defaultConfigPath())
	mode := normaliseMode(cfg.Mode)
	if mode != "server" && mode != "master" {
		fatalf("network-source add is server/master-only (mode=%s)", mode)
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	// Vendor validation FIRST — operators get a fast refusal without
	// needing the device to be online for the ARP probe. Same for the
	// --no-tls / vendor-requires-TLS conflict.
	v, ok := lookupVendorProfile(*vendor)
	if !ok {
		fmt.Fprintln(os.Stderr, "unknown vendor; supported vendors:")
		for _, id := range vendorIDs() {
			fmt.Fprintf(os.Stderr, "  %s\n", id)
		}
		os.Exit(2)
	}
	if v.TLSSyslogRequired && *noTLS {
		fatalf("vendor %s requires TLS-syslog; --no-tls refused", *vendor)
	}
	vp := v
	mac := normaliseMAC(*macFlag)
	if mac == "" {
		resolved, err := arpResolve(*ip)
		if err != nil {
			fatalf("arp resolve %s: %v", *ip, err)
		}
		mac = normaliseMAC(resolved)
		if mac == "" {
			fatalf("could not resolve MAC for %s — not on this L2 segment? "+
				"Run on a host on the device's segment, or pass --mac explicitly.", *ip)
		}
	}
	// rDNS at add time (locked-in, never live-resolved).
	resolvedLabel := *label
	if resolvedLabel == "" {
		// best-effort
		if names, _ := lookupAddrSafely(*ip); len(names) > 0 {
			resolvedLabel = strings.TrimSuffix(names[0], ".")
		}
	}
	if resolvedLabel == "" {
		resolvedLabel = *ip
	}
	tlsRequired := false
	if vp != nil {
		if vp.TLSSyslogRequired {
			tlsRequired = true
		} else if !*noTLS && vp.TLSSyslogSupported {
			tlsRequired = true
		}
	}
	store := newNetworkAllowlist(networkAllowlistPath(), nil)
	_ = store.Load()
	entry, err := store.Add(networkSource{
		IP:          *ip,
		MAC:         mac,
		Vendor:      *vendor,
		Label:       sanitiseHost(resolvedLabel),
		TLSRequired: tlsRequired,
		Kind:        networkSourceKindManual,
		Owners:      []string{"operator"},
		AddedBy:     "operator:cli",
	})
	if err != nil {
		fatalf("add: %v", err)
	}
	// Best-effort propagation: if a master is enrolled, queue the
	// snapshot for it; if we ARE the master, fan out to servers.
	queuePropagation(cfg, mode, store)
	fmt.Printf("Added: %s/%s vendor=%s label=%s tls_required=%v\n",
		entry.IP, entry.MAC, entry.Vendor, entry.Label, entry.TLSRequired)
}

func runNetworkSourceList(args []string) {
	fs := flag.NewFlagSet("network-source list", flag.ExitOnError)
	staleOnly := fs.Bool("stale-only", false, "only show stale entries")
	_ = fs.Parse(args)
	store := newNetworkAllowlist(networkAllowlistPath(), nil)
	if err := store.Load(); err != nil {
		fatalf("load allowlist: %v", err)
	}
	_, entries := store.Snapshot()
	rows := [][]string{
		{"IP", "MAC", "VENDOR", "LABEL", "KIND", "TLS", "STALE", "OWNERS", "ADDED"},
	}
	for _, e := range entries {
		if *staleOnly && !e.Stale && !e.PendingRevalidation {
			continue
		}
		stale := "no"
		if e.PendingRevalidation {
			stale = "pending"
		} else if e.Stale {
			stale = "yes"
		}
		owners := strings.Join(e.Owners, ",")
		if owners == "" {
			owners = "-"
		}
		rows = append(rows, []string{e.IP, e.MAC, e.Vendor, e.Label, e.Kind,
			yesNo(e.TLSRequired), stale, owners, e.AddedAt})
	}
	if len(rows) == 1 {
		fmt.Println("(no entries)")
		return
	}
	printTable(os.Stdout, rows)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func runNetworkSourceRemove(args []string) {
	args = permuteArgs(args, map[string]bool{"ip": true, "mac": true})
	fs := flag.NewFlagSet("network-source remove", flag.ExitOnError)
	ip := fs.String("ip", "", "IP address")
	macFlag := fs.String("mac", "", "MAC address (optional if IP is unique)")
	force := fs.Bool("force", false, "allow removing gateway entries")
	_ = fs.Parse(args)
	if *ip == "" {
		fatalf("--ip required")
	}
	cfg := loadConfig(defaultConfigPath())
	mode := normaliseMode(cfg.Mode)
	if mode != "server" && mode != "master" {
		fatalf("network-source remove is server/master-only (mode=%s)", mode)
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	store := newNetworkAllowlist(networkAllowlistPath(), nil)
	if err := store.Load(); err != nil {
		fatalf("load: %v", err)
	}
	mac := normaliseMAC(*macFlag)
	if mac == "" {
		// Resolve from the IP; if multiple, ask for explicit --mac.
		entry, _, _ := store.Lookup(*ip, "")
		if entry == nil {
			fatalf("no entry matching ip=%s; pass --mac to disambiguate", *ip)
		}
		mac = entry.MAC
	}
	if err := store.Remove(*ip, mac, *force); err != nil {
		fatalf("remove: %v", err)
	}
	queuePropagation(cfg, mode, store)
	fmt.Printf("Removed: %s/%s\n", *ip, mac)
}

func runNetworkSourceRename(args []string) {
	args = permuteArgs(args, map[string]bool{"ip": true, "mac": true, "label": true})
	fs := flag.NewFlagSet("network-source rename", flag.ExitOnError)
	ip := fs.String("ip", "", "IP address")
	macFlag := fs.String("mac", "", "MAC address (optional)")
	label := fs.String("label", "", "new label")
	_ = fs.Parse(args)
	if *ip == "" || *label == "" {
		fatalf("--ip and --label required")
	}
	cfg := loadConfig(defaultConfigPath())
	mode := normaliseMode(cfg.Mode)
	if mode != "server" && mode != "master" {
		fatalf("network-source rename is server/master-only (mode=%s)", mode)
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	store := newNetworkAllowlist(networkAllowlistPath(), nil)
	if err := store.Load(); err != nil {
		fatalf("load: %v", err)
	}
	mac := normaliseMAC(*macFlag)
	if mac == "" {
		entry, _, _ := store.Lookup(*ip, "")
		if entry == nil {
			fatalf("no entry matching ip=%s", *ip)
		}
		mac = entry.MAC
	}
	if err := store.Rename(*ip, mac, sanitiseHost(*label)); err != nil {
		fatalf("rename: %v", err)
	}
	queuePropagation(cfg, mode, store)
	fmt.Printf("Renamed: %s/%s -> %s\n", *ip, mac, sanitiseHost(*label))
}

func runNetworkSourceRevalidate(args []string) {
	cfg := loadConfig(defaultConfigPath())
	mode := normaliseMode(cfg.Mode)
	if mode != "server" && mode != "master" {
		fatalf("network-source revalidate is server/master-only (mode=%s)", mode)
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	store := newNetworkAllowlist(networkAllowlistPath(), nil)
	if err := store.Load(); err != nil {
		fatalf("load: %v", err)
	}
	resolved, stale := store.Revalidate(arpResolve)
	queuePropagation(cfg, mode, store)
	fmt.Printf("Revalidated: %d ok, %d stale\n", resolved, stale)
}

func runNetworkSourceResync(args []string) {
	cfg := loadConfig(defaultConfigPath())
	mode := normaliseMode(cfg.Mode)
	if mode != "server" && mode != "master" {
		fatalf("network-source resync is server/master-only (mode=%s)", mode)
	}
	if !isAdmin() {
		fatalf("must run as admin")
	}
	store := newNetworkAllowlist(networkAllowlistPath(), nil)
	if err := store.Load(); err != nil {
		fatalf("load: %v", err)
	}
	if mode == "server" {
		err := pullAllowlistFromMaster(cfg, store)
		if err != nil {
			fatalf("pull from master: %v", err)
		}
	} else {
		err := pullAllowlistFromServers(cfg, store)
		if err != nil {
			fatalf("pull from servers: %v", err)
		}
	}
	cfgVer, entries := store.Snapshot()
	fmt.Printf("Resync complete; %d entries (config_version=%d)\n", len(entries), cfgVer)
}

func runNetworkSourceVendors(args []string) {
	rows := [][]string{
		{"ID", "VENDOR", "TLS-SYSLOG", "REQUIRED", "DEFAULT-PORT", "NOTES"},
	}
	for _, id := range vendorIDs() {
		v := vendorProfiles[id]
		tlsCol := "no"
		if v.TLSSyslogSupported {
			tlsCol = "yes"
		}
		req := "optional"
		if v.TLSSyslogRequired {
			req = "required"
		}
		rows = append(rows, []string{id, v.DisplayName, tlsCol, req,
			fmt.Sprintf("%d", v.DefaultPort), v.Notes})
	}
	printTable(os.Stdout, rows)
}

// --------------------------------------------------------------------------
// Helpers shared with sync layer (defined in netingest_sync.go).
// --------------------------------------------------------------------------

func lookupAddrSafely(ip string) ([]string, error) {
	type result struct {
		names []string
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		defer close(ch)
		names, err := stdLookupAddr(ip)
		ch <- result{names, err}
	}()
	select {
	case r := <-ch:
		return r.names, r.err
	case <-time.After(2 * time.Second):
		return nil, fmt.Errorf("rdns lookup timed out")
	}
}

func printTable(w *os.File, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, c := range row {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	for _, row := range rows {
		for i, c := range row {
			fmt.Fprintf(w, "%-*s", widths[i]+2, c)
		}
		fmt.Fprintln(w)
	}
}

// queuePropagation is the post-CLI hook. On a server it appends the
// new state to the pending push queue (the running daemon's sync loop
// flushes it). On a master it triggers an immediate fan-out attempt
// to every consenting server.
func queuePropagation(cfg Config, mode string, store *networkAllowlist) {
	switch mode {
	case "server":
		appendPendingMasterPush(cfg, store)
	case "master":
		fanoutAllowlistToServers(cfg, store)
	}
}

// appendPendingMasterPush is best-effort: it tries an immediate POST
// to the master's bidirectional push endpoint, and on failure persists
// the snapshot to the pending-queue file.
func appendPendingMasterPush(cfg Config, store *networkAllowlist) {
	masterURL := firstMasterURL(cfg)
	if masterURL == "" {
		return // no master, no propagation
	}
	cfgVer, entries := store.Snapshot()
	body := struct {
		ConfigVersion int64           `json:"config_version"`
		Entries       []networkSource `json:"entries"`
		FromPeer      string          `json:"from_peer"`
	}{cfgVer, entries, deriveSelfPeerID(cfg.Server.Listen)}
	if err := postJSONToMaster(cfg, masterURL, "/v1/server/network-allowlist-changed", body); err != nil {
		// queue for retry
		queuePath := pendingPushPath(cfg)
		_ = saveJSONFile(queuePath, body)
	}
}

func fanoutAllowlistToServers(cfg Config, store *networkAllowlist) {
	cfgVer, entries := store.Snapshot()
	body := struct {
		ConfigVersion int64           `json:"config_version"`
		Entries       []networkSource `json:"entries"`
		FromPeer      string          `json:"from_peer"`
	}{cfgVer, entries, masterID(cfg)}
	for _, srv := range cfg.Master.Servers {
		_ = postJSONFromMaster(cfg, srv, "/v1/master/network-allowlist", body)
	}
}

// --- minor utilities -----------------------------------------------------

func saveJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Unique tmp per call — guards against the same shared-tmp race
	// fixed in saveNetworkAllowlistFile.
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	defer func() {
		if _, statErr := os.Stat(tmp); statErr == nil {
			_ = os.Remove(tmp)
		}
	}()
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func httpStatusOK(s int) bool { return s >= 200 && s < 300 }

// firstMasterURL is a best-effort guess at "where do we push edits."
// Until we add a server-side `master_url` config, we infer it from
// MasterCNs (when populated, a master is enrolled) and look up the
// hint in <state>/master_url.txt.
func firstMasterURL(cfg Config) string {
	if len(cfg.Server.MasterCNs) == 0 {
		return ""
	}
	hint, _ := os.ReadFile(masterURLHintPath())
	return strings.TrimSpace(string(hint))
}

func masterURLHintPath() string {
	return defaultStateDir() + string(os.PathSeparator) + "master_url.txt"
}

func pendingPushPath(cfg Config) string {
	dir := cfg.StateDir
	if dir == "" {
		dir = defaultStateDir()
	}
	return dir + string(os.PathSeparator) + "server" + string(os.PathSeparator) + pendingPushFile
}

// masterID returns the master's CN (used as from_peer when fanning out).
func masterID(cfg Config) string {
	if cfg.Master.MasterID != "" {
		return cfg.Master.MasterID
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "master"
	}
	return "master-" + host
}

// pullAllowlistFromMaster does a one-shot GET of the canonical
// allowlist from the master and reconciles. Used on daemon start +
// `network-source resync`.
func pullAllowlistFromMaster(cfg Config, store *networkAllowlist) error {
	masterURL := firstMasterURL(cfg)
	if masterURL == "" {
		return fmt.Errorf("no master enrolled")
	}
	resp, err := getFromMaster(cfg, masterURL, "/v1/server/network-allowlist")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !httpStatusOK(resp.StatusCode) {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	var body struct {
		ConfigVersion int64           `json:"config_version"`
		Entries       []networkSource `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	store.ApplySnapshot(body.ConfigVersion, body.Entries, "master")
	return nil
}

// pullAllowlistFromServers collects every server's snapshot and
// adopts the highest-version entries. Used on master daemon start.
func pullAllowlistFromServers(cfg Config, store *networkAllowlist) error {
	type peerSnap struct {
		from   string
		ver    int64
		entries []networkSource
	}
	var snaps []peerSnap
	for _, srv := range cfg.Master.Servers {
		resp, err := getFromMaster(cfg, srv, "/v1/server/network-allowlist-snapshot")
		if err != nil {
			continue
		}
		var body struct {
			ConfigVersion int64           `json:"config_version"`
			Entries       []networkSource `json:"entries"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
			snaps = append(snaps, peerSnap{srv, body.ConfigVersion, body.Entries})
		}
		_ = resp.Body.Close()
	}
	sort.Slice(snaps, func(i, j int) bool {
		if snaps[i].ver != snaps[j].ver {
			return snaps[i].ver > snaps[j].ver
		}
		return snaps[i].from > snaps[j].from
	})
	for _, s := range snaps {
		store.ApplySnapshot(s.ver, s.entries, s.from)
	}
	return nil
}

// HTTP helpers - implemented in netingest_sync.go for clean separation.
var (
	postJSONToMaster   = postJSONToMasterStub
	postJSONFromMaster = postJSONFromMasterStub
	getFromMaster      = getFromMasterStub
)

func postJSONToMasterStub(cfg Config, base, path string, body any) error {
	return fmt.Errorf("master push not wired in this build")
}

func postJSONFromMasterStub(cfg Config, base, path string, body any) error {
	return fmt.Errorf("server push not wired in this build")
}

func getFromMasterStub(cfg Config, base, path string) (*http.Response, error) {
	return nil, fmt.Errorf("master pull not wired in this build")
}
