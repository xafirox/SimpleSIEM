package sieg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Network-ingest sticky-IP allowlist. Servers and masters maintain a
// per-host list of (IP, MAC) tuples authorised to post syslog frames.
// Storage:
//   <config_dir>/network-allowlist.json   — atomic, fsync+rename writes
//   schema versioned + per-entry version (unix-nanos) for last-write-wins
//
// Servers and masters are the ONLY ingesters. Agent / standalone /
// collector modes refuse to enable the listener and refuse mutating
// operations on the allowlist (agents may still report their own
// gateway info up to the server).
//
// See docs/network-ingest.md for the full design.

const networkAllowlistSchemaVersion = 1
const networkAllowlistFilename = "network-allowlist.json"

const (
	networkSourceKindGateway = "gateway"
	networkSourceKindManual  = "manual"
)

// networkSource is one (IP, MAC) entry. Owners records which peers in
// the realm reference this entry — gateway entries come and go with
// peers, manual entries always have a single "operator" owner.
type networkSource struct {
	IP                  string   `json:"ip"`
	MAC                 string   `json:"mac"`
	Kind                string   `json:"kind"`
	Vendor              string   `json:"vendor,omitempty"`
	Label               string   `json:"label,omitempty"`
	TLSRequired         bool     `json:"tls_required"`
	Owners              []string `json:"owners"`
	AddedAt             string   `json:"added_at"`
	AddedBy             string   `json:"added_by"`
	LastValidatedAt     string   `json:"last_validated_at,omitempty"`
	Version             int64    `json:"version"`
	PendingRevalidation bool     `json:"pending_revalidation,omitempty"`
	Stale               bool     `json:"stale,omitempty"`
}

// networkAllowlistFile is the on-disk schema.
type networkAllowlistFile struct {
	Version       int             `json:"version"`
	ConfigVersion int64           `json:"config_version"`
	Entries       []networkSource `json:"entries"`
}

// networkAllowlist is the in-memory store. Hot-reloadable; every
// mutation goes through Save() which atomically rewrites the file.
//
// Concurrency:
//   - reads (frame validation hot path) take RLock
//   - writes (CLI add/remove, hot-reload, master-push) take Lock
type networkAllowlist struct {
	path string

	mu            sync.RWMutex
	configVersion int64
	byKey         map[string]*networkSource // key = ip+"/"+mac (lowercase mac)
	byIP          map[string][]*networkSource

	// Last in-memory snapshot is the "last working" copy. A malformed
	// reload preserves it; the operator's broken edit is rejected with
	// a meta:network_allowlist_reload_rejected event.
	logger *Storage // for emitting meta events; may be nil during early init
}

func newNetworkAllowlist(path string, logger *Storage) *networkAllowlist {
	return &networkAllowlist{
		path:   path,
		byKey:  map[string]*networkSource{},
		byIP:   map[string][]*networkSource{},
		logger: logger,
	}
}

// allowlistKey is the canonical lookup key. Both fields are lowercased
// and the MAC is normalised to colon-separated.
func allowlistKey(ip, mac string) string {
	return strings.ToLower(strings.TrimSpace(ip)) + "/" + normaliseMAC(mac)
}

// normaliseMAC converts variant MAC formats to "aa:bb:cc:dd:ee:ff".
// Accepts inputs like "AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff",
// "aabb.ccdd.eeff" (Cisco), or "aabbccddeeff". Returns empty string on
// any input that doesn't reduce to exactly 12 hex chars.
func normaliseMAC(s string) string {
	hex := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r + ('a' - 'A')
		}
		return -1
	}, s)
	if len(hex) != 12 {
		return ""
	}
	parts := make([]string, 0, 6)
	for i := 0; i < 12; i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	return strings.Join(parts, ":")
}

// rebuildIndex re-derives byKey + byIP from the entries slice. Caller
// must hold the write lock.
func (a *networkAllowlist) rebuildIndex(entries []networkSource) {
	a.byKey = map[string]*networkSource{}
	a.byIP = map[string][]*networkSource{}
	for i := range entries {
		e := &entries[i]
		key := allowlistKey(e.IP, e.MAC)
		if key == "/" {
			continue // skip rows with no IP at all
		}
		a.byKey[key] = e
		ipKey := strings.ToLower(strings.TrimSpace(e.IP))
		a.byIP[ipKey] = append(a.byIP[ipKey], e)
	}
}

// Load reads the on-disk file into the in-memory store. Errors:
//   - file missing → empty store, no error (fresh install path)
//   - parse error / schema mismatch → returned to caller; in-memory
//     state is left untouched (caller emits meta event)
//   - semantic-validation failure → same
func (a *networkAllowlist) Load() error {
	data, err := os.ReadFile(a.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.configVersion = 0
			a.rebuildIndex(nil)
			return nil
		}
		return err
	}
	var file networkAllowlistFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if file.Version != 0 && file.Version != networkAllowlistSchemaVersion {
		return fmt.Errorf("schema version %d not supported (expected %d)",
			file.Version, networkAllowlistSchemaVersion)
	}
	if err := validateNetworkAllowlist(file.Entries); err != nil {
		return fmt.Errorf("semantic: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.configVersion = file.ConfigVersion
	// Copy into a stable backing array so pointers in byKey/byIP stay
	// valid across mutations.
	clone := append([]networkSource(nil), file.Entries...)
	a.rebuildIndex(clone)
	return nil
}

// validateNetworkAllowlist checks for duplicate (IP, MAC), empty IPs,
// and TLS-downgrade attempts on vendors that require TLS.
func validateNetworkAllowlist(entries []networkSource) error {
	seen := map[string]bool{}
	for i := range entries {
		e := &entries[i]
		if strings.TrimSpace(e.IP) == "" {
			return fmt.Errorf("entry %d: empty ip", i)
		}
		if e.MAC != "" && normaliseMAC(e.MAC) == "" {
			return fmt.Errorf("entry %d: malformed mac %q", i, e.MAC)
		}
		key := allowlistKey(e.IP, e.MAC)
		if seen[key] {
			return fmt.Errorf("duplicate entry %s", key)
		}
		seen[key] = true
		if e.Vendor != "" {
			vp, ok := lookupVendorProfile(e.Vendor)
			if !ok {
				return fmt.Errorf("entry %d: unknown vendor %q", i, e.Vendor)
			}
			if vp.TLSSyslogRequired && !e.TLSRequired {
				return fmt.Errorf("entry %d: vendor %q requires tls_required=true",
					i, e.Vendor)
			}
		}
	}
	return nil
}

// Save serialises the current in-memory state to disk via temp+rename.
// Returns an error if write fails; in-memory state is unchanged.
func (a *networkAllowlist) Save() error {
	a.mu.RLock()
	entries := a.snapshotLocked()
	configVersion := a.configVersion
	a.mu.RUnlock()
	return saveNetworkAllowlistFile(a.path, configVersion, entries)
}

// snapshotLocked returns a sorted copy of the entries. Caller must
// hold at least RLock.
func (a *networkAllowlist) snapshotLocked() []networkSource {
	out := make([]networkSource, 0, len(a.byKey))
	for _, e := range a.byKey {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

func saveNetworkAllowlistFile(path string, configVersion int64, entries []networkSource) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file := networkAllowlistFile{
		Version:       networkAllowlistSchemaVersion,
		ConfigVersion: configVersion,
		Entries:       entries,
	}
	data, err := json.MarshalIndent(&file, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if f, err := os.OpenFile(tmp, os.O_RDWR, 0o600); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Snapshot returns the entries (copy) for read-only callers like CLI
// list / push fanout / backup.
func (a *networkAllowlist) Snapshot() (int64, []networkSource) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.configVersion, a.snapshotLocked()
}

// Lookup returns the entry matching the given (IP, MAC) tuple, plus
// whether-it-was-found AND a separate "ip-only-match" signal so the
// caller can distinguish "unknown source" from "spoof signal".
func (a *networkAllowlist) Lookup(ip, mac string) (entry *networkSource, exact bool, ipOnly bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if e, ok := a.byKey[allowlistKey(ip, mac)]; ok {
		copy := *e
		return &copy, true, false
	}
	if rows, ok := a.byIP[strings.ToLower(strings.TrimSpace(ip))]; ok && len(rows) > 0 {
		copy := *rows[0]
		return &copy, false, true
	}
	return nil, false, false
}

// upsertLocked inserts or updates an entry by (IP, MAC). Caller holds
// the write lock and is responsible for bumping version + configVersion
// and emitting the meta event AFTER writing to disk.
func (a *networkAllowlist) upsertLocked(e networkSource) {
	key := allowlistKey(e.IP, e.MAC)
	if existing, ok := a.byKey[key]; ok {
		// Merge owners, preserve added_at + added_by.
		owners := mergeOwners(existing.Owners, e.Owners)
		e.Owners = owners
		if e.AddedAt == "" {
			e.AddedAt = existing.AddedAt
		}
		if e.AddedBy == "" {
			e.AddedBy = existing.AddedBy
		}
	}
	if e.AddedAt == "" {
		e.AddedAt = time.Now().UTC().Format(time.RFC3339)
	}
	clone := e
	a.byKey[key] = &clone
	// rebuild byIP for this IP only
	ipKey := strings.ToLower(strings.TrimSpace(e.IP))
	rows := a.byIP[ipKey]
	rows = rows[:0]
	for _, ent := range a.byKey {
		if strings.ToLower(strings.TrimSpace(ent.IP)) == ipKey {
			rows = append(rows, ent)
		}
	}
	a.byIP[ipKey] = rows
}

// removeKeyLocked deletes by (ip, mac) key. Caller holds write lock.
func (a *networkAllowlist) removeKeyLocked(key string) bool {
	e, ok := a.byKey[key]
	if !ok {
		return false
	}
	delete(a.byKey, key)
	ipKey := strings.ToLower(strings.TrimSpace(e.IP))
	rows := a.byIP[ipKey][:0]
	for _, ent := range a.byKey {
		if strings.ToLower(strings.TrimSpace(ent.IP)) == ipKey {
			rows = append(rows, ent)
		}
	}
	if len(rows) == 0 {
		delete(a.byIP, ipKey)
	} else {
		a.byIP[ipKey] = rows
	}
	return true
}

// Add inserts a manual / auto entry. The caller fills in IP, MAC,
// Vendor, Label, TLSRequired, Kind, AddedBy, Owners. Returns the
// recorded entry (with timestamps + version stamped) or an error if
// validation failed.
func (a *networkAllowlist) Add(e networkSource) (networkSource, error) {
	if strings.TrimSpace(e.IP) == "" {
		return networkSource{}, fmt.Errorf("ip is required")
	}
	if e.MAC == "" {
		return networkSource{}, fmt.Errorf("mac is required")
	}
	mac := normaliseMAC(e.MAC)
	if mac == "" {
		return networkSource{}, fmt.Errorf("malformed mac %q", e.MAC)
	}
	e.MAC = mac
	if e.Vendor != "" {
		vp, ok := lookupVendorProfile(e.Vendor)
		if !ok {
			return networkSource{}, fmt.Errorf("unknown vendor %q", e.Vendor)
		}
		if vp.TLSSyslogRequired {
			e.TLSRequired = true
		}
	}
	if e.Kind == "" {
		e.Kind = networkSourceKindManual
	}
	if e.AddedAt == "" {
		e.AddedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if e.AddedBy == "" {
		e.AddedBy = "operator"
	}
	now := time.Now().UnixNano()
	e.Version = now
	a.mu.Lock()
	a.upsertLocked(e)
	a.configVersion = now
	a.mu.Unlock()
	if err := a.Save(); err != nil {
		return networkSource{}, err
	}
	a.emitMeta(map[string]any{
		"event":         "network_source_added",
		"ip":            e.IP,
		"mac":           e.MAC,
		"vendor":        e.Vendor,
		"label":         e.Label,
		"kind":          e.Kind,
		"tls_required":  e.TLSRequired,
		"added_by":      e.AddedBy,
	})
	return e, nil
}

// AddOrUpdateGateway is the auto-discovery path. Adds a gateway entry
// owned by the named peer; if the entry already exists, the peer is
// added to its owners list (idempotent).
func (a *networkAllowlist) AddOrUpdateGateway(ip, mac, peerID string) (networkSource, error) {
	if peerID == "" {
		return networkSource{}, fmt.Errorf("peer_id required")
	}
	mac = normaliseMAC(mac)
	if mac == "" {
		return networkSource{}, fmt.Errorf("malformed mac")
	}
	now := time.Now().UnixNano()
	a.mu.Lock()
	key := allowlistKey(ip, mac)
	existed := false
	if _, ok := a.byKey[key]; ok {
		existed = true
	}
	e := networkSource{
		IP:      strings.ToLower(strings.TrimSpace(ip)),
		MAC:     mac,
		Kind:    networkSourceKindGateway,
		Owners:  []string{peerID},
		AddedAt: time.Now().UTC().Format(time.RFC3339),
		AddedBy: "auto:gateway-discovery",
		Version: now,
	}
	a.upsertLocked(e)
	a.configVersion = now
	out := *a.byKey[key]
	a.mu.Unlock()
	if err := a.Save(); err != nil {
		return networkSource{}, err
	}
	evt := "network_gateway_added"
	if existed {
		evt = "network_gateway_owner_added"
	}
	a.emitMeta(map[string]any{
		"event":   evt,
		"ip":      out.IP,
		"mac":     out.MAC,
		"peer_id": peerID,
		"owners":  out.Owners,
	})
	return out, nil
}

// RotateGatewayForPeer applies a gateway-changed event to the allowlist.
// Adds the new (newIP, newMAC) entry owned by peerID, removes peerID
// from the old (oldIP, oldMAC) entry's owners, and prunes the old
// entry if no owners remain.
func (a *networkAllowlist) RotateGatewayForPeer(peerID, oldIP, oldMAC, newIP, newMAC string) error {
	newMACn := normaliseMAC(newMAC)
	if newMACn == "" {
		return fmt.Errorf("malformed new mac")
	}
	oldMACn := normaliseMAC(oldMAC)
	now := time.Now().UnixNano()
	a.mu.Lock()
	if oldIP != "" && oldMACn != "" {
		oldKey := allowlistKey(oldIP, oldMACn)
		if e, ok := a.byKey[oldKey]; ok {
			e.Owners = removeOwner(e.Owners, peerID)
			e.Version = now
			if len(e.Owners) == 0 {
				a.removeKeyLocked(oldKey)
			}
		}
	}
	newE := networkSource{
		IP:      strings.ToLower(strings.TrimSpace(newIP)),
		MAC:     newMACn,
		Kind:    networkSourceKindGateway,
		Owners:  []string{peerID},
		AddedAt: time.Now().UTC().Format(time.RFC3339),
		AddedBy: "auto:gateway-rotation",
		Version: now,
	}
	a.upsertLocked(newE)
	a.configVersion = now
	a.mu.Unlock()
	if err := a.Save(); err != nil {
		return err
	}
	a.emitMeta(map[string]any{
		"event":     "network_allowlist_rotated",
		"peer_id":   peerID,
		"old_ip":    oldIP,
		"old_mac":   oldMACn,
		"new_ip":    newIP,
		"new_mac":   newMACn,
	})
	return nil
}

// RemoveOwnerFromAll strips peerID from every entry's owners list and
// prunes orphans. Used when a peer is removed from the realm
// (uninstall, depart, master cascade).
func (a *networkAllowlist) RemoveOwnerFromAll(peerID string) {
	now := time.Now().UnixNano()
	a.mu.Lock()
	pruned := []string{}
	for k, e := range a.byKey {
		if !containsString(e.Owners, peerID) {
			continue
		}
		e.Owners = removeOwner(e.Owners, peerID)
		e.Version = now
		if len(e.Owners) == 0 && e.Kind == networkSourceKindGateway {
			a.removeKeyLocked(k)
			pruned = append(pruned, k)
		}
	}
	a.configVersion = now
	a.mu.Unlock()
	if err := a.Save(); err != nil {
		return
	}
	if len(pruned) > 0 {
		a.emitMeta(map[string]any{
			"event":   "network_allowlist_orphans_pruned",
			"peer_id": peerID,
			"removed": pruned,
		})
	}
}

// Remove deletes a (ip, mac) entry. Manual entries can be removed
// regardless of owners; gateway entries are refused unless force is
// true (preserves the auto-discovery contract).
func (a *networkAllowlist) Remove(ip, mac string, force bool) error {
	mac = normaliseMAC(mac)
	if mac == "" {
		return fmt.Errorf("malformed mac")
	}
	key := allowlistKey(ip, mac)
	now := time.Now().UnixNano()
	a.mu.Lock()
	e, ok := a.byKey[key]
	if !ok {
		a.mu.Unlock()
		return fmt.Errorf("not found: %s/%s", ip, mac)
	}
	if e.Kind == networkSourceKindGateway && !force {
		a.mu.Unlock()
		return fmt.Errorf("refusing to remove gateway entry without --force " +
			"(it will be re-added by auto-discovery on the next peer report)")
	}
	a.removeKeyLocked(key)
	a.configVersion = now
	a.mu.Unlock()
	if err := a.Save(); err != nil {
		return err
	}
	a.emitMeta(map[string]any{
		"event": "network_source_removed",
		"ip":    ip,
		"mac":   mac,
	})
	return nil
}

// Rename updates an entry's label. Frame validation is unaffected
// (label is purely human-facing).
func (a *networkAllowlist) Rename(ip, mac, newLabel string) error {
	mac = normaliseMAC(mac)
	if mac == "" {
		return fmt.Errorf("malformed mac")
	}
	key := allowlistKey(ip, mac)
	now := time.Now().UnixNano()
	a.mu.Lock()
	e, ok := a.byKey[key]
	if !ok {
		a.mu.Unlock()
		return fmt.Errorf("not found: %s/%s", ip, mac)
	}
	e.Label = newLabel
	e.Version = now
	a.configVersion = now
	a.mu.Unlock()
	if err := a.Save(); err != nil {
		return err
	}
	a.emitMeta(map[string]any{
		"event": "network_source_renamed",
		"ip":    ip,
		"mac":   mac,
		"label": newLabel,
	})
	return nil
}

// MarkPendingRevalidation flags every entry as needing re-validation
// (used after a backup-restore on a different host).
func (a *networkAllowlist) MarkPendingRevalidation() {
	now := time.Now().UnixNano()
	a.mu.Lock()
	for _, e := range a.byKey {
		e.PendingRevalidation = true
		e.Version = now
	}
	a.configVersion = now
	a.mu.Unlock()
	_ = a.Save()
}

// Revalidate iterates each entry, ARPs the IP, and updates
// LastValidatedAt + Stale. Caller provides the resolver so tests can
// mock it.
func (a *networkAllowlist) Revalidate(resolve func(string) (string, error)) (int, int) {
	now := time.Now().UnixNano()
	resolved := 0
	stale := 0
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.byKey {
		gotMAC, err := resolve(e.IP)
		if err != nil || normaliseMAC(gotMAC) == "" {
			e.Stale = true
			stale++
			continue
		}
		e.Stale = false
		e.PendingRevalidation = false
		e.LastValidatedAt = time.Now().UTC().Format(time.RFC3339)
		e.Version = now
		if normaliseMAC(gotMAC) == e.MAC {
			resolved++
		} else {
			// MAC drift — keep the entry, mark stale so frame validation
			// stops accepting it until operator updates.
			e.Stale = true
			stale++
		}
	}
	a.configVersion = now
	_ = a.Save()
	return resolved, stale
}

// SetLogger plugs in the meta-event sink. Called by serverState /
// masterState once their _server / _master Storage is open.
func (a *networkAllowlist) SetLogger(s *Storage) {
	a.mu.Lock()
	a.logger = s
	a.mu.Unlock()
}

func (a *networkAllowlist) emitMeta(payload map[string]any) {
	a.mu.RLock()
	logger := a.logger
	a.mu.RUnlock()
	if logger == nil {
		return
	}
	logger.Write("meta", payload)
}

// ApplySnapshot replaces the in-memory state with a snapshot pushed
// from the master (or pulled during resync). Reconciliation rule:
// higher config_version wins; entries the snapshot has but we don't
// → add; entries we have whose version < snapshot's config_version
// → remove; same-IP-different-MAC → higher version wins.
//
// Returns counts: added, removed, kept_local.
func (a *networkAllowlist) ApplySnapshot(snapshotConfigVersion int64, snapshotEntries []networkSource, sourcePeer string) (int, int, int) {
	a.mu.Lock()
	if snapshotConfigVersion <= a.configVersion {
		// Local is newer or equal; nothing to do.
		a.mu.Unlock()
		return 0, 0, 0
	}
	// Index incoming.
	incoming := map[string]*networkSource{}
	for i := range snapshotEntries {
		e := &snapshotEntries[i]
		incoming[allowlistKey(e.IP, e.MAC)] = e
	}
	added, removed, kept := 0, 0, 0
	// Pass 1: remove or update entries we have.
	for k, mine := range a.byKey {
		theirs, ok := incoming[k]
		if !ok {
			if mine.Version < snapshotConfigVersion {
				a.removeKeyLocked(k)
				removed++
			} else {
				kept++
			}
			continue
		}
		// Same key — pick higher version.
		if theirs.Version > mine.Version {
			clone := *theirs
			a.byKey[k] = &clone
		}
	}
	// Pass 2: add entries we don't have.
	for k, theirs := range incoming {
		if _, ok := a.byKey[k]; ok {
			continue
		}
		clone := *theirs
		a.byKey[k] = &clone
		ipKey := strings.ToLower(strings.TrimSpace(theirs.IP))
		a.byIP[ipKey] = append(a.byIP[ipKey], a.byKey[k])
		added++
	}
	a.configVersion = snapshotConfigVersion
	a.mu.Unlock()
	if err := a.Save(); err != nil {
		return added, removed, kept
	}
	a.emitMeta(map[string]any{
		"event":       "network_allowlist_resynced",
		"from":        sourcePeer,
		"added":       added,
		"removed":     removed,
		"kept_local":  kept,
	})
	return added, removed, kept
}

// EmitReloadRejected records a malformed-reload meta event.
func (a *networkAllowlist) EmitReloadRejected(reason, detail string) {
	a.emitMeta(map[string]any{
		"event":  "network_allowlist_reload_rejected",
		"reason": reason,
		"detail": detail,
	})
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func mergeOwners(a, b []string) []string {
	set := map[string]struct{}{}
	for _, o := range a {
		if o == "" {
			continue
		}
		set[o] = struct{}{}
	}
	for _, o := range b {
		if o == "" {
			continue
		}
		set[o] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for o := range set {
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

func removeOwner(owners []string, peerID string) []string {
	out := owners[:0]
	for _, o := range owners {
		if o == peerID {
			continue
		}
		out = append(out, o)
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// networkAllowlistPath returns the canonical sidecar path
// (<config_dir>/network-allowlist.json).
func networkAllowlistPath() string {
	return filepath.Join(defaultConfigDir(), networkAllowlistFilename)
}

// networkAllowlistWatcher polls the allowlist file and re-loads it on
// change. Malformed files are rejected with a meta event; the
// in-memory state is preserved.
type networkAllowlistWatcher struct {
	store    *networkAllowlist
	lastSeen int64
}

func newNetworkAllowlistWatcher(store *networkAllowlist) *networkAllowlistWatcher {
	w := &networkAllowlistWatcher{store: store}
	if info, err := os.Stat(store.path); err == nil {
		w.lastSeen = info.ModTime().UnixNano()
	}
	return w
}

func (w *networkAllowlistWatcher) run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		info, err := os.Stat(w.store.path)
		if err != nil {
			continue
		}
		mt := info.ModTime().UnixNano()
		if mt == w.lastSeen {
			continue
		}
		w.lastSeen = mt
		if err := w.store.Load(); err != nil {
			reason := "parse"
			if strings.HasPrefix(err.Error(), "semantic") {
				reason = "semantic"
			}
			w.store.EmitReloadRejected(reason, err.Error())
			continue
		}
		w.store.emitMeta(map[string]any{
			"event": "network_allowlist_reloaded",
		})
	}
}
