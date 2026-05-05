package sieg

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Storage writes JSONL events to <base>/<type>/YYYY-MM-DD.jsonl, rotating files
// at UTC date boundaries. Each line carries _seq, _prev, and _hash so a
// reader can verify the file wasn't tampered with: _hash is sha256 of the
// canonical JSON of the event with _hash itself stripped, and _prev links
// each entry to the previous one in the same file. Chains reset at the
// daily rotation boundary, on per-file size rotation, and on daemon
// restart (a verifier sees _prev transition from a non-empty hash to "").
//
// Writes are asynchronous. Callers enqueue events; a single writer goroutine
// drains the queue, doing the actual disk write under no lock contention
// with other producers. This keeps a hot collector loop from stalling on
// fsync. The queue is bounded — when full, the oldest queued events are
// dropped and a counter is incremented; the counter is flushed periodically
// into a meta event so the loss is visible.
type Storage struct {
	base       string
	groupGID   int
	maxFileSz  int64
	queue      chan queueItem
	done       chan struct{}
	dropped    uint64
	writerDone chan struct{}
	closeOnce  sync.Once

	// halted is set by the storage controller when free space on the
	// active volume drops below the configured halt threshold and no
	// failover location is usable. Write() rejects new events while
	// this is true; the controller clears it once recovery is detected
	// or a successful failover has switched the writer to a fresh
	// volume. Atomic so producers can probe it without contending on
	// the writer goroutine.
	halted atomic.Bool

	// haltedDropped counts events shed because halted was true at the
	// moment of Write. Reported as a separate field on the periodic
	// drop-flush meta event so operators can distinguish queue-overflow
	// drops (back-pressure) from quota-halt drops (out of space).
	haltedDropped uint64

	// forward, when non-nil, replaces the disk-write path: events are
	// shipped to it instead of persisting locally. Used in agent mode to
	// hand events off to the network shipper. The chain is NOT computed
	// for forwarded events — the receiving server appends its own chain.
	forward func(logType string, event map[string]any)

	// Mutated only by the writer goroutine, except SetRules; protected by
	// mutex so SetRules can race-safely swap the slice.
	handles     map[string]*os.File
	currentDate string
	prevHash    map[string]string
	seq         map[string]uint64

	rulesMu sync.RWMutex
	rules   []*alertRule

	// alertHooks is the list of fanout sinks called once per fired
	// alert AFTER it lands in the on-disk alerts log. Each sink (webhook
	// dispatcher, syslog dispatcher, ...) attaches via AddAlertHook at
	// daemon startup. Order is insertion order; sinks must be cheap and
	// non-blocking — Storage holds no lock during dispatch but the
	// writer goroutine waits for each call to return.
	alertHooks []func(alert map[string]any)

	// originServer, when non-empty, is stamped onto every event as
	// `origin_server` before write. Set on a server's localStore so
	// events the server collects on its own host are visible to the
	// realm's master via /v1/sync/events (which filters by
	// origin_server == self). Set once at daemon startup; not safe to
	// mutate while the writer goroutine is draining the queue.
	originServer string
}

type queueItem struct {
	logType string
	event   map[string]any
	// swap, when non-nil, is a control message asking the writer
	// goroutine to close its open handles, point its base directory at
	// swap.newBase, and rebuild chain state from the new location.
	// Sent by SwitchBase; never enqueued from a Write() caller. The
	// writer signals completion (or failure) on swap.done.
	swap *swapRequest
}

type swapRequest struct {
	newBase string
	done    chan error
}

const (
	logFileMode = 0o640
	logDirMode  = 0o750
)

func NewStorage(base string, groupGID int, maxFileSize int64, queueSize int) (*Storage, error) {
	if err := os.MkdirAll(base, logDirMode); err != nil {
		return nil, err
	}
	if groupGID > 0 {
		_ = os.Chown(base, 0, groupGID)
		_ = os.Chmod(base, logDirMode)
	}
	if queueSize <= 0 {
		queueSize = 4096
	}
	s := &Storage{
		base:        base,
		groupGID:    groupGID,
		maxFileSz:   maxFileSize,
		queue:       make(chan queueItem, queueSize),
		done:        make(chan struct{}),
		writerDone:  make(chan struct{}),
		handles:     map[string]*os.File{},
		prevHash:    map[string]string{},
		seq:         map[string]uint64{},
		currentDate: time.Now().UTC().Format("2006-01-02"),
	}
	// Warm up chain state from any existing files for today's date.
	// Without this, every daemon restart resets _seq back to 1 and
	// _prev to "", which breaks `simplesiem verify` on the recovered
	// chain. With it, the new daemon's first event continues from
	// the last on-disk hash, so the chain stays unbroken across
	// SIGKILL + restart cycles.
	s.warmChainFromDisk()
	go s.writer()
	go s.dropFlusher()
	return s, nil
}

// SetRules replaces the active rule set. Safe to call concurrently.
func (s *Storage) SetRules(rules []*alertRule) {
	s.rulesMu.Lock()
	s.rules = rules
	s.rulesMu.Unlock()
}

// Write enqueues an event. The actual disk write and rule evaluation happen
// in the writer goroutine. When the queue is full, the event is dropped and
// the dropped counter is bumped — better to lose a low-value event than to
// stall the calling collector on the hot path.
func (s *Storage) Write(logType string, event map[string]any) {
	if event == nil {
		return
	}
	if _, ok := event["ts"]; !ok {
		event["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, ok := event["type"]; !ok {
		event["type"] = logType
	}
	if s.originServer != "" {
		if _, ok := event["origin_server"]; !ok {
			event["origin_server"] = s.originServer
		}
		if _, ok := event["host"]; !ok {
			event["host"] = s.originServer
		}
	}
	// Halted volume: shed the event before it touches the queue. The
	// dropFlusher reports haltedDropped separately so an operator can
	// see exactly how many writes were rejected by the storage quota
	// (vs. how many were back-pressure drops from a saturated queue).
	// Halt-state transition events (storage_halt / storage_recovered)
	// emitted by the storage controller bypass this path because the
	// controller writes them via writeNow directly — they must reach
	// disk even while the daemon is otherwise refusing writes.
	if s.halted.Load() {
		atomic.AddUint64(&s.haltedDropped, 1)
		return
	}
	select {
	case s.queue <- queueItem{logType: logType, event: event}:
	case <-s.done:
		// Storage closing — drop silently.
	default:
		atomic.AddUint64(&s.dropped, 1)
	}
}

// WriteForced enqueues an event that must reach disk even when the
// storage layer is halted. Reserved for storage-controller events
// (halt entered / recovered, halt-attributable drop counts) so an
// operator running `simplesiem status` after free space recovered
// can see exactly what the controller did and when. Bypasses the
// halted check; still respects queue back-pressure.
func (s *Storage) WriteForced(logType string, event map[string]any) {
	if event == nil {
		return
	}
	if _, ok := event["ts"]; !ok {
		event["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, ok := event["type"]; !ok {
		event["type"] = logType
	}
	if s.originServer != "" {
		if _, ok := event["origin_server"]; !ok {
			event["origin_server"] = s.originServer
		}
		if _, ok := event["host"]; !ok {
			event["host"] = s.originServer
		}
	}
	select {
	case s.queue <- queueItem{logType: logType, event: event}:
	case <-s.done:
	default:
		atomic.AddUint64(&s.dropped, 1)
	}
}

// Base returns the active log directory. Read while holding nothing —
// the writer goroutine is the sole mutator (under swap control) so a
// snapshot read is enough for callers that just need to display or
// log the current location.
func (s *Storage) Base() string { return s.base }

// Halted reports whether the storage layer is currently rejecting new
// writes due to a quota halt.
func (s *Storage) Halted() bool { return s.halted.Load() }

// SetHalted toggles the halt flag. Writes enqueued before halt was set
// continue to drain to the previous location; new writes are rejected.
// Used by the storage controller; not part of the public API.
func (s *Storage) SetHalted(v bool) { s.halted.Store(v) }

// SwitchBase asks the writer goroutine to close its current file
// handles, rebase to newBase, and warm chain state from the new
// directory. The call blocks until the writer has acknowledged the
// switch (or returned an error). Synchronisation goes through the
// writer's queue so an in-flight Write never observes a half-swapped
// state — the swap happens between two complete event writes.
func (s *Storage) SwitchBase(newBase string) error {
	req := &swapRequest{newBase: newBase, done: make(chan error, 1)}
	select {
	case s.queue <- queueItem{swap: req}:
	case <-s.done:
		return fmt.Errorf("storage closing")
	}
	return <-req.done
}

func (s *Storage) writer() {
	defer close(s.writerDone)
	for item := range s.queue {
		if item.swap != nil {
			s.handleSwap(item.swap)
			continue
		}
		// Agent mode: hand off and skip everything else. The server will
		// stamp ts/type if missing and own the chain + rules.
		if s.forward != nil {
			s.forward(item.logType, item.event)
			continue
		}
		s.writeNow(item.logType, item.event)
		if item.logType != "alerts" {
			s.evaluateRules(item.logType, item.event)
		}
	}
}

// handleSwap performs a base-directory switch under the writer
// goroutine's exclusive ownership of the file handles + chain state.
// The previous location's handles are closed; chain state is reset and
// rebuilt from the new location so a new daily file at newBase starts
// a fresh chain (the file at the old location ends naturally on its
// last on-disk hash). On MkdirAll failure the swap is rejected and
// the writer keeps using the old base — operators see the failure
// surfaced through SwitchBase's return.
func (s *Storage) handleSwap(req *swapRequest) {
	if err := os.MkdirAll(req.newBase, logDirMode); err != nil {
		req.done <- err
		return
	}
	if s.groupGID > 0 {
		_ = os.Chown(req.newBase, 0, s.groupGID)
		_ = os.Chmod(req.newBase, logDirMode)
	}
	for k, h := range s.handles {
		_ = h.Close()
		delete(s.handles, k)
	}
	s.base = req.newBase
	s.prevHash = map[string]string{}
	s.seq = map[string]uint64{}
	s.warmChainFromDisk()
	req.done <- nil
}

// SetForward installs a hook that replaces the disk-write path. Must be
// called before any Write — it's not safe to swap the hook while the writer
// goroutine is draining the queue.
func (s *Storage) SetForward(f func(logType string, event map[string]any)) {
	s.forward = f
}

// SetOriginServer stamps `origin_server: <id>` AND `host: <id>` onto
// every event written through this Storage, unless the event already
// carries one. Used on a server's localStore so the server's own
// host activity:
//   - has origin_server set (so /v1/sync/events filtering by
//     origin_server == self includes these events), and
//   - has host set (so the master's writeMasterEvent files them under
//     <log_dir>/<id>/<type>/ — without `host`, writeMasterEvent
//     silently drops them and the master never sees the server's
//     own monitored host).
//
// Both stamps are idempotent: events arriving with the field already
// set keep their value, so this never overwrites legitimate per-event
// host/origin attribution (e.g. agent ingress at the server stamps
// host from the X-SimpleSIEM-Host header before write).
//
// Must be called before any Write — same constraint as SetForward.
func (s *Storage) SetOriginServer(id string) {
	s.originServer = id
}

// writeNow does the synchronous disk write. Only the writer goroutine calls
// this directly (alert eval calls it inline via evaluateRules → writeNow),
// so there's a single writer per Storage and no contention on the file
// handles or the hash chain state.
func (s *Storage) writeNow(logType string, event map[string]any) {
	// Idempotent ts/type stamping — Write() also does this, but
	// evaluateRules calls writeNow directly for alert events to keep
	// chain ordering deterministic, so this is the only place that
	// guarantees both call paths produce events with ts and type set.
	// Without this, alerts wrote chain-correct lines but had no ts and
	// loadEventsInRange's window filter silently dropped every one.
	if _, ok := event["ts"]; !ok {
		event["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, ok := event["type"]; !ok {
		event["type"] = logType
	}
	today := time.Now().UTC().Format("2006-01-02")
	if today != s.currentDate {
		for _, h := range s.handles {
			path := h.Name()
			_ = h.Close()
			// Apply the platform append-only / read-only seal to the
			// just-closed daily file. Best-effort: if the seal fails
			// (filesystem doesn't support it, missing tool, etc.) we
			// proceed unsealed — the chain hash is the authoritative
			// tamper signal. See seal.go for the threat model.
			_ = sealClosedLogFile(path)
		}
		s.handles = map[string]*os.File{}
		s.currentDate = today
		s.prevHash = map[string]string{}
		s.seq = map[string]uint64{}
	}

	s.seq[logType]++
	event["_seq"] = s.seq[logType]
	event["_prev"] = s.prevHash[logType]

	pre, err := json.Marshal(event)
	if err != nil {
		return
	}
	// SHA-384 chain hash: paired with P-384 certs for ~192-bit
	// security throughout. Hex encoding is now 96 chars instead of
	// 64; verify auto-detects by length so legacy SHA-256 chains
	// keep validating.
	sum := sha512.Sum384(pre)
	hashHex := hex.EncodeToString(sum[:])
	event["_hash"] = hashHex

	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	data = append(data, '\n')

	h, err := s.getHandle(logType, today)
	if err != nil {
		return
	}
	if _, err := h.Write(data); err != nil {
		// Disk write failed. Don't advance the in-memory prevHash —
		// otherwise the NEXT event's `_prev` references a hash that
		// never made it to disk, breaking chain validation. Also roll
		// back the seq counter so the next write retries the same
		// position cleanly.
		s.seq[logType]--
		return
	}
	// Only advance the chain head AFTER the line successfully landed
	// on disk.
	s.prevHash[logType] = hashHex

	// Per-file size cap: once exceeded, close + rotate to .jsonl.N and
	// open a fresh file. The chain resets at this boundary; verifier sees
	// the same thing as a daemon restart.
	if s.maxFileSz > 0 {
		if st, err := h.Stat(); err == nil && st.Size() >= s.maxFileSz {
			s.rotateBySize(logType, today)
		}
	}
}

// warmChainFromDisk inspects today's log file for each existing log-type
// directory and recovers the last _seq and _hash so the new daemon's
// first write continues the chain instead of resetting it. Best-effort:
// any read or parse error leaves the in-memory state empty for that
// type, which is the same as the old behaviour (chain restart) — strictly
// no worse than before.
//
// Without this, a SIGKILL + `simplesiem start` cycle produced a file
// like:
//   ... _seq=87, _prev=A, _hash=B
//   ... _seq=88, _prev=B, _hash=C   <-- last line before kill
//   ... _seq=1,  _prev="", _hash=Z  <-- first line after restart
// and `simplesiem verify` flagged the seam as tampering.
func (s *Storage) warmChainFromDisk() {
	today := s.currentDate
	entries, err := os.ReadDir(s.base)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		logType := entry.Name()
		path := filepath.Join(s.base, logType, today+".jsonl")
		seq, hash, ok := readLastChainEntry(path)
		if !ok {
			continue
		}
		s.seq[logType] = seq
		s.prevHash[logType] = hash
		// Catch-up sealing: walk past-day files in this type dir and
		// apply the seal to anything that's strictly older than today
		// and still un-sealed. This handles the case where the daemon
		// crashed mid-day yesterday and never sealed yesterday's
		// file. Best-effort — already-sealed files no-op or fail
		// idempotently.
		typeDir := filepath.Join(s.base, logType)
		if files, err := os.ReadDir(typeDir); err == nil {
			for _, f := range files {
				name := f.Name()
				date := dateFromLogName(name)
				if date.IsZero() || date.Format("2006-01-02") == today {
					continue
				}
				_ = sealClosedLogFile(filepath.Join(typeDir, name))
			}
		}
	}
}

// readLastChainEntry scans a JSONL file from the start and returns the
// _seq and _hash of the LAST valid line. We accept the cost of scanning
// — daily files are bounded by retention/rotation so this stays small,
// and the function only runs at startup.
func readLastChainEntry(path string) (seq uint64, hash string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var obj map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &obj); err != nil {
			continue
		}
		if h, _ := obj["_hash"].(string); h != "" {
			hash = h
			ok = true
		}
		switch v := obj["_seq"].(type) {
		case float64:
			if v >= 0 {
				seq = uint64(v)
			}
		case int64:
			if v >= 0 {
				seq = uint64(v)
			}
		case json.Number:
			n, _ := v.Int64()
			if n >= 0 {
				seq = uint64(n)
			}
		}
	}
	return seq, hash, ok
}

func (s *Storage) getHandle(logType, today string) (*os.File, error) {
	if h, ok := s.handles[logType]; ok {
		return h, nil
	}
	dir := filepath.Join(s.base, logType)
	if err := os.MkdirAll(dir, logDirMode); err != nil {
		return nil, err
	}
	if s.groupGID > 0 {
		_ = os.Chown(dir, 0, s.groupGID)
		_ = os.Chmod(dir, logDirMode)
	}
	path := filepath.Join(dir, today+".jsonl")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, logFileMode)
	if err != nil {
		return nil, err
	}
	if s.groupGID > 0 {
		_ = os.Chown(path, 0, s.groupGID)
		_ = os.Chmod(path, logFileMode)
	}
	s.handles[logType] = f
	return f, nil
}

func (s *Storage) rotateBySize(logType, today string) {
	h := s.handles[logType]
	if h == nil {
		return
	}
	_ = h.Close()
	delete(s.handles, logType)
	dir := filepath.Join(s.base, logType)
	src := filepath.Join(dir, today+".jsonl")
	// Find the next free .jsonl.N suffix.
	n := 1
	for {
		dst := fmt.Sprintf("%s.%d", src, n)
		if _, err := os.Stat(dst); os.IsNotExist(err) {
			_ = os.Rename(src, dst)
			break
		}
		n++
		if n > 100000 {
			return
		}
	}
	// Reset chain for the new file.
	s.prevHash[logType] = ""
	// Surface as a meta event so the chain break is visible. Use the
	// queue so we don't recurse into writeNow under a fresh chain.
	go s.Write("meta", map[string]any{
		"event": "log_rotated_by_size", "log_type": logType,
		"max_bytes": s.maxFileSz,
	})
}

// dropFlusher periodically reports the dropped-event counter so backpressure
// is visible to operators. Cheap atomic read; only emits when nonzero.
func (s *Storage) dropFlusher() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		if n := atomic.SwapUint64(&s.dropped, 0); n > 0 {
			s.Write("meta", map[string]any{
				"event": "writes_dropped",
				"count": n,
				"hint":  "increase write_queue_size or reduce collector load",
			})
		}
		if n := atomic.SwapUint64(&s.haltedDropped, 0); n > 0 {
			// Halt-state events themselves bypass the queue, so this
			// counter increments only for everyday collector writes
			// rejected by the storage quota. WriteForced lets us land
			// the report even while halted is still asserted.
			s.WriteForced("meta", map[string]any{
				"event": "writes_dropped_storage_halt",
				"count": n,
				"hint":  "free space recovered or configure storage.failover_locations",
			})
		}
	}
}

func (s *Storage) evaluateRules(logType string, event map[string]any) {
	s.rulesMu.RLock()
	rules := s.rules
	s.rulesMu.RUnlock()
	if len(rules) == 0 {
		return
	}
	for _, r := range rules {
		fire, extra := r.shouldFire(logType, event)
		if !fire {
			continue
		}
		alert := map[string]any{
			"event":         "rule_match",
			"rule":          r.Name,
			"severity":      r.Severity,
			"matched_type":  logType,
			"matched_event": event["event"],
			"original":      event,
		}
		// Operator annotations + MITRE alignment flow through to
		// webhooks / syslog so the on-call has triage context.
		if r.Notes != "" {
			alert["notes"] = r.Notes
		}
		if r.RunbookURL != "" {
			alert["runbook_url"] = r.RunbookURL
		}
		if r.Tactic != "" {
			alert["tactic"] = r.Tactic
		}
		if r.Technique != "" {
			alert["technique"] = r.Technique
		}
		for k, v := range extra {
			alert[k] = v
		}
		s.writeNow("alerts", alert)
		// Dispatch to every operator-configured sink AFTER the
		// alert is durably on disk. Order matters: a sink failure
		// must never lose the alert. Sinks are expected to be
		// non-blocking (queue-based), so this doesn't add latency
		// to the writer goroutine.
		for _, h := range s.alertHooks {
			h(alert)
		}
	}
}

// EvaluateRules runs the configured rule set against (logType, event)
// without first writing the event to disk. Fired alerts still go
// through the regular writeNow path, so they land in alerts/* and
// fan out to alert hooks (webhook, syslog, metrics). Used by the
// master so it can detect cross-host correlations on pulled events
// without re-storing them under master ownership (the master mirrors,
// it doesn't own).
func (s *Storage) EvaluateRules(logType string, event map[string]any) {
	if s == nil {
		return
	}
	s.evaluateRules(logType, event)
}

// AddAlertHook appends a sink to the per-Storage alert fan-out list.
// Caller-set at daemon startup; not safe to mutate while writes are
// in flight. Used by the webhook + syslog dispatchers.
func (s *Storage) AddAlertHook(f func(map[string]any)) {
	if f == nil {
		return
	}
	s.alertHooks = append(s.alertHooks, f)
}

// SetAlertHook is the legacy single-hook API kept for callers that only
// install one sink. Replaces any previously-set hooks.
func (s *Storage) SetAlertHook(f func(map[string]any)) {
	if f == nil {
		s.alertHooks = nil
		return
	}
	s.alertHooks = []func(map[string]any){f}
}

func (s *Storage) Close() {
	// Idempotent: server mode has two shutdown paths (the ctx-done
	// goroutine in runServer plus daemonState.Stop) that both end up
	// calling Close on every Storage in the host map. close()-ing the
	// same channel twice panics, so guard with sync.Once.
	s.closeOnce.Do(func() {
		close(s.done)
		close(s.queue)
		<-s.writerDone
		for _, h := range s.handles {
			_ = h.Close()
		}
		s.handles = map[string]*os.File{}
	})
}

// resolveGroupGID returns the numeric gid for the named group, or 0 if the
// group doesn't exist (or we're on Windows where ownership is handled via
// ACLs we don't touch from Go).
func resolveGroupGID(name string) int {
	if name == "" || runtime.GOOS == "windows" {
		return 0
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0
	}
	return gid
}

// Retention: once per hour, delete per-type daily files older than N days,
// and gzip yesterday's and older daily files (saving 8-15x on JSONL).
func startRetention(ctx context.Context, wg *sync.WaitGroup, base string, days int) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		sweepRetention(base, days)
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sweepRetention(base, days)
			}
		}
	}()
}

func sweepRetention(base string, days int) {
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Truncate(24 * time.Hour)
	today := time.Now().UTC().Format("2006-01-02")
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		typeDir := filepath.Join(base, e.Name())
		files, err := os.ReadDir(typeDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			name := f.Name()
			date := dateFromLogName(name)
			if date.IsZero() {
				continue
			}
			full := filepath.Join(typeDir, name)
			if date.Before(cutoff) {
				// Strip the append-only / read-only seal applied on
				// rotation so os.Remove can succeed. Best-effort:
				// if unseal fails (missing tool, permission denied,
				// concurrent root-clearing), the Remove also fails
				// and the file simply lingers an extra retention
				// cycle. Retention is best-effort by design.
				_ = unsealLogFileForRetention(full)
				_ = os.Remove(full)
				continue
			}
			// Compress only past days and only un-compressed files.
			if date.Format("2006-01-02") != today && !strings.HasSuffix(name, ".gz") &&
				(strings.HasSuffix(name, ".jsonl") || strings.Contains(name, ".jsonl.")) {
				_ = compressFile(full)
			}
		}
	}
}

// dateFromLogName parses the date prefix from log file names. Accepts:
//
//	2026-04-25.jsonl, 2026-04-25.jsonl.3, 2026-04-25.jsonl.gz, 2026-04-25.jsonl.3.gz
//
// Returns zero time if the prefix doesn't look like a date.
func dateFromLogName(name string) time.Time {
	if len(name) < 10 {
		return time.Time{}
	}
	d, err := time.Parse("2006-01-02", name[:10])
	if err != nil {
		return time.Time{}
	}
	return d
}

func compressFile(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := path + ".gz.tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, logFileMode)
	if err != nil {
		return err
	}
	gz, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if _, err := io.Copy(gz, in); err != nil {
		gz.Close()
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := gz.Close(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path+".gz"); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Remove(path)
}

// openLogReader transparently opens a .jsonl or .jsonl.gz file. Caller closes
// the returned ReadCloser, which in turn closes both the gzip reader and the
// underlying file.
func openLogReader(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(path, ".gz") {
		return f, nil
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &gzReader{gz: gz, f: f}, nil
}

type gzReader struct {
	gz *gzip.Reader
	f  *os.File
}

func (r *gzReader) Read(p []byte) (int, error) { return r.gz.Read(p) }
func (r *gzReader) Close() error {
	err1 := r.gz.Close()
	err2 := r.f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// listLogFilesForType returns the files under <base>/<type> sorted by date
// then by rotation suffix. Includes both .jsonl and .jsonl.gz, and the
// .jsonl.N rotated chunks.
func listLogFilesForType(base, logType string) []string {
	dir := filepath.Join(base, logType)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !strings.Contains(name, ".jsonl") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	sort.Slice(out, func(i, j int) bool { return logFileSortKey(out[i]) < logFileSortKey(out[j]) })
	return out
}

// logFileSortKey turns a log-file path into a string that sorts the daily
// files in the order events were written: by date, then by rotation suffix
// (chunked files come before today's open file is even ambiguous — we put
// .jsonl.N before .jsonl since N-suffixed files are older within a day).
func logFileSortKey(path string) string {
	name := filepath.Base(path)
	d := dateFromLogName(name)
	if d.IsZero() {
		return "z" + name
	}
	rest := strings.TrimPrefix(name, d.Format("2006-01-02"))
	rest = strings.TrimSuffix(rest, ".gz")
	// rest is now ".jsonl" or ".jsonl.N". Pad N for stable lexicographic sort.
	if rest == ".jsonl" {
		return d.Format("2006-01-02") + " 99999"
	}
	if strings.HasPrefix(rest, ".jsonl.") {
		nstr := strings.TrimPrefix(rest, ".jsonl.")
		n, _ := strconv.Atoi(nstr)
		return fmt.Sprintf("%s %05d", d.Format("2006-01-02"), n)
	}
	return d.Format("2006-01-02") + " 99999"
}

// dnsCache: bounded reverse-DNS cache with TTL and an async worker pool. The
// public Lookup never blocks the caller; if the IP isn't cached, it returns
// "" immediately and schedules a worker to resolve it for next time. This
// keeps a burst of new connections from stalling collector loops on DNS.
type dnsEntry struct {
	name string
	ts   time.Time
}

type dnsCache struct {
	mu       sync.Mutex
	data     map[string]dnsEntry
	inflight map[string]struct{}
	ttl      time.Duration
	limit    int
	fallback *net.Resolver

	work chan string
	stop chan struct{}
}

var publicResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, network, "1.1.1.1:53")
	},
}

func newDNSCache(ttl time.Duration, limit int) *dnsCache {
	c := &dnsCache{
		data:     map[string]dnsEntry{},
		inflight: map[string]struct{}{},
		ttl:      ttl,
		limit:    limit,
		fallback: publicResolver,
		work:     make(chan string, 1024),
		stop:     make(chan struct{}),
	}
	for i := 0; i < 4; i++ {
		go c.worker()
	}
	return c
}

func (c *dnsCache) Close() {
	close(c.stop)
}

// Lookup never blocks. Cache hits return the cached name; misses return ""
// and enqueue an async lookup. Callers should accept that the first sighting
// of a new IP gets an empty PTR; the next event for the same IP (typically
// seconds later, given the network collector's 2s tick) will be enriched.
func (c *dnsCache) Lookup(_ context.Context, ip string) string {
	c.mu.Lock()
	if e, ok := c.data[ip]; ok && time.Since(e.ts) < c.ttl {
		c.mu.Unlock()
		return e.name
	}
	if _, busy := c.inflight[ip]; !busy {
		c.inflight[ip] = struct{}{}
		select {
		case c.work <- ip:
		default:
			delete(c.inflight, ip)
		}
	}
	c.mu.Unlock()
	return ""
}

func (c *dnsCache) worker() {
	for {
		select {
		case <-c.stop:
			return
		case ip := <-c.work:
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			name := lookupPTR(ctx, net.DefaultResolver, ip)
			if name == "" && c.fallback != nil {
				name = lookupPTR(ctx, c.fallback, ip)
			}
			cancel()
			c.mu.Lock()
			c.data[ip] = dnsEntry{name: name, ts: time.Now()}
			delete(c.inflight, ip)
			if len(c.data) > c.limit {
				target := c.limit / 2
				for k, e := range c.data {
					if time.Since(e.ts) > c.ttl/2 || len(c.data) > c.limit {
						delete(c.data, k)
					}
					if len(c.data) <= target {
						break
					}
				}
			}
			c.mu.Unlock()
		}
	}
}

func lookupPTR(ctx context.Context, r *net.Resolver, ip string) string {
	resolveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	names, err := r.LookupAddr(resolveCtx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
