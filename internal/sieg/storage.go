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

	// writeFailed counts events whose disk write failed (open/write/permission
	// errors — typically a misconfigured systemd ReadWritePaths or a chmod
	// that locked us out of log_dir). The previous behaviour was to silently
	// drop these events; the daemon would accept on the wire, ack 200, and
	// lose the data. Now we keep a counter, capture the most recent error
	// reason (lastWriteErr), and have writeFailureFlusher emit a meta event
	// so the loss is visible in `simplesiem status` and queryable via
	// `simplesiem query --grep storage_write_failed`.
	writeFailed   uint64
	lastWriteErr  atomic.Pointer[string]
	writeFailedTotal uint64

	// forward, when non-nil, replaces the disk-write path: events are
	// shipped to it instead of persisting locally. Used in agent mode to
	// hand events off to the network shipper. The chain is NOT computed
	// for forwarded events — the receiving server appends its own chain.
	forward func(logType string, event map[string]any)

	// mirror, when non-nil, is called with a clone of every event
	// AFTER it's enqueued for local writing but BEFORE the writer
	// stamps _seq/_prev/_hash. The clone is what gets handed to the
	// hook so the local hash chain and the mirrored copy can be
	// chained independently by their respective storages. Used on
	// the agent's local Storage so meta + errors written for local
	// triage ALSO ship to the server (the as3 manual-test ask:
	// "the server must collect all logs"). The local write is
	// preserved — operator audit trail on the agent stays intact
	// even when the shipper is offline.
	mirror func(logType string, event map[string]any)

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
	//
	// hooksMu guards the slice so hooks installed after the first alert
	// fires (e.g. a webhook dispatcher attached after the metrics hook)
	// can't race a writer-goroutine iteration.
	hooksMu    sync.RWMutex
	alertHooks []func(alert map[string]any)

	// originServer, when non-empty, is stamped onto every event as
	// `origin_server` before write. Set on a server's localStore so
	// events the server collects on its own host are visible to the
	// realm's master via /v1/sync/events (which filters by
	// origin_server == self). Set once at daemon startup; not safe to
	// mutate while the writer goroutine is draining the queue.
	originServer string

	// lastWriterActivity is the unix-nano timestamp of the last
	// successful pass through the writer loop body. The writer
	// watchdog reads it to decide whether the writer is still
	// processing items — if the queue is non-empty but the timestamp
	// hasn't moved for a long stretch, the watchdog records a
	// "writer_wedged" diagnostic directly to disk (bypassing the
	// queue, which is by hypothesis not draining) so an operator
	// running `simplesiem status` later sees what happened.
	lastWriterActivity atomic.Int64

	// writerPanics counts panics caught + recovered inside the writer
	// loop. Surfaced on the periodic drop flush so the operator can
	// see if a bad event keeps tripping the writer (e.g. a malformed
	// rule's regex panicking on every match attempt).
	writerPanics uint64
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
	// flush, when non-nil, is a control message asking the writer to
	// signal back as soon as it dequeues this item. Sent by Flush();
	// callers (mostly tests) use it to wait for in-flight writes to
	// reach disk without sleeping for an arbitrary duration.
	flush chan struct{}
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
	s.lastWriterActivity.Store(time.Now().UnixNano())
	go s.writer()
	go s.dropFlusher()
	go s.writerWatchdog()
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
	// Path-derived user attribution: if an event has no user but its
	// path lives under a known per-user root (C:\Users\X, /home/X,
	// /Users/X, /root), tag the owning user. Cheap, no syscalls.
	// Does not overwrite a user value the source collector already
	// set (e.g. from a PID lookup via gopsutil).
	if _, hasUser := event["user"]; !hasUser {
		if pv, ok := event["path"].(string); ok && pv != "" {
			if u := userFromPath(pv); u != "" {
				event["user"] = u
			}
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

// Flush blocks until every queued event ahead of this call has been
// processed by the writer goroutine. Useful for tests that need to
// observe on-disk state right after Write(), without sleeping for an
// arbitrary "long enough" duration. Returns when the flush sentinel
// reaches the writer; if the storage is already closing/closed, also
// returns (the writer has already drained whatever was queued, so the
// post-close on-disk state is final).
func (s *Storage) Flush() {
	// Storage.Close() closes both s.done and s.queue. Sending on a
	// closed queue panics, so guard with a recover and let the early
	// s.done check short-circuit when possible. Treat both states as
	// "nothing more to wait for."
	defer func() { _ = recover() }()
	select {
	case <-s.done:
		return
	default:
	}
	ch := make(chan struct{})
	select {
	case s.queue <- queueItem{flush: ch}:
	case <-s.done:
		return
	}
	select {
	case <-ch:
	case <-s.done:
	}
}

func (s *Storage) writer() {
	defer close(s.writerDone)
	for item := range s.queue {
		s.processOneItem(item)
		s.lastWriterActivity.Store(time.Now().UnixNano())
	}
}

// processOneItem runs the per-item body of the writer loop with a panic
// recover so one malformed event (e.g. a rule regex that panics on a
// pathological input, or a JSON marshal that trips on a NaN/Inf number)
// can't kill the goroutine and leave Write() callers silently dropped
// for the rest of the daemon's life. On panic we record the cause, bump
// a counter the dropFlusher reports, and continue with the next item —
// "the daemon ran SILENT for 8m34s and a restart fixed it" only happens
// when the writer goroutine is dead, so the simplest self-heal is
// keeping it alive across hostile input.
func (s *Storage) processOneItem(item queueItem) {
	defer func() {
		if r := recover(); r != nil {
			atomic.AddUint64(&s.writerPanics, 1)
			// Snapshot context for diagnostics. We can't trust the
			// queue (writer is mid-recover), so write directly to
			// the meta path on disk via writeNow on a fresh stack.
			// writeNow is itself wrapped here, so a second panic
			// inside the diagnostic path is also caught — at worst
			// we lose the diagnostic line and the counter still
			// records the event.
			defer func() { _ = recover() }()
			s.writeNow("errors", map[string]any{
				"collector": "storage_writer",
				"error":     fmt.Sprintf("writer panic recovered: %v", r),
				"log_type":  item.logType,
				"hint":      "a single event tripped the writer; writer continues. Watch writer_panics in meta drop reports.",
			})
		}
	}()
	if item.swap != nil {
		s.handleSwap(item.swap)
		return
	}
	if item.flush != nil {
		// All previously-enqueued items ahead of this sentinel have
		// been processed by virtue of FIFO queue draining. Closing
		// the channel signals the caller it's safe to read on-disk
		// state.
		close(item.flush)
		return
	}
	// Agent mode: hand off and skip everything else. The server will
	// stamp ts/type if missing and own the chain + rules.
	if s.forward != nil {
		s.forward(item.logType, item.event)
		return
	}
	// Mirror runs BEFORE writeNow so the cloned event the hook
	// receives doesn't carry the local _seq/_prev/_hash — the
	// receiver storage chains it independently. Best-effort: a
	// mirror panic is caught by the surrounding recover() and the
	// local write still proceeds.
	if s.mirror != nil {
		cloned := make(map[string]any, len(item.event))
		for k, v := range item.event {
			if k == "_seq" || k == "_prev" || k == "_hash" {
				continue
			}
			cloned[k] = v
		}
		func() {
			defer func() { _ = recover() }()
			s.mirror(item.logType, cloned)
		}()
	}
	s.writeNow(item.logType, item.event)
	if item.logType != "alerts" {
		s.evaluateRules(item.logType, item.event)
	}
}

// writerWatchdog monitors lastWriterActivity. If the writer hasn't
// made any progress for >2 minutes AND the queue isn't empty (so
// progress IS expected), it appends a "writer_wedged" diagnostic
// directly to the meta log file — bypassing the channel, which by
// hypothesis isn't draining. The next `simplesiem status` run will
// surface this via the existing wedge detector.
//
// Self-heal is best-effort: if the writer goroutine has exited (panic
// without recover), Storage callers see Write() drop into the default
// branch of the select, but the daemon keeps trying. Manual restart
// is still required when the writer goroutine itself is gone — but
// the watchdog gives the operator a durable on-disk trail of WHEN
// activity stopped, where previously the only signal was the
// 5-minute mtime check in `status`.
func (s *Storage) writerWatchdog() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	var reported time.Time
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		last := time.Unix(0, s.lastWriterActivity.Load())
		stalled := time.Since(last)
		if stalled < 2*time.Minute {
			continue
		}
		// Empty queue means no work to do — silence is healthy.
		if len(s.queue) == 0 {
			continue
		}
		// Don't spam: re-report at most every 5 minutes.
		if !reported.IsZero() && time.Since(reported) < 5*time.Minute {
			continue
		}
		reported = time.Now()
		s.writeMetaDirect(map[string]any{
			"event":         "writer_wedged",
			"stalled_for":   stalled.Round(time.Second).String(),
			"queue_depth":   len(s.queue),
			"writer_panics": atomic.LoadUint64(&s.writerPanics),
			"hint":          "writer goroutine isn't draining the queue; restart the daemon if this persists",
		})
	}
}

// writeMetaDirect appends a single meta event to today's meta JSONL
// without going through the writer goroutine. Used by the watchdog so
// "writer is wedged" diagnostics actually reach disk when the queue
// itself is the failing path. No chain hash is computed (we'd need to
// race with the writer for the chain state) — the line carries
// `_chain_skip: true` so verify ignores it.
//
// Best-effort: any error here is silently swallowed because there's
// no other place to surface it. The function is fast enough on the
// 60-second watchdog tick that any I/O contention with a recovering
// writer is irrelevant.
func (s *Storage) writeMetaDirect(event map[string]any) {
	if event == nil {
		return
	}
	if _, ok := event["ts"]; !ok {
		event["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	event["type"] = "meta"
	event["_chain_skip"] = true
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	data = append(data, '\n')
	today := time.Now().UTC().Format("2006-01-02")
	dir := filepath.Join(s.base, "meta")
	if err := os.MkdirAll(dir, logDirMode); err != nil {
		return
	}
	path := filepath.Join(dir, today+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, logFileMode)
	if err != nil {
		return
	}
	_, _ = f.Write(data)
	_ = f.Close()
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

// SetMirror installs a hook that's called with a clone of every
// outgoing event ALONGSIDE the local disk write (not as a
// replacement). Used on the agent's local Storage so meta+errors
// written for local triage ALSO ship to the server. Must be set
// before any Write — same constraint as SetForward.
func (s *Storage) SetMirror(f func(logType string, event map[string]any)) {
	s.mirror = f
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
		s.recordWriteFailure(logType, "open", err)
		s.seq[logType]--
		return
	}
	if _, err := h.Write(data); err != nil {
		// Disk write failed. Don't advance the in-memory prevHash —
		// otherwise the NEXT event's `_prev` references a hash that
		// never made it to disk, breaking chain validation. Also roll
		// back the seq counter so the next write retries the same
		// position cleanly.
		s.recordWriteFailure(logType, "write", err)
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
		if n := atomic.SwapUint64(&s.writerPanics, 0); n > 0 {
			// Writer recovered from one or more panics since the last
			// flush. Surface so the operator can correlate which
			// rule/event family is tripping the panic — repeat
			// occurrences are the actionable signal.
			s.Write("meta", map[string]any{
				"event": "writer_panics_recovered",
				"count": n,
				"hint":  "writer goroutine caught a panic per item; daemon kept running. Check rules/* for a pattern that panics on match.",
			})
		}
		if n := atomic.SwapUint64(&s.writeFailed, 0); n > 0 {
			// Disk-write failures since the last flush. The most common
			// cause is a misconfigured systemd ReadWritePaths after the
			// operator changed log_dir without re-running install — the
			// daemon binds the listener and accepts events on the wire,
			// then silently drops the disk write. Surface a loud meta
			// event with the most recent error reason and a cumulative
			// total so the operator can see the loss in `simplesiem
			// status` instead of waiting for "events aren't appearing"
			// to surface days later. WriteForced because the event must
			// reach disk even when the storage layer is otherwise
			// rejecting writes (e.g., the failure is intermittent and a
			// later write succeeds — we still want the report itself
			// preserved).
			reason := ""
			if r := s.lastWriteErr.Load(); r != nil {
				reason = *r
			}
			total := atomic.LoadUint64(&s.writeFailedTotal)
			s.WriteForced("meta", map[string]any{
				"event":            "storage_write_failed",
				"count":            n,
				"cumulative_total": total,
				"last_error":       reason,
				"log_dir":          s.base,
				"hint":             "writes to log_dir are failing. Common cause: log_dir was changed without rerunning `simplesiem install` so the systemd unit's ReadWritePaths still points at the old path. Re-run install with --log-dir matching config.json, or check filesystem permissions.",
			})
		}
	}
}

// recordWriteFailure tags a failed disk write so the periodic flusher can
// surface it as a meta event. Cheap: an atomic add + an atomic pointer
// store. The error reason is also written to stderr so it appears in the
// systemd journal (operator's first-look location when a host goes silent).
func (s *Storage) recordWriteFailure(logType, op string, err error) {
	atomic.AddUint64(&s.writeFailed, 1)
	total := atomic.AddUint64(&s.writeFailedTotal, 1)
	reason := op + " " + filepath.Join(s.base, logType) + ": " + err.Error()
	s.lastWriteErr.Store(&reason)
	// First failure gets the full remediation hint — that's the message
	// an operator running `journalctl -u simplesiem` will look for when
	// the host appears silent. Subsequent failures are rate-limited so
	// we don't flood the journal.
	switch {
	case total == 1:
		fmt.Fprintln(os.Stderr, "simplesiem: STORAGE WRITE FAILED: "+reason)
		fmt.Fprintln(os.Stderr, "simplesiem: log_dir="+s.base+" — daemon will keep accepting events but cannot persist them.")
		fmt.Fprintln(os.Stderr, "simplesiem: most common cause is a stale systemd unit ReadWritePaths after log_dir was changed in config.json.")
		fmt.Fprintln(os.Stderr, "simplesiem: fix: rerun `sudo simplesiem install --log-dir "+s.base+"` to regenerate the systemd unit, or check filesystem permissions on log_dir.")
	case total <= 3 || total%1000 == 0:
		fmt.Fprintln(os.Stderr, "simplesiem: storage write failed (#"+strconv.FormatUint(total, 10)+"): "+reason)
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
		// to the writer goroutine. Snapshot under hooksMu so
		// concurrent AddAlertHook calls can't tear the iteration.
		s.hooksMu.RLock()
		hooks := s.alertHooks
		s.hooksMu.RUnlock()
		for _, h := range hooks {
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

// SnapshotAlertHooks returns a stable snapshot of the alert-hook slice
// for callers that fan an external alert through the same set of sinks
// the writer goroutine uses (e.g. master rule eval, network-ingest
// listener, alert escalation watcher).
func (s *Storage) SnapshotAlertHooks() []func(map[string]any) {
	if s == nil {
		return nil
	}
	s.hooksMu.RLock()
	defer s.hooksMu.RUnlock()
	return s.alertHooks
}

// AddAlertHook appends a sink to the per-Storage alert fan-out list.
// Safe to call after the writer is running — hooksMu serialises the
// append against the writer's snapshot read.
func (s *Storage) AddAlertHook(f func(map[string]any)) {
	if f == nil {
		return
	}
	s.hooksMu.Lock()
	// Copy-on-write: keep any iterator snapshot stable while the
	// writer is mid-dispatch. Cheap because hooks are rare and small.
	next := make([]func(map[string]any), len(s.alertHooks)+1)
	copy(next, s.alertHooks)
	next[len(s.alertHooks)] = f
	s.alertHooks = next
	s.hooksMu.Unlock()
}

// SetAlertHook is the legacy single-hook API kept for callers that only
// install one sink. Replaces any previously-set hooks.
func (s *Storage) SetAlertHook(f func(map[string]any)) {
	s.hooksMu.Lock()
	if f == nil {
		s.alertHooks = nil
	} else {
		s.alertHooks = []func(map[string]any){f}
	}
	s.hooksMu.Unlock()
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
