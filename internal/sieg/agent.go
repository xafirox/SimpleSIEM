package sieg

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Shipper batches events from the collectors and POSTs them to a server
// over mTLS. When the server is unreachable, events spill onto a bounded
// disk spool and drain back into the queue once connectivity returns.
//
// Design choices:
//
//   - Events flow Collectors → Storage.forward → Shipper.in → batcher →
//     HTTP POST. Storage's writer goroutine still owns the in-memory buffer
//     so collectors keep their non-blocking enqueue semantics.
//   - The hash chain is NOT computed agent-side. Server appends it on
//     receive — we get a consistent chain per (host, type) at the durable
//     end of the pipeline rather than at the chatty wire end.
//   - Spool files are NDJSON, one batch per file. On reconnect, files are
//     re-uploaded oldest-first and removed only after the server returns
//     2xx. A power loss between enqueue and POST means we ship a couple
//     of duplicates on next start — acceptable.
type Shipper struct {
	id string
	// urls is [primary, failover_1, failover_2, ...]. send() iterates
	// from currentIdx, picks the first that succeeds, and sticks to
	// that index for the next call. On total failure (every URL down)
	// markDegraded fires and the spool path runs as before. Index
	// resets to 0 (primary) when markRecovered fires, so an agent
	// drifts back to the primary as soon as it's healthy again.
	urls       []string
	currentIdx atomic.Int32
	client     *http.Client
	auth       string

	in       chan map[string]any
	wg       sync.WaitGroup
	done     chan struct{}
	stopOnce sync.Once

	batchSize    int
	batchEvery   time.Duration
	spoolDir     string
	spoolMaxByte int64

	// noLocalStorage gates every on-disk fallback the shipper would
	// otherwise apply. When true: failed batches are dropped (counter
	// increments) instead of spooled; the local-mirror write into
	// `<log_dir>/_agent/` is skipped on ship failure; shutdown drops
	// in-flight batches instead of spooling them. Mirrors
	// cfg.Agent.NoLocalStorage; default false. Threat-model + caveats
	// in docs/agent-server.md ("Maximum exfiltration resistance").
	noLocalStorage bool

	// drainMu ensures only one drainSpool runs at a time. It's
	// TryLock-ed so concurrent kickers (timer + post-send opportunistic
	// drain) don't pile up — second arrivals just bail.
	drainMu sync.Mutex

	logger *Storage // local Storage used only for meta + errors output

	// localMirror is the agent's quasi-standalone storage. While the
	// shipper is healthy, events flow only to the network. While the
	// shipper is degraded (server unreachable / rejecting), every
	// event is also written here so triage / verify / query / the
	// local rule engine all keep working — same UX as standalone
	// mode for the duration of the outage. The events are still
	// spooled for forwarding, so the server gets them when it
	// returns (no gap, "as if the outage never happened").
	localMirror *Storage

	// degraded transitions false -> true on first send failure and
	// true -> false on first subsequent success, bracketing the
	// outage with meta:server_unreachable_started / server_recovered
	// events that are queryable via triage --type meta. The atomic
	// makes the transition observable from the heartbeat goroutine
	// too, so a heartbeat 403/connection-refused can also flip the
	// flag.
	degraded     atomic.Bool
	degradedAt   atomic.Int64 // unix nano of the transition; 0 when healthy
	// lastSendErr is the most recent send failure reason. Status
	// reads it to show the operator WHY the link is degraded,
	// rather than just "degraded for N minutes" without a cause.
	// Without this an operator looking at status can't tell if
	// they hit a TLS/cert problem vs a connection-refused vs an
	// allowlist 403.
	lastSendErr atomic.Pointer[string]

	dropped uint64
}

// newShipper builds the shipper from a configured AgentConfig. The local
// Storage given here is used to write meta/errors events ABOUT the
// shipping pipeline (so failures are visible in the agent's local error
// log even when the server is down). Real collector events are forwarded
// over the network.
func newShipper(cfg AgentConfig, hostname string, local *Storage) (*Shipper, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("agent.server_url is required in agent mode")
	}
	tlsCfg, err := agentTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	id := cfg.ID
	if id == "" {
		id = hostname
	}
	if !validAgentID(id) {
		return nil, fmt.Errorf("agent.id %q is unsafe (must start alphanumeric, contain only [A-Za-z0-9._-], no '..', not a reserved name)", id)
	}
	tr := &http.Transport{
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	auth := ""
	if cfg.BearerToken != "" {
		auth = "Bearer " + cfg.BearerToken
	}
	if cfg.SpoolDir == "" {
		cfg.SpoolDir = filepath.Join(defaultStateDir(), "spool")
	}
	// no_local_storage skips spool-dir creation entirely. The shipper
	// never writes to it and we don't want a stale spool from a prior
	// run (different config) to be silently inherited. The shipper's
	// drainSpool path just no-ops when noLocalStorage is true so any
	// pre-existing files aren't drained either.
	if !cfg.NoLocalStorage {
		if err := os.MkdirAll(cfg.SpoolDir, 0o750); err != nil {
			return nil, fmt.Errorf("spool dir: %w", err)
		}
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchIntervalSec <= 0 {
		cfg.BatchIntervalSec = 5
	}
	if cfg.SpoolMaxMB <= 0 {
		cfg.SpoolMaxMB = 512
	}
	// Build the URL pool: primary first, then any failover servers
	// configured in the agent block (populated automatically on enroll
	// from the server's realm.peers). Each URL gets the /v1/events
	// suffix once here so send() doesn't have to compute it per call.
	pool := []string{strings.TrimRight(cfg.ServerURL, "/") + "/v1/events"}
	for _, p := range cfg.FailoverServers {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		pool = append(pool, p+"/v1/events")
	}
	s := &Shipper{
		id:           id,
		urls:         pool,
		client:       &http.Client{Transport: tr, Timeout: 60 * time.Second},
		auth:         auth,
		in:           make(chan map[string]any, 4096),
		done:         make(chan struct{}),
		batchSize:    cfg.BatchSize,
		batchEvery:   time.Duration(cfg.BatchIntervalSec) * time.Second,
		spoolDir:       cfg.SpoolDir,
		spoolMaxByte:   int64(cfg.SpoolMaxMB) * 1024 * 1024,
		noLocalStorage: cfg.NoLocalStorage,
		logger:         local,
		// localMirror reuses the agent's local Storage. Writes go to
		// the same `_agent` directory the diagnostic logger uses, so
		// `triage --host _agent --type network` works end-to-end
		// during an outage. The chain is per-(host,type) so collector
		// events sit alongside meta/errors without colliding. When
		// noLocalStorage is true, mirrorBatch / spool calls are
		// gated off — see Shipper.flush.
		localMirror: local,
	}
	if cfg.InsecureSkipTLS {
		// Surface the dangerous setting in the audit trail.
		local.Write("meta", map[string]any{
			"event":  "agent_insecure_tls",
			"reason": "agent.insecure_skip_tls=true; certificate validation disabled",
		})
	}
	return s, nil
}

// Enqueue is the Storage forward callback. Non-blocking: when the buffer
// is full we drop the event and bump a counter rather than stall the
// collectors. Drops are reported into the local meta log every 30s.
func (s *Shipper) Enqueue(logType string, event map[string]any) {
	if event == nil {
		return
	}
	if _, ok := event["type"]; !ok {
		event["type"] = logType
	}
	if _, ok := event["ts"]; !ok {
		event["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	select {
	case s.in <- event:
	case <-s.done:
	default:
		atomic.AddUint64(&s.dropped, 1)
	}
}

func (s *Shipper) Start(ctx context.Context) {
	s.wg.Add(1)
	go s.run(ctx)
	s.wg.Add(1)
	go s.dropFlusher(ctx)
}

func (s *Shipper) Stop() {
	// Idempotent: agent shutdown can be triggered both by ctx.Done()
	// (the goroutine in startAgentDaemon waits on it and calls Stop)
	// and by daemonState.Stop calling shipper.Stop directly. Without
	// sync.Once, the second close() panics.
	s.stopOnce.Do(func() {
		close(s.done)
		s.wg.Wait()
	})
}

// run is the batcher + sender loop. Drains the spool first on startup,
// then alternates between accumulating events and shipping them.
func (s *Shipper) run(ctx context.Context) {
	defer s.wg.Done()

	// Drain anything left in the spool from a prior run before accepting
	// new events. If the server is still down, files stay on disk and
	// we'll retry next time around.
	s.drainSpool(ctx)

	tick := time.NewTicker(s.batchEvery)
	defer tick.Stop()
	// 10s drain ticker keeps recovery latency low when the server comes
	// back up. Combined with the post-success opportunistic drain in
	// flush() below, the worst-case time between server-up and the
	// agent draining its spool is ~one batch interval.
	drainTick := time.NewTicker(10 * time.Second)
	defer drainTick.Stop()

	batch := make([]map[string]any, 0, s.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Shutdown path: ctx canceled or s.done closed. Don't try to
		// send (it would return "context canceled" which then trips
		// markDegraded into writing a misleading
		// `server_unreachable_started` meta event during graceful
		// shutdown). Just spool the batch so the next daemon picks it
		// up. Mirror to local storage too — same intent as the
		// degraded-mode mirroring, to preserve operator visibility
		// across the restart.
		if ctx.Err() != nil || isDoneClosed(s.done) {
			if !s.noLocalStorage {
				s.mirrorBatch(batch)
				if serr := s.spool(batch); serr != nil {
					s.logger.Write("errors", map[string]any{
						"collector": "agent_shipper",
						"error":     "shutdown spool: " + serr.Error(),
					})
				}
			} else {
				atomic.AddUint64(&s.dropped, uint64(len(batch)))
			}
			batch = batch[:0]
			return
		}
		if err := s.send(ctx, batch); err != nil {
			s.markDegraded(err)
			if !s.noLocalStorage {
				// Mirror this batch to local storage so triage/verify can
				// see the events while the server is unreachable. The
				// agent effectively acts like standalone for the duration
				// of the outage.
				s.mirrorBatch(batch)
				// Persist to spool. If the spool is full, oldest files
				// are deleted and the dropped counter incremented.
				if serr := s.spool(batch); serr != nil {
					s.logger.Write("errors", map[string]any{
						"collector": "agent_shipper", "error": serr.Error(),
					})
				}
			} else {
				// no_local_storage: drop the batch with a counter
				// bump rather than persisting it anywhere on disk.
				// dropFlusher publishes the running count into the
				// meta log so the operator can see the impact.
				atomic.AddUint64(&s.dropped, uint64(len(batch)))
			}
		} else {
			s.markRecovered()
			// Successful send proves the server is reachable. Kick a
			// drain to flush any spooled history without waiting for
			// the periodic ticker. drainSpool is mutex-guarded, so
			// concurrent kickers serialize cleanly.
			go s.drainSpool(ctx)
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-s.done:
			flush()
			return
		case ev := <-s.in:
			batch = append(batch, ev)
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-tick.C:
			flush()
		case <-drainTick.C:
			s.drainSpool(ctx)
		}
	}
}

// markDegraded records the false->true transition exactly once,
// emitting a meta:server_unreachable_started event so the operator
// can `triage --type meta` and see when shipping started failing.
// Subsequent failures during the same outage update lastSendErr so
// status keeps showing the CURRENT reason — useful when an outage
// starts as connection-refused but turns into something else (cert
// mismatch, allowlist removal) and the operator is debugging.
func (s *Shipper) markDegraded(err error) {
	msg := err.Error()
	prev := s.lastSendErr.Load()
	s.lastSendErr.Store(&msg)
	if s.degraded.CompareAndSwap(false, true) {
		s.degradedAt.Store(time.Now().UnixNano())
		s.logger.Write("meta", map[string]any{
			"event":  "server_unreachable_started",
			"reason": msg,
			"hint":   "agent is now in quasi-standalone mode: events written locally + spooled for forwarding when server returns",
		})
		return
	}
	// Already degraded; only re-log when the failure mode CHANGES
	// (e.g., outage started as 'connection refused', then morphed
	// into 'tls: certificate is valid for X, not Y'). Repeated
	// identical failures stay quiet so we don't flood the errors log.
	if prev != nil && *prev != msg {
		s.logger.Write("errors", map[string]any{
			"collector": "agent_shipper",
			"error":     "send still failing, reason changed: " + msg,
			"hint":      "see status for current state; previous reason was: " + *prev,
		})
	}
}

// markRecovered is the symmetric true->false transition, emitting
// meta:server_recovered with the outage duration. Idempotent: a
// healthy ping after an already-healthy state is a no-op.
func (s *Shipper) markRecovered() {
	s.lastSendErr.Store(nil)
	// Drift back to the primary on recovery — failover is a last
	// resort, not a permanent state. The next send re-tries the
	// primary; if it's down again, the rotation logic finds the
	// next working peer.
	s.currentIdx.Store(0)
	if s.degraded.CompareAndSwap(true, false) {
		startNs := s.degradedAt.Swap(0)
		var dur time.Duration
		if startNs > 0 {
			dur = time.Since(time.Unix(0, startNs))
		}
		s.logger.Write("meta", map[string]any{
			"event":             "server_recovered",
			"outage_started_at": time.Unix(0, startNs).UTC().Format(time.RFC3339Nano),
			"outage_seconds":    int(dur.Seconds()),
			"hint":              "spooled events from the outage are now being forwarded to the server",
		})
	}
}

// mirrorBatch writes every event in the batch to localMirror under
// its log-type subdirectory. Best-effort: a write error here just
// means triage won't see this event locally. The spool is the
// authoritative store-and-forward path for delivery to the server.
func (s *Shipper) mirrorBatch(batch []map[string]any) {
	if s.localMirror == nil {
		return
	}
	for _, ev := range batch {
		t, _ := ev["type"].(string)
		if t == "" {
			t = "events"
		}
		// Copy the event so the local-mirror write doesn't share a map
		// with the in-flight spool batch (the storage writer adds
		// chain fields, and we don't want those to leak into the
		// spooled copy that ships to the server).
		c := make(map[string]any, len(ev))
		for k, v := range ev {
			c[k] = v
		}
		s.localMirror.Write(t, c)
	}
}

// isDoneClosed reports whether a "done" channel has been closed
// without blocking. Used by the shutdown-aware flush to distinguish a
// real send failure from "we were told to stop mid-flush."
func isDoneClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func (s *Shipper) dropFlusher(ctx context.Context) {
	defer s.wg.Done()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-t.C:
		}
		if n := atomic.SwapUint64(&s.dropped, 0); n > 0 {
			s.logger.Write("meta", map[string]any{
				"event": "agent_drops",
				"count": n,
				"hint":  "increase agent buffer or reduce collector load",
			})
		}
	}
}

// send builds a gzip-NDJSON body and tries each URL in the pool until
// one succeeds. Returns nil on first 2xx; aggregated error from each
// attempt on total failure. Caller decides whether to spool or drop.
//
// Always starts from the primary (index 0). When the primary is up
// the cost is zero — we hit it first. When it's down, we pay one
// failed connect (capped by TLSHandshakeTimeout) before sliding to
// the next peer. The agent NEVER permanently sticks to a backup —
// the moment the primary recovers, the next send goes through it.
// Without this, an outage that flips to a backup leaves the agent
// pinned there forever (markRecovered only fires on degraded→healthy
// and we never went degraded if a backup succeeded).
//
// On 4xx (e.g., 403 allowlist removal) we DON'T fail over — the next
// peer would reject for the same reason, and we want to spool with
// the original error so the operator's status line names the real
// problem. Only network/timeout/5xx errors trigger failover.
func (s *Shipper) send(ctx context.Context, events []map[string]any) error {
	if len(events) == 0 {
		return nil
	}
	body, err := encodeBatch(events)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	if len(s.urls) == 0 {
		return fmt.Errorf("no server URL configured")
	}
	var firstErr error
	for idx := 0; idx < len(s.urls); idx++ {
		url := s.urls[idx]
		req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if rerr != nil {
			if firstErr == nil {
				firstErr = rerr
			}
			continue
		}
		req.Header.Set("Content-Type", "application/x-ndjson")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("X-SimpleSIEM-Host", s.id)
		if s.auth != "" {
			req.Header.Set("Authorization", s.auth)
		}
		resp, derr := s.client.Do(req)
		if derr != nil {
			if firstErr == nil {
				firstErr = derr
			}
			// Drop stale connections to THIS dead peer; next iteration
			// of the loop will open a fresh handshake to a different one.
			if tr, ok := s.client.Transport.(*http.Transport); ok {
				tr.CloseIdleConnections()
			}
			continue
		}
		ok := resp.StatusCode/100 == 2
		if ok {
			resp.Body.Close()
			s.currentIdx.Store(int32(idx))
			return nil
		}
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		statusErr := fmt.Errorf("http %d (%s): %s", resp.StatusCode, url, strings.TrimSpace(string(buf)))
		// 4xx: peer is reachable but rejecting our payload. Failing
		// over would just collect more 4xx with less informative
		// error context. Stick with this error.
		if resp.StatusCode/100 == 4 {
			return statusErr
		}
		if firstErr == nil {
			firstErr = statusErr
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("all %d server URL(s) failed", len(s.urls))
	}
	return firstErr
}

func encodeBatch(events []map[string]any) ([]byte, error) {
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return nil, err
		}
	}
	var gzipped bytes.Buffer
	gz, err := gzip.NewWriterLevel(&gzipped, gzip.BestSpeed)
	if err != nil {
		return nil, fmt.Errorf("gzip writer init: %w", err)
	}
	if _, err := gz.Write(raw.Bytes()); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return gzipped.Bytes(), nil
}

// spool persists a failed batch to disk. Filename is timestamp-prefixed so
// drainSpool can replay them in order. Returns an error if writing or
// pruning fails.
func (s *Shipper) spool(events []map[string]any) error {
	if err := s.pruneSpool(); err != nil {
		return err
	}
	body, err := encodeBatch(events)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%d.%s.ndjson.gz", time.Now().UnixNano(), s.id)
	path := filepath.Join(s.spoolDir, name)
	if err := os.WriteFile(path, body, 0o640); err != nil {
		return err
	}
	return nil
}

// pruneSpool keeps the spool under spoolMaxByte by deleting the oldest
// files. Each delete is counted as a dropped batch.
func (s *Shipper) pruneSpool() error {
	if s.spoolMaxByte <= 0 {
		return nil
	}
	entries, err := os.ReadDir(s.spoolDir)
	if err != nil {
		return err
	}
	type item struct {
		path string
		size int64
		name string
	}
	var items []item
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// `os.Stat(path)` rather than `e.Info()` — Windows
		// directory-cached size is stale for spool files the
		// shipper still has open in O_APPEND mode (the live
		// "should-I-trim-the-spool" decision needs the actual
		// on-disk size, not the MFT entry which only refreshes
		// when the file is closed).
		path := filepath.Join(s.spoolDir, e.Name())
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		items = append(items, item{path: path, size: info.Size(), name: e.Name()})
		total += info.Size()
	}
	if total <= s.spoolMaxByte {
		return nil
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	for _, it := range items {
		if total <= s.spoolMaxByte {
			break
		}
		_ = os.Remove(it.path)
		total -= it.size
		atomic.AddUint64(&s.dropped, 1)
	}
	return nil
}

// drainSpool tries to ship every spooled file in order. Stops on the first
// failure (server still down) so we don't waste CPU re-encoding files we
// can't deliver. Successful uploads delete the file; failures leave it.
//
// drainMu enforces at-most-one concurrent drain; second callers bail
// immediately rather than queueing, which prevents a thundering-herd of
// drainers when many flushes succeed in quick succession.
func (s *Shipper) drainSpool(ctx context.Context) {
	// no_local_storage: never read from a spool we never wrote to.
	// Bypassing this guard keeps a stale spool from a previous
	// (different-config) run from leaking events that the operator
	// has explicitly opted out of persisting.
	if s.noLocalStorage {
		return
	}
	if !s.drainMu.TryLock() {
		return
	}
	defer s.drainMu.Unlock()
	entries, err := os.ReadDir(s.spoolDir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Skip files we've already given up on. Without this guard the
		// drain re-reads them on every cycle, the server 4xx's again,
		// and we keep appending ".rejected" until the filename is
		// hilariously long. The files stay on disk for forensic review.
		if strings.HasSuffix(e.Name(), ".rejected") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names) // timestamp-prefixed -> chronological
	for _, name := range names {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}
		path := filepath.Join(s.spoolDir, name)
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// Body is already gzip-NDJSON; ship as-is, trying each peer
		// in the pool just like send() does. Without iterating, a
		// dead primary + healthy backup would leave the spool stuck
		// even though the live channel exists.
		var resp *http.Response
		for _, url := range s.urls {
			req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if rerr != nil {
				return
			}
			req.Header.Set("Content-Type", "application/x-ndjson")
			req.Header.Set("Content-Encoding", "gzip")
			req.Header.Set("X-SimpleSIEM-Host", s.id)
			if s.auth != "" {
				req.Header.Set("Authorization", s.auth)
			}
			r, derr := s.client.Do(req)
			if derr != nil {
				if tr, ok := s.client.Transport.(*http.Transport); ok {
					tr.CloseIdleConnections()
				}
				continue
			}
			resp = r
			break
		}
		if resp == nil {
			// Every peer failed at the network layer; stop the drain
			// for this cycle, the next ticker will retry.
			return
		}
		ok := resp.StatusCode/100 == 2
		resp.Body.Close()
		if ok {
			_ = os.Remove(path)
			continue
		}
		if resp.StatusCode/100 == 4 {
			// 4xx means the server rejected the payload — replaying won't
			// help. Move it aside so it doesn't loop forever, and log
			// once per rejection so the operator can see *why* events
			// aren't reaching the server (e.g. allowlist removal, cert
			// CN mismatch). Without this log entry, an operator who
			// revoked an agent gets only the heartbeat 403 and no clue
			// that the queue is silently piling up rejected files.
			s.logger.Write("errors", map[string]any{
				"collector": "agent_shipper",
				"error":     fmt.Sprintf("batch rejected by server (HTTP %d); moved to %s", resp.StatusCode, name+".rejected"),
				"hint":      "common cause: agent_id removed from agent_allowlist on the server, or client cert CN no longer matches",
			})
			_ = os.Rename(path, path+".rejected")
			continue
		}
		// 5xx / network: stop, retry on next tick.
		return
	}
}

// agentLocalStorage builds the slim Storage used in agent mode for meta
// and errors only. No rules, no public log writes — this is purely a
// local audit trail for the shipping pipeline. Uses a separate
// subdirectory so it doesn't get confused with collected events (there
// shouldn't be any in agent mode anyway). Registered with the group so
// it follows the active root through any storage failover.
func agentLocalStorage(cfg Config, group *storageGroup) (*Storage, error) {
	gid := resolveGroupGID(cfg.LogOwnerGroup)
	return group.Open("_agent", gid, int64(cfg.MaxLogFileMB)*1024*1024, 256)
}

// agentTLSPing performs a one-shot TLS handshake against the server URL
// at startup so credential errors surface immediately rather than
// silently spooling forever. Best-effort; failures are logged and ignored.
func agentTLSPing(cfg AgentConfig, log *Storage) {
	if cfg.ServerURL == "" {
		return
	}
	tlsCfg, err := agentTLSConfig(cfg)
	if err != nil {
		log.Write("errors", map[string]any{"collector": "agent_tls", "error": err.Error()})
		return
	}
	hostport := strings.TrimPrefix(strings.TrimPrefix(cfg.ServerURL, "https://"), "http://")
	hostport = strings.TrimRight(hostport, "/")
	if !strings.Contains(hostport, ":") {
		hostport += ":443"
	}
	d := &tls.Dialer{Config: tlsCfg, NetDialer: nil}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		log.Write("errors", map[string]any{
			"collector": "agent_tls", "error": "ping failed: " + err.Error(),
			"hint": "verify server is up, certs match, and ca_cert points at the issuing CA",
		})
		return
	}
	conn.Close()
	log.Write("meta", map[string]any{"event": "agent_tls_ping_ok", "server": cfg.ServerURL})
}
