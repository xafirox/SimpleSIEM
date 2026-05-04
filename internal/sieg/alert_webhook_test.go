package sieg

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAlertWebhook_Dispatches verifies a fired alert is POSTed to
// the configured URL with the expected JSON shape. Synchronous
// inside the test via the dispatch + sleep + check path; production
// is async via the queue goroutine.
func TestAlertWebhook_Dispatches(t *testing.T) {
	var got map[string]any
	var hits int32
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		_ = json.Unmarshal(body, &got)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := ServerConfig{
		AlertWebhooks: []string{srv.URL},
	}
	d := newAlertWebhookDispatcher(cfg, nil, nil)
	if d == nil {
		t.Fatal("dispatcher should not be nil with one URL")
	}
	defer d.Stop()

	d.dispatch(map[string]any{
		"event":    "rule_match",
		"rule":     "test-rule",
		"severity": "high",
	})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&hits) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("webhook hits: got %d want 1", atomic.LoadInt32(&hits))
	}
	mu.Lock()
	defer mu.Unlock()
	if got["rule"] != "test-rule" || got["severity"] != "high" {
		t.Errorf("payload mismatch: %+v", got)
	}
}

// TestAlertWebhook_SeverityFilter verifies the min-severity gate
// drops alerts below the threshold without delivering them.
func TestAlertWebhook_SeverityFilter(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := ServerConfig{
		AlertWebhooks:           []string{srv.URL},
		AlertWebhookMinSeverity: "high",
	}
	d := newAlertWebhookDispatcher(cfg, nil, nil)
	defer d.Stop()

	d.dispatch(map[string]any{"event": "rule_match", "severity": "low"})
	d.dispatch(map[string]any{"event": "rule_match", "severity": "medium"})
	d.dispatch(map[string]any{"event": "rule_match", "severity": "critical"})

	time.Sleep(500 * time.Millisecond)
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("hits with min=high: got %d, expected 1 (only critical passes)", atomic.LoadInt32(&hits))
	}
}

// TestAlertWebhook_NoURLsReturnsNil verifies the empty-config case:
// no dispatcher created, the nil-receiver dispatch path is a no-op
// so callers don't need to nil-check.
func TestAlertWebhook_NoURLsReturnsNil(t *testing.T) {
	d := newAlertWebhookDispatcher(ServerConfig{}, nil, nil)
	if d != nil {
		t.Errorf("dispatcher with no URLs: got non-nil, want nil")
	}
	// Nil-receiver dispatch must not panic.
	d.dispatch(map[string]any{"severity": "high"})
	d.Stop()
}

// TestAlertWebhook_RetryOn5xx verifies a 5xx response triggers a
// retry. The handler returns 500 once, then 200 — second attempt
// should succeed and not bump dropped.
func TestAlertWebhook_RetryOn5xx(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := ServerConfig{AlertWebhooks: []string{srv.URL}}
	d := newAlertWebhookDispatcher(cfg, nil, nil)
	defer d.Stop()

	d.dispatch(map[string]any{"event": "rule_match", "severity": "high"})

	// First attempt fails, retry after 1s, second attempt succeeds.
	time.Sleep(2 * time.Second)
	if atomic.LoadInt32(&hits) < 2 {
		t.Errorf("expected at least 2 attempts, got %d", atomic.LoadInt32(&hits))
	}
	if got := atomic.LoadUint64(&d.dropped); got != 0 {
		t.Errorf("dropped: got %d want 0 (retry succeeded)", got)
	}
}

// TestAlertWebhook_4xxNoRetry verifies a 4xx response is treated as
// permanent — no retry, drop counter bumps.
func TestAlertWebhook_4xxNoRetry(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	cfg := ServerConfig{AlertWebhooks: []string{srv.URL}}
	d := newAlertWebhookDispatcher(cfg, nil, nil)
	defer d.Stop()

	d.dispatch(map[string]any{"event": "rule_match", "severity": "high"})

	time.Sleep(500 * time.Millisecond)
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("4xx attempts: got %d, want 1 (no retry)", atomic.LoadInt32(&hits))
	}
	if got := atomic.LoadUint64(&d.dropped); got != 1 {
		t.Errorf("dropped: got %d want 1", got)
	}
}
