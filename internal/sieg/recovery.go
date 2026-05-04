package sieg

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"
)

// runCollector launches fn under panic recovery and an exponential-backoff
// restart loop. A collector that panics is logged once with its stack and
// then restarted after a delay, capped so an endlessly broken collector
// doesn't hot-spin. The wg add/done is handled here so callers don't have
// to remember it.
//
// Stack traces are written to the errors log type — they ARE included
// despite GOTRACEBACK=none, because GOTRACEBACK only governs the runtime's
// own panic dump to stderr; explicit debug.Stack() calls still work and we
// want the trace for diagnosis. Operators who consider these traces
// sensitive can drop or redact the field at log shipping time.
func runCollector(ctx context.Context, wg *sync.WaitGroup, name string, storage *Storage, loop func(context.Context)) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		backoff := 5 * time.Second
		const maxBackoff = 5 * time.Minute
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			panicked := func() (recovered bool) {
				defer func() {
					if r := recover(); r != nil {
						recovered = true
						storage.Write("errors", map[string]any{
							"collector": name,
							"error":     fmt.Sprintf("panic: %v", r),
							"stack":     string(debug.Stack()),
						})
					}
				}()
				loop(ctx)
				return false
			}()
			if !panicked {
				// Normal exit (ctx.Done or returned cleanly). Don't restart.
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}()
}
