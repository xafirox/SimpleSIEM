//go:build !linux

package sieg

import "context"

// Non-Linux stub. macOS has kqueue EVFILT_PROC but it can only
// monitor an already-open process descriptor — not "every new
// process on the host" — so it doesn't help close the polling gap.
// Windows has ETW (Microsoft-Windows-Kernel-Process), which would
// help but requires a meaningful pure-Go ETW client (third-party
// libraries exist but none are CGO-free as of writing).
//
// Both platforms therefore continue to rely on ProcessCollector's
// /proc-equivalent polling. Operators on those hosts can lower
// process_interval below the default 2 seconds at the cost of
// extra CPU; sub-poll-interval lifetimes (a one-shot curl) remain
// best-effort.

type procEventListener struct {
	events chan procExec // always-closed; type-compatible with the Linux variant
}

type procExec struct {
	pid int32
}

func startProcEventListener(ctx context.Context) (*procEventListener, bool) {
	return nil, false
}

func (pl *procEventListener) stop() {}

// procEventsLastErrString is a no-op on non-Linux (the start function
// always returns ok=false here without setting an error).
func procEventsLastErrString() string { return "" }
