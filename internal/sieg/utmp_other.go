//go:build !linux && !darwin

package sieg

import "context"

// whoSnapshot is a no-op on Windows. The AuthCollector primary
// path is gopsutil.host.Users(), which uses NetWkstaUserEnum on
// Windows and works without CGO. The unix utmp fallback doesn't
// apply.
func whoSnapshot(_ context.Context) map[userSession]struct{} {
	return map[userSession]struct{}{}
}
