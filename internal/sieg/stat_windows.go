//go:build windows

package sieg

import "os"

// Windows: owner SID would require GetFileSecurity; skipped to keep the
// binary dependency-free. size + mode are still captured by the caller.
func addFileStat(rec map[string]any, st os.FileInfo) {}
