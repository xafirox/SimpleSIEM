//go:build linux || darwin

package sieg

import "os"

// applyFileMode is a no-op on Linux/macOS: os.WriteFile already honored
// the mode argument when the temp file was written, so atomicWriteFile's
// rename preserves the intended POSIX bits.
func applyFileMode(path string, mode os.FileMode) {
	_ = path
	_ = mode
}
