//go:build !windows

package sieg

// enableVTProcessing is a no-op outside Windows; ANSI codes work natively
// on any modern terminal emulator on Linux/macOS.
func enableVTProcessing() {}
