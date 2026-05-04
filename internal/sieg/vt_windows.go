//go:build windows

package sieg

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVTProcessing turns on ENABLE_VIRTUAL_TERMINAL_PROCESSING on stdout
// and stderr so ANSI escape codes render as colours instead of literal
// `^[[31m` text on classic Windows consoles.
//
// Modern Windows Terminal and PowerShell 7 sessions enable this by default,
// but cmd.exe and Windows PowerShell 5.1 require explicit opt-in. The call
// is a no-op on consoles that don't support it (any error is swallowed),
// so it's safe to invoke unconditionally at startup.
func enableVTProcessing() {
	enableOn(os.Stdout.Fd())
	enableOn(os.Stderr.Fd())
}

func enableOn(fd uintptr) {
	handle := windows.Handle(fd)
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return
	}
	mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	_ = windows.SetConsoleMode(handle, mode)
}
