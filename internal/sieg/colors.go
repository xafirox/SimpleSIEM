package sieg

import (
	"os"
)

// useColor reports whether ANSI colour codes should be emitted to stdout.
// Off when not a TTY, when NO_COLOR is set (https://no-color.org), or when
// TERM=dumb. The same check is used by every command that prints a styled
// summary; --no-color overrides set the COLOR_OVERRIDE env at command level.
var colorDisabled = false

func disableColor() { colorDisabled = true }

func useColor() bool {
	if colorDisabled {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// ANSI codes for the small palette we use. Kept narrow so output stays
// readable on dim/light backgrounds and tmux/screen.
const (
	colReset  = "\033[0m"
	colBold   = "\033[1m"
	colDim    = "\033[2m"
	colRed    = "\033[31m"
	colGreen  = "\033[32m"
	colYellow = "\033[33m"
	colBlue   = "\033[34m"
	colCyan   = "\033[36m"
)

func colorize(s, code string) string {
	if !useColor() {
		return s
	}
	return code + s + colReset
}

// severityColor maps a rule severity ("low"/"medium"/"high"/"critical") to
// the right ANSI code. Unknown values stay un-coloured.
func severityColor(sev string) string {
	switch sev {
	case "critical":
		return colBold + colRed
	case "high":
		return colRed
	case "medium":
		return colYellow
	case "low":
		return colBlue
	}
	return ""
}
