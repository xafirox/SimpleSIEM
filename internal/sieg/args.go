package sieg

import "strings"

// permuteArgs reorders args so flag-tokens (and their values) come before
// positional tokens. The Go stdlib flag package stops parsing at the first
// positional, which is a sharp edge for users who type flags after a
// command's required positional ("certs server hostname --config X").
// We invoke this on subcommands that mix positionals with flags so either
// order works.
//
// flagsTakingValue is the set of flag names (without leading dashes) that
// consume a separate token as their value. The bundled "-flag=value" form
// is always handled regardless of this set.
func permuteArgs(args []string, flagsTakingValue map[string]bool) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue // value bundled
		}
		// If this flag is known to take a value AND the next token is
		// not itself a flag, consume it as the value.
		if flagsTakingValue[name] && i+1 < len(args) {
			next := args[i+1]
			if !strings.HasPrefix(next, "-") {
				flags = append(flags, next)
				i++
			}
		}
	}
	return append(flags, pos...)
}
