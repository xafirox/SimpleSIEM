// SimpleSIEM — single-binary on-box SIEM.
//
// This file is intentionally tiny: it dispatches into the internal/sieg
// package which holds the actual implementation. Keeping main.go thin
// is the Go convention for binaries with a non-trivial codebase — it
// keeps the module root uncluttered and makes the source layout
// self-documenting (everything that's not the entry point lives under
// internal/).
package main

import "simplesiem/internal/sieg"

func main() {
	sieg.Run()
}
