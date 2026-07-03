// Command mallcop is the customer-facing CLI for running mallcop scans. It is
// a thin shim over the importable github.com/mallcop-app/mallcop/cli package
// (see cli/main.go for the full command reference); this file exists to own
// the detector-registration blank import, so an external embedder of the cli
// package controls its own detector linkage the same way this binary does.
package main

import (
	"github.com/mallcop-app/mallcop/cli"

	// Link the agent-authored detector aggregator so its own-package detectors
	// register with core/detect and become reachable by detect.Detect across
	// every subcommand (scan / detect / exam-detect). This single blank import
	// is the human-wired registration seam (K7 L1); core/detect cannot import
	// the aggregator itself without a cycle. cmd/ is a guard-protected path, so
	// this line is frozen after the human wires it once — thereafter only the
	// aggregator's append-only blank-import list grows.
	_ "github.com/mallcop-app/mallcop/core/detect/authored"
)

func main() {
	cli.Main()
}
