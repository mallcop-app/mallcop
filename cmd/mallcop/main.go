// Command mallcop is the customer-facing CLI for running mallcop scans. It is
// a thin shim over the importable github.com/mallcop-app/mallcop/cli package
// (see cli/main.go for the full command reference); this file exists to own
// the detector-registration blank import, so an external embedder of the cli
// package controls its own detector linkage the same way this binary does.
package main

import (
	"github.com/mallcop-app/mallcop/cli"
	"github.com/mallcop-app/mallcop/selfext/jail"

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
	// `mallcop selfext --run` runs the headless opencode authoring child under an
	// OS-enforced Landlock jail (selfext/jail) by re-execing THIS binary with the
	// jail marker as argv[1]. MaybeReexec intercepts that marker at the very top
	// of main(), applies the jail, and execs opencode — it NEVER returns on that
	// path. On the normal invocation (argv[1] is a real subcommand) it returns
	// immediately and the CLI proceeds unchanged.
	jail.MaybeReexec()
	cli.Main()
}
