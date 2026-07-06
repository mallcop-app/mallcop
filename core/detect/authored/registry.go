// Package authored is the human-bootstrapped REGISTRATION AGGREGATOR for
// agent-authored detectors (K7 L1). Each authored detector lives in its own
// package under core/detect/authored/<name>/ and registers itself in that
// package's init(); an own-package init() runs ONLY when the package is linked.
// core/detect cannot import this aggregator (that would cycle: an authored
// package imports core/detect), so this file is the single seam that pulls the
// authored packages in.
//
// LINKAGE: cmd/mallcop/main.go blank-imports this package once (a human edit to
// a guard-protected path, frozen thereafter). That single import propagates
// through the whole cmd/mallcop binary — scan, detect, and exam-detect all see
// the authored detectors via detect.Detect, including validate.go's stage-3
// subprocess, which builds and execs the head tree's own cmd/mallcop binary.
//
// GROWTH: adding an authored detector `foo` appends exactly one blank import
// line below (`_ ".../core/detect/authored/foo"`). The self-extension guard
// (core/selfgate) permits ONLY append-only blank imports under
// core/detect/authored/ here — no funcs, no non-blank imports, no removals — so
// this file stays a pure, human-reviewed link list.
package authored

import (
	// Authored detectors register in their own package's init(); each is linked
	// by a blank import below.
	_ "github.com/mallcop-app/mallcop/core/detect/authored/synthmarker"
	_ "github.com/mallcop-app/mallcop/core/detect/authored/deployflood"
)
