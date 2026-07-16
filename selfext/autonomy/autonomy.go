// Package autonomy is the mallcop-pro-side DUPLICATE of mallcop's
// core/config.Learning.Autonomy enum, over the PROCESS
// BOUNDARY: mallcop-pro does not import the mallcop module (see
// internal/selfext/engine/gate.go), so the operator-owned dial value crosses
// as a plain string (a CLI flag on `mallcop-ops selfext`, mirrored from
// mallcop.yaml's learning.autonomy) and this package is the single place that
// string is parsed and interpreted.
//
// Dial is the SHARED autonomy policy both the router (DATA lane: learned
// mappings / tuning overlays) and the engine (CODE lane: opencode-authored
// detectors/connectors) consume, so the three tiers behave identically
// wherever they are read from:
//
//	non   - propose-only. Nothing auto-applies; every gate-GREEN change (data
//	        AND code) waits for a human to approve it. The fail-safe default.
//	semi  - DATA changes auto-apply on a gate-GREEN clean widen; CODE changes
//	        still always wait for a human review.
//	fully - DATA and CODE both auto-apply on a gate-GREEN clean widen.
//
// Contribute-back to the shared OSS pool is NEVER auto-merged at ANY dial
// position — that hard line lives in the router's OSS-CONTRIB tier
// unconditionally and is not gated by Dial at all, by
// construction: nothing in this package can loosen it.
package autonomy

import (
	"fmt"
	"strings"
)

// Dial is one of the three self-extension autonomy tiers.
type Dial string

const (
	// NonAutonomy: propose-only. Human approves ALL changes (data and code).
	NonAutonomy Dial = "non"
	// SemiAutonomy: DATA auto-applies; CODE still waits for a human.
	SemiAutonomy Dial = "semi"
	// FullyAutonomy: DATA and CODE both auto-apply.
	FullyAutonomy Dial = "fully"
)

// Parse strict-decodes a dial string — the CLI flag / config value crossing
// the process boundary. Empty defaults to NonAutonomy (fail-safe: an
// unconfigured caller gets the safest behavior, never a silent auto-apply).
// Comparison is case-insensitive/trimmed (operator-typed flag values), but any
// value other than the three known spellings is a loud error — a typo must
// never be silently coerced into a specific tier.
func Parse(s string) (Dial, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return NonAutonomy, nil
	case string(NonAutonomy):
		return NonAutonomy, nil
	case string(SemiAutonomy):
		return SemiAutonomy, nil
	case string(FullyAutonomy):
		return FullyAutonomy, nil
	default:
		return "", fmt.Errorf("autonomy: unknown dial %q (want %q, %q, or %q)", s, NonAutonomy, SemiAutonomy, FullyAutonomy)
	}
}

// Normalized returns d, or NonAutonomy (fail-safe) when d is the empty
// zero-value — the case a caller (e.g. a struct literal in a test or a wiring
// site) never explicitly set the field. This is the ONLY place a zero Dial is
// interpreted; router.Router and engine.Engine both call it so "no dial set"
// and "non" are the exact same code path everywhere.
func (d Dial) Normalized() Dial {
	if d == "" {
		return NonAutonomy
	}
	return d
}

// AutoAppliesData reports whether this dial auto-applies a gate-GREEN DATA
// (mapping/tuning overlay) change without waiting for a human. Only "non"
// withholds it.
func (d Dial) AutoAppliesData() bool {
	n := d.Normalized()
	return n == SemiAutonomy || n == FullyAutonomy
}

// AutoAppliesCode reports whether this dial auto-applies a gate-GREEN CODE
// (authored detector/connector) change without waiting for a human. ONLY
// "fully" does; "non" and "semi" both always leave authored code for a human
// to review and merge.
func (d Dial) AutoAppliesCode() bool {
	return d.Normalized() == FullyAutonomy
}
