// corpus.go — the embedded operator-decisions corpus.
//
// //go:embed cannot traverse "..", so the embed directive must live in a .go
// file at a directory level whose subtree contains the corpus. The corpus is at
// <root>/agents/rules/operator-decisions.yaml, so ONLY the repo root qualifies.
// This is the sole production package at the root (hello_test.go is the external
// `mallcoplegion_test` package, which Go permits to coexist with `mallcoplegion`
// in the same directory).
//
// The bytes are exposed so the production runtime loaders (core/agent's
// escalate-route floor and core/tools' operator-rules loader) can FALL BACK to a
// baked-in corpus when no on-disk corpus can be located — e.g. a standalone
// `/tmp/mallcop` binary with MALLCOP_REPO_ROOT unset and no project marker above
// it. This is a strict FALLBACK: an on-disk corpus (binary-walk hit or
// MALLCOP_REPO_ROOT) always wins, so dev edit-and-reload of the corpus is
// preserved. See the loaders' corpusBytes helpers.
//
// This package imports ONLY "embed" — it carries no dependency that could let
// the floor path reach inference, so importing it from core/agent and core/tools
// does not violate either import-lint.
package mallcoplegion

import _ "embed"

// OperatorDecisionsYAML is the byte-for-byte contents of
// agents/rules/operator-decisions.yaml at build time. Because //go:embed copies
// the exact file, these bytes are identical to the on-disk corpus the SHA pin
// (core/tools.expectedOperatorRulesSHA256) describes — by construction, with no
// separate copy that could drift. The embed==disk test makes that invariant
// explicit and catches a stale checked-in pin.
//
//go:embed agents/rules/operator-decisions.yaml
var OperatorDecisionsYAML []byte
