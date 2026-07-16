// Package redact scrubs secret-bearing key tokens (metered run keys and BYOI
// vendor keys) from transcripts and diffs before they are persisted to disk.
//
// It is a pure, dependency-free helper — it holds no inference-provider handle
// and imports nothing from the commercial billing layer — so the self-extension
// authoring packages (engine, opencode, proposer, router) can run their
// untrusted authoring output through it without pulling the commercial
// credential lifecycle into their dependency graph.
package redact

import (
	"regexp"
	"strings"
)

// redactedMarker replaces secrets in persisted transcripts.
const redactedMarker = "***REDACTED***"

// skPattern matches secret-bearing key tokens so Redact can scrub keys that are
// not the exact one handed to it (e.g. a SIBLING key emitted by nested tooling
// output). Three alternatives, most specific first:
//
//   - mallcop-sk-*   — the product's own short-lived run keys.
//   - sk-ant-*       — Anthropic-style vendor keys (the common BYOI shape).
//   - sk-<20+ alnum> — a conservative catch for other "sk-"-prefixed vendor
//     keys. It requires 20+ unbroken alphanumerics (no space/hyphen), so it
//     matches real keys but not prose; the exact-string pass remains the primary
//     guarantee, this is defense-in-depth for leaked siblings.
//
// mallcop-sk-* is listed first and, because it starts at an earlier byte than
// any bare "sk-", is chosen by leftmost match — so a mallcop key is redacted
// whole (no "mallcop-" prefix is left dangling by the bare-sk alternative).
var skPattern = regexp.MustCompile(`mallcop-sk-[A-Za-z0-9_\-]+|sk-ant-[A-Za-z0-9_\-]+|sk-[A-Za-z0-9]{20,}`)

// Redact replaces the exact key and any mallcop-sk-*/sk-ant-*/sk-<20+> token in
// s with a fixed marker. The exact-string pass runs first so the EXACT key is
// always scrubbed regardless of its shape (a vendor "sk-ant-..." or "sk-..."
// BYOI key is caught by this pass even where the regexp is conservative); the
// regexp then catches any other key. Callers MUST run transcripts through Redact
// before persisting them to disk.
func Redact(s, key string) string {
	if key != "" {
		s = strings.ReplaceAll(s, key, redactedMarker)
	}
	return skPattern.ReplaceAllString(s, redactedMarker)
}
