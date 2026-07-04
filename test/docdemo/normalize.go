//go:build docdemo

package docdemo

import (
	"regexp"
	"strings"
)

// Normalization for non-deterministic fields. Every substitution here is
// documented with the shown-output placeholder it maps to — the doc text uses
// the SAME placeholder literal, so after normalization the two strings are
// directly comparable. Nothing here weakens a comparison by dropping a field;
// it only substitutes a value that cannot be pinned (a temp dir path, a
// timestamp, a git SHA) for the placeholder the doc already shows.
var (
	// RFC3339-ish timestamps -> <timestamp>.
	reTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z`)

	// git SHAs, 12-40 lowercase hex chars -> <sha>. Word-boundary guarded so
	// it doesn't eat unrelated hex-looking identifiers.
	reSHA = regexp.MustCompile(`\b[0-9a-f]{12,40}\b`)
)

// normalizeDynamic replaces non-deterministic substrings with the fixed
// placeholders the docs use, so a captured real run and the doc's shown text
// become directly comparable. dirs are the exact absolute temp-dir paths this
// test created (known exactly, not guessed by regex) that the real binary's
// output embeds verbatim (e.g. `mallcop init`'s printed --dir-derived paths).
func normalizeDynamic(s string, dirs ...string) string {
	for _, d := range dirs {
		if d == "" {
			continue
		}
		s = strings.ReplaceAll(s, d, "<dir>")
	}
	s = reTimestamp.ReplaceAllString(s, "<timestamp>")
	s = reSHA.ReplaceAllString(s, "<sha>")
	return s
}
