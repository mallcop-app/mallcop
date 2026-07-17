// id_lenience.go — the "finding-" prefix leniency shared by the id filters on
// search_findings, search_events, and get_raw_event (mallcoppro-45c), plus
// the git-style unique-prefix ("short SHA") id lookup layered on top of it
// (mallcoppro-448).
//
// Finding IDs are stored with a "finding-" prefix (e.g. "finding-ca24a2...");
// event IDs are the bare hash. A model reading the console sees both forms —
// the finding row shows the prefixed id, the underlying event's own id field
// is bare — and reliably guesses the wrong one for whichever tool it calls
// (mallcoppro-45c: search_findings({ids:["ca24a2..."]}) exact-matched nothing
// because the stored finding id was "finding-ca24a2..."). Both directions are
// tried so either form always resolves:
//
//   - findingIDCandidates: a bare id also matches a finding stored under
//     "finding-"+id.
//   - eventIDCandidates: a "finding-"-prefixed id also matches an event
//     stored under the bare id (the prefix stripped).
//
// mallcoppro-448: a truncated id — copied from a UI list that only shows the
// first several characters, or paraphrased by the model from earlier
// conversation context — used to dead-end at exact match even after the
// finding-/bare lenience above. resolveEventIDPrefix / resolveFindingIDPrefix
// add a SECOND fallback, tried only after exact match (including the
// finding-/bare forms) has already failed: git-style unique-prefix
// resolution. A requested id that is a prefix of EXACTLY ONE stored id
// resolves to it; a prefix shorter than minIDPrefixLen is never eligible
// (too likely to coincidentally match many ids); a prefix matching more than
// one stored id is reported back to the caller as ambiguous (via
// ambiguousIDError) rather than silently picking one, so the model can
// retry with a longer prefix or the exact id.
package tools

import (
	"fmt"
	"sort"
	"strings"
)

// minIDPrefixLen is the shortest a truncated id may be before it is eligible
// for unique-prefix resolution (mallcoppro-448). Below this length a prefix
// is too likely to coincidentally match multiple stored hex/slug ids —
// treated as no-match (the existing exact-match dead end), never as an
// auto-resolved or ambiguous result.
const minIDPrefixLen = 4

// maxAmbiguousIDCandidates caps how many candidate ids an ambiguous-prefix
// error lists, so an under-specified prefix against a large store doesn't
// blow the tool_result out to hundreds/thousands of ids.
const maxAmbiguousIDCandidates = 10

// findingIDCandidates returns the case-insensitive lookup keys for a
// requested finding id: the id as given, and the id with a "finding-" prefix
// added. A stored finding matches a requested id when its own id (lowercased)
// appears in this set.
func findingIDCandidates(id string) []string {
	lower := strings.ToLower(id)
	return []string{lower, strings.ToLower("finding-" + id)}
}

// eventIDCandidates returns the case-insensitive lookup keys for a requested
// event id: the id as given, and — when the id itself carries a "finding-"
// prefix — the id with that prefix stripped. A stored event matches a
// requested id when its own id (lowercased) appears in this set.
func eventIDCandidates(id string) []string {
	lower := strings.ToLower(id)
	out := []string{lower}
	if stripped, ok := strings.CutPrefix(lower, "finding-"); ok {
		out = append(out, stripped)
	}
	return out
}

// resolveEventIDPrefix is the mallcoppro-448 unique-prefix fallback for event
// ids: it tries requested as a git-style short-SHA prefix against pool (the
// full set of stored event ids), using the SAME finding-/bare candidate forms
// eventIDCandidates tries for exact match — so a truncated
// "finding-"-prefixed id still strips to a bare-event-id prefix, exactly
// mirroring the exact-match lenience direction. Call ONLY after exact match
// (via eventIDCandidates) has already failed.
func resolveEventIDPrefix(requested string, pool []string) (matched string, ambiguous []string, total int) {
	return resolveIDPrefixMulti(requested, eventIDCandidates(requested), pool)
}

// resolveFindingIDPrefix is the mallcoppro-448 unique-prefix fallback for
// finding ids: it tries requested as a git-style short-SHA prefix against
// pool (the full set of stored finding ids), using the SAME bare/"finding-"
// candidate forms findingIDCandidates tries for exact match — so a truncated
// BARE hash still resolves a "finding-"-prefixed stored id. Call ONLY after
// exact match (via findingIDCandidates) has already failed.
func resolveFindingIDPrefix(requested string, pool []string) (matched string, ambiguous []string, total int) {
	return resolveIDPrefixMulti(requested, findingIDCandidates(requested), pool)
}

// resolveIDPrefixMulti is the shared git-style unique-prefix resolver.
// requested is the RAW id as given (before the finding-/bare lenience
// expansion); prefixes is the set of already-lowercased lenient candidate
// forms (from eventIDCandidates / findingIDCandidates) to try as a prefix
// into pool (any casing). Matches are unioned across all candidate prefixes
// (deduplicated, since the finding-/bare candidate forms can otherwise
// double-count the same stored id).
//
// The minIDPrefixLen gate is enforced against requested itself, NOT against
// each expanded candidate: findingIDCandidates unconditionally prepends the
// literal "finding-" (8 chars), so gating per-candidate would let a
// genuinely short, unspecific fragment like "fee" sail through disguised as
// the 11-char candidate "finding-fee" — defeating the whole point of the
// length floor. Gating on the raw input instead means "fee" is rejected
// before any candidate is ever tried, exactly as if no lenience existed.
//
// Returns:
//   - (id, nil, 1) when exactly one stored id matched any candidate prefix.
//   - ("", candidates, total) when MORE THAN ONE stored id matched — total is
//     the full match count, candidates is capped at
//     maxAmbiguousIDCandidates (sorted, so the cap is deterministic) for the
//     caller to report back to the model via ambiguousIDError.
//   - ("", nil, 0) when requested is shorter than minIDPrefixLen, or no
//     candidate prefix matched anything — the caller keeps its existing
//     not-found behavior.
func resolveIDPrefixMulti(requested string, prefixes []string, pool []string) (matched string, ambiguous []string, total int) {
	if len(requested) < minIDPrefixLen {
		return "", nil, 0
	}

	seen := map[string]bool{}
	var matches []string
	for _, id := range pool {
		lower := strings.ToLower(id)
		if seen[lower] {
			continue
		}
		for _, p := range prefixes {
			if strings.HasPrefix(lower, p) {
				seen[lower] = true
				matches = append(matches, lower)
				break
			}
		}
	}

	switch len(matches) {
	case 0:
		return "", nil, 0
	case 1:
		return matches[0], nil, 1
	default:
		sort.Strings(matches)
		total = len(matches)
		if len(matches) > maxAmbiguousIDCandidates {
			matches = matches[:maxAmbiguousIDCandidates]
		}
		return "", matches, total
	}
}

// ambiguousIDError formats the standard "which one did you mean" error text
// for an ambiguous prefix match (mallcoppro-448), shared by get_raw_event,
// search_events, and search_findings so the model sees the same shape of
// disambiguation prompt — the full candidate list (capped) plus the total
// match count — regardless of which tool it called.
func ambiguousIDError(toolName, requested string, candidates []string, total int) error {
	shown := candidates
	suffix := ""
	if total > len(candidates) {
		suffix = fmt.Sprintf(" (showing first %d)", len(candidates))
	}
	return fmt.Errorf("%s: id %q is ambiguous — prefix matches %d stored ids%s: %s. "+
		"Supply a longer prefix or the exact id.",
		toolName, requested, total, suffix, strings.Join(shown, ", "))
}
