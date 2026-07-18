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

// eventIDSuffixStripBound bounds how many trailing "-<segment>" pieces
// eventIDSuffixStrippedCandidates strips off a "finding-"-stripped id when
// generating suffix-stripped candidates (mallcoppro-323). Bounded so a
// pathological id with many hyphens cannot turn this into unbounded work;
// every real suffix-ID detector's suffix is a handful of "-"-joined words at
// most (e.g. "-inj-command-injection-chain" is 4 segments).
const eventIDSuffixStripBound = 6

// eventIDCandidates returns the case-insensitive lookup keys SAFE FOR EXACT
// MATCH on a requested event id: the id as given, and — when the id carries
// a "finding-" prefix — the id with that prefix stripped. A stored event
// matches a requested id when its own id (lowercased) appears in this set.
//
// mallcoppro-323 code review (MAJOR): this function does NOT generate
// suffix-stripped candidates (see eventIDSuffixStrippedCandidates below) —
// an earlier version of this fix did, and that was a live correctness bug.
// Both callers of eventIDCandidates (get_raw_event.go, search_events.go)
// feed its output straight into a SILENT exact-match set: the first stored
// event whose id is a MEMBER of that set wins, with no ambiguity check at
// all. A suffix-stripped candidate is a GUESS, not a genuine alternate
// identity for the requested id — treating it as exact-match-safe meant a
// query for an EXISTING, EXACT stored id ("abc-1-2-3") could silently return
// a WRONG, shorter, unrelated stored event ("abc") whenever the store
// happened to contain one, with no error, no ambiguity signal, nothing. Only
// the finding-/bare "finding-" prefix strip is safe here, because it is a
// literal, unconditional, LOSSLESS transform of a FIXED 8-character prefix —
// never a heuristic truncation of the id's own content. Suffix-stripped
// guesses are routed EXCLUSIVELY through resolveEventIDPrefix's
// ambiguity-aware unique-prefix resolution instead (a collision there is a
// hard error, never a silent pick) — see that function's doc comment.
func eventIDCandidates(id string) []string {
	lower := strings.ToLower(id)
	out := []string{lower}
	if stripped, ok := strings.CutPrefix(lower, "finding-"); ok {
		out = append(out, stripped)
	}
	return out
}

// eventIDSuffixStrippedCandidates returns ADDITIONAL, HEURISTIC candidates
// for a requested event id, generated by progressively stripping trailing
// "-<segment>" pieces off the id's "finding-"-stripped form (bounded,
// eventIDSuffixStripBound iterations) — mallcoppro-323. Generated ONLY when
// id actually carried a "finding-" prefix: a BARE id (no "finding-" prefix)
// is never suffix-stripped at all, because there is no signal it is a
// compound "eventID-<suffix>" shape rather than simply a legitimate
// hyphenated event id a customer's own id scheme assigned (file/exec/sibling
// connectors and --events JSONL preserve arbitrary caller-supplied ids
// verbatim — GitHub's evt_+hex ids are the only shape actually produced by a
// suffix-ID detector, but this function must not assume every store only
// ever holds GitHub ids).
//
// The suffix-stripping direction exists because 5 detector families
// (injection-probe, git-oops, secrets-exposure, malicious-skill,
// dependency-tamper) mint Finding.ID = "finding-"+ev.ID+"-<suffix>" — e.g.
// "finding-evt_ab12cd34ef56-inj-command-injection-chain". The PLAIN
// "finding-" strip alone leaves "evt_ab12cd34ef56-inj-command-injection-chain",
// which is LONGER than the stored event id "evt_ab12cd34ef56" and so can
// never resolve as an exact match, nor as a unique PREFIX match on its own
// (a longer candidate can never be a prefix of a shorter stored id).
// Stripping trailing "-<segment>" pieces one at a time recovers the bare
// event id as one of the generated candidates.
//
// SAFETY: the caller (resolveEventIDPrefix) feeds these candidates ONLY into
// resolveIDPrefixMulti's ambiguity-aware unique-prefix resolution, NEVER
// into an exact-match set — see eventIDCandidates' doc comment for why that
// distinction is load-bearing, not stylistic. If a stripped candidate is a
// prefix of MORE THAN ONE stored id, resolveIDPrefixMulti reports it as
// ambiguous (an error) rather than silently picking one.
//
// mallcoppro-323 also adds Finding.EventIDs as the primary, structured
// linkage for these detectors — this id-lenience widening is the defensive
// backstop for a finding id a model echoes from earlier conversation
// context, or an older stored record predating EventIDs.
func eventIDSuffixStrippedCandidates(id string) []string {
	lower := strings.ToLower(id)
	stripped, hadFindingPrefix := strings.CutPrefix(lower, "finding-")
	if !hadFindingPrefix {
		return nil
	}

	var out []string
	cur := stripped
	for i := 0; i < eventIDSuffixStripBound; i++ {
		idx := strings.LastIndex(cur, "-")
		if idx <= 0 {
			break
		}
		cur = cur[:idx]
		out = append(out, cur)
	}
	return out
}

// resolveEventIDPrefix is the mallcoppro-448 unique-prefix fallback for event
// ids: it tries requested as a git-style short-SHA prefix against pool (the
// full set of stored event ids), using the SAME finding-/bare candidate forms
// eventIDCandidates tries for exact match, PLUS (mallcoppro-323) the
// heuristic suffix-stripped candidates from eventIDSuffixStrippedCandidates
// — so a truncated "finding-"-prefixed id still strips to a bare-event-id
// prefix, and a suffix-ID finding id's compound suffix still resolves to its
// bare event id, both exactly mirroring the exact-match lenience direction
// but through the ambiguity-aware resolver, never a silent guess. Call ONLY
// after exact match (via eventIDCandidates) has already failed — an EXACT
// match on the id as given always wins before any candidate here is even
// considered, by construction of that call order in every caller.
func resolveEventIDPrefix(requested string, pool []string) (matched string, ambiguous []string, total int) {
	prefixes := append(eventIDCandidates(requested), eventIDSuffixStrippedCandidates(requested)...)
	return resolveIDPrefixMulti(requested, prefixes, pool)
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
