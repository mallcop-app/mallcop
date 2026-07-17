// id_lenience.go — the "finding-" prefix leniency shared by the id filters on
// search_findings, search_events, and get_raw_event (mallcoppro-45c).
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
package tools

import "strings"

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
