// search_findings.go — the search-findings pure read tool, reusing pkg/finding
// and reading the findings stream from core/store.
//
// SearchFindings replays the findings stream from a *store.Store and returns the
// typed finding.Finding records that pass the actor/source/since filters. It is
// a PURE read: it opens no channel, runs no inference, and never writes. Its
// only effect is to read committed records from the git-backed store.
package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// SearchFindingsInput is the filter for SearchFindings. Every field is optional;
// an empty filter returns every finding in the stream.
//
// Actor / Source / Type are case-insensitive equality filters. IDs restricts to
// findings whose exact id is listed (case-insensitive) — the "ground on the
// on-screen finding" filter that lets the analyst confirm a seeded finding by its
// id instead of guessing a filter from prose. Since bounds the finding timestamp
// (inclusive lower bound); a zero time means "unbounded".
//
// Type and IDs mirror SearchEventsInput (core/tools/search_events.go): before
// they existed, a model that (correctly) scoped a lookup with {"type":"..."} or
// {"ids":[...]} had those keys SILENTLY dropped by the JSON decoder and got the
// ENTIRE stream back — 2000+ findings of garbage — instead of the one finding it
// asked for (mallcoppro-a8b). Supporting them lets a question ABOUT a finding be
// scoped to that finding's real type/id.
type SearchFindingsInput struct {
	Actor  string    `json:"actor,omitempty"`
	Source string    `json:"source,omitempty"`
	Type   string    `json:"type,omitempty"`
	IDs    []string  `json:"ids,omitempty"`
	Since  time.Time `json:"since,omitempty"`
}

// SearchFindings reads the findings stream from the store and returns the
// findings matching the filter, oldest first.
//
// A finding with a zero timestamp is dropped when a Since bound is set (it
// cannot be proven to fall within the window), consistent with the original
// tool which skipped findings whose timestamp could not be parsed. Without a
// Since bound, timestamp is ignored entirely.
//
// SearchFindings returns an error when the store cannot be read, a record is
// not valid finding JSON, or (mallcoppro-448) a requested id in IDs has no
// exact match and its git-style unique-prefix resolution is ambiguous
// (matches more than one stored finding id) — the error text lists the
// candidate ids so the caller can disambiguate. An id with no match at all
// (exact or prefix) is NOT an error; it simply contributes nothing to the
// result, same as today.
func SearchFindings(s *store.Store, in SearchFindingsInput) ([]finding.Finding, error) {
	if s == nil {
		return nil, fmt.Errorf("search-findings: nil store")
	}
	raws, err := s.Load(store.KindFindings)
	if err != nil {
		return nil, fmt.Errorf("search-findings: load findings: %w", err)
	}

	all := make([]finding.Finding, 0, len(raws))
	for i, raw := range raws {
		var f finding.Finding
		// §3.7: normalize key casing at the boundary so PascalCase / camelCase /
		// kebab-case fixtures parse into the snake_case struct tags.
		if err := json.Unmarshal(normalizeRecordKeys(raw), &f); err != nil {
			return nil, fmt.Errorf("search-findings: decode finding %d: %w", i, err)
		}
		all = append(all, f)
	}

	// An empty-string entry in IDs would otherwise match no finding and, being a
	// filter, wrongly empty the result; build a normalized lookup set that skips
	// blanks so a model that echoes an "" id is tolerated (mirrors search_events).
	//
	// mallcoppro-45c: each requested id also matches a stored finding whose id
	// carries the standard "finding-" prefix — a model that queried with the
	// bare event hash (as shown elsewhere in the console) still finds the
	// prefixed finding, instead of exact-equality silently returning nothing.
	//
	// mallcoppro-448: an id with no exact match (even with the bare/"finding-"
	// lenience above) falls back to git-style unique-prefix resolution — a
	// truncated id still resolves as long as it is a prefix of exactly one
	// stored finding id. An ambiguous prefix errors out the whole call (with the
	// candidate ids in the error text) so the model disambiguates before
	// trusting a (possibly wrong) result; a prefix that matches nothing is left
	// to fall through to the existing no-match behavior for that id.
	pool := make(map[string]struct{}, len(all))
	poolList := make([]string, 0, len(all))
	for _, f := range all {
		lower := strings.ToLower(f.ID)
		if _, ok := pool[lower]; ok {
			continue
		}
		pool[lower] = struct{}{}
		poolList = append(poolList, f.ID)
	}

	// idsRequested tracks whether an id FILTER was in effect (at least one
	// non-blank entry in in.IDs), independent of whether idSet ends up
	// populated. mallcoppro-448 can legitimately leave idSet empty for a
	// requested id that resolves to nothing (short prefix, or a prefix/exact
	// match that matches no stored finding) — that must still filter the
	// result down to zero, not be mistaken for "no id filter was given at
	// all" (the len(idSet)>0 check below would otherwise return everything).
	idSet := map[string]struct{}{}
	idsRequested := false
	for _, id := range in.IDs {
		if id == "" {
			continue
		}
		idsRequested = true
		matchedExact := false
		for _, c := range findingIDCandidates(id) {
			if _, ok := pool[c]; ok {
				idSet[c] = struct{}{}
				matchedExact = true
			}
		}
		if matchedExact {
			continue
		}
		if matched, ambiguous, total := resolveFindingIDPrefix(id, poolList); matched != "" {
			idSet[matched] = struct{}{}
		} else if len(ambiguous) > 0 {
			return nil, ambiguousIDError("search-findings", id, ambiguous, total)
		}
	}

	out := make([]finding.Finding, 0, len(all))
	for _, f := range all {
		if in.Actor != "" && !strings.EqualFold(f.Actor, in.Actor) {
			continue
		}
		if in.Source != "" && !strings.EqualFold(f.Source, in.Source) {
			continue
		}
		if in.Type != "" && !strings.EqualFold(f.Type, in.Type) {
			continue
		}
		if idsRequested {
			if _, ok := idSet[strings.ToLower(f.ID)]; !ok {
				continue
			}
		}
		if !in.Since.IsZero() {
			if f.Timestamp.IsZero() || f.Timestamp.Before(in.Since) {
				continue
			}
		}
		out = append(out, f)
	}
	return out, nil
}
