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
// Actor / Source are case-insensitive equality filters. Since bounds the
// finding timestamp (inclusive lower bound); a zero time means "unbounded".
type SearchFindingsInput struct {
	Actor  string    `json:"actor,omitempty"`
	Source string    `json:"source,omitempty"`
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
// SearchFindings returns an error only when the store cannot be read or a record
// is not valid finding JSON.
func SearchFindings(s *store.Store, in SearchFindingsInput) ([]finding.Finding, error) {
	if s == nil {
		return nil, fmt.Errorf("search-findings: nil store")
	}
	raws, err := s.Load(store.KindFindings)
	if err != nil {
		return nil, fmt.Errorf("search-findings: load findings: %w", err)
	}

	out := make([]finding.Finding, 0, len(raws))
	for i, raw := range raws {
		var f finding.Finding
		// §3.7: normalize key casing at the boundary so PascalCase / camelCase /
		// kebab-case fixtures parse into the snake_case struct tags.
		if err := json.Unmarshal(normalizeRecordKeys(raw), &f); err != nil {
			return nil, fmt.Errorf("search-findings: decode finding %d: %w", i, err)
		}
		if in.Actor != "" && !strings.EqualFold(f.Actor, in.Actor) {
			continue
		}
		if in.Source != "" && !strings.EqualFold(f.Source, in.Source) {
			continue
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
