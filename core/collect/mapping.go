// Package collect is the OFFLINE, DETERMINISTIC feedstock-collector half of the
// self-extension loop. It mines a completed scan's OWN store — the six
// append-only streams plus the directive stream — for coverage gaps that the
// mallcop-pro proposer can turn into add-only proposals. It does NO inference, NO
// network I/O, and NO spend: every function is a pure read of a *store.Store,
// with deterministic (sorted) output.
//
// It emits plain, JSON-taggable data structs (MappingGap, GapCandidate) that
// cross the module boundary into mallcop-pro's proposer unchanged — so the shapes
// here are a stable contract, not internal detail.
//
// Two collectors:
//
//	UnmappedActions — ranks the raw source actions that fell through to a
//	                  connector's "<source>_other" default bucket (a mapping gap).
//	DetectorGaps    — surfaces three flavors of detection gap: real detect-miss
//	                  false-negatives (from exam-detect fidelity rows), human-
//	                  override false-positives (suppress directive vs. agent
//	                  decision), and consensus-dissent clusters.
package collect

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// defaultBucketSuffix is the suffix every connector appends to its source id for
// the "no classifier matched" default event type — "github_other",
// "<sourceID>_other" (decl). An event whose Type is exactly Source+suffix is,
// by construction, unmapped. Kept in one place so the collector's filter and the
// connectors' emission stay coupled.
const defaultBucketSuffix = "_other"

// maxSampleIDs caps the sample event ids carried on a gap so a hot, high-volume
// unmapped action does not bloat the proposal feed. Samples are for provenance
// (jump to the raw event), not exhaustive enumeration — Count carries the volume.
const maxSampleIDs = 10

// MappingGap is a proposer-ready record of one unmapped (Source, RawAction) pair:
// a raw source action a connector could not classify, so it landed in the
// "<source>_other" default bucket. The proposer maps RawAction to one of
// SuggestedVocabulary to close the gap. Plain data with json tags — it crosses
// the module boundary into mallcop-pro unchanged.
type MappingGap struct {
	// Source is the connector source id (e.g. "github", "stripe").
	Source string `json:"source"`
	// RawAction is the raw, unclassified source action string (the "unmapped_action"
	// tag the connector wrote into the flat event payload). May be empty for a
	// legacy default-bucket event that predates the tag.
	RawAction string `json:"raw_action"`
	// Count is how many events in the scan share this (Source, RawAction) gap.
	Count int `json:"count"`
	// SampleEventIDs are up to maxSampleIDs event ids for this gap, sorted, for
	// provenance.
	SampleEventIDs []string `json:"sample_event_ids"`
	// SuggestedVocabulary is the sorted set of known event types the proposer may
	// map RawAction onto (detect.KnownEventTypes()). Identical across gaps — the
	// proposer picks which member fits.
	SuggestedVocabulary []string `json:"suggested_vocabulary"`
}

// UnmappedActions replays the events stream, keeps only events that stayed in a
// connector's "<source>_other" default bucket, groups them by
// (Source, unmapped_action), and returns one ranked MappingGap per group. Ranking
// is deterministic: Count descending, then Source ascending, then RawAction
// ascending. It is a pure read — no inference, no network.
func UnmappedActions(st *store.Store) ([]MappingGap, error) {
	raws, err := st.Load(store.KindEvents)
	if err != nil {
		return nil, fmt.Errorf("collect: load events: %w", err)
	}

	type key struct{ source, action string }
	agg := map[key]*MappingGap{}
	// Deterministic iteration: track insertion order is unnecessary because we
	// sort the final slice, but we must not rely on map order for correctness.
	for i, raw := range raws {
		var ev event.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("collect: decode event %d: %w", i, err)
		}
		// Only default-bucket events are mapping gaps.
		if ev.Type != ev.Source+defaultBucketSuffix {
			continue
		}
		var pl struct {
			UnmappedAction string `json:"unmapped_action"`
		}
		if len(ev.Payload) > 0 {
			// A payload that fails to decode is not fatal — the event still counts
			// as an unmapped-bucket event, just with an empty raw action.
			_ = json.Unmarshal(ev.Payload, &pl)
		}
		k := key{ev.Source, pl.UnmappedAction}
		g := agg[k]
		if g == nil {
			g = &MappingGap{Source: ev.Source, RawAction: pl.UnmappedAction}
			agg[k] = g
		}
		g.Count++
		g.SampleEventIDs = append(g.SampleEventIDs, ev.ID)
	}

	vocab := knownVocabulary()
	out := make([]MappingGap, 0, len(agg))
	for _, g := range agg {
		sort.Strings(g.SampleEventIDs)
		if len(g.SampleEventIDs) > maxSampleIDs {
			g.SampleEventIDs = g.SampleEventIDs[:maxSampleIDs]
		}
		g.SuggestedVocabulary = vocab
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count // rank: most frequent gap first
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].RawAction < out[j].RawAction
	})
	return out, nil
}

// knownVocabulary returns the sorted set of event types some built-in detector
// gates on — the vocabulary a proposer may map an unmapped action onto.
func knownVocabulary() []string {
	m := detect.KnownEventTypes()
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
