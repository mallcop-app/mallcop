// recalldelta.go — RECALL-AWARE gate deltas (C6, rd mallcoppro-a07).
//
// diffExamReports already enforces the monotonic-widen CONTRACT (no regression /
// coverage +1 / no new firings) as pass/fail findings. This file exposes the
// same base..head exam-report pair as a MACHINE-READABLE recall/precision delta
// the self-heal loop consumes to CONFIRM a gap closed without regressing recall —
// separate from the yes/no verdict, at per-(scenario, family) resolution.
//
// It is a pure function over the two examReports the in-tree stage-3 lane already
// computes (base + head); it adds NO exam run and NO detection change (R9
// untouched). The result rides on GateResult as the omitempty RecallDelta /
// PrecisionDelta fields — additive and backward-compatible, exactly like NovelGap
// (which was likewise added without a GateSchemaVersion bump): a consumer that
// does not know the fields ignores them; the mallcop-pro decoder
// (internal/selfext/engine/gate.go) should be updated to READ them when it wants
// the recall signal, but is not broken by their presence.
//
// RECALL is measured over must_fire labels: an "attack caught" unit is one
// (scenario, must_fire family) whose family appears among the scenario's emitted
// findings. PRECISION is measured over must_not_fire labels: a "benign kept
// silent" unit is one (scenario, must_not_fire family) whose family is ABSENT
// from the emitted set. The deltas name exactly which units flipped base->head.
package selfgate

// ScenarioFamily identifies one (scenario, detector-family) unit — the atom the
// recall/precision deltas are reported at. Family is normalized (lowercase).
type ScenarioFamily struct {
	ScenarioID string `json:"scenario_id"`
	Family     string `json:"family"`
}

// RecallDelta is the base..head change in ATTACKS CAUGHT, over must_fire labels.
// BaseDetected / HeadDetected are the total (scenario, must_fire family) units
// whose family was emitted at base / head. NewlyDetected are the units caught at
// head but not base (the recall this proposal ADDS — the gap-close it must
// demonstrate); NewlyMissed are units caught at base but not head (a recall
// REGRESSION the self-heal loop must never accept). Both lists are sorted for
// deterministic output.
type RecallDelta struct {
	BaseDetected  int              `json:"base_detected"`
	HeadDetected  int              `json:"head_detected"`
	NewlyDetected []ScenarioFamily `json:"newly_detected"`
	NewlyMissed   []ScenarioFamily `json:"newly_missed"`
}

// PrecisionDelta is the base..head change in BENIGN KEPT SILENT, over
// must_not_fire labels. BaseClean / HeadClean are the total (scenario,
// must_not_fire family) units whose family was ABSENT (correctly silent) at base
// / head. NewlyViolated are units that were clean at base but FIRE at head (new
// false positives — the precision REGRESSION the loop must never accept);
// NewlyClean are units that fired at base but are silent at head (precision
// improvements). Both lists are sorted for deterministic output.
type PrecisionDelta struct {
	BaseClean     int              `json:"base_clean"`
	HeadClean     int              `json:"head_clean"`
	NewlyViolated []ScenarioFamily `json:"newly_violated"`
	NewlyClean    []ScenarioFamily `json:"newly_clean"`
}

// recallPrecisionDelta computes the recall and precision deltas between the base
// and head exam reports. It is pure — no I/O, no exam run — over the SAME rows
// diffExamReports consumes. Families are normalized the same way (normalizeFamily)
// so the deltas agree with the contract findings.
//
// A scenario present in only one report contributes its units to that side only:
// a must_fire family detected only at head (scenario newly added, or newly
// passing) is NewlyDetected; a must_not_fire family that fires only at head is
// NewlyViolated. Detection at each side is read from that side's OWN emitted set,
// so an added scenario's units are attributed correctly even with no base row.
func recallPrecisionDelta(base, head examReport) (*RecallDelta, *PrecisionDelta) {
	// emittedByScenario maps scenario id -> set of normalized emitted families.
	index := func(rep examReport) map[string]map[string]bool {
		out := make(map[string]map[string]bool, len(rep.Rows))
		for _, r := range rep.Rows {
			set := make(map[string]bool, len(r.Emitted))
			for _, e := range r.Emitted {
				if f := normalizeFamily(e); f != "" {
					set[f] = true
				}
			}
			out[r.ScenarioID] = set
		}
		return out
	}
	baseEmitted := index(base)
	headEmitted := index(head)

	// detectedUnits collects every (scenario, must_fire family) unit whose family
	// is emitted in the given report's OWN row set — recall, side by side.
	// cleanUnits collects every (scenario, must_not_fire family) unit whose family
	// is ABSENT — precision, side by side. Both are keyed by "scenario|family" so
	// the base/head sets can be diffed.
	detected := func(rep examReport, emitted map[string]map[string]bool) map[string]ScenarioFamily {
		out := map[string]ScenarioFamily{}
		for _, r := range rep.Rows {
			for _, fam := range r.MustFire {
				f := normalizeFamily(fam)
				if f == "" {
					continue
				}
				if emitted[r.ScenarioID][f] {
					out[r.ScenarioID+"|"+f] = ScenarioFamily{ScenarioID: r.ScenarioID, Family: f}
				}
			}
		}
		return out
	}
	clean := func(rep examReport, emitted map[string]map[string]bool) map[string]ScenarioFamily {
		out := map[string]ScenarioFamily{}
		for _, r := range rep.Rows {
			for _, fam := range r.MustNotFire {
				f := normalizeFamily(fam)
				if f == "" {
					continue
				}
				if !emitted[r.ScenarioID][f] {
					out[r.ScenarioID+"|"+f] = ScenarioFamily{ScenarioID: r.ScenarioID, Family: f}
				}
			}
		}
		return out
	}

	baseDet := detected(base, baseEmitted)
	headDet := detected(head, headEmitted)
	baseClean := clean(base, baseEmitted)
	headClean := clean(head, headEmitted)

	rd := &RecallDelta{
		BaseDetected:  len(baseDet),
		HeadDetected:  len(headDet),
		NewlyDetected: diffUnits(headDet, baseDet),
		NewlyMissed:   diffUnits(baseDet, headDet),
	}
	pd := &PrecisionDelta{
		BaseClean:     len(baseClean),
		HeadClean:     len(headClean),
		NewlyViolated: diffUnits(baseClean, headClean), // clean at base, not clean at head
		NewlyClean:    diffUnits(headClean, baseClean), // clean at head, not clean at base
	}
	return rd, pd
}

// diffUnits returns the ScenarioFamily values whose key is in a but not b,
// sorted (by scenario id, then family) for deterministic output.
func diffUnits(a, b map[string]ScenarioFamily) []ScenarioFamily {
	out := []ScenarioFamily{}
	for k, v := range a {
		if _, ok := b[k]; !ok {
			out = append(out, v)
		}
	}
	sortScenarioFamilies(out)
	return out
}

// sortScenarioFamilies orders by scenario id then family — a small insertion
// sort keeps this file dependency-free (sort is already imported by validate.go,
// but keeping the helper local and explicit documents the ordering contract).
func sortScenarioFamilies(s []ScenarioFamily) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0; j-- {
			if less(s[j], s[j-1]) {
				s[j], s[j-1] = s[j-1], s[j]
			} else {
				break
			}
		}
	}
}

func less(a, b ScenarioFamily) bool {
	if a.ScenarioID != b.ScenarioID {
		return a.ScenarioID < b.ScenarioID
	}
	return a.Family < b.Family
}
