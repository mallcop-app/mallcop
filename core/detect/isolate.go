package detect

import (
	"encoding/json"

	"github.com/mallcop-app/mallcop/pkg/event"
)

// cloneEventsForDetector returns a per-detector ISOLATED view of the events: a
// fresh slice whose elements are value copies of each event, with every event's
// mutable Payload (a json.RawMessage / []byte) DEEP-cloned into its own backing
// array. All other event fields (ID, Source, Type, Actor, Org, Timestamp) are
// immutable value types, so the shallow struct copy already isolates them.
//
// This is the framework half of K7 HOLE 1a: detect.Detect threads one events
// slice (and its backing array) through every registered detector, so without
// this a detector that wrote through its argument — events[i].Payload = nil —
// would silence every later security detector reading that payload, and (since
// detectors run in their own goroutines) race with them. Handing each detector
// its own deep copy makes that structurally impossible while staying
// behaviour-identical for the pure framework detectors.
//
// SCOPE: this isolates the INPUT only. It is one of three things that together
// let detect.go accept a leaked timed-out goroutine: the other two are the
// immutable priv-escalation tuning snapshot (privEscalationTuning — so a leaked
// goroutine reads a frozen copy of the knobs, never the live maps ApplyTuning
// writes) and the K7 shape gate's ban on an authored detector naming any
// framework mutator (core/selfgate RuleShapeFrameworkRef). Do not read the old
// claim that the input clone alone means a leaked goroutine "mutates only its own
// copy": that was false while detect.ApplyTuning was reachable from an authored
// Detect; it holds now because all three pieces are in place.
//
// A nil events slice clones to nil (detectors treat nil and empty identically),
// and a nil Payload stays nil rather than becoming an empty non-nil slice, so
// the copy is byte-for-byte equivalent to the input for every reader.
func cloneEventsForDetector(events []event.Event) []event.Event {
	if events == nil {
		return nil
	}
	out := make([]event.Event, len(events))
	copy(out, events) // value copy of every field, incl. the Payload slice header
	for i := range out {
		if out[i].Payload != nil {
			p := make(json.RawMessage, len(out[i].Payload))
			copy(p, out[i].Payload)
			out[i].Payload = p
		}
	}
	return out
}
