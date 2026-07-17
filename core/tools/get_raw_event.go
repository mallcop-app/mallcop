// get_raw_event.go — the get-raw-event pure read tool (mallcoppro-37d).
//
// search_events projects an event down to a flat id/source/type/actor/target/
// action + a fixed discriminatingMetaKeys allowlist (envelope.go) — payload.raw,
// the full record a connector collected (e.g. the complete CloudTrail record for
// an AssumeRole event: userIdentity.arn, sourceIPAddress, requestParameters), is
// never serialized to the model. When the operator asks a provenance question
// ("who did this") that the projected view doesn't answer, the chat agent had no
// way to reach the underlying record and punted to "check CloudTrail" — even
// though the answer was sitting in the store the whole time.
//
// GetRawEvent closes that gap: given an event id, it returns that ONE event's
// full Payload, decoded and re-marshaled as real JSON (never a doubly-escaped
// string blob), with two defensive passes applied at READ time:
//
//   - credential scrub: any key matching (case-insensitively) "sessionToken" or
//     "secretAccessKey" at any depth is replaced with "[REDACTED]". This is a
//     belt-and-suspenders read-time scrub — historical stores may already
//     contain this material from before connector-side redaction
//     (mallcoppro-132) existed, and this tool must never re-surface it to the
//     model regardless of what mallcoppro-132 does at write time.
//   - size cap: a payload whose serialized form exceeds ~64KB is shrunk to
//     fit — leaf string truncation first, then long-array capping, then (as
//     an unconditional final guarantee) replacing the largest remaining
//     values or pruning excess map/array entries — so the returned payload
//     is ALWAYS at or under the cap and ALWAYS valid JSON. NEVER an error: a
//     big payload is still useful evidence; dropping it entirely is worse
//     than trimming it.
//
// Id lookup is lenient exactly like search_events (mallcoppro-45c):
// eventIDCandidates tries the id as given and, if it carries a "finding-"
// prefix, the id with that prefix stripped — so a finding id echoed from
// earlier in the conversation still resolves to its underlying event.
//
// mallcoppro-448: when no exact match (including the finding-/bare lenience
// above) is found, GetRawEvent falls back to git-style unique-prefix
// resolution — a truncated id (copied from a UI list, or paraphrased by the
// model from earlier context) still resolves as long as it is a prefix of
// exactly one stored event id. An ambiguous prefix (more than one match) is
// reported back as an error listing the candidate ids so the model can
// disambiguate; a prefix shorter than minIDPrefixLen, or one matching
// nothing, falls through to the existing not-found result unchanged.
package tools

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// getRawEventPayloadCap bounds the serialized size of the payload this tool
// returns. ~64KB keeps a single tool_result well inside a reasonable context
// budget even for a verbose CloudTrail-style record.
const getRawEventPayloadCap = 64 * 1024

// getRawEventInitialLeafCap / getRawEventMinLeafCap bound the leaf-string
// truncation pass capPayloadSize runs when the whole payload is over cap: it
// starts truncating every leaf string longer than getRawEventInitialLeafCap,
// and if that still doesn't fit, halves the leaf cap (down to
// getRawEventMinLeafCap) and tries again. The largest values shrink first and
// most; short discriminating fields (an actor name, an event type) are the
// last thing to lose bytes.
const (
	getRawEventInitialLeafCap = 4096
	getRawEventMinLeafCap     = 64
)

// credentialKeyNames are the exact (case-insensitive) key names redacted at
// any depth in a raw event payload. Kept as literal names (not normalized
// snake/camel forms) per the mallcoppro-37d spec — connector payloads store
// these under their native CloudTrail-style camelCase names.
var credentialKeyNames = []string{"sessionToken", "secretAccessKey"}

// GetRawEventInput is the input for GetRawEvent: the event id to fetch.
type GetRawEventInput struct {
	ID string `json:"id"`
}

// GetRawEventOutput is the output contract for get-raw-event. Every field is
// always populated (one-shape-always, portable-agent-architecture.md §3.3):
// Found reports whether the id resolved to a stored event; Payload is "null"
// (never omitted, never an empty string) when there is nothing to show;
// Redacted/Truncated report whether either defensive pass actually fired;
// Notes explains anything non-obvious (redaction happened, truncation
// happened, the id didn't resolve) — never the channel for an error.
type GetRawEventOutput struct {
	ID        string          `json:"id"`
	Found     bool            `json:"found"`
	Payload   json.RawMessage `json:"payload"`
	Redacted  bool            `json:"redacted"`
	Truncated bool            `json:"truncated"`
	Notes     string          `json:"notes"`
}

// GetRawEvent reads the events stream from the store and returns the full,
// scrubbed, size-capped payload of the ONE event whose id matches (leniently,
// per eventIDCandidates, then — if that fails — per a git-style unique-prefix
// resolution, mallcoppro-448). GetRawEvent returns an error for a genuine
// schema violation (nil store, unreadable store, malformed record JSON, empty
// input id) AND for an ambiguous prefix match (more than one stored event
// shares the requested prefix — the candidate list is in the error text so
// the model can disambiguate). An id that resolves to no event (exactly, nor
// as a unique prefix) is NOT an error, it is Found: false with an
// explanatory Notes, so the model can self-recover (broaden, try
// search_events/search_findings) instead of the call itself failing.
func GetRawEvent(s *store.Store, in GetRawEventInput) (GetRawEventOutput, error) {
	if s == nil {
		return GetRawEventOutput{}, fmt.Errorf("get-raw-event: nil store")
	}
	if in.ID == "" {
		return GetRawEventOutput{}, fmt.Errorf("get-raw-event: id is required")
	}

	raws, err := s.Load(store.KindEvents)
	if err != nil {
		return GetRawEventOutput{}, fmt.Errorf("get-raw-event: load events: %w", err)
	}

	candidates := map[string]struct{}{}
	for _, c := range eventIDCandidates(in.ID) {
		candidates[c] = struct{}{}
	}

	events := make([]event.Event, 0, len(raws))
	for i, raw := range raws {
		var ev event.Event
		if err := json.Unmarshal(normalizeRecordKeys(raw), &ev); err != nil {
			return GetRawEventOutput{}, fmt.Errorf("get-raw-event: decode event %d: %w", i, err)
		}
		if _, ok := candidates[strings.ToLower(ev.ID)]; ok {
			return buildRawEventOutput(ev.ID, ev.Payload), nil
		}
		events = append(events, ev)
	}

	// mallcoppro-448: no exact match — fall back to git-style unique-prefix
	// resolution before giving up. events already holds every decoded record
	// (the exact-match loop above only returns early on a hit), so this reuses
	// that decode work rather than re-reading the store.
	pool := make([]string, len(events))
	for i, ev := range events {
		pool[i] = ev.ID
	}
	if matched, ambiguous, total := resolveEventIDPrefix(in.ID, pool); matched != "" {
		for _, ev := range events {
			if strings.EqualFold(ev.ID, matched) {
				return buildRawEventOutput(ev.ID, ev.Payload), nil
			}
		}
	} else if len(ambiguous) > 0 {
		return GetRawEventOutput{}, ambiguousIDError("get-raw-event", in.ID, ambiguous, total)
	}

	return GetRawEventOutput{
		ID:      in.ID,
		Found:   false,
		Payload: json.RawMessage("null"),
		Notes: fmt.Sprintf("no event found for id %q — this may be a finding id rather than an "+
			"event id; use search_findings or search_events to confirm the exact event id first", in.ID),
	}, nil
}

// buildRawEventOutput applies the credential scrub and size cap to a matched
// event's payload and assembles the output. Never returns an error — a
// payload that fails to parse as JSON (should not happen: it was already
// validated as part of decoding the enclosing event record) is handed back
// verbatim with a Notes explanation rather than blocking the tool call.
func buildRawEventOutput(id string, payload json.RawMessage) GetRawEventOutput {
	out := GetRawEventOutput{ID: id, Found: true}

	if len(strings.TrimSpace(string(payload))) == 0 {
		out.Payload = json.RawMessage("null")
		out.Notes = "event has no payload"
		return out
	}

	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		out.Payload = payload
		out.Notes = "payload is not valid JSON; returned verbatim, unscrubbed"
		return out
	}

	redactedVal, redacted := redactCredentialFields(decoded)
	out.Redacted = redacted

	// Redaction has already run — capPayloadSize only ever truncates/prunes
	// the post-redaction tree, so a credential field can never surface as a
	// partial live-value prefix: it is already the fixed "[REDACTED]" marker
	// by the time any size logic looks at it (either left alone, or — if it
	// happens to sit inside a subtree that gets pruned wholesale — replaced
	// by a size marker, never a substring of the original secret).
	capped, report := capPayloadSize(redactedVal)
	out.Payload = capped
	out.Truncated = report.any()

	var notes []string
	if redacted {
		notes = append(notes, "credential fields (sessionToken/secretAccessKey) were redacted")
	}
	if report.any() {
		var techniques []string
		if report.LeafTruncated {
			techniques = append(techniques, "leaf truncation")
		}
		if report.ArrayCapped {
			techniques = append(techniques, "array capping")
		}
		if report.SubtreePruned {
			techniques = append(techniques, "subtree pruning")
		}
		notes = append(notes, fmt.Sprintf("payload exceeded %d bytes; applied: %s (result is guaranteed ≤ the cap)",
			getRawEventPayloadCap, strings.Join(techniques, ", ")))
	}
	out.Notes = strings.Join(notes, "; ")
	return out
}

// redactCredentialFields recursively walks a decoded JSON value (the output
// of json.Unmarshal into `any`: map[string]any / []any / string / float64 /
// bool / nil) and replaces the value of any object key matching
// credentialKeyNames (case-insensitive) at ANY depth with "[REDACTED]".
// Returns a new value (the input is never mutated in place) and whether any
// redaction fired.
func redactCredentialFields(v any) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		redacted := false
		for k, val := range t {
			if isCredentialKey(k) {
				out[k] = "[REDACTED]"
				redacted = true
				continue
			}
			nv, r := redactCredentialFields(val)
			out[k] = nv
			redacted = redacted || r
		}
		return out, redacted
	case []any:
		out := make([]any, len(t))
		redacted := false
		for i, val := range t {
			nv, r := redactCredentialFields(val)
			out[i] = nv
			redacted = redacted || r
		}
		return out, redacted
	default:
		return v, false
	}
}

// isCredentialKey reports whether k case-insensitively matches one of
// credentialKeyNames.
func isCredentialKey(k string) bool {
	for _, name := range credentialKeyNames {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// sizeCapReport records which of capPayloadSize's three passes actually
// fired, so buildRawEventOutput's Notes can say precisely what happened
// (leaf truncation / array capping / subtree pruning) instead of a generic
// "it was truncated somehow".
type sizeCapReport struct {
	LeafTruncated bool
	ArrayCapped   bool
	SubtreePruned bool
}

func (r sizeCapReport) any() bool {
	return r.LeafTruncated || r.ArrayCapped || r.SubtreePruned
}

// capPayloadSize serializes v and, if the result exceeds
// getRawEventPayloadCap, shrinks it in three passes until it fits:
//
//  1. leaf-string truncation (existing behavior): shorten leaf strings
//     longer than a shrinking leafCap, largest leaves losing the most bytes
//     first. On its own this only helps when the payload is dominated by a
//     few huge string leaves.
//  2. array capping: any array whose own serialized form is still too big
//     is capped to a head of elements plus one trailing
//     "[TRUNCATED: N more items]" marker. This is what actually bounds a
//     payload dominated by a huge NUMBER of small elements (e.g. a
//     40,000-element int array) — pass 1 can't touch that shape at all,
//     since none of the leaves are long strings.
//  3. final guarantee (enforceSizeCap): while still over cap, replace the
//     largest remaining map values / array segments with size markers, and
//     — if sheer key/element COUNT rather than any single value's size is
//     what blows the budget (e.g. a 6000-field object of short strings) —
//     drop entries outright behind one summary marker. This pass is what
//     makes the cap an unconditional guarantee rather than a best effort:
//     it always returns something at or under getRawEventPayloadCap.
//
// This NEVER errors: an oversized payload always comes back as usable,
// valid, size-bounded JSON — truncated/pruned rather than dropped or left
// over budget.
func capPayloadSize(v any) (json.RawMessage, sizeCapReport) {
	b, err := json.Marshal(v)
	if err != nil {
		// v was decoded from valid JSON by json.Unmarshal, so re-marshaling it
		// should never fail — but this tool never errors on a payload problem,
		// so degrade to an explicit placeholder instead of propagating err.
		return json.RawMessage(`"[unserializable payload]"`), sizeCapReport{SubtreePruned: true}
	}
	if len(b) <= getRawEventPayloadCap {
		return b, sizeCapReport{}
	}

	var report sizeCapReport

	// Pass 1: leaf-string truncation, cut at a rune boundary.
	cur := v
	for leafCap := getRawEventInitialLeafCap; leafCap >= getRawEventMinLeafCap; leafCap /= 2 {
		tv, changed := truncateLeaves(v, leafCap)
		if !changed {
			// No leaf exceeded this cap — a smaller cap might still catch a
			// mid-sized leaf, so keep trying smaller caps, just nothing to
			// fold into cur/report at this leafCap.
			continue
		}
		tb, terr := json.Marshal(tv)
		if terr != nil {
			continue
		}
		cur = tv
		report.LeafTruncated = true
		if len(tb) <= getRawEventPayloadCap {
			return tb, report
		}
	}

	// Pass 2: array capping.
	if capped, changed := capArrays(cur); changed {
		cur = capped
		report.ArrayCapped = true
		if cb, cerr := json.Marshal(cur); cerr == nil && len(cb) <= getRawEventPayloadCap {
			return cb, report
		}
	}

	// Pass 3: final guarantee — unconditionally gets under cap.
	final := enforceSizeCap(cur, getRawEventPayloadCap)
	fb, ferr := json.Marshal(final)
	if ferr != nil || len(fb) > getRawEventPayloadCap {
		// Absolute last resort: enforceSizeCap budgets by estimate (to stay
		// out of O(n^2) territory on thousands of keys/elements), not by
		// re-marshaling after every single change. Confirm the estimate
		// actually held; if it didn't (or marshaling itself somehow failed),
		// a bare marker string is always small and always valid JSON, so
		// this is the one branch that is not allowed to fail the guarantee.
		return json.RawMessage(fmt.Sprintf("%q", sizeMarker(len(b)))), sizeCapReport{
			LeafTruncated: report.LeafTruncated,
			ArrayCapped:   report.ArrayCapped,
			SubtreePruned: true,
		}
	}
	report.SubtreePruned = true
	return fb, report
}

// sizeMarker is the placeholder string capPayloadSize's later passes use in
// place of a value/subtree they drop for size, naming (approximately) how
// many bytes of the original were removed.
func sizeMarker(n int) string {
	return fmt.Sprintf("[TRUNCATED: ~%d bytes]", n)
}

// truncateLeaves returns a copy of v with every leaf string longer than
// leafCap shortened to at most leafCap BYTES — cut at a UTF-8 rune boundary,
// never mid-rune, so the result is always valid UTF-8 — plus a
// "...[truncated]" marker. Maps and slices are walked recursively;
// non-string scalars and nil pass through unchanged. The second return value
// reports whether any leaf was actually shortened, so a caller iterating
// leafCap values can tell a no-op pass from a real one.
func truncateLeaves(v any, leafCap int) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		changed := false
		for k, val := range t {
			nv, c := truncateLeaves(val, leafCap)
			out[k] = nv
			changed = changed || c
		}
		return out, changed
	case []any:
		out := make([]any, len(t))
		changed := false
		for i, val := range t {
			nv, c := truncateLeaves(val, leafCap)
			out[i] = nv
			changed = changed || c
		}
		return out, changed
	case string:
		if len(t) > leafCap {
			return runeSafeTruncate(t, leafCap) + "...[truncated]", true
		}
		return t, false
	default:
		return t, false
	}
}

// runeSafeTruncate returns the longest prefix of s that is at most maxBytes
// bytes long and never splits a multi-byte UTF-8 rune. Slicing a Go string
// by byte offset (s[:maxBytes]) can land inside a multi-byte rune's
// continuation bytes, producing an invalid UTF-8 tail that decodes as U+FFFD
// — this trims that incomplete tail off byte by byte until the prefix ends
// on a genuine rune boundary.
func runeSafeTruncate(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	b := s[:maxBytes]
	for len(b) > 0 {
		r, size := utf8.DecodeLastRuneInString(b)
		if r != utf8.RuneError || size > 1 {
			break
		}
		// RuneError with size 1 means the last byte(s) of b don't form a
		// complete rune (either a genuinely invalid byte, or — the common
		// case here — the truncated tail of a multi-byte rune whose leading
		// byte(s) got cut by the s[:maxBytes] slice). Drop one byte and
		// recheck; this never removes a rune DecodeLastRuneInString had
		// already validated as complete.
		b = b[:len(b)-1]
	}
	return b
}

// capArrays returns a copy of v with every array whose own serialized form
// exceeds getRawEventPayloadCap capped to a head of elements plus one
// trailing "[TRUNCATED: N more items]" marker string. This is what bounds
// the pathological shape leaf-string truncation cannot touch at all: a huge
// NUMBER of small elements (e.g. 40,000 ints) rather than a few huge
// strings. Applied recursively so a long array nested anywhere in the
// payload is capped, not just one at the root. The second return value
// reports whether any array was actually capped.
func capArrays(v any) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		changed := false
		for k, val := range t {
			nv, c := capArrays(val)
			out[k] = nv
			changed = changed || c
		}
		return out, changed
	case []any:
		capped, headChanged := capArrayHead(t)
		out := make([]any, len(capped))
		innerChanged := false
		for i, val := range capped {
			nv, c := capArrays(val)
			out[i] = nv
			innerChanged = innerChanged || c
		}
		return out, headChanged || innerChanged
	default:
		return t, false
	}
}

// capArrayHead returns arr unchanged if its own serialized form already
// fits getRawEventPayloadCap; otherwise it returns a head slice of arr —
// sized so the head's own serialized form fits the budget — plus one
// trailing "[TRUNCATED: N more items]" marker string standing in for the
// dropped tail.
func capArrayHead(arr []any) ([]any, bool) {
	if len(arr) == 0 {
		return arr, false
	}
	b, err := json.Marshal(arr)
	if err == nil && len(b) <= getRawEventPayloadCap {
		return arr, false
	}

	const trailerBudget = 64 // headroom for the "[TRUNCATED: N more items]" element plus brackets/commas
	budget := getRawEventPayloadCap - trailerBudget
	if budget < 0 {
		budget = 0
	}

	size := 2 // []
	head := 0
	for i, el := range arr {
		eb, eerr := json.Marshal(el)
		if eerr != nil {
			break
		}
		add := len(eb)
		if i > 0 {
			add++ // comma
		}
		if size+add > budget {
			break
		}
		size += add
		head = i + 1
	}

	dropped := len(arr) - head
	if dropped <= 0 {
		return arr, false
	}
	out := make([]any, 0, head+1)
	out = append(out, arr[:head]...)
	out = append(out, fmt.Sprintf("[TRUNCATED: %d more items]", dropped))
	return out, true
}

// enforceSizeCap is capPayloadSize's unconditional final guarantee: it
// returns a value whose serialized JSON is at most capBytes, regardless of
// shape — including the case passes 1 and 2 cannot fully solve on their
// own, thousands of small map keys whose sheer COUNT (not any single
// value's size) is what blows the budget. At a map or array node that is
// still over budget, it first replaces the largest remaining children with
// short "[TRUNCATED: ~N bytes]" markers, largest first (handles "one huge
// value"); if replacing every child with a marker still doesn't fit — too
// many children, not too-big children — it drops children from the tail
// outright behind one summary marker entry (handles "many small values"). A
// scalar leaf that alone still exceeds capBytes (should not happen after
// truncateLeaves, but handled regardless) is replaced by a marker wholesale.
//
// Termination is guaranteed without an unbounded loop: shrinkMap/shrinkArray
// are each a single, bounded (O(n log n)) pass over the node's immediate
// children that strictly reduces its serialized byte count — a marker is
// always shorter than the value it replaces, and a drop removes bytes
// outright — down to a small, fixed floor (an empty container or one marker
// string). capPayloadSize additionally re-marshals and re-checks the result
// against capBytes and falls back to a single top-level marker if the
// estimate-based budgeting in shrinkMap/shrinkArray ever slipped, so the
// guarantee holds even if that arithmetic has an off-by-a-few-bytes bug.
func enforceSizeCap(v any, capBytes int) any {
	b, err := json.Marshal(v)
	if err != nil {
		return sizeMarker(0)
	}
	if len(b) <= capBytes {
		return v
	}

	switch t := v.(type) {
	case map[string]any:
		return shrinkMap(t, capBytes)
	case []any:
		return shrinkArray(t, capBytes)
	default:
		return sizeMarker(len(b))
	}
}

// shrinkMap implements enforceSizeCap for a map[string]any node: replace the
// largest-by-serialized-size values with markers first (helps the "one huge
// value" case), then, if key-count overhead alone still exceeds the budget
// even with every value minimized, drop entries in a deterministic
// (sorted-key) order behind a single "_truncated" summary entry (helps the
// "many small values" case, e.g. a 6000-field object of short strings, where
// the KEYS alone — not the values — are what blow the budget).
func shrinkMap(t map[string]any, capBytes int) map[string]any {
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic order

	entrySize := func(k string, val any) int {
		kb, _ := json.Marshal(k)
		vb, err := json.Marshal(val)
		if err != nil {
			vb = []byte("null")
		}
		return len(kb) + 1 + len(vb) // "key":value
	}

	sizes := make(map[string]int, len(keys))
	total := 2 // {}
	for i, k := range keys {
		sz := entrySize(k, t[k])
		sizes[k] = sz
		total += sz
		if i > 0 {
			total++ // comma
		}
	}

	out := make(map[string]any, len(t))
	for k, val := range t {
		out[k] = val
	}
	if total <= capBytes {
		return out
	}

	// Phase 1: shrink the largest values to markers, largest first.
	byLargest := append([]string(nil), keys...)
	sort.SliceStable(byLargest, func(i, j int) bool { return sizes[byLargest[i]] > sizes[byLargest[j]] })
	for _, k := range byLargest {
		curSize := sizes[k]
		orig, _ := json.Marshal(out[k])
		marker := sizeMarker(len(orig))
		mb, _ := json.Marshal(marker)
		kb, _ := json.Marshal(k)
		newSize := len(kb) + 1 + len(mb)
		if newSize >= curSize {
			continue // already minimal; shrinking it further gains nothing
		}
		out[k] = marker
		sizes[k] = newSize
		total -= curSize - newSize
		if total <= capBytes {
			return out
		}
	}

	// Phase 2: key-count overhead alone exceeds the budget even with every
	// value minimized — keep a deterministic head of entries plus one
	// summary entry, drop the rest.
	const summaryBudget = 64 // generous fixed room for `"_truncated":"[TRUNCATED: N more fields]"`
	budget := capBytes - 2 - summaryBudget
	if budget < 0 {
		budget = 0
	}
	kept := make(map[string]any, len(keys))
	used := 0
	keptCount := 0
	for _, k := range keys {
		add := sizes[k]
		if keptCount > 0 {
			add++ // comma
		}
		if used+add > budget {
			break
		}
		used += add
		kept[k] = out[k]
		keptCount++
	}
	dropped := len(keys) - keptCount
	if dropped > 0 {
		kept["_truncated"] = fmt.Sprintf("[TRUNCATED: %d more fields]", dropped)
	}
	return kept
}

// shrinkArray implements enforceSizeCap for a []any node: the same
// two-phase strategy as shrinkMap, but for array elements. In practice this
// mostly backstops capArrayHead's own estimate (arrays are already
// head-capped by pass 2 before enforceSizeCap ever runs), but it is fully
// self-contained so the guarantee holds even for an array that reaches this
// pass uncapped.
func shrinkArray(t []any, capBytes int) []any {
	elemSize := func(val any) int {
		vb, err := json.Marshal(val)
		if err != nil {
			return len("null")
		}
		return len(vb)
	}

	sizes := make([]int, len(t))
	total := 2 // []
	for i, val := range t {
		sizes[i] = elemSize(val)
		total += sizes[i]
		if i > 0 {
			total++ // comma
		}
	}

	out := append([]any(nil), t...)
	if total <= capBytes {
		return out
	}

	// Phase 1: shrink the largest elements to markers, largest first.
	order := make([]int, len(t))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool { return sizes[order[i]] > sizes[order[j]] })
	for _, i := range order {
		curSize := sizes[i]
		marker := sizeMarker(curSize)
		mb, _ := json.Marshal(marker)
		newSize := len(mb)
		if newSize >= curSize {
			continue
		}
		out[i] = marker
		sizes[i] = newSize
		total -= curSize - newSize
		if total <= capBytes {
			return out
		}
	}

	// Phase 2: element-count overhead alone exceeds the budget — keep a
	// head of elements plus one trailing summary marker, drop the rest.
	const summaryBudget = 48 // room for `"[TRUNCATED: N more items]"`
	budget := capBytes - 2 - summaryBudget
	if budget < 0 {
		budget = 0
	}
	used := 0
	head := 0
	for i, sz := range sizes {
		add := sz
		if i > 0 {
			add++
		}
		if used+add > budget {
			break
		}
		used += add
		head = i + 1
	}
	dropped := len(t) - head
	if dropped <= 0 {
		return out[:head]
	}
	kept := append([]any(nil), out[:head]...)
	kept = append(kept, fmt.Sprintf("[TRUNCATED: %d more items]", dropped))
	return kept
}
