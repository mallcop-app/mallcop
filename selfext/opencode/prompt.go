package opencode

import (
	"fmt"
	"strings"
)

// synthmarkerExemplar is the reference own-package authored detector shape the
// prompt hands opencode verbatim. It is the K7 L1 exemplar (mallcop
// core/detect/authored/synthmarker): own package, pure Detect, imports limited
// to detect+event+finding+baseline, self-registering init(). Embedding it means
// opencode does not have to discover the shape by reading the repo, and it
// cannot be tempted to imitate a framework detector that mutates shared state.
const synthmarkerExemplar = "" +
	"package synthmarker\n\n" +
	"import (\n" +
	"\t\"github.com/mallcop-app/mallcop/core/detect\"\n" +
	"\t\"github.com/mallcop-app/mallcop/pkg/baseline\"\n" +
	"\t\"github.com/mallcop-app/mallcop/pkg/event\"\n" +
	"\t\"github.com/mallcop-app/mallcop/pkg/finding\"\n" +
	")\n\n" +
	"func init() { detect.Register(detector{}) }\n\n" +
	"const markerType = \"mallcop.synthetic-marker\"\n" +
	"const detectorName = \"authored-synthetic-marker\"\n\n" +
	"type detector struct{}\n\n" +
	"func (detector) Name() string { return \"authored-synthetic-marker\" }\n\n" +
	"func (detector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {\n" +
	"\tvar out []finding.Finding\n" +
	"\tfor _, ev := range events {\n" +
	"\t\tif ev.Type != markerType {\n" +
	"\t\t\tcontinue\n" +
	"\t\t}\n" +
	"\t\tout = append(out, finding.Finding{\n" +
	"\t\t\tID:        \"finding-\" + ev.ID + \"-synthetic-marker\",\n" +
	"\t\t\tSource:    \"detector:\" + detectorName,\n" +
	"\t\t\tSeverity:  \"low\",\n" +
	"\t\t\tType:      detectorName,\n" +
	"\t\t\tActor:     ev.Actor,\n" +
	"\t\t\tTimestamp: ev.Timestamp,\n" +
	"\t\t\tReason:    \"synthetic marker event observed\",\n" +
	"\t\t})\n" +
	"\t}\n" +
	"\treturn out\n" +
	"}\n"

// mustFireScenarioExemplar is a COMPLETE, valid exam scenario the prompt hands
// opencode verbatim so it copies the exact schema (esp. baseline.known_entities,
// whose absence is the "malformed baseline" load error). exam.Load is non-strict,
// so the model adapts the values and may add fields. This one is the MUST-FIRE
// shape: an event that trips the detector + expected_detection.must_fire.
const mustFireScenarioExemplar = `id: authored-example-must-fire
detector: authored-example
category: authored
difficulty: authored-easy
finding:
  id: fnd_authored_001
  detector: authored-example
  title: 'authored-example fired on example.event'
  severity: warn
  event_ids:
    - evt_001
  metadata:
    actor: example-actor
    source: example-source
    event_type: example.event
events:
  - id: evt_001
    timestamp: '2026-03-10T11:22:00Z'
    ingested_at: '2026-03-10T11:23:00Z'
    source: example-source
    event_type: example.event
    actor: example-actor
    action: example-action
    target: example-target
    severity: warn
    metadata: {}
    raw: {}
baseline:
  known_entities:
    actors:
      - example-actor
    sources:
      - example-source
  frequency_tables: {}
expected:
  chain_action: escalate
expected_detection:
  must_fire:
    - authored-example
  must_not_fire: []
`

// benignTwinScenarioExemplar is the BENIGN look-alike shape: same structure, but
// the event does NOT trip the detector (here a different event_type), and
// expected_detection.must_not_fire — proving the false-positive floor.
const benignTwinScenarioExemplar = `id: authored-example-benign-twin
detector: authored-example
category: authored
difficulty: authored-easy
finding:
  id: fnd_authored_benign_001
  detector: authored-example
  title: 'benign look-alike does not fire'
  severity: info
  event_ids:
    - evt_001
  metadata:
    actor: example-actor
    source: example-source
    event_type: example.other-event
events:
  - id: evt_001
    timestamp: '2026-03-10T11:22:00Z'
    ingested_at: '2026-03-10T11:23:00Z'
    source: example-source
    event_type: example.other-event
    actor: example-actor
    action: example-action
    target: example-target
    severity: info
    metadata: {}
    raw: {}
baseline:
  known_entities:
    actors:
      - example-actor
    sources:
      - example-source
  frequency_tables: {}
expected:
  chain_action: resolve
expected_detection:
  must_fire: []
  must_not_fire:
    - authored-example
`

// BuildTaskPrompt constructs the headless authoring instruction from the gap's
// TRUSTED STRUCTURAL fields only. It never interpolates raw untrusted sample
// text — the only variable data are the detector id, event type, family, and
// the structural severity/actor/source, all of which the gap-builder derived
// from trusted signals.
//
// customerShaped selects WHICH delivery shape the prompt targets: the
// engine derives it from the SAME trusted signal the gate
// already uses (gate.go's hasCmdMallcop on the trusted worktree jail's own
// TargetRepo — never anything the untrusted proposal content could set).
//
//   - false (in-tree lane — TargetRepo IS the mallcop OSS repo itself, or any
//     tree with its own cmd/mallcop): the prompt targets the ORIGINAL
//     own-package shape (core/detect/authored/<name>/, init()+detect.Register)
//     that core/selfgate's authoredast.go (K7 L3) grades — unchanged from
//     before this fix.
//   - true (a customer-shaped THIN-EMBED target repo — `mallcop init
//     --create-repo`'s scaffold: go.mod pins mallcop, NO cmd/mallcop, NO
//     core/detect/authored/ tree at all): the prompt targets the SIDECAR shape
//     (detectors/<name>/main.go, package main, detectorhost.Run) that
//     core/selfgate's sidecarshape.go grades instead.
//     Authoring the in-tree shape here is the exact live-leg bug: the
//     engine's registry-linkage step then tries to restore a
//     core/detect/authored/registry.go that never existed in this repo's
//     history and fails loud. See engine.Run's customerShaped branch, which
//     ALSO skips that registry step entirely for this case — the
//     detectors/<name>/ directory IS the registration under the sidecar model.
func (a *Adapter) BuildTaskPrompt(gap TrustedGap, customerShaped bool) string {
	if customerShaped {
		return a.buildSidecarTaskPrompt(gap)
	}
	return a.buildInTreeTaskPrompt(gap)
}

// buildInTreeTaskPrompt is BuildTaskPrompt's ORIGINAL branch (unchanged
// behavior): it pins the four-layer gate's hard requirements (own package,
// import allow-list, must-fire scenario, benign twin) so a compliant run
// passes core/selfgate's in-tree (authoredast.go) lane.
func (a *Adapter) buildInTreeTaskPrompt(gap TrustedGap) string {
	pkg := gap.PackageName()
	name := gap.DetectorID
	if strings.TrimSpace(name) == "" {
		name = "authored-" + pkg
	}
	family := gap.TargetFamily
	if strings.TrimSpace(family) == "" {
		family = name
	}
	severity := gap.Severity
	if strings.TrimSpace(severity) == "" {
		severity = "medium"
	}

	var b strings.Builder
	fmt.Fprintf(&b, `You are extending the mallcop security-monitoring product with ONE new
offline DETECTOR. This is DEFENSIVE security tooling. Author ONLY the files
listed below; do not touch any other file, and do not run any command.

Detector identity (use these EXACT values):
  detector name / finding.Type : %s
  own-package directory        : core/detect/authored/%s/
  connector event type it keys : %s
  finding family it emits      : %s
  structural severity          : %s
  structural actor field       : %s
  structural source field      : %s

REQUIRED FILES (all three, or the merge gate rejects the proposal):

1) core/detect/authored/%s/%s.go
   - MUST be its own package %q (NOT package detect).
   - MUST be PURE: no package-level mutation, no I/O, no goroutines, no
     network, no os/exec. Imports are restricted to EXACTLY:
       github.com/mallcop-app/mallcop/core/detect
       github.com/mallcop-app/mallcop/pkg/baseline
       github.com/mallcop-app/mallcop/pkg/event
       github.com/mallcop-app/mallcop/pkg/finding
     Any other import fails the authored-detector import allow-list.
   - MUST self-register in init() via detect.Register(detector{}).
   - Name() MUST return a single compile-time STRING LITERAL directly (the
     detector id in double quotes) — NOT a const/var reference, concatenation,
     or any computation. The structural gate rejects a non-literal Name().
   - Detect MUST fire (emit exactly one finding with Type == %q) only on
     events whose Type == %q, and stay SILENT on everything else. Keep the
     trigger tight so a benign look-alike does NOT fire.
   Model it on this reference detector (adapt names/logic, keep the shape):

%s

2) exams/scenarios/authored/%s-must-fire.yaml
   - A labeled scenario carrying at least one event of Type %q that triggers
     your detector, with an expected_detection.must_fire entry naming family %q.
   Every scenario MUST carry ALL of these top-level fields, or exam.Load rejects
   it (this is the exact shape — adapt the values, keep every key). Note
   baseline.known_entities.actors and .sources are REQUIRED (a baseline without
   known_entities is "malformed baseline: known_entities must be present"):

%s

3) exams/scenarios/authored/%s-benign-twin.yaml
   - A labeled BENIGN look-alike (similar shape, event Type NOT %q or lacking the
     trigger) with expected_detection.must_not_fire naming family %q, proving the
     detector STAYS SILENT on a benign neighbor. SAME full shape as above,
     including baseline.known_entities:

%s

Do NOT create or edit core/detect/authored/registry.go — the build registers
your detector package automatically (a trusted, guaranteed-correct step). If
the scenario corpus is pinned (exams/scenarios/corpus.pin), regenerate the pin
so the two new scenarios are included; otherwise exam-detect will reject the
proposal for corpus drift.

Do NOT modify go.mod, cmd/mallcop/main.go, or any existing detector. Author the
three files above and stop.`,
		name, pkg, gap.EventType, family, severity, gap.Actor, gap.Source,
		pkg, pkg, pkg,
		name, gap.EventType,
		synthmarkerExemplar,
		pkg, gap.EventType, family,
		mustFireScenarioExemplar,
		pkg, gap.EventType, family,
		benignTwinScenarioExemplar,
	)
	return b.String()
}

// eventAPIGuidance documents pkg/event.Event's REAL field set and the
// REQUIRED way to read a payload value (round-6 LIVE
// evidence — see the opencode package doc's "Code-authoring model override"
// section). A coder that GUESSES Payload is a method hallucinates a
// signature that does not exist: Payload is a json.RawMessage ([]byte alias)
// STRUCT FIELD, not a method, so calling it as one is a compile error (go
// build/go vet fails, and the merge gate rejects the proposal at the
// STRUCTURAL stage before any behavior is even graded). Reading any key out
// of it always requires an explicit json.Unmarshal call first — this text is
// handed to opencode VERBATIM so no coder (strong or weak) has to guess. It
// deliberately never spells out the hallucinated call-shaped form itself
// (even as a "don't do this" example) — a weak coder can pattern-match on a
// literal string regardless of surrounding "never" framing, so the only safe
// guidance is to show the ONE real, working way to read Payload and nothing
// else.
const eventAPIGuidance = `pkg/event.Event — THE REAL API (fields, not methods):

	type Event struct {
		ID        string          // event id
		Source    string          // e.g. "connector:github"
		Type      string          // event type, e.g. "mallcop.synthetic-marker"
		Actor     string          // acting principal
		Timestamp time.Time       // when the event occurred
		Org       string          // owning org
		Payload   json.RawMessage // raw JSON bytes — a FIELD, never a method
	}

Payload is a json.RawMessage (an alias for []byte) FIELD, not a method, and
takes no arguments. To read a value out of it, ALWAYS decode it first:

	var m map[string]any
	if err := json.Unmarshal(ev.Payload, &m); err != nil {
		continue // malformed payload: do not fire
	}
	action, _ := m["action"].(string)

(A typed struct with json tags works too: json.Unmarshal(ev.Payload, &typed).)
This json.Unmarshal call is the ONLY correct way to read a Payload value.`

// sidecarExemplar is the reference CUSTOMER-TREE SIDECAR detector shape the
// prompt hands opencode verbatim for a customerShaped target. It mirrors the
// ground-truth fixtures on the mallcop side: examples/sidecar-detector/main.go
// and core/selfgate/customergate_test.go's customerFixtureDetectorMainSrc —
// package main, a package-local Detector impl (Name+Detect, no core/detect
// import), one func main() whose only statement is
// os.Exit(detectorhost.Run(<local value>{})), no init(). Embedding it means
// opencode does not have to discover the sidecar shape by reading the mallcop
// module, and it cannot imitate the STRUCTURALLY INCOMPATIBLE in-tree
// (init()+detect.Register) shape sidecarshape.go's gate would reject outright
// (RuleSidecarInit).
//
// The Detect body ALSO demonstrates the REAL pkg/event.Event.Payload API:
// json.Unmarshal into a typed struct, never a Payload(...)
// method call (see eventAPIGuidance) — round-6 LIVE evidence showed a coder
// hallucinating ev.Payload("action") as a method, which fails go build/go vet
// at the sound gate. This ALSO matches the payload field
// (sidecarScenarioMustFireExemplar/BenignTwinExemplar's action: target-action
// / routine-action below) so the exemplar detector, the scenario pair, and
// this guidance all agree on one concrete, working example.
const sidecarExemplar = "" +
	"package main\n\n" +
	"import (\n" +
	"\t\"encoding/json\"\n" +
	"\t\"os\"\n\n" +
	"\t\"github.com/mallcop-app/mallcop/pkg/baseline\"\n" +
	"\t\"github.com/mallcop-app/mallcop/pkg/detectorhost\"\n" +
	"\t\"github.com/mallcop-app/mallcop/pkg/event\"\n" +
	"\t\"github.com/mallcop-app/mallcop/pkg/finding\"\n" +
	")\n\n" +
	"type detector struct{}\n\n" +
	"func (detector) Name() string { return \"authored-synthetic-marker\" }\n\n" +
	"func (detector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {\n" +
	"\tvar out []finding.Finding\n" +
	"\tfor _, ev := range events {\n" +
	"\t\tif ev.Type != \"mallcop.synthetic-marker\" {\n" +
	"\t\t\tcontinue\n" +
	"\t\t}\n" +
	"\t\t// Payload is a json.RawMessage FIELD (NOT a method) — unmarshal to read it.\n" +
	"\t\tvar payload struct {\n" +
	"\t\t\tAction string `json:\"action\"`\n" +
	"\t\t}\n" +
	"\t\tif err := json.Unmarshal(ev.Payload, &payload); err != nil || payload.Action != \"target-action\" {\n" +
	"\t\t\tcontinue\n" +
	"\t\t}\n" +
	"\t\tout = append(out, finding.Finding{\n" +
	"\t\t\tID:        \"finding-\" + ev.ID + \"-synthetic-marker\",\n" +
	"\t\t\tSource:    \"detector:authored-synthetic-marker\",\n" +
	"\t\t\tSeverity:  \"low\",\n" +
	"\t\t\tType:      \"authored-synthetic-marker\",\n" +
	"\t\t\tActor:     ev.Actor,\n" +
	"\t\t\tTimestamp: ev.Timestamp,\n" +
	"\t\t\tReason:    \"synthetic marker event observed\",\n" +
	"\t\t})\n" +
	"\t}\n" +
	"\treturn out\n" +
	"}\n\n" +
	"func main() { os.Exit(detectorhost.Run(detector{})) }\n"

// sidecarLocalTypeName is the local detector type name the sidecar prompt and
// sidecarExemplar agree on ("detector", matching sidecarExemplar's `type
// detector struct{}`) — kept as one constant so the prompt text and the
// exemplar source can never drift apart.
const sidecarLocalTypeName = "detector"

// sidecarScenarioMustFireExemplar / sidecarScenarioBenignTwinExemplar are the
// reference EXAM-DETECT YAML shape (RULING, Approach A) the
// sidecar prompt hands opencode verbatim for its OWN co-located
// detectors/<name>/scenarios/*.yaml pair — the EXACT same format (id,
// finding:, events:, expected_detection.must_fire/must_not_fire) the
// reference corpus's own exams/scenarios/*.yaml use, graded through the same
// real .wasm run via `mallcop exam-detect --extra-scenarios-dir`.
//
// The benign twin is a MEASURED MINIMAL MUTATION of the must-fire scenario:
// SAME event_type/actor/source (structural identity) and event count/order,
// differing ONLY on a bounded, substantive PAYLOAD value — here the `action`
// field (target-action vs routine-action) — mirroring the reference corpus's
// own near-miss convention (exams/scenarios/privilege PE-08/PE-09: same
// event_type/source, discriminated by the substantive policy payload, never
// by event_type itself).
//
// mallcop core/selfgate's checkMinimalMutationCoverage NOW ENFORCES this in
// the gate itself (round 2, veracity-reproduced fix — this
// prompt is guidance for the untrusted author, not the enforcement): a twin
// that instead differs in event_type (an EARLIER version of this exemplar
// did — differing only event.target-event vs event.routine-event) is
// REJECTED as an arbitrary carve-out, because it is mechanically
// indistinguishable from a detector that special-cases exactly one
// hand-picked, unrelated event_type as its "benign twin" while firing on
// everything else. Forcing the twin to share the must-fire event's type
// means that same carve-out logic would ALSO silence the must-fire event
// itself — so the detector is forced into genuine discrimination on the
// substantive payload value instead.
const sidecarScenarioMustFireExemplar = `id: SIDECAR-EXAMPLE-01-must-fire
finding:
  id: fnd_example_01
  detector: example-family
  title: 'example: target event observed'
  severity: medium
events:
- id: evt_example_01
  timestamp: '2026-01-01T00:00:00Z'
  source: connector:example
  event_type: example.event
  actor: example-actor
  action: target-action
expected_detection:
  must_fire:
  - example-family
`

const sidecarScenarioBenignTwinExemplar = `id: SIDECAR-EXAMPLE-02-benign-twin
finding:
  id: fnd_example_02
  detector: example-family
  title: 'example: benign look-alike (measured minimal mutation: same event_type/actor/source, action differs)'
  severity: low
events:
- id: evt_example_02
  timestamp: '2026-01-01T00:05:00Z'
  source: connector:example
  event_type: example.event
  actor: example-actor
  action: routine-action
expected_detection:
  must_not_fire:
  - example-family
`

// buildSidecarTaskPrompt is BuildTaskPrompt's CUSTOMER-SHAPED branch.
// See BuildTaskPrompt's doc for when this fires.
//
// Grading model (superseding the -era comment
// this replaces): RunCustomerTreeExam (mallcop core/selfgate/customerexam.go)
// grades detectors/<name>/ against the UNION of the REFERENCE tree's
// (--exam-repo) OWN pinned exam corpus (regression) AND this detector's OWN
// co-located detectors/<name>/scenarios/*.yaml (efficacy) — a customer-tree
// detector for a NOVEL gap (an event type the reference corpus has zero
// scenarios for) cannot prove itself against the reference corpus alone, so
// its own scenarios/ pair IS the proof the gate grades. They are UNPINNED
// (never touch the reference tree's corpus.pin) but graded through the
// IDENTICAL real wasip1 .wasm + detecthost host pass
// (customerTreeExamStage's --extra-scenarios-dir union). A companion
// detectors/<name>/main_test.go is ALSO required (core/selfgate/guard.go's
// listDirGoFiles EXEMPTS *_test.go from the sidecar shape check — production
// files only — so this stays safely additive) as human-reviewable evidence
// alongside the machine-graded scenarios.
func (a *Adapter) buildSidecarTaskPrompt(gap TrustedGap) string {
	pkg := gap.PackageName()
	name := gap.DetectorID
	if strings.TrimSpace(name) == "" {
		name = "authored-" + pkg
	}
	family := gap.TargetFamily
	if strings.TrimSpace(family) == "" {
		family = name
	}
	severity := gap.Severity
	if strings.TrimSpace(severity) == "" {
		severity = "medium"
	}

	var b strings.Builder
	fmt.Fprintf(&b, `You are extending a mallcop CUSTOMER deployment with ONE new offline
DETECTOR, delivered as a wasip1 WASM SIDECAR (NOT code compiled into mallcop
itself). This is DEFENSIVE security tooling. Author ONLY the files listed
below; do not touch any other file (especially go.mod, go.sum, cmd/, or
anything under core/), and do not run any command.

Detector identity (use these EXACT values):
  detector name / finding.Type : %s
  sidecar source directory     : detectors/%s/
  connector event type it keys : %s
  finding family it emits      : %s
  structural severity          : %s
  structural actor field       : %s
  structural source field      : %s

REQUIRED FILES (all three, or the merge gate rejects the proposal):

1) detectors/%s/main.go
   - package main. This is a STANDALONE Go program built GOOS=wasip1
     GOARCH=wasm and run inside the detecthost/wazero sidecar host — never
     linked into mallcop's own binary.
   - MUST define exactly one func main(), whose ENTIRE body is exactly one
     statement: os.Exit(detectorhost.Run(%s{})) — a LOCAL detector value
     (a bare, package-local type literal), never an imported one.
   - MUST NOT define an init() function anywhere in the package — forbidden;
     it runs before main()'s single verified statement.
   - Imports are restricted to EXACTLY:
       os                                              (ONLY the single
         os.Exit(...) wrapper above — no other os.* call anywhere in the
         package: no file I/O, no environment, no process control)
       github.com/mallcop-app/mallcop/pkg/baseline
       github.com/mallcop-app/mallcop/pkg/detectorhost  (ONLY the single
         detectorhost.Run(...) call above — no other detectorhost.* reference
         anywhere in the package)
       github.com/mallcop-app/mallcop/pkg/event
       github.com/mallcop-app/mallcop/pkg/finding
     Do NOT import github.com/mallcop-app/mallcop/core/detect — a sidecar
     implements the Detector interface STRUCTURALLY (a Name() string method
     and a Detect(events []event.Event, b *baseline.Baseline) []finding.Finding
     method); it never needs to name the interface type. Pure-computation
     stdlib (fmt, strings, strconv, time, regexp, sort, encoding/json,
     encoding/base64, ...) is allowed for parsing event.Event.Payload. net,
     net/*, os/exec, syscall, unsafe, and cgo are all hard-forbidden.
   - Detect MUST fire (emit exactly one finding with Type == %q) only on
     events whose Type == %q, and stay SILENT on everything else. Keep the
     trigger tight so a benign look-alike does NOT fire. IMPORTANT: the merge
     gate's benign-twin scenario (below) now REQUIRES the twin event to share
     this SAME event_type (see item 3b) — so matching event_type ALONE can no
     longer be the whole trigger once a same-type benign twin exists. Detect
     must also inspect a substantive field on event.Event.Payload (a JSON
     object carrying action/target/severity/metadata — see pkg/event.Event's
     doc) that genuinely distinguishes the attack condition from the benign
     near-miss, and fire only when BOTH the event type matches AND that
     condition holds.

%s

   Model it on this reference sidecar (adapt names/logic, keep the shape
   EXACTLY — one main(), one os.Exit(detectorhost.Run(...)) call, nothing
   else touching os or detectorhost):

%s

2) detectors/%s/main_test.go
   - A normal Go test (package main) calling %s{}.Detect(...) directly with
     two synthetic []event.Event slices: one containing an event of Type %q
     (assert exactly one finding with Type %q comes back) and one BENIGN
     look-alike slice that does NOT contain that event Type (assert Detect
     returns no findings). This is the human-reviewable "fires on target,
     silent on a neighbor" evidence, alongside the machine-graded scenario
     pair below.

3) detectors/%s/scenarios/ — EXACTLY TWO files, in the exam-detect YAML
   format (id / finding / events / expected_detection, the SAME schema the
   reference corpus's own exams/scenarios/*.yaml use):

   a) detectors/%s/scenarios/must-fire.yaml
      - id: any unique string.
      - events: at least one event with event_type: %q (and actor: %s,
        source: %s to match this detector's structural identity), carrying
        whatever action/target/severity/metadata value makes this event the
        ATTACK condition (the substantive field Detect checks, per item 1
        above).
      - expected_detection.must_fire: [%s]
      - This is the machine-graded proof the detector fires on its target —
        the merge gate REJECTS the proposal if this scenario does not pass
        through the real .wasm run.

   b) detectors/%s/scenarios/benign-twin.yaml
      - A MEASURED MINIMAL MUTATION of must-fire.yaml, mechanically ENFORCED
        by the merge gate (core/selfgate's checkMinimalMutationCoverage), NOT
        just a style suggestion:
          * SAME event_type: %q, SAME actor: %s, SAME source: %s, SAME event
            count and order as must-fire.yaml. The gate REJECTS a twin that
            differs in event type, actor, source, or event count as an
            ARBITRARY CARVE-OUT — a hand-picked, structurally different event
            the detector merely happens to ignore, not a genuine near-miss
            (this is the exact shape of a fire-on-everything-except-one-type
            detector, which the gate exists to catch).
          * Differ ONLY on a small, bounded number (1 to 3) of substantive
            action/target/severity/metadata field(s) — the SAME
            discriminating condition Detect's payload check above tests,
            flipped to its ROUTINE value (e.g. must-fire's action denotes the
            attack condition; the twin's action denotes the routine one).
            Zero fields differing (a byte-identical twin) proves nothing and
            is REJECTED; too many fields differing is REJECTED as too broad
            to be a genuine near-miss.
          * NEVER just delete the triggering event, swap in an unrelated
            scenario, or pick a different event_type — those are exactly the
            rejected carve-out shapes above.
      - expected_detection.must_not_fire: [%s]
      - The merge gate REJECTS the proposal if this scenario's family fires
        (over-broad detection), if it is missing entirely (unproven
        false-positive floor), or if it fails the measured-minimal-mutation
        check above (an unproven near-miss).

   Reference shape (adapt the id/event_type/actor/source/family to THIS
   detector's identity above; keep every other field name and structure
   EXACTLY as shown):

%s
%s

Do NOT create or touch core/detect/authored/registry.go, or any path under
core/detect/authored/ — this is a customer deployment repo; it has no such
tree, and there is nothing to register. detectors/%s/ existing on disk IS the
whole registration; the build discovers and compiles it automatically. Do NOT
author anything under the TOP-LEVEL exams/scenarios/ path — that is the
operator's reference corpus, not this repo's; your scenarios live ONLY under
detectors/%s/scenarios/.

Do NOT modify go.mod, go.sum, or any existing detector. Author the three files
above and stop.`,
		name, pkg, gap.EventType, family, severity, gap.Actor, gap.Source,
		pkg, sidecarLocalTypeName,
		gap.EventType, gap.EventType,
		eventAPIGuidance,
		sidecarExemplar,
		pkg, sidecarLocalTypeName, gap.EventType, gap.EventType,
		pkg,
		pkg, gap.EventType, gap.Actor, gap.Source, family,
		pkg, gap.EventType, gap.Actor, gap.Source, family,
		sidecarScenarioMustFireExemplar, sidecarScenarioBenignTwinExemplar,
		pkg,
		pkg,
	)
	return b.String()
}
