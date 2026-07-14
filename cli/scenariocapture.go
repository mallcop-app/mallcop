// scenariocapture.go — `mallcop scenario capture` (mallcoppro-65c4, corpus-
// expansion axis ii / db0's "flag things like this"): grow the operator's
// LOCAL scenarios/ corpus from THEIR OWN real telemetry instead of
// hand-writing YAML.
//
// This is the AUTHOR-INDEPENDENT ground-truth capture lane the reserved-test
// mechanism (internal/exam's ExpectedDetection.Reserved doc, mallcoppro-db0)
// describes in the abstract: the scenario predates and is authored by someone
// OTHER than whoever eventually writes the detector that satisfies it. An
// operator who saw a real attack (or a real false alarm) in their own store
// asserts the ground truth NOW, from the events as they actually occurred —
// not from a detector author's imagination of what an attack looks like.
//
// Capture reads REAL stored events (core/store) and the store's DERIVED
// baseline — the identical projection core/pipeline.Run's step (1a) computes
// (persisted KindBaseline snapshot merged with pkg/baseline.Build over every
// OTHER stored event) — so grading the captured scenario later reproduces the
// baseline state the real scan actually gated on when these events came in.
//
// R2/R9 (constraint, load-bearing): the output is DATA — a scenario YAML
// fixture, schema-identical to the shipped reference corpus — never a
// detector, lookup rule, or any runtime behavior change. Capturing an attack
// must NEVER synthesize a match rule for it; the operator's captured ground
// truth is graded by whatever detector already exists (or shows up as a
// tracked gap via --reserved when none does).
package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/internal/exam"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// runScenario implements `mallcop scenario <capture|lint> ...` — the shared
// dispatcher for both scenario-authoring subcommands, mirroring how
// runFeedback dispatches report-miss internally (cli/feedback.go).
func runScenario(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("scenario: usage: mallcop scenario capture --store <dir> [--event-ids <ids>] [--actor <a> --window <dur>] --must-fire <family>|--must-not-fire <family> [--reserved]\n       mallcop scenario lint [--scenarios-dir <dir>] [--json]\n       mallcop scenario contribute [--yes] [--dry-run] [--allow-authored] [--repo owner/name] <scenarios/file.yaml>")
	}
	switch args[0] {
	case "capture":
		return runScenarioCapture(args[1:])
	case "lint":
		return runScenarioLint(args[1:])
	case "contribute":
		return runScenarioContribute(args[1:])
	default:
		return fmt.Errorf("scenario: unknown subcommand %q (want capture|lint|contribute)", args[0])
	}
}

// runScenarioCapture implements `mallcop scenario capture`.
func runScenarioCapture(args []string) error {
	fs := flag.NewFlagSet("scenario capture", flag.ContinueOnError)
	storePath := fs.String("store", "", "Path to the git-repo store written by 'mallcop scan' (required)")
	eventIDsFlag := fs.String("event-ids", "", "Comma-separated explicit event IDs to capture")
	actorFlag := fs.String("actor", "", "Actor to select events for (requires --window)")
	windowFlag := fs.String("window", "", "Duration (e.g. \"24h\") of the actor's OWN activity, measured back from that actor's latest matching event in the store (requires --actor)")
	mustFireFlag := fs.String("must-fire", "", "Comma-separated detector family token(s) this event set MUST trigger — an attack the operator saw or fears")
	mustNotFireFlag := fs.String("must-not-fire", "", "Comma-separated detector family token(s) this event set must NOT trigger — a benign activity that was false-alarmed (pairs with 'mallcop feedback dismiss')")
	reserved := fs.Bool("reserved", false, "Mark --must-fire as a RESERVED TEST: a detector for it may not exist in this repo yet (see internal/exam's ExpectedDetection.Reserved doc). Invalid with --must-not-fire.")
	idFlag := fs.String("id", "", "Scenario id (default: auto-generated LOCAL-<family>-<hash>)")
	title := fs.String("title", "", "Finding title (default: derived from the family + actor)")
	severity := fs.String("severity", "medium", "Finding severity")
	scenariosDir := fs.String("scenarios-dir", "", "Directory to write the scenario into (default: <repo-root>/scenarios, repo-root via eval.RepoRoot())")
	force := fs.Bool("force", false, "Overwrite an existing scenario file at the resolved output path")
	by := fs.String("by", "", "Operator identity recorded in the file header comment (defaults to $USER)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *storePath == "" {
		return fmt.Errorf("scenario capture: --store is required (the git-repo path written by 'mallcop scan')")
	}

	eventIDs := splitScenarioList(*eventIDsFlag)
	actor := strings.TrimSpace(*actorFlag)
	windowStr := strings.TrimSpace(*windowFlag)
	if (actor == "") != (windowStr == "") {
		return fmt.Errorf("scenario capture: --actor and --window must be given together")
	}
	if len(eventIDs) == 0 && actor == "" {
		return fmt.Errorf("scenario capture: an event selector is required (--event-ids and/or --actor + --window)")
	}

	mustFire := splitScenarioList(*mustFireFlag)
	mustNotFire := splitScenarioList(*mustNotFireFlag)
	if len(mustFire) == 0 && len(mustNotFire) == 0 {
		return fmt.Errorf("scenario capture: exactly one of --must-fire or --must-not-fire is required")
	}
	if len(mustFire) > 0 && len(mustNotFire) > 0 {
		return fmt.Errorf("scenario capture: --must-fire and --must-not-fire are mutually exclusive (capture one labeled scenario at a time)")
	}
	if *reserved && len(mustFire) == 0 {
		return fmt.Errorf("scenario capture: --reserved requires --must-fire")
	}

	var window time.Duration
	if windowStr != "" {
		var err error
		window, err = time.ParseDuration(windowStr)
		if err != nil {
			return fmt.Errorf("scenario capture: --window %q: %w", windowStr, err)
		}
		if window <= 0 {
			return fmt.Errorf("scenario capture: --window must be positive")
		}
	}

	st, err := store.Open(*storePath)
	if err != nil {
		return fmt.Errorf("scenario capture: open store %q: %w", *storePath, err)
	}

	allEvents, err := loadStoredEventsForCapture(st)
	if err != nil {
		return fmt.Errorf("scenario capture: %w", err)
	}

	selected, missingIDs, err := selectCaptureEvents(allEvents, eventIDs, actor, window)
	if err != nil {
		return fmt.Errorf("scenario capture: %w", err)
	}
	if len(missingIDs) > 0 {
		return fmt.Errorf("scenario capture: --event-ids not found in store: %s", strings.Join(missingIDs, ", "))
	}
	if len(selected) == 0 {
		return fmt.Errorf("scenario capture: no events matched the given selector")
	}

	// Derive the baseline the SAME way core/pipeline.Run's step (1a) does: the
	// persisted KindBaseline snapshot merged with pkg/baseline.Build over every
	// OTHER stored event -- i.e. as if the captured events had not happened yet.
	// This reproduces the baseline state the real scan gated on when these
	// events actually came in, so grading this scenario later is faithful to
	// what happened, not to an empty or after-the-fact baseline.
	selectedIDs := make(map[string]bool, len(selected))
	for _, ev := range selected {
		selectedIDs[ev.ID] = true
	}
	var priorEvents []event.Event
	for _, ev := range allEvents {
		if ev.ID == "" || !selectedIDs[ev.ID] {
			priorEvents = append(priorEvents, ev)
		}
	}
	persisted, err := loadPersistedBaseline(st)
	if err != nil {
		return fmt.Errorf("scenario capture: %w", err)
	}
	derivedBaseline := persisted.Merge(baseline.Build(priorEvents))

	primaryFamily := ""
	if len(mustFire) > 0 {
		primaryFamily = mustFire[0]
	} else {
		primaryFamily = mustNotFire[0]
	}

	scenarioID := strings.TrimSpace(*idFlag)
	if scenarioID == "" {
		scenarioID = generateCaptureScenarioID(primaryFamily, selected)
	} else if err := validateScenarioID(scenarioID); err != nil {
		return fmt.Errorf("scenario capture: --id %q: %w", scenarioID, err)
	}

	titleText := strings.TrimSpace(*title)
	if titleText == "" {
		actorLabel := firstNonEmptyActor(selected)
		if len(mustFire) > 0 {
			titleText = fmt.Sprintf("Captured: %s (actor %s)", strings.Join(mustFire, ", "), actorLabel)
		} else {
			titleText = fmt.Sprintf("Captured benign twin: %s (actor %s)", strings.Join(mustNotFire, ", "), actorLabel)
		}
	}

	doc := buildCaptureScenarioDoc(scenarioID, primaryFamily, titleText, *severity, selected, derivedBaseline, priorEvents, mustFire, mustNotFire, *reserved)

	resolvedScenariosDir := strings.TrimSpace(*scenariosDir)
	if resolvedScenariosDir == "" {
		root, err := eval.RepoRoot()
		if err != nil {
			return fmt.Errorf("scenario capture: resolving deploy repo root (for the default scenarios/ directory; pass --scenarios-dir to override): %w", err)
		}
		resolvedScenariosDir = filepath.Join(root, "scenarios")
	}
	if err := os.MkdirAll(resolvedScenariosDir, 0o755); err != nil {
		return fmt.Errorf("scenario capture: creating %s: %w", resolvedScenariosDir, err)
	}
	outPath, err := confinedScenarioPath(resolvedScenariosDir, scenarioID)
	if err != nil {
		return fmt.Errorf("scenario capture: %w", err)
	}
	if _, statErr := os.Stat(outPath); statErr == nil && !*force {
		return fmt.Errorf("scenario capture: %s already exists (pass --force to overwrite, or --id to choose a different id)", outPath)
	}

	operator := *by
	if operator == "" {
		operator = os.Getenv("USER")
	}
	if operator == "" {
		operator = "operator"
	}

	out, err := renderCaptureScenarioYAML(doc, operator, *storePath)
	if err != nil {
		return fmt.Errorf("scenario capture: rendering YAML: %w", err)
	}
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		return fmt.Errorf("scenario capture: writing %s: %w", outPath, err)
	}

	// Round-trip verify immediately: a captured scenario that mallcop's own
	// loader cannot parse is a silent authoring bug in THIS command, not
	// something that should be discovered three commands later by
	// 'mallcop eval'.
	if _, err := exam.Load(outPath); err != nil {
		return fmt.Errorf("scenario capture: generated scenario failed to parse (internal bug, please report): %w", err)
	}

	fmt.Printf("Captured scenario %s\n", scenarioID)
	fmt.Printf("  Wrote:  %s\n", outPath)
	fmt.Printf("  Events: %d (%s)\n", len(selected), strings.Join(eventIDList(selected), ", "))
	if len(mustFire) > 0 {
		fmt.Printf("  Must fire:     %s%s\n", strings.Join(mustFire, ", "), reservedSuffix(*reserved))
	} else {
		fmt.Printf("  Must NOT fire: %s\n", strings.Join(mustNotFire, ", "))
	}
	fmt.Println("Run 'mallcop eval' to grade this scenario locally, or 'mallcop scenario lint' to check benign-twin coverage.")
	return nil
}

// splitScenarioList splits a comma-separated flag value into a trimmed,
// non-empty token list. An empty input yields a nil (not empty-non-nil) slice.
func splitScenarioList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// loadStoredEventsForCapture replays the store's KindEvents stream into typed
// event.Event records, oldest first — mirrors core/pipeline.go's
// loadPriorEvents (unexported there, duplicated here for the same
// no-cross-package-reach reason cli/investigate.go's loadPersistedBaseline
// already documents).
func loadStoredEventsForCapture(st *store.Store) ([]event.Event, error) {
	raws, err := st.Load(store.KindEvents)
	if err != nil {
		return nil, fmt.Errorf("load stored events: %w", err)
	}
	out := make([]event.Event, 0, len(raws))
	for i, raw := range raws {
		var ev event.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("decode stored event %d: %w", i, err)
		}
		out = append(out, ev)
	}
	return out, nil
}

// selectCaptureEvents resolves the operator's event selector against the
// store's full event history, preserving the store's own chronological order
// and de-duplicating by ID across the two selector halves. missingIDs lists
// any explicit --event-ids not found in the store (the caller turns this into
// a loud error — an operator who names a specific event expects it to exist).
// An --actor selector with no matching events is an error (nothing to
// capture); --event-ids alone tolerates a partial store scan (the caller
// still errors on any miss, just via missingIDs instead of an empty result).
func selectCaptureEvents(all []event.Event, eventIDs []string, actor string, window time.Duration) (selected []event.Event, missingIDs []string, err error) {
	byID := make(map[string]event.Event, len(all))
	order := make([]string, 0, len(all))
	for _, ev := range all {
		if ev.ID == "" {
			continue
		}
		byID[ev.ID] = ev
		order = append(order, ev.ID)
	}

	want := map[string]bool{}

	for _, id := range eventIDs {
		if _, ok := byID[id]; !ok {
			missingIDs = append(missingIDs, id)
			continue
		}
		want[id] = true
	}

	if actor != "" {
		var maxTs time.Time
		found := false
		for _, ev := range all {
			if ev.Actor != actor {
				continue
			}
			if !found || ev.Timestamp.After(maxTs) {
				maxTs = ev.Timestamp
				found = true
			}
		}
		if !found {
			return nil, missingIDs, fmt.Errorf("no events found for actor %q", actor)
		}
		cutoff := maxTs.Add(-window)
		for _, ev := range all {
			if ev.Actor != actor || ev.ID == "" {
				continue
			}
			if ev.Timestamp.Before(cutoff) {
				continue
			}
			want[ev.ID] = true
		}
	}

	for _, id := range order {
		if want[id] {
			selected = append(selected, byID[id])
		}
	}
	return selected, missingIDs, nil
}

// generateCaptureScenarioID builds a default id: "LOCAL-<family-slug>-<hash8>"
// where hash8 is the first 8 hex chars of sha256(joined event IDs) — stable
// for the same event selection, distinct across different captures of the
// same family.
func generateCaptureScenarioID(family string, selected []event.Event) string {
	h := sha256.New()
	for _, ev := range selected {
		h.Write([]byte(ev.ID))
		h.Write([]byte{0})
	}
	sum := hex.EncodeToString(h.Sum(nil))[:8]
	slug := slugifyCaptureToken(family)
	if slug == "" {
		slug = "captured"
	}
	return fmt.Sprintf("LOCAL-%s-%s", slug, sum)
}

// maxScenarioIDLen bounds an operator-supplied --id. 128 chars plus ".yaml"
// stays comfortably under every mainstream filesystem's 255-byte name limit
// while being far longer than any sane scenario id.
const maxScenarioIDLen = 128

// validateScenarioID rejects any operator-supplied scenario id that is not a
// plain, single-path-element slug: it must start with an alphanumeric and
// contain only [A-Za-z0-9_-]. This is a SECURITY check, not stylistic
// hygiene: the id becomes a filename under scenarios/ (outPath below), and
// without it a crafted id like "../../elsewhere/evil" WRITES OUTSIDE the
// scenarios directory (path traversal). That matters doubly because
// `mallcop scenario capture` is also reachable conversationally (the
// flag-like-this investigate chat tool, core/investigate/evaltools.go),
// where the id can be influenced by attacker-controlled conversation
// content (indirect prompt injection) — the propose-safe claim ("writes
// only a local scenario file under scenarios/") is only true if this
// confinement actually holds. Auto-generated ids (generateCaptureScenarioID)
// satisfy this by construction.
func validateScenarioID(id string) error {
	if id == "" {
		return errors.New("scenario id must not be empty")
	}
	if len(id) > maxScenarioIDLen {
		return fmt.Errorf("scenario id too long (%d chars, max %d)", len(id), maxScenarioIDLen)
	}
	for i, r := range id {
		alnum := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if i == 0 {
			if !alnum {
				return errors.New("scenario id must start with a letter or digit")
			}
			continue
		}
		if !alnum && r != '-' && r != '_' {
			return fmt.Errorf("scenario id may only contain letters, digits, '-' and '_' (found %q)", string(r))
		}
	}
	return nil
}

// confinedScenarioPath returns the output path for scenarioID inside
// scenariosDir, HARD-VERIFYING that it resolves to a direct child of the
// (symlink-resolved) directory. Belt+suspenders behind validateScenarioID: a
// validated id cannot escape, but the write must stay confined even if the
// charset rule ever regresses — path traversal out of scenarios/ must be
// structurally impossible, not just filtered. The check compares
// filepath.Dir of the joined path against the canonical directory; note a
// filepath.Rel round-trip is NOT sufficient here (Rel reproduces the same
// "../" traversal it was fed, so it compares equal for the exact attack this
// exists to stop). scenariosDir must already exist (the caller MkdirAlls it).
func confinedScenarioPath(scenariosDir, scenarioID string) (string, error) {
	canonDir, err := filepath.EvalSymlinks(scenariosDir)
	if err != nil {
		return "", fmt.Errorf("resolving scenarios dir %s: %w", scenariosDir, err)
	}
	outPath := filepath.Join(canonDir, scenarioID+".yaml")
	if filepath.Dir(outPath) != canonDir || filepath.Base(outPath) != scenarioID+".yaml" {
		return "", fmt.Errorf("scenario id %q escapes the scenarios directory %s (refusing to write %s)", scenarioID, canonDir, outPath)
	}
	return outPath, nil
}

// slugifyCaptureToken lowercases s and collapses any run of non
// [a-z0-9] characters into a single '-', trimming leading/trailing dashes —
// keeps a family token filesystem- and YAML-id safe.
func slugifyCaptureToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// firstNonEmptyActor returns the first non-empty actor among selected, or
// "unknown" if none carry one — used only for a human-readable default title.
func firstNonEmptyActor(selected []event.Event) string {
	for _, ev := range selected {
		if ev.Actor != "" {
			return ev.Actor
		}
	}
	return "unknown"
}

// eventIDList returns the IDs of selected, in order.
func eventIDList(selected []event.Event) []string {
	out := make([]string, 0, len(selected))
	for _, ev := range selected {
		out = append(out, ev.ID)
	}
	return out
}

func reservedSuffix(reserved bool) string {
	if reserved {
		return " (reserved)"
	}
	return ""
}

// --- scenario YAML doc shape -------------------------------------------------
//
// These local types mirror internal/exam.Scenario's YAML keys exactly but add
// `omitempty` throughout, so a captured file reads like a hand-authored one
// (no `null`/`[]` clutter for unused optional blocks) while still round-
// tripping through exam.Load byte-for-byte on the fields that matter — Load
// only cares about YAML keys, not which Go type produced them.

type captureScenarioDoc struct {
	ID                string                      `yaml:"id"`
	Category          string                      `yaml:"category,omitempty"`
	Detector          string                      `yaml:"detector,omitempty"`
	Provenance        string                      `yaml:"provenance"`
	Finding           captureFindingDoc           `yaml:"finding"`
	Events            []captureEventDoc           `yaml:"events"`
	Baseline          *captureBaselineDoc         `yaml:"baseline,omitempty"`
	ExpectedDetection captureExpectedDetectionDoc `yaml:"expected_detection"`
}

type captureFindingDoc struct {
	ID       string   `yaml:"id"`
	Detector string   `yaml:"detector"`
	Title    string   `yaml:"title"`
	Severity string   `yaml:"severity"`
	EventIDs []string `yaml:"event_ids"`
}

type captureEventDoc struct {
	ID        string         `yaml:"id"`
	Timestamp string         `yaml:"timestamp,omitempty"`
	Source    string         `yaml:"source"`
	EventType string         `yaml:"event_type"`
	Actor     string         `yaml:"actor"`
	Action    string         `yaml:"action,omitempty"`
	Metadata  map[string]any `yaml:"metadata,omitempty"`
}

type captureBaselineDoc struct {
	KnownEntities   captureKnownEntitiesDoc           `yaml:"known_entities"`
	FrequencyTables map[string]int                    `yaml:"frequency_tables,omitempty"`
	Relationships   map[string]captureRelationshipDoc `yaml:"relationships,omitempty"`
}

type captureKnownEntitiesDoc struct {
	Actors     []string            `yaml:"actors,omitempty"`
	Sources    []string            `yaml:"sources,omitempty"`
	ActorRoles map[string][]string `yaml:"actor_roles,omitempty"`
	ActorHours map[string][]int    `yaml:"actor_hours,omitempty"`
}

type captureRelationshipDoc struct {
	Count     int    `yaml:"count"`
	FirstSeen string `yaml:"first_seen,omitempty"`
	LastSeen  string `yaml:"last_seen,omitempty"`
}

type captureExpectedDetectionDoc struct {
	MustFire    []string `yaml:"must_fire,omitempty"`
	MustNotFire []string `yaml:"must_not_fire,omitempty"`
	Reserved    bool     `yaml:"reserved,omitempty"`
}

// buildCaptureScenarioDoc assembles the full scenario document from the
// selected events, the derived baseline, and the operator's label.
func buildCaptureScenarioDoc(id, primaryFamily, title, severity string, selected []event.Event, derivedBaseline *baseline.Baseline, priorEvents []event.Event, mustFire, mustNotFire []string, reserved bool) captureScenarioDoc {
	events := make([]captureEventDoc, 0, len(selected))
	for _, ev := range selected {
		events = append(events, examEventDocFromStored(ev))
	}

	findingDetector := primaryFamily
	if findingDetector == "" {
		findingDetector = "captured"
	}

	return captureScenarioDoc{
		ID:         id,
		Category:   "captured",
		Detector:   findingDetector,
		Provenance: exam.ProvenanceCaptured,
		Finding: captureFindingDoc{
			ID:       id + "-finding",
			Detector: findingDetector,
			Title:    title,
			Severity: severity,
			EventIDs: eventIDList(selected),
		},
		Events:            events,
		Baseline:          captureBaselineDocFromDerived(derivedBaseline, priorEvents),
		ExpectedDetection: captureExpectedDetectionDoc{MustFire: mustFire, MustNotFire: mustNotFire, Reserved: reserved},
	}
}

// captureBaselineDocFromDerived projects a *pkg/baseline.Baseline into the
// scenario YAML's baseline: block. When the derived baseline carries no known
// actors (a brand-new store, or a captured actor with no baselineable prior
// history), it falls back to the distinct event sources seen in priorEvents
// so the block still satisfies internal/exam.Load's "known_entities must not
// be entirely empty" validation (ErrMalformedBaseline). If there is truly
// NOTHING to baseline (no actors, no sources — the very first event ever
// stored), it returns nil: a scenario with no baseline: block at all is
// itself valid ground truth ("no baseline data").
func captureBaselineDocFromDerived(bl *baseline.Baseline, priorEvents []event.Event) *captureBaselineDoc {
	if bl == nil {
		bl = &baseline.Baseline{}
	}

	doc := &captureBaselineDoc{
		KnownEntities: captureKnownEntitiesDoc{
			Actors: append([]string{}, bl.KnownActors...),
		},
	}
	sort.Strings(doc.KnownEntities.Actors)

	if len(bl.ActorHours) > 0 {
		doc.KnownEntities.ActorHours = map[string][]int{}
		for actor, hrs := range bl.ActorHours {
			cp := append([]int{}, hrs...)
			sort.Ints(cp)
			doc.KnownEntities.ActorHours[actor] = cp
		}
	}
	if len(bl.ActorRoles) > 0 {
		doc.KnownEntities.ActorRoles = map[string][]string{}
		for actor, roles := range bl.ActorRoles {
			cp := append([]string{}, roles...)
			sort.Strings(cp)
			doc.KnownEntities.ActorRoles[actor] = cp
		}
	}
	if len(bl.FrequencyTables) > 0 {
		doc.FrequencyTables = map[string]int{}
		for k, v := range bl.FrequencyTables {
			doc.FrequencyTables[k] = v
		}
	}
	if len(bl.Relationships) > 0 {
		doc.Relationships = map[string]captureRelationshipDoc{}
		for k, r := range bl.Relationships {
			doc.Relationships[k] = captureRelationshipDoc{Count: r.Count, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen}
		}
	}

	if len(doc.KnownEntities.Actors) == 0 {
		seen := map[string]bool{}
		var sources []string
		for _, ev := range priorEvents {
			if ev.Source == "" || seen[ev.Source] {
				continue
			}
			seen[ev.Source] = true
			sources = append(sources, ev.Source)
		}
		sort.Strings(sources)
		doc.KnownEntities.Sources = sources
	}

	if len(doc.KnownEntities.Actors) == 0 && len(doc.KnownEntities.Sources) == 0 {
		return nil
	}
	return doc
}

// examEventDocFromStored projects a stored event.Event into the scenario
// YAML's event shape. The event's Payload is unmarshaled to a flat map and
// carried WHOLESALE as the scenario event's metadata: block (after
// scrubPayloadMap redaction) — this is the shape core/detect's payloadMeta
// reads back from a round-tripped scenario (payload.metadata present -> use
// it), so every original discriminating field (role, ip, collaborator,
// resource_id, ...) survives under its ORIGINAL key name regardless of which
// alias a given detector happens to look for. The one field promoted to its
// own top-level YAML key is `action`: priv-escalation's readPrivPayload (via
// pkg/baseline's buildTopAction) reads action from the payload ROOT, never
// from the nested metadata block, so it must round-trip there too (see
// core/eval/scenario_tools.go's eventRecord, the mirror-image projection).
func examEventDocFromStored(ev event.Event) captureEventDoc {
	flat := map[string]any{}
	if len(ev.Payload) > 0 {
		// Best-effort: a malformed stored payload yields an empty (never nil)
		// metadata block rather than failing the whole capture.
		_ = json.Unmarshal(ev.Payload, &flat)
	}
	// Scrub the payload FIRST, then promote fields out of the SCRUBBED copy —
	// never out of raw `flat`. Audit of promotions: `action` is the ONLY field
	// lifted from the payload; ID/Source/EventType/Actor below come from the
	// ev.* envelope (not the payload), and actor/target are intentionally
	// preserved (see the scrub note). Promoting action from raw `flat` would
	// leak a credential the metadata copy already redacted.
	meta := scrubPayloadMap(flat)
	action, _ := meta["action"].(string)

	ts := ""
	if !ev.Timestamp.IsZero() {
		ts = ev.Timestamp.UTC().Format(time.RFC3339)
	}

	doc := captureEventDoc{
		ID:        ev.ID,
		Timestamp: ts,
		Source:    ev.Source,
		EventType: ev.Type,
		Actor:     ev.Actor,
		Action:    action,
	}
	if len(meta) > 0 {
		doc.Metadata = meta
	}
	return doc
}

// renderCaptureScenarioYAML marshals doc and prepends a short header comment
// recording who captured it, from which store, and when.
func renderCaptureScenarioYAML(doc captureScenarioDoc, operator, storePath string) ([]byte, error) {
	body, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	header := fmt.Sprintf(
		"# Captured by `mallcop scenario capture` (operator=%s) from store %s\n"+
			"# captured_at: %s\n"+
			"#\n"+
			"# This file is LOCAL to your own deploy repo: it is UNIONED into 'mallcop\n"+
			"# eval' grading but never touches the shipped reference corpus or\n"+
			"# exams/scenarios/corpus.pin. Run 'mallcop scenario lint' after adding or\n"+
			"# editing scenarios here to check benign-twin coverage.\n",
		operator, storePath, time.Now().UTC().Format(time.RFC3339))
	return append([]byte(header), body...), nil
}

// --- secret scrubbing --------------------------------------------------------
//
// No exported sanitize helper in this repo matches "redact credential-shaped
// values from an arbitrary metadata map" (core/agent.SanitizeField/
// SanitizeToolResult exists for a DIFFERENT purpose — prompt-injection
// boundary-marking on untrusted tool output, not secret redaction — and
// core/detect/secrets_exposure.go's patterns are unexported detector-package
// internals). This is a standalone, minimal implementation of the same idea:
// common credential shapes, redacted by pattern; common credential-shaped KEY
// NAMES, redacted regardless of value shape (a safety net for a secret format
// not covered by any pattern below). Actors/targets are left untouched by
// design (scrubPayloadMap only ever runs over the METADATA map, never over
// ev.Actor/ev.Target) — this file stays local to the customer's own repo, and
// actor/target identity is exactly what makes a captured scenario useful.
var captureSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                                     // AWS access key id
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),                                  // GitHub PAT
	regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),                                  // GitHub OAuth token
	regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`),                                  // GitHub app token
	regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{82}`),                          // GitHub fine-grained PAT
	regexp.MustCompile(`xox[bpsar]-[0-9a-zA-Z\-]{10,}`),                        // Slack token
	regexp.MustCompile(`sk-[a-zA-Z0-9\-_]{20,}`),                               // OpenAI/Anthropic-shaped secret key
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),                   // PEM private key
	regexp.MustCompile(`eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+`), // JWT
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-_.]{20,}`),                    // bearer token
	regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9+/=]{16,}`),                      // HTTP Basic auth (base64 decodes straight to user:password)
	regexp.MustCompile(`sk_(live|test)_[a-zA-Z0-9]{16,}`),                      // Stripe secret key (underscore form; hyphen sk- covered above)
	regexp.MustCompile(`rk_(live|test)_[a-zA-Z0-9]{16,}`),                      // Stripe restricted key
}

// captureURLUserinfoRE strips credentials embedded in a URL's userinfo for ANY
// scheme (scheme://user:pass@host, or scheme://token@host) — a GENERIC scheme
// pattern, NOT a fixed (postgres|mysql|...) whitelist, so mssql://, oracle://,
// https://, ftp://, amqps://, etc. are all covered. The scheme and host are
// preserved; the whole userinfo span (username included) is blanked. Bias: for
// a LOCAL fixture, redacting the entire userinfo is preferred over trying to
// keep the username and risking password residue.
var captureURLUserinfoRE = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)[^\s/@]+@`)

// captureSecretKeyAlt is the credential-key alternation shared by the k=v and
// colon-delimited value-blanking nets below. Longer forms are listed before
// their prefixes (password before pass) for leftmost-first matching; the \b
// in the composed regexes keeps `pass` from matching inside "bypass".
const captureSecretKeyAlt = `password|passwd|pwd|pass|accountkey|account_key|sharedaccesssignature|shared_access_signature|secret|access[_-]?key|api[_-]?key|apikey|auth[_-]?token|token|sig|credential`

// captureKVSecretRE blanks the VALUE of a credential-shaped KEY inside a
// delimited key=value connection string: ADO/JDBC ("Server=..;Password=..;"),
// an Azure storage string ("..;AccountKey=..;"), or a SAS query ("..&sig=..").
// Case-insensitive; the value is taken up to the next delimiter (';', '&',
// whitespace, or end of string). Bias: for a LOCAL fixture, over-redaction
// beats residue — when in doubt whether a value carries a secret, blank it.
var captureKVSecretRE = regexp.MustCompile(`(?i)\b(` + captureSecretKeyAlt + `)\s*=\s*[^;&\s]+`)

// captureColonSecretRE is the colon-delimited sibling of captureKVSecretRE:
// it blanks credential values in stringified JSON ("password":"hunter2"),
// YAML fragments and log lines (password: hunter2) that ride along inside a
// metadata string value. The optional quotes absorb JSON key/value quoting;
// the value runs to the next quote/delimiter/whitespace. Same over-redaction
// bias as the k=v net.
var captureColonSecretRE = regexp.MustCompile(`(?i)["']?\b(` + captureSecretKeyAlt + `)\b["']?\s*:\s*["']?[^"',;&\s]+`)

// captureCLIDBPassRE blanks the value of an inline -p<password> flag on a
// mysql/psql-family command line captured inside a metadata value (e.g.
// "mysql -u root -pHUNTER2 db"). Guarded by the command name since a bare
// `-p\S+` would shred unrelated flags; mangling the rest of a command string
// is acceptable (over-redaction bias) but this keeps it surgical.
var captureCLIDBPassRE = regexp.MustCompile(`(?i)\b((?:mysqldump|mysqladmin|mysql|mariadb|psql|pg_dumpall|pg_dump|pg_restore)\b[^\n;|&]*?\s-p)[^\s;|&]+`)

// captureCLIUserPassRE blanks curl-style inline credentials: `-u user:pass`
// or `--user=user:pass`. The whole user:pass span is blanked (username
// included) — same never-leak bias as the URL userinfo redactor.
var captureCLIUserPassRE = regexp.MustCompile(`((?:^|\s)(?:-u|--user)(?:\s+|=))[^\s:]+:[^\s]+`)

// captureSensitiveKeySubstrings: a metadata value whose KEY contains any of
// these (case-insensitive) is redacted unconditionally, regardless of whether
// the value matches a known secret pattern — the safety net for credential
// shapes this file's pattern list doesn't recognize.
var captureSensitiveKeySubstrings = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"access_key", "private_key", "client_secret", "credential",
	// Connection-string / DSN carriers: a value under any of these keys is
	// assumed to embed live credentials (URL userinfo or k=v pairs) and is
	// blanked wholesale. Over-redaction of an occasional benign URL is the
	// intended trade for a LOCAL fixture — never leak, even when the pattern
	// nets below don't recognize the specific secret shape.
	"url", "uri", "dsn", "conn", "connection_string", "database_url",
}

const captureRedactedPlaceholder = "[REDACTED]"

// scrubPayloadMap returns a deep copy of m with every string value that looks
// like a credential (by key name or by pattern match) replaced with
// captureRedactedPlaceholder. Keys are always left intact — only values are
// ever redacted, so a detector's alias-based lookup still finds the field, it
// just no longer carries the live secret.
func scrubPayloadMap(m map[string]any) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = scrubMetadataValue(k, v)
	}
	return out
}

func scrubMetadataValue(key string, v any) any {
	switch val := v.(type) {
	case string:
		lk := strings.ToLower(key)
		for _, sk := range captureSensitiveKeySubstrings {
			if strings.Contains(lk, sk) {
				return captureRedactedPlaceholder
			}
		}
		for _, re := range captureSecretPatterns {
			if re.MatchString(val) {
				return captureRedactedPlaceholder
			}
		}
		// In-string redactors: strip credentials embedded inside an otherwise
		// non-secret value (a URL's userinfo, k=v or k:v credential pairs in
		// connection strings / stringified JSON / log lines, and inline CLI
		// credentials) without discarding the whole value. Each deliberately
		// blanks the entire matched credential span — for a LOCAL fixture,
		// over-redaction is always preferable to residue.
		val = captureURLUserinfoRE.ReplaceAllString(val, "${1}"+captureRedactedPlaceholder+"@")
		val = captureKVSecretRE.ReplaceAllString(val, "${1}="+captureRedactedPlaceholder)
		val = captureColonSecretRE.ReplaceAllString(val, "${1}:"+captureRedactedPlaceholder)
		val = captureCLIDBPassRE.ReplaceAllString(val, "${1}"+captureRedactedPlaceholder)
		val = captureCLIUserPassRE.ReplaceAllString(val, "${1}"+captureRedactedPlaceholder)
		return val
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, vv := range val {
			out[k] = scrubMetadataValue(k, vv)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, vv := range val {
			out[i] = scrubMetadataValue(key, vv)
		}
		return out
	default:
		return v
	}
}
