// scenariocontribute_test.go — targeted tests for `mallcop scenario
// contribute` (mallcoppro-c78).
//
// SAFETY (load-bearing, do not weaken): NOT ONE test in this file may reach
// openContributePR — that function is the only code path in
// cli/scenariocontribute.go that touches git/gh or the network, and calling
// it here would open a REAL pull request against github.com/mallcop-app/
// mallcop. Every test below either calls runScenarioContribute with
// --dry-run (which returns before openContributePR is ever reached — see
// runScenarioContribute's early return) or exercises the pure plan-assembly
// functions (sanitizeScenarioForContribution, computeContributePin) directly.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/internal/exam"
)

// fixtureScenarioYAML returns a minimal, exam.Load-valid scenario document
// for the given id/family — used to build small on-disk fixture corpora.
func fixtureScenarioYAML(id, family string) string {
	return fmt.Sprintf(`id: %s
category: identity
detector: %s
provenance: reference
finding:
  id: %s-finding
  detector: %s
  title: fixture
  severity: low
  event_ids: [evt-1]
events:
- id: evt-1
  timestamp: '2026-01-01T00:00:00Z'
  source: test
  event_type: test.event
  actor: test-actor
expected_detection:
  must_fire: [%s]
`, id, family, id, family, family)
}

// newFixtureCorpusDir builds a tiny, self-consistent, pin-valid corpus (two
// scenarios) under a fresh temp dir and returns its root.
func newFixtureCorpusDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	scenariosDir := filepath.Join(dir, "exams", "scenarios", "identity")
	if err := os.MkdirAll(scenariosDir, 0o755); err != nil {
		t.Fatalf("mkdir fixture scenarios dir: %v", err)
	}

	files := map[string]string{
		"a.yaml": fixtureScenarioYAML("FIX-A", "new-actor"),
		"b.yaml": fixtureScenarioYAML("FIX-B", "new-actor"),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(scenariosDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write fixture scenario %s: %v", name, err)
		}
	}

	// Bootstrap the pin via computeContributePin itself, starting from an
	// EMPTY base corpus and adding each file in turn — this exercises the
	// SAME production pin-math the real contribute flow uses, so the fixture
	// corpus's own pin is trustworthy without duplicating the hash algorithm
	// by hand.
	base := eval.Corpus{}
	for _, name := range []string{"a.yaml", "b.yaml"} {
		data, err := os.ReadFile(filepath.Join(scenariosDir, name))
		if err != nil {
			t.Fatalf("read fixture scenario %s: %v", name, err)
		}
		manifestPath := "identity/" + name            // manifest-relative -- relative to exams/scenarios/, NOT the full disk path
		fileSHA := contentHashToken(string(data), 64) // full 32-byte sha256 hex
		diff, err := computeContributePin(base, manifestPath, fileSHA)
		if err != nil {
			t.Fatalf("bootstrap pin for %s: %v", name, err)
		}
		base = eval.Corpus{
			Scenarios: append(base.Scenarios, eval.LoadedScenario{RelPath: manifestPath, FileSHA: fileSHA}),
			Count:     diff.NewCount,
			SHA:       diff.NewSHA,
		}
	}

	pinBody := fmt.Sprintf("count %d\nsha256 %s\n", base.Count, base.SHA)
	if err := os.WriteFile(filepath.Join(dir, "exams", "scenarios", "corpus.pin"), []byte(pinBody), 0o644); err != nil {
		t.Fatalf("write fixture corpus.pin: %v", err)
	}
	return dir
}

// TestScenarioContribute_PinRegenCorrectness proves computeContributePin's
// output round-trips through the REAL production loader (eval.Load): adding
// the computed manifest line's file at its relpath and writing the computed
// pin values must make eval.Load succeed with the new count/sha, exactly as
// core/eval/corpus.go documents the manifest format.
func TestScenarioContribute_PinRegenCorrectness(t *testing.T) {
	dir := newFixtureCorpusDir(t)

	base, err := eval.Load(dir)
	if err != nil {
		t.Fatalf("eval.Load(fixture): %v (fixture corpus itself must be valid)", err)
	}
	if base.Count != 2 {
		t.Fatalf("fixture corpus count = %d, want 2", base.Count)
	}

	newContent := fixtureScenarioYAML("FIX-C", "new-actor")
	manifestPath := "identity/c.yaml"             // relative to exams/scenarios/ -- the manifest convention
	diskPath := "exams/scenarios/" + manifestPath // full repo-relative path, for the actual file write
	fileSHA := contentHashToken(newContent, 64)

	diff, err := computeContributePin(base, manifestPath, fileSHA)
	if err != nil {
		t.Fatalf("computeContributePin: %v", err)
	}
	if diff.OldCount != 2 || diff.NewCount != 3 {
		t.Errorf("count delta = %d -> %d, want 2 -> 3", diff.OldCount, diff.NewCount)
	}
	if diff.OldSHA != base.SHA {
		t.Errorf("OldSHA = %s, want base.SHA %s", diff.OldSHA, base.SHA)
	}
	if diff.NewSHA == diff.OldSHA {
		t.Error("NewSHA must differ from OldSHA after adding a scenario")
	}

	// Physically apply the delta and prove the REAL loader accepts it.
	if err := os.WriteFile(filepath.Join(dir, diskPath), []byte(newContent), 0o644); err != nil {
		t.Fatalf("write new scenario: %v", err)
	}
	newPin := fmt.Sprintf("count %d\nsha256 %s\n", diff.NewCount, diff.NewSHA)
	if err := os.WriteFile(filepath.Join(dir, "exams/scenarios/corpus.pin"), []byte(newPin), 0o644); err != nil {
		t.Fatalf("write regenerated pin: %v", err)
	}

	updated, err := eval.Load(dir)
	if err != nil {
		t.Fatalf("eval.Load after pin regen: %v", err)
	}
	if updated.Count != 3 {
		t.Errorf("updated.Count = %d, want 3", updated.Count)
	}
	if updated.SHA != diff.NewSHA {
		t.Errorf("updated.SHA = %s, want %s", updated.SHA, diff.NewSHA)
	}

	// Collision guard: contributing to an already-occupied relpath errors.
	if _, err := computeContributePin(updated, manifestPath, fileSHA); err == nil {
		t.Error("expected an error contributing to an already-occupied relpath")
	}
}

// contributeFixtureYAML is a captured-style scenario carrying real-looking
// actors, secrets, target identifiers, and timestamps — the input
// sanitizeScenarioForContribution must scrub before anything is safe to
// contribute.
const contributeFixtureYAML = `id: LOCAL-test-abc123
category: captured
detector: volume-anomaly
provenance: captured
trap_description: 'jane.doe@realcorp.com read from sub-169efd95/resourceGroups/prod-rg outside business hours.'
finding:
  id: LOCAL-test-abc123-finding
  detector: volume-anomaly
  title: 'Volume anomaly for jane.doe@realcorp.com'
  severity: medium
  event_ids: [evt-1, evt-2]
  metadata:
    actor: jane.doe@realcorp.com
    api_key: sk-liveAAAAAAAAAAAAAAAAAAAAAAAAAAAA
events:
- id: evt-1
  timestamp: '2025-11-04T10:00:00Z'
  source: azure
  event_type: storage_access
  actor: jane.doe@realcorp.com
  target: sub-169efd95/resourceGroups/prod-rg/storageAccounts/proddata
  metadata:
    github_token: ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    region: us-east-1
- id: evt-2
  timestamp: '2025-11-04T10:15:00Z'
  source: azure
  event_type: storage_access
  actor: jane.doe@realcorp.com
  target: sub-169efd95/resourceGroups/prod-rg/storageAccounts/proddata
baseline:
  known_entities:
    actors: [jane.doe@realcorp.com]
  relationships:
    'jane.doe@realcorp.com:sub-169efd95/resourceGroups/prod-rg':
      count: 12
      first_seen: '2025-05-01'
      last_seen: '2025-11-03'
expected_detection:
  must_fire: [volume-anomaly]
`

// TestScenarioContribute_SanitizeRoundTrip is the sanitize round-trip test:
// canonical tokens replace real actors/identifiers, no secret substring
// survives ANYWHERE in the sanitized output (grep-class, mirroring C5's
// scenariocapture_test.go shapes), non-secret fields survive (over-redaction
// guard), and the relative timing between events is preserved exactly.
func TestScenarioContribute_SanitizeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "captured.yaml")
	if err := os.WriteFile(src, []byte(contributeFixtureYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	sc, err := exam.Load(src)
	if err != nil {
		t.Fatalf("exam.Load(fixture): %v", err)
	}

	sanitized, diff, err := sanitizeScenarioForContribution(sc)
	if err != nil {
		t.Fatalf("sanitizeScenarioForContribution: %v", err)
	}

	out, err := marshalScenarioForTest(t, sanitized)
	if err != nil {
		t.Fatalf("marshal sanitized scenario: %v", err)
	}
	body := string(out)

	// Grep-class residue assertions: not one secret/identifying substring may
	// survive anywhere in the sanitized document.
	for _, secret := range []string{
		"jane.doe@realcorp.com",
		"sk-liveAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"169efd95",
	} {
		if strings.Contains(body, secret) {
			t.Errorf("sanitized YAML still contains residue %q:\n%s", secret, body)
		}
	}

	if !strings.Contains(body, "ci-bot") {
		t.Error("expected the first-seen actor to be canonicalized to ci-bot (pool[0])")
	}
	if !strings.Contains(body, "sub-") {
		t.Error("expected the 8-hex-char subscription-style identifier to keep the sub- prefix convention")
	}
	if diff.SecretsRedacted == 0 {
		t.Error("expected at least one secret-shaped metadata value redacted")
	}
	if len(diff.ActorRenames) == 0 {
		t.Error("expected at least one actor rename in the diff")
	}
	if len(diff.TargetRenames) == 0 {
		t.Error("expected at least one target identifier rename in the diff")
	}

	// Over-redaction guard: non-secret content must survive verbatim.
	if !strings.Contains(body, "us-east-1") {
		t.Error("sanitized YAML dropped non-secret metadata field region=us-east-1 -- over-redaction")
	}
	if !strings.Contains(body, "REDACTED") {
		t.Error("sanitized YAML has no REDACTED marker -- secret scrub did not run")
	}

	// Preserved relative timing: evt-2 was 15m after evt-1 originally, and
	// MUST remain exactly 15m apart after the timestamp shift.
	if len(sanitized.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(sanitized.Events))
	}
	t1, err := time.Parse(time.RFC3339, sanitized.Events[0].Timestamp)
	if err != nil {
		t.Fatalf("parse events[0].timestamp %q: %v", sanitized.Events[0].Timestamp, err)
	}
	t2, err := time.Parse(time.RFC3339, sanitized.Events[1].Timestamp)
	if err != nil {
		t.Fatalf("parse events[1].timestamp %q: %v", sanitized.Events[1].Timestamp, err)
	}
	if got := t2.Sub(t1); got != 15*time.Minute {
		t.Errorf("relative delta not preserved: got %s, want 15m", got)
	}
	// The earliest event must land exactly on the corpus's canonical anchor.
	if got := sanitized.Events[0].Timestamp; got != contributeAnchorTime {
		t.Errorf("earliest event timestamp = %s, want anchor %s", got, contributeAnchorTime)
	}
	// The baseline relationship's multi-month history delta relative to the
	// anchor event must also be preserved. wantDelta is computed from the
	// FIXTURE's own original values (first_seen 2025-05-01 relative to the
	// original earliest event 2025-11-04T10:00:00Z), never hardcoded, so this
	// assertion can't drift from the fixture above.
	originalEarliest, err := time.Parse(time.RFC3339, "2025-11-04T10:00:00Z")
	if err != nil {
		t.Fatalf("parse original earliest event: %v", err)
	}
	originalFirstSeen, err := time.Parse("2006-01-02", "2025-05-01")
	if err != nil {
		t.Fatalf("parse original first_seen: %v", err)
	}
	wantDelta := originalFirstSeen.Sub(originalEarliest)

	anchor, err := time.Parse(time.RFC3339, contributeAnchorTime)
	if err != nil {
		t.Fatalf("parse contributeAnchorTime: %v", err)
	}
	if sanitized.Baseline == nil || len(sanitized.Baseline.Relationships) != 1 {
		t.Fatalf("expected exactly 1 sanitized relationship, got %+v", sanitized.Baseline)
	}
	for _, r := range sanitized.Baseline.Relationships {
		fs, err := time.Parse("2006-01-02", r.FirstSeen)
		if err != nil {
			t.Fatalf("parse relationship first_seen %q: %v", r.FirstSeen, err)
		}
		gotDelta := fs.Sub(anchor)
		// Slack: the shift includes a sub-day (2h) component, and first_seen is
		// re-rendered date-only after shifting (formatContributeTimestamp keeps
		// a date-only field date-only) — that truncation can round to an
		// adjacent calendar day relative to a pure-day delta.
		slack := 24 * time.Hour
		if diff := gotDelta - wantDelta; diff < -slack || diff > slack {
			t.Errorf("relationship first_seen delta not preserved: got %s relative to anchor, want %s (+/- %s)", gotDelta, wantDelta, slack)
		}
	}
}

// TestScenarioContribute_SanitizedScenarioParsesViaExamLoad proves the
// sanitized output is not just string-clean but STRUCTURALLY valid: it
// parses via the exact loader ('mallcop eval' / 'mallcop scenario lint' /
// core/eval) uses, with no validation errors.
func TestScenarioContribute_SanitizedScenarioParsesViaExamLoad(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "captured.yaml")
	if err := os.WriteFile(src, []byte(contributeFixtureYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	sc, err := exam.Load(src)
	if err != nil {
		t.Fatalf("exam.Load(fixture): %v", err)
	}
	sanitized, _, err := sanitizeScenarioForContribution(sc)
	if err != nil {
		t.Fatalf("sanitizeScenarioForContribution: %v", err)
	}
	sanitized.Provenance = exam.ProvenanceContributed
	sanitized.ID = "CONTRIB-volume-anomaly-deadbeef"
	if sanitized.Finding != nil {
		sanitized.Finding.ID = sanitized.ID + "-finding"
	}

	out, err := marshalScenarioForTest(t, sanitized)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	outPath := filepath.Join(dir, "sanitized.yaml")
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		t.Fatalf("write sanitized: %v", err)
	}

	reloaded, err := exam.Load(outPath)
	if err != nil {
		t.Fatalf("exam.Load(sanitized output) failed -- sanitize must produce structurally valid YAML: %v", err)
	}
	if reloaded.EffectiveProvenance() != exam.ProvenanceContributed {
		t.Errorf("reloaded provenance = %s, want %s", reloaded.EffectiveProvenance(), exam.ProvenanceContributed)
	}
}

// TestScenarioContribute_AuthoredRefusal_AndOverride proves a
// provenance:authored scenario is refused by default (author-independence:
// the commons should predominantly grow from operator/captured ground
// truth) and accepted only with --allow-authored.
func TestScenarioContribute_AuthoredRefusal_AndOverride(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "authored.yaml")
	content := strings.Replace(contributeFixtureYAML, "provenance: captured", "provenance: authored", 1)
	if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out, err := withStdio(t, "", func() error {
		return runScenarioContribute([]string{"--dry-run", src})
	})
	if err == nil {
		t.Fatalf("expected refusal for provenance:authored without --allow-authored, got success:\n%s", out)
	}
	if !strings.Contains(err.Error(), "authored") {
		t.Errorf("refusal error should mention 'authored', got: %v", err)
	}

	out, err = withStdio(t, "", func() error {
		return runScenarioContribute([]string{"--dry-run", "--allow-authored", src})
	})
	if err != nil {
		t.Fatalf("runScenarioContribute with --allow-authored: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "dry-run") {
		t.Errorf("expected dry-run confirmation text in output:\n%s", out)
	}
}

// TestScenarioContribute_DryRun_PrintsRedactionDiffAndPRContent is the DONE
// condition from the item spec: a dry-run against a fixture prints the
// redaction diff AND the would-be PR content (repo, branch, file, pin delta,
// title, body) -- and, structurally, can NEVER reach openContributePR (see
// this file's package doc note): runScenarioContribute returns immediately
// after printing when --dry-run is set, before any git/gh invocation.
func TestScenarioContribute_DryRun_PrintsRedactionDiffAndPRContent(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "captured.yaml")
	if err := os.WriteFile(src, []byte(contributeFixtureYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out, err := withStdio(t, "", func() error {
		return runScenarioContribute([]string{"--dry-run", "--repo", "mallcop-app/mallcop", src})
	})
	if err != nil {
		t.Fatalf("runScenarioContribute --dry-run: %v\noutput:\n%s", err, out)
	}

	for _, want := range []string{
		"Redaction diff",
		"Actors renamed:",
		"Target identifiers redacted:",
		"Secret-shaped metadata values redacted:",
		"Timestamps shifted:",
		"Sanitized scenario YAML",
		"Would-be PR:",
		"Repo:   mallcop-app/mallcop",
		"Branch: contribute/CONTRIB-volume-anomaly-",
		"File:   exams/scenarios/behavioral/CONTRIB-volume-anomaly-",
		"Pin:    count",
		"Title:  scenario: contribute CONTRIB-volume-anomaly-",
		"dry-run: no PR opened, nothing left this machine.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\nfull output:\n%s", want, out)
		}
	}

	// No confirmation was requested and none should be needed post-dry-run;
	// PR body counts (not raw values) must appear too.
	if !strings.Contains(out, "actor(s) renamed to canonical corpus tokens") {
		t.Errorf("PR body summary missing from output:\n%s", out)
	}
}

// TestScenarioContribute_NoYesNoDryRun_StopsWithoutConfirming proves that
// invoking contribute with neither --yes nor --dry-run shows the diff but
// takes no action (does not error, does not reach openContributePR).
func TestScenarioContribute_NoYesNoDryRun_StopsWithoutConfirming(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "captured.yaml")
	if err := os.WriteFile(src, []byte(contributeFixtureYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out, err := withStdio(t, "", func() error {
		return runScenarioContribute([]string{src})
	})
	if err != nil {
		t.Fatalf("runScenarioContribute (no flags): %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "Re-run with --yes") {
		t.Errorf("expected a re-run-with---yes nudge, got:\n%s", out)
	}
}

// TestScenarioContribute_NoExpectedDetection_Errors proves a scenario with no
// must_fire/must_not_fire family is rejected (nothing to categorize or
// contribute).
func TestScenarioContribute_NoExpectedDetection_Errors(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "no-detection.yaml")
	content := `id: LOCAL-no-detection
provenance: operator
finding:
  id: LOCAL-no-detection-finding
  detector: x
  title: t
  severity: low
  event_ids: [evt-1]
events:
- id: evt-1
  timestamp: '2026-01-01T00:00:00Z'
  source: test
  event_type: test.event
  actor: solo-actor
`
	if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, err := withStdio(t, "", func() error {
		return runScenarioContribute([]string{"--dry-run", src})
	})
	if err == nil {
		t.Fatal("expected an error for a scenario with no expected_detection family")
	}
}

// marshalScenarioForTest marshals sc via the SAME yaml package the
// production code uses.
func marshalScenarioForTest(t *testing.T, sc *exam.Scenario) ([]byte, error) {
	t.Helper()
	return yaml.Marshal(sc)
}
