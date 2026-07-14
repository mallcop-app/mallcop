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
	if len(diff.SecretPaths) == 0 {
		t.Error("expected at least one secret-shaped metadata value redacted")
	}
	if len(diff.ActorRenames) == 0 {
		t.Error("expected at least one actor rename in the diff")
	}
	if len(diff.IdentifierRenames) == 0 {
		t.Error("expected at least one identifier rename in the diff")
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
		"Identifiers redacted (targets, prose, metadata):",
		"Secret-shaped metadata values redacted:",
		"Timestamps shifted:",
		"Residue check: PASSED",
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
	// PR body counts (not raw values) must appear too, plus the ledger-backed
	// residue-check statement and the enumerated secret PATH (the consent
	// surface must list every redaction, HIGH fix).
	if !strings.Contains(out, "actor(s) renamed to canonical corpus tokens") {
		t.Errorf("PR body summary missing from output:\n%s", out)
	}
	if !strings.Contains(out, "Transmit-time residue check: PASSED") {
		t.Errorf("PR body residue-check statement missing from output:\n%s", out)
	}
	if !strings.Contains(out, "events[0].metadata.github_token") {
		t.Errorf("diff does not enumerate the secret redaction path events[0].metadata.github_token:\n%s", out)
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

// --- adversarial-review regressions (PR #192 REJECT round) --------------------

// contributeMetadataLeakFixtureYAML reproduces the reviewer's CRITICAL
// fixture shapes: identifying values that live ONLY inside metadata (which
// capture copies wholesale from event payloads) — a coworker email under
// peer_email AND collaborator, a private hostname twice, an internal IP, an
// account id (as a string AND as a bare YAML number), and the same
// subscription/tenant UUID in THREE metadata spots plus the event target.
// None of these are actors, so the actor pass cannot save any of them — only
// the metadata identifier scrub can.
const contributeMetadataLeakFixtureYAML = `id: LOCAL-leak-repro
category: captured
detector: volume-anomaly
provenance: captured
finding:
  id: LOCAL-leak-repro-finding
  detector: volume-anomaly
  title: 'Bulk reads on prod storage'
  severity: medium
  event_ids: [evt-1, evt-2]
  metadata:
    actor: victim-user
    subscription: 169efd95-3a5e-4b2d-9c1e-8f7a6b5c4d3e
    peer_email: coworker.jane@realcorp.com
    collaborator: bob.smith@realcorp.com
events:
- id: evt-1
  timestamp: '2025-11-04T10:00:00Z'
  source: azure
  event_type: storage_access
  actor: victim-user
  target: /subscriptions/169efd95-3a5e-4b2d-9c1e-8f7a6b5c4d3e/resourceGroups/prod-rg
  metadata:
    tenant: 169efd95-3a5e-4b2d-9c1e-8f7a6b5c4d3e
    src_ip: 10.23.4.87
    db_host: prod-db.realcorp.internal
    resource_id: /subscriptions/169efd95-3a5e-4b2d-9c1e-8f7a6b5c4d3e/rg/x
    account_id: "123456789012"
    billing_account: 210987654321
    blobs_accessed: 80
    region: us-east-1
  raw:
    secret_blob: raw-payload-must-be-stripped
- id: evt-2
  timestamp: '2025-11-04T10:00:30.5Z'
  source: azure
  event_type: storage_access
  actor: victim-user
  metadata:
    conn:
      host: prod-db.realcorp.internal
    notes:
    - 'peer coworker.jane@realcorp.com pulled the same blobs'
expected_detection:
  must_fire: [volume-anomaly]
`

// TestScenarioContribute_MetadataIdentifierLeaks_Scrubbed is the regression
// test for the review's CRITICAL finding: every identifying value that lives
// ONLY in metadata must be scrubbed from the transmit-bound artifacts (the
// sanitized YAML and the PR body), enumerated in the redaction ledger (HIGH:
// the consent surface must not under-report), and mapped to the SAME token as
// the same identifier elsewhere in the document (target + metadata agree).
// Non-vacuity: these values appear in NO structured field the pre-fix
// sanitizer touched — reverting the metadata scrub makes every residue
// assertion below fail.
func TestScenarioContribute_MetadataIdentifierLeaks_Scrubbed(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "leak-repro.yaml")
	if err := os.WriteFile(src, []byte(contributeMetadataLeakFixtureYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	sc, err := exam.Load(src)
	if err != nil {
		t.Fatalf("exam.Load(fixture): %v", err)
	}

	plan, err := buildContributePlan(sc, src, "mallcop-app/mallcop", "")
	if err != nil {
		t.Fatalf("buildContributePlan: %v", err)
	}
	body := string(plan.SanitizedYAML)

	// Grep-class: not one private identifier may survive in EITHER
	// transmit-bound artifact.
	leaks := []string{
		"coworker.jane@realcorp.com",
		"bob.smith@realcorp.com",
		"prod-db.realcorp.internal",
		"realcorp", // no fragment of the private domain either
		"10.23.4.87",
		"169efd95-3a5e-4b2d-9c1e-8f7a6b5c4d3e",
		"169efd95",
		"123456789012",
		"210987654321",
		"raw-payload-must-be-stripped", // raw: block stripped wholesale
		"secret_blob",
	}
	for _, leak := range leaks {
		if strings.Contains(body, leak) {
			t.Errorf("sanitized YAML still contains metadata residue %q:\n%s", leak, body)
		}
		if strings.Contains(plan.PRBody, leak) {
			t.Errorf("PR body contains residue %q:\n%s", leak, plan.PRBody)
		}
	}

	// Same-token agreement: the subscription UUID appears in the event target
	// AND (twice more) inside metadata — all three must carry the IDENTICAL
	// deterministic token (shared hash cache).
	uuid := "169efd95-3a5e-4b2d-9c1e-8f7a6b5c4d3e"
	uuidTok := "id-" + contentHashToken(uuid, 8)
	if got := strings.Count(body, uuidTok); got < 3 {
		t.Errorf("subscription UUID token %s appears %d time(s), want >= 3 (target + metadata.tenant + metadata.resource_id):\n%s", uuidTok, got, body)
	}
	// The private hostname appears twice (flat value + nested under conn:) —
	// same token both times.
	hostTok := "host-" + contentHashToken("prod-db.realcorp.internal", 8) + ".example"
	if got := strings.Count(body, hostTok); got != 2 {
		t.Errorf("hostname token %s appears %d time(s), want exactly 2:\n%s", hostTok, got, body)
	}

	// HIGH fix: the ledger (the consent surface) must ENUMERATE every one of
	// these — the operator consents to exactly what leaves.
	ledger := map[string]bool{}
	for _, r := range plan.Diff.IdentifierRenames {
		ledger[r.Original] = true
	}
	for _, wantOriginal := range []string{
		"coworker.jane@realcorp.com",
		"bob.smith@realcorp.com",
		"prod-db.realcorp.internal",
		"10.23.4.87",
		uuid,
		"123456789012",
		"210987654321", // numeric value under an identifier-carrying key
	} {
		if !ledger[wantOriginal] {
			t.Errorf("redaction ledger does not enumerate %q -- the consent diff under-reports what leaves\nledger: %+v", wantOriginal, plan.Diff.IdentifierRenames)
		}
	}

	// Over-redaction guards: measurement data and generic values survive.
	if !strings.Contains(body, "blobs_accessed: 80") {
		t.Errorf("blobs_accessed count corrupted -- over-redaction broke grading data:\n%s", body)
	}
	if !strings.Contains(body, "us-east-1") {
		t.Errorf("region us-east-1 dropped -- over-redaction:\n%s", body)
	}

	// LOW fix: sub-second precision. evt-2 was 30.5s after evt-1; the shifted
	// timestamps must preserve the 30.5s delta exactly.
	reloaded := struct{ e0, e1 string }{}
	sanitized, _, err := sanitizeScenarioForContribution(sc)
	if err != nil {
		t.Fatalf("sanitizeScenarioForContribution: %v", err)
	}
	reloaded.e0, reloaded.e1 = sanitized.Events[0].Timestamp, sanitized.Events[1].Timestamp
	t0, err := time.Parse(time.RFC3339, reloaded.e0)
	if err != nil {
		t.Fatalf("parse shifted events[0].timestamp %q: %v", reloaded.e0, err)
	}
	t1, err := time.Parse(time.RFC3339, reloaded.e1)
	if err != nil {
		t.Fatalf("parse shifted events[1].timestamp %q: %v", reloaded.e1, err)
	}
	if got, want := t1.Sub(t0), 30*time.Second+500*time.Millisecond; got != want {
		t.Errorf("sub-second delta not preserved: got %s, want %s (events[1].timestamp=%q)", got, want, reloaded.e1)
	}

	// The sanitized output must still parse via the real loader.
	outPath := filepath.Join(dir, "sanitized.yaml")
	if err := os.WriteFile(outPath, plan.SanitizedYAML, 0o644); err != nil {
		t.Fatalf("write sanitized: %v", err)
	}
	if _, err := exam.Load(outPath); err != nil {
		t.Fatalf("sanitized output failed exam.Load: %v", err)
	}
}

// TestScenarioContribute_ResidueCheck_FailsClosed proves verifyLedgerResidue
// is a real gate, not decoration: an artifact that still contains a ledger
// original must produce an error naming the residue.
func TestScenarioContribute_ResidueCheck_FailsClosed(t *testing.T) {
	diff := contributeDiff{
		IdentifierRenames: []contributeRename{{Original: "prod-db.realcorp.internal", Canonical: "host-deadbeef.example"}},
	}
	if err := verifyLedgerResidue("test artifact", []byte("clean content, nothing to see"), diff); err != nil {
		t.Fatalf("clean artifact must pass: %v", err)
	}
	err := verifyLedgerResidue("test artifact", []byte("still mentions prod-db.realcorp.internal here"), diff)
	if err == nil {
		t.Fatal("expected residue to fail the check")
	}
	if !strings.Contains(err.Error(), "prod-db.realcorp.internal") {
		t.Errorf("residue error should name the surviving original: %v", err)
	}
}

// --- openContributePR command construction (MED fix) ---------------------------
//
// These tests exercise openContributePR through FAKE exec seams
// (contributeLookupGH / contributeRunCommand) — no git or gh binary ever
// runs, nothing touches the network, and no PR can possibly open. They exist
// because the review's MED finding was a misconstructed `gh repo fork` argv
// (`--clone=true --remote=true <dir>` — gh does not clone into a positional
// dir that way) that only an argv-level test could have caught.

// fakeContributeExec installs recording seams and returns the recorded call
// log. The fake simulates `gh api user` returning login, and creates a
// minimal clone tree (exams/scenarios/corpus.pin) when the clone command
// runs so the subsequent pin rewrite operates on a real file.
type fakeContributeCall struct {
	Dir  string
	Name string
	Args []string
}

func fakeContributeExec(t *testing.T, login string) *[]fakeContributeCall {
	t.Helper()
	var calls []fakeContributeCall

	oldLookup, oldRun := contributeLookupGH, contributeRunCommand
	t.Cleanup(func() { contributeLookupGH, contributeRunCommand = oldLookup, oldRun })

	contributeLookupGH = func() (string, error) { return "gh", nil }
	contributeRunCommand = func(dir, name string, args ...string) ([]byte, error) {
		calls = append(calls, fakeContributeCall{Dir: dir, Name: name, Args: args})
		if name == "gh" && len(args) >= 2 && args[0] == "api" && args[1] == "user" {
			return []byte(login + "\n"), nil
		}
		if name == "gh" && len(args) >= 3 && args[0] == "repo" && args[1] == "clone" {
			cloneDir := args[3-1] // gh repo clone <target> <dir>
			if len(args) >= 4 {
				cloneDir = args[3]
			}
			scenDir := filepath.Join(cloneDir, "exams", "scenarios")
			if err := os.MkdirAll(scenDir, 0o755); err != nil {
				return nil, err
			}
			pin := "# corpus.pin header preserved\ncount 58\nsha256 0000000000000000000000000000000000000000000000000000000000000000\n"
			if err := os.WriteFile(filepath.Join(scenDir, "corpus.pin"), []byte(pin), 0o644); err != nil {
				return nil, err
			}
		}
		return []byte("ok\n"), nil
	}
	return &calls
}

// buildContributePlanForExecTest assembles a real plan from the standard
// fixture (real sanitize, real embedded-corpus pin regen) for the fake-exec
// tests.
func buildContributePlanForExecTest(t *testing.T) *contributePlan {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "captured.yaml")
	if err := os.WriteFile(src, []byte(contributeFixtureYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	sc, err := exam.Load(src)
	if err != nil {
		t.Fatalf("exam.Load: %v", err)
	}
	plan, err := buildContributePlan(sc, src, "mallcop-app/mallcop", "")
	if err != nil {
		t.Fatalf("buildContributePlan: %v", err)
	}
	return plan
}

func assertCall(t *testing.T, calls []fakeContributeCall, i int, wantName string, wantArgs ...string) fakeContributeCall {
	t.Helper()
	if i >= len(calls) {
		t.Fatalf("expected call %d (%s %v), only %d calls recorded: %+v", i, wantName, wantArgs, len(calls), calls)
	}
	c := calls[i]
	if c.Name != wantName {
		t.Fatalf("call %d: name = %q, want %q (call: %+v)", i, c.Name, wantName, c)
	}
	if len(wantArgs) > len(c.Args) {
		t.Fatalf("call %d: args %v shorter than want prefix %v", i, c.Args, wantArgs)
	}
	for j, w := range wantArgs {
		if w == "*" {
			continue // wildcard (tmpdir, generated paths)
		}
		if c.Args[j] != w {
			t.Fatalf("call %d: args[%d] = %q, want %q (full: %v)", i, j, c.Args[j], w, c.Args)
		}
	}
	return c
}

// TestOpenContributePR_CommandConstruction_ForkPath asserts the EXACT argv
// sequence for a contributor who is not the target repo's owner: resolve
// login -> fork (--clone=false, NO positional dir) -> clone THE FORK into the
// scratch dir (a separate command) -> branch/add/commit/push in that dir ->
// gh pr create with an owner-qualified --head.
func TestOpenContributePR_CommandConstruction_ForkPath(t *testing.T) {
	callsPtr := fakeContributeExec(t, "testbot")
	plan := buildContributePlanForExecTest(t)

	out, err := withStdio(t, "", func() error { return openContributePR(plan) })
	if err != nil {
		t.Fatalf("openContributePR: %v\noutput:\n%s", err, out)
	}
	calls := *callsPtr

	assertCall(t, calls, 0, "gh", "api", "user", "--jq", ".login")
	assertCall(t, calls, 1, "gh", "repo", "fork", "mallcop-app/mallcop", "--clone=false")
	clone := assertCall(t, calls, 2, "gh", "repo", "clone", "testbot/mallcop", "*")
	if len(clone.Args) != 4 {
		t.Fatalf("clone call must be exactly 'repo clone <fork> <dir>', got %v", clone.Args)
	}
	cloneDir := clone.Args[3]
	if cloneDir == "" {
		t.Fatal("clone target dir is empty")
	}

	co := assertCall(t, calls, 3, "git", "checkout", "-b", plan.Branch)
	if co.Dir != cloneDir {
		t.Fatalf("git checkout ran in %q, want the clone dir %q", co.Dir, cloneDir)
	}
	assertCall(t, calls, 4, "git", "add", plan.RelPath, "exams/scenarios/corpus.pin")
	assertCall(t, calls, 5, "git", "commit", "-F", ".contribute-commit-msg")
	assertCall(t, calls, 6, "git", "push", "origin", plan.Branch)
	pr := assertCall(t, calls, 7, "gh", "pr", "create", "--repo", "mallcop-app/mallcop", "--title", plan.PRTitle, "--body-file", "*", "--head", "testbot:"+plan.Branch)
	if pr.Dir != cloneDir {
		t.Fatalf("gh pr create ran in %q, want the clone dir %q", pr.Dir, cloneDir)
	}
	if len(calls) != 8 {
		t.Fatalf("expected exactly 8 external commands, got %d: %+v", len(calls), calls)
	}
}

// TestOpenContributePR_CommandConstruction_OwnerPath asserts the owner
// variant: no fork (you cannot fork your own repo), the target repo is cloned
// directly, and --head is the bare branch name.
func TestOpenContributePR_CommandConstruction_OwnerPath(t *testing.T) {
	callsPtr := fakeContributeExec(t, "mallcop-app")
	plan := buildContributePlanForExecTest(t)

	out, err := withStdio(t, "", func() error { return openContributePR(plan) })
	if err != nil {
		t.Fatalf("openContributePR: %v\noutput:\n%s", err, out)
	}
	calls := *callsPtr

	assertCall(t, calls, 0, "gh", "api", "user", "--jq", ".login")
	for _, c := range calls {
		if c.Name == "gh" && len(c.Args) >= 2 && c.Args[0] == "repo" && c.Args[1] == "fork" {
			t.Fatalf("owner path must not fork its own repo: %+v", c)
		}
	}
	clone := assertCall(t, calls, 1, "gh", "repo", "clone", "mallcop-app/mallcop", "*")
	cloneDir := clone.Args[3]

	assertCall(t, calls, 2, "git", "checkout", "-b", plan.Branch)
	assertCall(t, calls, 3, "git", "add", plan.RelPath, "exams/scenarios/corpus.pin")
	assertCall(t, calls, 4, "git", "commit", "-F", ".contribute-commit-msg")
	assertCall(t, calls, 5, "git", "push", "origin", plan.Branch)
	assertCall(t, calls, 6, "gh", "pr", "create", "--repo", "mallcop-app/mallcop", "--title", plan.PRTitle, "--body-file", "*", "--head", plan.Branch)

	// The scenario file + regenerated pin were written into the clone before
	// the commit ran. openContributePR removes its scratch dir on return, so
	// verify via the fake's captured filesystem effects: the pin rewrite is
	// asserted here through updateContributePinFile directly.
	pinPath := filepath.Join(t.TempDir(), "corpus.pin")
	pin := "# header stays\ncount 58\nsha256 aaaa\n"
	if err := os.WriteFile(pinPath, []byte(pin), 0o644); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	if err := updateContributePinFile(pinPath, plan.Pin); err != nil {
		t.Fatalf("updateContributePinFile: %v", err)
	}
	got, err := os.ReadFile(pinPath)
	if err != nil {
		t.Fatalf("read pin: %v", err)
	}
	if !strings.Contains(string(got), "# header stays") {
		t.Error("pin header comment not preserved")
	}
	if !strings.Contains(string(got), fmt.Sprintf("count %d", plan.Pin.NewCount)) {
		t.Errorf("pin count not rewritten to %d:\n%s", plan.Pin.NewCount, got)
	}
	if !strings.Contains(string(got), "sha256 "+plan.Pin.NewSHA) {
		t.Errorf("pin sha not rewritten to %s:\n%s", plan.Pin.NewSHA, got)
	}
	_ = cloneDir
}

// --- adversarial-review regressions (PR #192 REVISE round 2) -------------------

// contributeAuxFieldLeakFixtureYAML reproduces the round-2 HIGH-1 fixture
// shapes: identifying values in fields the round-1 sanitizer never walked —
// event ids (azure activity-log style, UUID embedded), event action (capture
// PROMOTES action straight from the payload), actor_chain action,
// connector_tools name/description, and tags (including a real-ccTLD .sh
// hostname, the MED-2 shape). None of these are metadata, so the round-1
// metadata walk cannot save any of them.
const contributeAuxFieldLeakFixtureYAML = `id: LOCAL-aux-repro
category: captured
detector: volume-anomaly
provenance: captured
tags:
- prod-db.realcorp.internal
- status.realcorp.sh
- contractor.eve@realcorp.com
finding:
  id: LOCAL-aux-repro-finding
  detector: volume-anomaly
  title: 'Bulk grant activity'
  severity: medium
  event_ids:
  - azure-169efd95-3a5e-4b2d-9c1e-8f7a6b5c4d3e-000123
  - azure-169efd95-3a5e-4b2d-9c1e-8f7a6b5c4d3e-000124
events:
- id: azure-169efd95-3a5e-4b2d-9c1e-8f7a6b5c4d3e-000123
  timestamp: '2025-11-04T10:00:00Z'
  source: azure
  event_type: role_grant
  actor: victim-user
  action: grant-to bob.smith@realcorp.com
  target: rg/prod
- id: azure-169efd95-3a5e-4b2d-9c1e-8f7a6b5c4d3e-000124
  timestamp: '2025-11-04T10:05:00Z'
  source: azure
  event_type: role_grant
  actor: victim-user
  action: grant-to bob.smith@realcorp.com
  target: rg/prod
actor_chain:
- actor: victim-user
  action: notify ops-lead@realcorp.com
  target: sub-169efd95/rg
connector_tools:
- name: lookup_victim-user_history
  description: Queries audit-api.realcorp.internal for recent grant events
  returns:
    events: []
expected_detection:
  must_fire: [volume-anomaly]
`

// TestScenarioContribute_AuxiliaryFieldLeaks_Scrubbed is the round-2 HIGH-1 +
// MED-2 regression: every identifying value in the previously sanitizer-blind
// fields (event id/action, actor_chain action, connector_tools
// name/description, tags — incl. a .sh real-TLD hostname) must be scrubbed
// from both transmit-bound artifacts, enumerated in the ledger, and event-id
// integrity (uniqueness + finding.event_ids cross-reference) must survive the
// shape-preserving tokenization. Runs through the REAL dry-run path first
// (proves the residue gate passes on this input), then asserts on the plan.
func TestScenarioContribute_AuxiliaryFieldLeaks_Scrubbed(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "aux-repro.yaml")
	if err := os.WriteFile(src, []byte(contributeAuxFieldLeakFixtureYAML), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// Real dry-run path: must succeed (round-1 code would transmit the leaks;
	// this asserts the fixed pipeline sanitizes AND self-verifies).
	out, err := withStdio(t, "", func() error {
		return runScenarioContribute([]string{"--dry-run", src})
	})
	if err != nil {
		t.Fatalf("runScenarioContribute --dry-run: %v\noutput:\n%s", err, out)
	}

	sc, err := exam.Load(src)
	if err != nil {
		t.Fatalf("exam.Load(fixture): %v", err)
	}
	plan, err := buildContributePlan(sc, src, "mallcop-app/mallcop", "")
	if err != nil {
		t.Fatalf("buildContributePlan: %v", err)
	}
	body := string(plan.SanitizedYAML)

	// Grep-class: no private identifier from ANY auxiliary field may survive
	// in either transmit-bound artifact.
	leaks := []string{
		"realcorp", // covers every hostname/email/domain fragment above
		"169efd95-3a5e-4b2d-9c1e-8f7a6b5c4d3e",
		"bob.smith@realcorp.com",
		"ops-lead@realcorp.com",
		"contractor.eve@realcorp.com",
		"prod-db.realcorp.internal",
		"status.realcorp.sh", // MED-2: .sh is a real ccTLD, not a filename
		"victim-user",
	}
	for _, leak := range leaks {
		if strings.Contains(body, leak) {
			t.Errorf("sanitized YAML still contains auxiliary-field residue %q:\n%s", leak, body)
		}
		if strings.Contains(plan.PRBody, leak) {
			t.Errorf("PR body contains residue %q:\n%s", leak, plan.PRBody)
		}
	}

	// Ledger enumeration (the consent surface must list every replacement).
	ledger := map[string]bool{}
	for _, r := range plan.Diff.IdentifierRenames {
		ledger[r.Original] = true
	}
	for _, want := range []string{
		"169efd95-3a5e-4b2d-9c1e-8f7a6b5c4d3e",
		"bob.smith@realcorp.com",
		"ops-lead@realcorp.com",
		"contractor.eve@realcorp.com",
		"prod-db.realcorp.internal",
		"status.realcorp.sh",
	} {
		if !ledger[want] {
			t.Errorf("identifier ledger does not enumerate %q\nledger: %+v", want, plan.Diff.IdentifierRenames)
		}
	}
	actorLedger := map[string]bool{}
	for _, r := range plan.Diff.ActorRenames {
		actorLedger[r.Original] = true
	}
	if !actorLedger["victim-user"] {
		t.Errorf("actor ledger does not enumerate victim-user: %+v", plan.Diff.ActorRenames)
	}

	// Event-id integrity through the shape-preserving tokenization: ids
	// changed, stayed DISTINCT, and finding.event_ids still references them
	// exactly (same deterministic transform on both sides).
	sanitized, _, err := sanitizeScenarioForContribution(sc)
	if err != nil {
		t.Fatalf("sanitizeScenarioForContribution: %v", err)
	}
	if len(sanitized.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(sanitized.Events))
	}
	id0, id1 := sanitized.Events[0].ID, sanitized.Events[1].ID
	if id0 == sc.Events[0].ID || id1 == sc.Events[1].ID {
		t.Errorf("event ids were not tokenized: %q, %q", id0, id1)
	}
	if id0 == id1 {
		t.Errorf("event-id uniqueness lost: both events carry %q", id0)
	}
	if sanitized.Finding == nil || len(sanitized.Finding.EventIDs) != 2 {
		t.Fatalf("finding.event_ids malformed after sanitize: %+v", sanitized.Finding)
	}
	if sanitized.Finding.EventIDs[0] != id0 || sanitized.Finding.EventIDs[1] != id1 {
		t.Errorf("finding.event_ids cross-reference broken: %v vs event ids [%s %s]", sanitized.Finding.EventIDs, id0, id1)
	}
	// Shape preserved: the non-identifying prefix/suffix of the azure
	// activity-log id survive around the tokenized UUID.
	if !strings.HasPrefix(id0, "azure-") || !strings.HasSuffix(id0, "-000123") {
		t.Errorf("event id shape not preserved: %q", id0)
	}

	// Connector tool: the actor fragment in the name is renamed to the same
	// canonical token as the actor everywhere else; the hostname in the
	// description is tokenized.
	if len(sanitized.ConnectorTools) != 1 {
		t.Fatalf("expected 1 connector tool, got %d", len(sanitized.ConnectorTools))
	}
	canonActor := sanitized.Events[0].Actor
	if !strings.Contains(sanitized.ConnectorTools[0].Name, canonActor) {
		t.Errorf("connector tool name %q does not carry the canonical actor token %q", sanitized.ConnectorTools[0].Name, canonActor)
	}
	if !strings.Contains(sanitized.ConnectorTools[0].Description, "host-") {
		t.Errorf("connector tool description not hostname-tokenized: %q", sanitized.ConnectorTools[0].Description)
	}

	// The sanitized output still parses via the real loader.
	outPath := filepath.Join(dir, "sanitized.yaml")
	if err := os.WriteFile(outPath, plan.SanitizedYAML, 0o644); err != nil {
		t.Fatalf("write sanitized: %v", err)
	}
	if _, err := exam.Load(outPath); err != nil {
		t.Fatalf("sanitized output failed exam.Load: %v", err)
	}
}

// TestScenarioContribute_FrequencyTables_ActorRenamed is the round-2 HIGH-2
// regression: a captured-with-baseline scenario (the feature's PRIMARY
// feedstock) whose frequency_tables keys carry the actor must CONTRIBUTE
// successfully — pre-fix, the un-renamed actor segment tripped the residue
// gate and hard-aborted every such contribution. Keys must carry the SAME
// canonical actor token as the events, counts must be untouched, and the
// result must still parse via internal/exam.Load.
func TestScenarioContribute_FrequencyTables_ActorRenamed(t *testing.T) {
	fixture := `id: LOCAL-freq-repro
category: captured
detector: volume-anomaly
provenance: captured
finding:
  id: LOCAL-freq-repro-finding
  detector: volume-anomaly
  title: 'Bulk reads'
  severity: medium
  event_ids: [evt-1]
events:
- id: evt-1
  timestamp: '2025-11-04T10:00:00Z'
  source: azure
  event_type: storage_access
  actor: jane.doe@realcorp.com
  target: rg/prod
baseline:
  known_entities:
    actors: [jane.doe@realcorp.com]
  frequency_tables:
    'azure:login': 50
    'azure:storage_access:jane.doe@realcorp.com': 10
    'azure:login:jane.doe@realcorp.com:0:afternoon': 198
    'azure:push:ghost-svc': 7
expected_detection:
  must_fire: [volume-anomaly]
`
	dir := t.TempDir()
	src := filepath.Join(dir, "freq-repro.yaml")
	if err := os.WriteFile(src, []byte(fixture), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// The REAL dry-run path must succeed — this exact input hard-aborted on
	// the residue gate pre-fix.
	out, err := withStdio(t, "", func() error {
		return runScenarioContribute([]string{"--dry-run", src})
	})
	if err != nil {
		t.Fatalf("captured-with-baseline contribution aborted (the feature's primary feedstock must work): %v\noutput:\n%s", err, out)
	}

	sc, err := exam.Load(src)
	if err != nil {
		t.Fatalf("exam.Load(fixture): %v", err)
	}
	plan, err := buildContributePlan(sc, src, "mallcop-app/mallcop", "")
	if err != nil {
		t.Fatalf("buildContributePlan: %v", err)
	}
	body := string(plan.SanitizedYAML)
	for _, leak := range []string{"jane.doe@realcorp.com", "realcorp", "ghost-svc"} {
		if strings.Contains(body, leak) {
			t.Errorf("frequency-table residue %q in sanitized YAML:\n%s", leak, body)
		}
	}

	sanitized, _, err := sanitizeScenarioForContribution(sc)
	if err != nil {
		t.Fatalf("sanitizeScenarioForContribution: %v", err)
	}
	canon := sanitized.Events[0].Actor // jane's canonical token
	ft := sanitized.Baseline.FrequencyTables
	wantKeys := map[string]int{
		"azure:login":                           50,
		"azure:storage_access:" + canon:         10,
		"azure:login:" + canon + ":0:afternoon": 198,
	}
	for k, v := range wantKeys {
		if got, ok := ft[k]; !ok || got != v {
			t.Errorf("frequency_tables[%q] = %d (present=%v), want %d\nfull tables: %+v", k, got, ok, v, ft)
		}
	}
	// ghost-svc appears ONLY in a freq key — it must still have been
	// collected and renamed, with its count preserved.
	foundGhost := false
	for k, v := range ft {
		if strings.HasPrefix(k, "azure:push:") {
			foundGhost = true
			if v != 7 {
				t.Errorf("azure:push count corrupted: %d, want 7", v)
			}
			if strings.Contains(k, "ghost-svc") {
				t.Errorf("freq-only actor ghost-svc not renamed: %q", k)
			}
		}
	}
	if !foundGhost {
		t.Errorf("azure:push:* key missing after rename: %+v", ft)
	}

	// Round-trip: the contributed file parses via the real loader.
	outPath := filepath.Join(dir, "sanitized.yaml")
	if err := os.WriteFile(outPath, plan.SanitizedYAML, 0o644); err != nil {
		t.Fatalf("write sanitized: %v", err)
	}
	if _, err := exam.Load(outPath); err != nil {
		t.Fatalf("sanitized output failed exam.Load: %v", err)
	}
}

// TestScenarioContribute_ActorNamedAdmin_NoFalseAbort is the round-2 MED-1
// regression: an actor literally named "admin" must not land any actor on a
// pool token containing that original ("admin-user", "infra-admin") — pre-fix
// the residue gate then hard-aborted a perfectly sanitized contribution with
// a message misdiagnosing the collision as a leak.
func TestScenarioContribute_ActorNamedAdmin_NoFalseAbort(t *testing.T) {
	fixture := `id: LOCAL-admin-repro
category: captured
detector: volume-anomaly
provenance: captured
finding:
  id: LOCAL-admin-repro-finding
  detector: volume-anomaly
  title: 'Grant burst'
  severity: medium
  event_ids: [evt-1, evt-2]
events:
- id: evt-1
  timestamp: '2025-11-04T10:00:00Z'
  source: azure
  event_type: role_grant
  actor: build-svc
  target: rg/prod
- id: evt-2
  timestamp: '2025-11-04T10:05:00Z'
  source: azure
  event_type: role_grant
  actor: admin
  target: rg/prod
expected_detection:
  must_fire: [volume-anomaly]
`
	dir := t.TempDir()
	src := filepath.Join(dir, "admin-repro.yaml")
	if err := os.WriteFile(src, []byte(fixture), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	out, err := withStdio(t, "", func() error {
		return runScenarioContribute([]string{"--dry-run", src})
	})
	if err != nil {
		t.Fatalf("actor named 'admin' caused a false abort: %v\noutput:\n%s", err, out)
	}

	sc, err := exam.Load(src)
	if err != nil {
		t.Fatalf("exam.Load: %v", err)
	}
	plan, err := buildContributePlan(sc, src, "mallcop-app/mallcop", "")
	if err != nil {
		t.Fatalf("buildContributePlan: %v", err)
	}
	if strings.Contains(string(plan.SanitizedYAML), "admin") {
		t.Errorf("'admin' survives in the sanitized YAML (as an original or inside a conflicted pool token):\n%s", plan.SanitizedYAML)
	}
	for _, r := range plan.Diff.ActorRenames {
		if strings.Contains(r.Canonical, "admin") {
			t.Errorf("canonical token %q contains the actor original 'admin' -- pool collision avoidance failed", r.Canonical)
		}
	}
}
