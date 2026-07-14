package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/internal/exam"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// seedCaptureStore opens a fresh git-backed store at t.TempDir() and appends
// the given events to KindEvents, one at a time, in order — mirroring what a
// real 'mallcop scan' run would have durably committed over time.
func seedCaptureStore(t *testing.T, events []event.Event) *store.Store {
	t.Helper()
	st, err := openOrInitStore(t.TempDir())
	if err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}
	for _, ev := range events {
		if _, err := st.Append(store.KindEvents, ev); err != nil {
			t.Fatalf("append event %s: %v", ev.ID, err)
		}
	}
	return st
}

func mustPayload(t *testing.T, v map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return raw
}

// TestScenarioCapture_ByActorWindow_RoundTripsThroughEval is the C5
// acceptance test: capture a brand-new actor's activity from a seeded store,
// write it as a must_fire scenario, and prove the SAME grading path
// 'mallcop eval' uses (eval.LoadExtraScenarios + eval.RunExamDetectOverCorpus)
// passes it — the captured event set genuinely triggers the registered
// "new-actor" detector because the derived baseline (built from every OTHER
// stored event) never saw this actor before.
func TestScenarioCapture_ByActorWindow_RoundTripsThroughEval(t *testing.T) {
	detect.ResetTuning()
	t.Cleanup(detect.ResetTuning)

	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	st := seedCaptureStore(t, []event.Event{
		// Background history: "carol" is a known, established actor.
		{ID: "bg-1", Source: "github", Type: "push", Actor: "carol", Timestamp: base.Add(-72 * time.Hour), Payload: mustPayload(t, map[string]any{"action": "push"})},
		{ID: "bg-2", Source: "github", Type: "push", Actor: "carol", Timestamp: base.Add(-48 * time.Hour), Payload: mustPayload(t, map[string]any{"action": "push"})},
		// The captured attack: a brand-new actor "mallory" shows up.
		{ID: "atk-1", Source: "github", Type: "repo.permission.grant", Actor: "mallory", Timestamp: base.Add(-2 * time.Hour), Payload: mustPayload(t, map[string]any{"action": "grant_admin", "role_name": "admin"})},
		{ID: "atk-2", Source: "github", Type: "repo.clone", Actor: "mallory", Timestamp: base.Add(-1 * time.Hour), Payload: mustPayload(t, map[string]any{"action": "clone_all_repos"})},
	})

	scenariosDir := filepath.Join(t.TempDir(), "scenarios")

	out, err := withStdio(t, "", func() error {
		return runScenarioCapture([]string{
			"--store", st.Path(),
			"--actor", "mallory",
			"--window", "24h",
			"--must-fire", "new-actor",
			"--id", "LOCAL-TEST-mallory",
			"--scenarios-dir", scenariosDir,
		})
	})
	if err != nil {
		t.Fatalf("runScenarioCapture: %v\noutput:\n%s", err, out)
	}

	outPath := filepath.Join(scenariosDir, "LOCAL-TEST-mallory.yaml")
	if _, statErr := os.Stat(outPath); statErr != nil {
		t.Fatalf("expected scenario file at %s: %v", outPath, statErr)
	}

	sc, err := exam.Load(outPath)
	if err != nil {
		t.Fatalf("internal/exam.Load(%s): %v", outPath, err)
	}
	if sc.EffectiveProvenance() != exam.ProvenanceCaptured {
		t.Errorf("provenance = %q, want %q", sc.Provenance, exam.ProvenanceCaptured)
	}
	if sc.ExpectedDetection == nil || len(sc.ExpectedDetection.MustFire) != 1 || sc.ExpectedDetection.MustFire[0] != "new-actor" {
		t.Fatalf("expected_detection = %+v, want must_fire=[new-actor]", sc.ExpectedDetection)
	}
	if len(sc.Events) != 2 {
		t.Fatalf("captured %d events, want 2 (atk-1, atk-2 only — background events excluded)", len(sc.Events))
	}
	for _, ev := range sc.Events {
		if ev.ID != "atk-1" && ev.ID != "atk-2" {
			t.Errorf("unexpected captured event id %q", ev.ID)
		}
	}
	if sc.Baseline == nil {
		t.Fatal("expected a baseline block (carol's background history should have baselined)")
	}
	found := false
	for _, a := range sc.Baseline.KnownEntities.Actors {
		if a == "carol" {
			found = true
		}
		if a == "mallory" {
			t.Error("mallory must NOT be in the derived baseline's known actors — that is exactly the finding under test")
		}
	}
	if !found {
		t.Errorf("expected carol in baseline known_entities.actors, got %v", sc.Baseline.KnownEntities.Actors)
	}

	// The round-trip: grade the captured scenario through the IDENTICAL path
	// 'mallcop eval' uses for an operator's own scenarios/ directory.
	extra, err := eval.LoadExtraScenarios(scenariosDir)
	if err != nil {
		t.Fatalf("eval.LoadExtraScenarios: %v", err)
	}
	if len(extra) != 1 {
		t.Fatalf("loaded %d extra scenarios, want 1", len(extra))
	}
	report := eval.RunExamDetectOverCorpus(eval.Corpus{}, extra)
	if report.Totals.Labeled != 1 {
		t.Fatalf("totals.labeled = %d, want 1", report.Totals.Labeled)
	}
	if report.Totals.Passed != 1 || report.Totals.Failed != 0 {
		t.Fatalf("totals = %+v, want exactly 1 passed row (new-actor genuinely fires on mallory)", report.Totals)
	}
}

// TestScenarioCapture_ByEventIDs proves the explicit --event-ids selector
// captures exactly the named events, in store order, regardless of actor.
func TestScenarioCapture_ByEventIDs(t *testing.T) {
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	st := seedCaptureStore(t, []event.Event{
		{ID: "e1", Source: "aws", Type: "console_login", Actor: "alice", Timestamp: base, Payload: mustPayload(t, map[string]any{"action": "login"})},
		{ID: "e2", Source: "aws", Type: "console_login", Actor: "bob", Timestamp: base.Add(time.Hour), Payload: mustPayload(t, map[string]any{"action": "login"})},
		{ID: "e3", Source: "aws", Type: "console_login", Actor: "carol", Timestamp: base.Add(2 * time.Hour), Payload: mustPayload(t, map[string]any{"action": "login"})},
	})

	scenariosDir := t.TempDir()
	out, err := withStdio(t, "", func() error {
		return runScenarioCapture([]string{
			"--store", st.Path(),
			"--event-ids", "e3,e1",
			"--must-not-fire", "new-actor",
			"--id", "LOCAL-TEST-explicit",
			"--scenarios-dir", scenariosDir,
		})
	})
	if err != nil {
		t.Fatalf("runScenarioCapture: %v\noutput:\n%s", err, out)
	}

	sc, err := exam.Load(filepath.Join(scenariosDir, "LOCAL-TEST-explicit.yaml"))
	if err != nil {
		t.Fatalf("exam.Load: %v", err)
	}
	if len(sc.Events) != 2 {
		t.Fatalf("captured %d events, want 2", len(sc.Events))
	}
	// Store order (e1 before e3), not request order (e3,e1).
	if sc.Events[0].ID != "e1" || sc.Events[1].ID != "e3" {
		t.Errorf("event order = [%s,%s], want [e1,e3] (store chronological order)", sc.Events[0].ID, sc.Events[1].ID)
	}
}

// TestScenarioCapture_MissingEventID_Errors proves a nonexistent explicit
// event id fails loudly rather than silently capturing a smaller set.
func TestScenarioCapture_MissingEventID_Errors(t *testing.T) {
	st := seedCaptureStore(t, []event.Event{
		{ID: "e1", Source: "aws", Type: "console_login", Actor: "alice", Timestamp: time.Now()},
	})
	_, err := withStdio(t, "", func() error {
		return runScenarioCapture([]string{
			"--store", st.Path(),
			"--event-ids", "e1,does-not-exist",
			"--must-not-fire", "new-actor",
			"--scenarios-dir", t.TempDir(),
		})
	})
	if err == nil {
		t.Fatal("expected an error for a nonexistent --event-ids entry")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error = %v, want it to name the missing id", err)
	}
}

// TestScenarioCapture_RedactsSecrets proves a credential-shaped metadata
// value is scrubbed from the captured YAML while ordinary fields (actor,
// action, non-secret metadata) survive verbatim.
func TestScenarioCapture_RedactsSecrets(t *testing.T) {
	st := seedCaptureStore(t, []event.Event{
		{
			ID: "leak-1", Source: "github", Type: "secret_scan_alert", Actor: "ci-bot",
			Timestamp: time.Now(),
			Payload: mustPayload(t, map[string]any{
				"action":       "commit_push",
				"github_token": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"repo":         "acme/widgets",
			}),
		},
	})

	scenariosDir := t.TempDir()
	out, err := withStdio(t, "", func() error {
		return runScenarioCapture([]string{
			"--store", st.Path(),
			"--event-ids", "leak-1",
			"--must-fire", "secrets-exposure",
			"--id", "LOCAL-TEST-secret",
			"--scenarios-dir", scenariosDir,
		})
	})
	if err != nil {
		t.Fatalf("runScenarioCapture: %v\noutput:\n%s", err, out)
	}

	raw, err := os.ReadFile(filepath.Join(scenariosDir, "LOCAL-TEST-secret.yaml"))
	if err != nil {
		t.Fatalf("read captured file: %v", err)
	}
	body := string(raw)
	if strings.Contains(body, "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") {
		t.Error("captured YAML contains the raw GitHub token — must be redacted")
	}
	if !strings.Contains(body, "REDACTED") {
		t.Error("captured YAML has no [REDACTED] marker — secret scrub did not run")
	}
	if !strings.Contains(body, "acme/widgets") {
		t.Error("captured YAML dropped a non-secret metadata field (repo) — over-redaction")
	}
	if !strings.Contains(body, "ci-bot") {
		t.Error("captured YAML dropped the actor — actors must be kept")
	}

	sc, err := exam.Load(filepath.Join(scenariosDir, "LOCAL-TEST-secret.yaml"))
	if err != nil {
		t.Fatalf("exam.Load: %v", err)
	}
	if len(sc.Events) != 1 {
		t.Fatalf("captured %d events, want 1", len(sc.Events))
	}
	if got, _ := sc.Events[0].Metadata["github_token"].(string); got != captureRedactedPlaceholder {
		t.Errorf("metadata.github_token = %q, want %q", got, captureRedactedPlaceholder)
	}
}

// TestScenarioCapture_RedactsConnectionCreds is the regression guard for the
// REVISE on PR #190 (rd mallcoppro-aa9): credential-carrying shapes that the
// original scrubber missed — URL userinfo for ANY scheme, key=value
// connection strings (ADO/JDBC, Azure storage AccountKey, SAS sig), and the
// promotion of a raw payload `action` into the top-level YAML key without
// scrubbing. It seeds ONE event whose payload embeds every reviewer repro
// string, captures it, and asserts (grep-class) that NO secret substring
// survives ANYWHERE in the emitted YAML, while non-secret fields (repo, actor)
// are preserved.
func TestScenarioCapture_RedactsConnectionCreds(t *testing.T) {
	// action is credential-shaped so the LOW promotion bypass is exercised:
	// pre-fix, the metadata copy was scrubbed but the promoted top-level
	// action carried the raw token. Kept a ghp_ PAT so the existing pattern
	// list scrubs it in metadata — isolating the promotion bug specifically.
	const actionToken = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	st := seedCaptureStore(t, []event.Event{
		{
			ID: "leak-2", Source: "aws", Type: "config_change", Actor: "ci-bot",
			Timestamp: time.Now(),
			Payload: mustPayload(t, map[string]any{
				"action": actionToken, // promoted -> top-level Action; must be scrubbed there too
				// Four reviewer repro strings, under keys that do NOT trip the
				// key-substring net, so the URL-userinfo / k=v redactors are what
				// must catch them:
				"db_endpoint": "mssql://sa:P4ssw0rd@dbhost:1433/db",
				"webhook":     "https://admin:hunter2@internal.example",
				"datasource":  "Server=x;User=sa;Password=hunter2;",
				"legacy_db":   "oracle://scott:tiger@ora:1521/orcl",
				// A generic-scheme URL userinfo (proves it's not a scheme whitelist):
				"mirror": "ftp://ftpuser:s3cr3tpw@ftp.example/pub",
				// Azure storage connection string (AccountKey=...):
				"storage": "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=Zm9vYmFyYmF6cXV4Cg==;EndpointSuffix=core.windows.net",
				// A SAS token (the sig= value is the secret):
				"download_link": "https://acct.blob.core.windows.net/c/b?sv=2021-06-08&ss=b&srt=o&sp=r&se=2026-01-01T00:00:00Z&sig=aB3xYzSecretSig%3D",
				// Non-secret — must survive verbatim:
				"repo": "acme/widgets",
			}),
		},
	})

	scenariosDir := t.TempDir()
	out, err := withStdio(t, "", func() error {
		return runScenarioCapture([]string{
			"--store", st.Path(),
			"--event-ids", "leak-2",
			"--must-fire", "config-drift",
			"--id", "LOCAL-TEST-conncreds",
			"--scenarios-dir", scenariosDir,
		})
	})
	if err != nil {
		t.Fatalf("runScenarioCapture: %v\noutput:\n%s", err, out)
	}

	raw, err := os.ReadFile(filepath.Join(scenariosDir, "LOCAL-TEST-conncreds.yaml"))
	if err != nil {
		t.Fatalf("read captured file: %v", err)
	}
	body := string(raw)

	// grep-class residue assertions: not one secret substring may appear
	// anywhere in the emitted YAML.
	for _, secret := range []string{
		actionToken,            // promoted-action bypass (LOW)
		"P4ssw0rd",             // mssql:// userinfo
		"hunter2",              // https:// userinfo AND Password= k=v
		"tiger",                // oracle:// userinfo
		"s3cr3tpw",             // ftp:// userinfo (generic scheme)
		"Zm9vYmFyYmF6cXV4Cg==", // Azure AccountKey value
		"aB3xYzSecretSig",      // SAS sig= value
	} {
		if strings.Contains(body, secret) {
			t.Errorf("captured YAML still contains secret residue %q:\n%s", secret, body)
		}
	}

	// Redaction actually ran, and non-secret fields survived.
	if !strings.Contains(body, "REDACTED") {
		t.Error("captured YAML has no [REDACTED] marker — secret scrub did not run")
	}
	if !strings.Contains(body, "acme/widgets") {
		t.Error("captured YAML dropped a non-secret metadata field (repo) — over-redaction")
	}
	if !strings.Contains(body, "ci-bot") {
		t.Error("captured YAML dropped the actor — actors must be kept")
	}

	// The promoted top-level action must be redacted, not merely the metadata copy.
	sc, err := exam.Load(filepath.Join(scenariosDir, "LOCAL-TEST-conncreds.yaml"))
	if err != nil {
		t.Fatalf("exam.Load: %v", err)
	}
	if len(sc.Events) != 1 {
		t.Fatalf("captured %d events, want 1", len(sc.Events))
	}
	if sc.Events[0].Action != captureRedactedPlaceholder {
		t.Errorf("top-level event action = %q, want %q (promotion bypass not scrubbed)",
			sc.Events[0].Action, captureRedactedPlaceholder)
	}
}

// TestScenarioCapture_RedactsRereviewLeakShapes is the regression guard for
// the adversarial re-review REJECT on PR #190 (after 77516ad): four more
// empirically-proven leak classes — HTTP Basic auth (base64 = user:password),
// Stripe underscore keys (sk_live_/sk_test_/rk_live_), colon-delimited
// credentials riding inside stringified JSON / YAML / log-line values, and
// inline CLI-arg credentials (mysql -p<pass>, curl -u user:pass, bare
// pass=). All eight reviewer repro strings go through the REAL capture path
// under keys that deliberately do NOT trip the key-substring net, and the
// grep-class assertions prove no secret substring survives anywhere in the
// emitted YAML while non-secret content (repo, actor, hostnames, benign
// query params) is preserved.
func TestScenarioCapture_RedactsRereviewLeakShapes(t *testing.T) {
	// The Stripe-shaped fixtures are constructed at runtime so this source
	// file never contains a key-shaped literal — GitHub push protection
	// (rightly) blocks pushes containing anything matching a live Stripe key,
	// fake or not. The concatenation is invisible to the scrubber, which only
	// ever sees the assembled string through the real capture path.
	stripeSecret := "sk_live_" + strings.Repeat("A", 24)
	stripeRestricted := "rk_test_" + strings.Repeat("B", 24)

	st := seedCaptureStore(t, []event.Event{
		{
			ID: "leak-3", Source: "aws", Type: "config_change", Actor: "ci-bot",
			Timestamp: time.Now(),
			Payload: mustPayload(t, map[string]any{
				"action": "config_change",
				// 1. HTTP Basic auth — Bearer was handled, Basic was not:
				"authorization": "Basic dXNlcjpzM2NyM3RiYXNpYw==",
				// 2. Stripe underscore keys — only hyphen sk- was covered:
				"billing":    stripeSecret,
				"restricted": stripeRestricted,
				// 3. Colon-delimited creds — the k=v net only knew `=`:
				"details": `{"user":"sa","password":"hunter2json"}`,
				"raw_log": "2026-07-14T10:33:07Z login ok password: topsecretyaml retry=0",
				// 4. Inline CLI-arg creds:
				"command":   "mysql -u root -phunter2cli acme_db",
				"fetch_cmd": "curl -u admin:hunter2curl https://api.internal.example/v1/status",
				"query":     "region=us-east-1&pass=hunter2pass&limit=10",
				// Non-secret — must survive verbatim:
				"repo": "acme/widgets",
			}),
		},
	})

	scenariosDir := t.TempDir()
	out, err := withStdio(t, "", func() error {
		return runScenarioCapture([]string{
			"--store", st.Path(),
			"--event-ids", "leak-3",
			"--must-fire", "config-drift",
			"--id", "LOCAL-TEST-rereview",
			"--scenarios-dir", scenariosDir,
		})
	})
	if err != nil {
		t.Fatalf("runScenarioCapture: %v\noutput:\n%s", err, out)
	}

	raw, err := os.ReadFile(filepath.Join(scenariosDir, "LOCAL-TEST-rereview.yaml"))
	if err != nil {
		t.Fatalf("read captured file: %v", err)
	}
	body := string(raw)

	// grep-class residue assertions: not one secret substring may appear
	// anywhere in the emitted YAML.
	for _, secret := range []string{
		"dXNlcjpzM2NyM3RiYXNpYw", // Basic auth base64 (user:s3cr3tbasic)
		stripeSecret,             // Stripe secret key (sk_live_..., underscore form)
		stripeRestricted,         // Stripe restricted key (rk_test_...)
		"hunter2json",            // "password":"..." in stringified JSON
		"topsecretyaml",          // password: ... in a log/yaml line
		"hunter2cli",             // mysql -p<pass>
		"hunter2curl",            // curl -u user:pass
		"hunter2pass",            // bare pass= in a query string
	} {
		if strings.Contains(body, secret) {
			t.Errorf("captured YAML still contains secret residue %q:\n%s", secret, body)
		}
	}

	// Redaction actually ran, and non-secret content survived the in-string
	// redactors (no whole-value nuking of command/query/log strings).
	if !strings.Contains(body, "REDACTED") {
		t.Error("captured YAML has no [REDACTED] marker — secret scrub did not run")
	}
	if !strings.Contains(body, "acme/widgets") {
		t.Error("captured YAML dropped a non-secret metadata field (repo) — over-redaction")
	}
	if !strings.Contains(body, "ci-bot") {
		t.Error("captured YAML dropped the actor — actors must be kept")
	}
	if !strings.Contains(body, "us-east-1") {
		t.Error("captured YAML dropped the benign query param (region) — over-redaction")
	}
	if !strings.Contains(body, "api.internal.example") {
		t.Error("captured YAML dropped the curl target host — over-redaction")
	}
	if !strings.Contains(body, "acme_db") {
		t.Error("captured YAML dropped the mysql database arg — over-redaction")
	}

	// Round-trip: the scenario must still load through the exam parser.
	sc, err := exam.Load(filepath.Join(scenariosDir, "LOCAL-TEST-rereview.yaml"))
	if err != nil {
		t.Fatalf("exam.Load: %v", err)
	}
	if len(sc.Events) != 1 {
		t.Fatalf("captured %d events, want 1", len(sc.Events))
	}
}

// TestScenarioCapture_MustFireAndMustNotFireMutuallyExclusive and the
// selector-validation cases below prove the flag-combination guard rails.
func TestScenarioCapture_ValidationErrors(t *testing.T) {
	st := seedCaptureStore(t, []event.Event{
		{ID: "e1", Source: "aws", Type: "console_login", Actor: "alice", Timestamp: time.Now()},
	})

	cases := []struct {
		name string
		args []string
	}{
		{"no store", []string{"--must-fire", "x", "--event-ids", "e1"}},
		{"no selector", []string{"--store", st.Path(), "--must-fire", "x"}},
		{"actor without window", []string{"--store", st.Path(), "--actor", "alice", "--must-fire", "x"}},
		{"window without actor", []string{"--store", st.Path(), "--window", "24h", "--must-fire", "x"}},
		{"no label", []string{"--store", st.Path(), "--event-ids", "e1"}},
		{"both labels", []string{"--store", st.Path(), "--event-ids", "e1", "--must-fire", "x", "--must-not-fire", "y"}},
		{"reserved without must-fire", []string{"--store", st.Path(), "--event-ids", "e1", "--must-not-fire", "y", "--reserved"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := withStdio(t, "", func() error { return runScenarioCapture(tc.args) })
			if err == nil {
				t.Fatalf("runScenarioCapture(%v): expected an error, got nil", tc.args)
			}
		})
	}
}
