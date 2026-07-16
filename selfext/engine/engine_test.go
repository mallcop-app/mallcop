package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mallcop-app/mallcop/selfext/autonomy"
	"github.com/mallcop-app/mallcop/selfext/opencode"
	"github.com/mallcop-app/mallcop/selfext/sandbox"
	"github.com/mallcop-app/mallcop/selfext/session"
)

// The engine graph is the forge-free BYOK surface slated to relocate to the public
// MIT mallcop repo, so its TEST layer — like
// its production code — must reach NEITHER internal/forge NOR internal/donut NOR
// internal/selfext/subkey NOR internal/spendcap NOR internal/config. These tests
// therefore drive the engine through its OWN seam (session.Session +
// session.SpendController) using the library-pure fakeSession below. The genuinely
// commercial assertions that used to live inline here — authorize-before-mint
// ordering, subkey revoke-by-sha256, the real Forge usage-delta, and a REAL
// over-cap spendcap refusal — are RELOCATED to internal/selfext/integration, where
// importing the commercial layer is legitimate.

// ---- library-pure fake session ----------------------------------------------

// fakeSession is a library-pure session.Session that models the donut credential/
// billing lifecycle's OBSERVABLE behavior WITHOUT importing internal/forge,
// internal/donut, internal/selfext/subkey or internal/spendcap:
//
//   - Authorize delegates to a plain session.SpendController spy and, on success,
//     counts a "mint" (the donut rail mints its capped subkey iff the gate grants).
//     A gate denial is wrapped in *session.RefusalError exactly as DonutSession does.
//   - Credentials hands back the run's (baseURL, key) — the minted-subkey analogue
//     the engine flows into the adapter and records as the provenance endpoint.
//   - Record delegates the ledger fold to the spy gate and returns the canned cost
//     (the Forge usage-delta analogue).
//   - Close counts the teardown (the subkey-revoke analogue).
//
// The REAL forge/DonutSession wiring (mint, revoke-by-hash, usage-delta) is proven
// in internal/selfext/integration.
type fakeSession struct {
	gate    SpendController
	class   string
	baseURL string
	key     string
	cost    float64

	mints      int
	closeCalls int
}

var _ session.Session = (*fakeSession)(nil)

func (s *fakeSession) Authorize(ctx context.Context, estUSD float64) error {
	if err := s.gate.Authorize(ctx, s.class, estUSD); err != nil {
		return &session.RefusalError{Err: err}
	}
	s.mints++
	return nil
}

func (s *fakeSession) Credentials(context.Context) (string, string, error) {
	return s.baseURL, s.key, nil
}

func (s *fakeSession) Record(_ context.Context, success bool, _ float64) (float64, error) {
	if err := s.gate.Record(s.class, s.cost, success); err != nil {
		return 0, err
	}
	return s.cost, nil
}

func (s *fakeSession) Close() error { s.closeCalls++; return nil }

// ---- spy spend gate ----------------------------------------------------------

type recordCall struct {
	class   string
	cost    float64
	success bool
}

type spySpendGate struct {
	denyErr error // non-nil → Authorize refuses

	mu             sync.Mutex
	authorizeCalls int
	records        []recordCall
}

func (s *spySpendGate) Authorize(_ context.Context, class string, _ float64) error {
	s.mu.Lock()
	s.authorizeCalls++
	s.mu.Unlock()
	return s.denyErr
}

func (s *spySpendGate) Record(class string, cost float64, success bool) error {
	s.mu.Lock()
	s.records = append(s.records, recordCall{class, cost, success})
	s.mu.Unlock()
	return nil
}

func (s *spySpendGate) CapUSD() float64 { return 25.0 }

func (s *spySpendGate) lastRecord(t *testing.T) recordCall {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) == 0 {
		t.Fatalf("Record was never called")
	}
	return s.records[len(s.records)-1]
}

// ---- git fixture -------------------------------------------------------------

func initFixtureRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-b", "main")
	run("config", "user.email", "fixture@example.com")
	run("config", "user.name", "Fixture")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The authored-detector registry aggregator exists at base (as in real
	// mallcop); the engine appends the authored package's blank import to it
	// deterministically, so the fixture must carry a proper, appendable file.
	regDir := filepath.Join(repo, "core", "detect", "authored")
	if err := os.MkdirAll(regDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(regDir, "registry.go"), []byte("package authored\n\nimport (\n)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-m", "initial")
	return repo
}

// ---- fake opencode + validate stubs -----------------------------------------

// writeOpencodeStub writes a fake opencode that authors a deployburst detector
// into the worktree. mode "clean" writes an allow-list-clean own-package
// detector; mode "narrowing" adds a forbidden `os/exec` import that the gate
// must reject.
func writeOpencodeStub(t *testing.T, mode string) string {
	t.Helper()
	extraImport := ""
	if mode == "narrowing" {
		extraImport = "\t\"os/exec\"\n"
	}
	script := `#!/bin/sh
d=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--dir" ]; then d="$a"; fi
  prev="$a"
done
mkdir -p "$d/core/detect/authored/deployburst"
mkdir -p "$d/exams/scenarios/authored"
cat > "$d/core/detect/authored/deployburst/deployburst.go" <<'GOEOF'
package deployburst

import (
` + extraImport + `	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func init() { detect.Register(detector{}) }

type detector struct{}

func (detector) Name() string { return "authored-deploy-burst" }

func (detector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	return nil
}
GOEOF
printf 'scenario: deploy-burst must fire\n' > "$d/exams/scenarios/authored/deployburst-must-fire.yaml"
printf 'scenario: deploy-burst benign twin\n' > "$d/exams/scenarios/authored/deployburst-benign-twin.yaml"
printf '{"type":"text","text":"authored deployburst detector"}\n'
printf '{"type":"tool","tool":"write","state":{"input":{"filePath":"core/detect/authored/deployburst/deployburst.go"}}}\n'
exit 0
`
	return writeScript(t, "opencode-"+mode+".sh", script)
}

// writeValidateStub writes a fake `mallcop validate-proposal` that inspects the
// head worktree (its cwd) for a forbidden import and emits a GateResult
// mirroring the real gate: RED (exit 1) if os/exec is present under
// core/detect/authored, GREEN (exit 0) otherwise.
func writeValidateStub(t *testing.T) string {
	t.Helper()
	script := `#!/bin/sh
# args: validate-proposal --base <sha> --head HEAD --json ; cwd = head worktree
if grep -rq "os/exec" core/detect/authored 2>/dev/null; then
  cat <<'EOF'
{"schema_version":1,"tier":"free","passed":false,"base_sha":"BASE","head_sha":"HEAD","stages":[{"name":"guard","passed":true,"evidence":"guard ok","findings":[]},{"name":"structural","passed":false,"evidence":"import allow-list","findings":[{"path":"core/detect/authored/deployburst/deployburst.go","rule":"structural-import-allowlist","detail":"illegal import \"os/exec\""}]}],"coverage_plus":0,"new_firings":[]}
EOF
  exit 1
fi
cat <<'EOF'
{"schema_version":1,"tier":"free","passed":true,"base_sha":"BASE","head_sha":"HEAD","stages":[{"name":"guard","passed":true,"evidence":"guard ok","findings":[]},{"name":"structural","passed":true,"evidence":"builds + allow-list clean","findings":[]},{"name":"exam-detect","passed":true,"evidence":"coverage +1","findings":[]}],"coverage_plus":1,"new_firings":[]}
EOF
exit 0
`
	return writeScript(t, "validate-stub.sh", script)
}

// writeValidateStubRequiringExamRepo writes a fake `mallcop validate-proposal`
// that mirrors the REAL gate's customer-tree contract: it
// inspects its own argv for `--exam-repo <dir>`. Missing, or naming a
// nonexistent directory, it fails loudly (exit 2, a message naming
// --exam-repo) — exactly like the real gate does for a customer-shaped
// (no cmd/mallcop) tree in default mode. Present and pointing at a real
// directory, it returns a GREEN GateResult. This is the fixture
// TestRunProposedOnCustomerShapedTargetRepoWithExamRepo /
// TestRunFailsLoudlyOnCustomerShapedTargetRepoWithoutExamRepo use to prove
// Engine.ExamRepo actually reaches the gate subprocess's argv end-to-end,
// not just that the Go field exists.
func writeValidateStubRequiringExamRepo(t *testing.T) string {
	t.Helper()
	script := `#!/bin/sh
examrepo=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--exam-repo" ]; then examrepo="$a"; fi
  prev="$a"
done
if [ -z "$examrepo" ]; then
  echo "gate: this looks like a customer-shaped tree with no cmd/mallcop -- pass --exam-repo" >&2
  exit 2
fi
if [ ! -d "$examrepo" ]; then
  echo "gate: --exam-repo $examrepo is not a directory" >&2
  exit 2
fi
cat <<'EOF'
{"schema_version":1,"tier":"free","passed":true,"base_sha":"BASE","head_sha":"HEAD","stages":[{"name":"guard","passed":true,"evidence":"guard ok","findings":[]},{"name":"structural","passed":true,"evidence":"builds","findings":[]},{"name":"exam-detect","passed":true,"evidence":"customer-tree exam via reference tree","findings":[]}],"coverage_plus":0,"new_firings":[]}
EOF
exit 0
`
	return writeScript(t, "validate-stub-exam-repo.sh", script)
}

// writeValidateStubNovelGap writes a fake `mallcop validate-proposal` that
// returns a GateResult that is otherwise GREEN (Passed, coverage_plus>=1, no
// new_firings) but carries novel_gap:true — the BOTH ruling
// part-B shape: the customer detector's declared family has zero labeled
// must_fire rows in the reference corpus, so the corpus cannot independently
// grade it. Used to prove the engine withholds merge automation at
// autonomy=fully for this shape, the same dial-independent treatment already
// proven for OSS contribute-back on the router side.
func writeValidateStubNovelGap(t *testing.T) string {
	t.Helper()
	script := `#!/bin/sh
cat <<'EOF'
{"schema_version":1,"tier":"free","passed":true,"base_sha":"BASE","head_sha":"HEAD","stages":[{"name":"guard","passed":true,"evidence":"guard ok","findings":[]},{"name":"structural","passed":true,"evidence":"builds + allow-list clean","findings":[]},{"name":"exam-detect","passed":true,"evidence":"coverage +1; NOVEL GAP","findings":[]}],"coverage_plus":1,"new_firings":[],"novel_gap":true,"novel_gap_families":["deployburst"]}
EOF
exit 0
`
	return writeScript(t, "validate-stub-novelgap.sh", script)
}

func writeScript(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---- harness -----------------------------------------------------------------

type harness struct {
	session   *fakeSession // set by engine(); the run's credential/billing seam
	usageCost float64      // the "Forge usage delta" the fake session Records
	repo      string
	rejects   *RejectSet
	artifacts string
}

func newHarness(t *testing.T, usageCostUSD float64) *harness {
	t.Helper()
	rejects, err := LoadRejectSet(t.TempDir())
	if err != nil {
		t.Fatalf("LoadRejectSet: %v", err)
	}
	return &harness{
		usageCost: usageCostUSD,
		repo:      initFixtureRepo(t),
		rejects:   rejects,
		artifacts: t.TempDir(),
	}
}

// engine drives the engine through a library-pure fakeSession that delegates the
// spend-cap surface to the injected spy gate — the same seam the commercial
// DonutSession sits behind, minus the Forge/subkey guts. These tests assert the
// ENGINE's behavior (refusal, GREEN→artifact, teardown, autonomy routing) through
// that seam; the real DonutSession wiring (authorize-before-mint, revoke-by-hash,
// usage-delta) is proven in internal/selfext/integration.
func (h *harness) engine(gate SpendController, adapter Authorer, validateBin string) *Engine {
	h.session = &fakeSession{
		gate:    gate,
		class:   "selfext-author",
		baseURL: "https://forge.fake.local",
		key:     "mallcop-sk-fake-subkey",
		cost:    h.usageCost,
	}
	return &Engine{
		Session:       h.session,
		Jail:          &sandbox.Jail{TargetRepo: h.repo, BaseRef: "main"},
		Adapter:       adapter,
		Fingerprints:  h.rejects,
		ValidateBin:   validateBin,
		ArtifactDir:   h.artifacts,
		Class:         "selfext-author",
		AuthoringLane: "heal",
		Sovereignty:   "open",
		BudgetUSD:     2.00,
	}
}

func testGap() opencode.TrustedGap {
	return opencode.TrustedGap{
		DetectorID:   "authored-deploy-burst",
		EventType:    "github.deployment",
		TargetFamily: "deploy-burst",
		Severity:     "high",
		Actor:        "ci-bot",
		Source:       "connector:github",
	}
}

func realAdapter(bin string) *opencode.Adapter {
	return &opencode.Adapter{Bin: bin, Lane: "heal", Provider: sandbox.ProviderName, ForgeBaseURL: "https://forge.example.com"}
}

// ---- fake authorers for panic / refusal --------------------------------------

type panicAuthorer struct{}

func (panicAuthorer) BuildTaskPrompt(opencode.TrustedGap, bool) string { return "prompt" }
func (panicAuthorer) Invoke(context.Context, *sandbox.Worktree, string, string) (opencode.Result, error) {
	panic("opencode blew up mid-authoring")
}

type countingAuthorer struct{ invoked int }

func (c *countingAuthorer) BuildTaskPrompt(opencode.TrustedGap, bool) string { return "prompt" }
func (c *countingAuthorer) Invoke(context.Context, *sandbox.Worktree, string, string) (opencode.Result, error) {
	c.invoked++
	return opencode.Result{}, nil
}

// keyCapturingAuthorer records the apiKey it was handed and authors a clean,
// allow-list-safe detector into the worktree so there is something committable
// to gate. It stands in for a real opencode run on the BYOI rail and lets a test
// assert the USER's key (not a minted subkey) flowed through Invoke.
type keyCapturingAuthorer struct {
	gotKey  string
	invoked int
}

func (a *keyCapturingAuthorer) BuildTaskPrompt(opencode.TrustedGap, bool) string { return "prompt" }
func (a *keyCapturingAuthorer) Invoke(_ context.Context, wt *sandbox.Worktree, apiKey, _ string) (opencode.Result, error) {
	a.gotKey = apiKey
	a.invoked++
	dir := filepath.Join(wt.Dir, "core/detect/authored/deployburst")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return opencode.Result{}, err
	}
	body := "package deployburst\n\nfunc Name() string { return \"authored-deploy-burst\" }\n"
	if err := os.WriteFile(filepath.Join(dir, "deployburst.go"), []byte(body), 0o644); err != nil {
		return opencode.Result{}, err
	}
	return opencode.Result{TranscriptRedacted: []byte("BYOI transcript (redacted)")}, nil
}

// fastFailAuthorer authors NOTHING and returns a redacted transcript with a
// non-zero exit code — the live "opencode gave up" fast-fail. It stands in for a
// transient upstream failure the adapter already exhausted its retries on.
type fastFailAuthorer struct {
	transcript string
	exit       int
}

func (fastFailAuthorer) BuildTaskPrompt(opencode.TrustedGap, bool) string { return "prompt" }
func (f fastFailAuthorer) Invoke(context.Context, *sandbox.Worktree, string, string) (opencode.Result, error) {
	return opencode.Result{TranscriptRedacted: []byte(f.transcript), ExitCode: f.exit}, nil
}

// TestRunFailedRunPersistsTranscript proves the debuggability fix: when opencode
// authors nothing committable (the commit step fails), the run is Failed AND its
// redacted transcript + partial provenance are persisted under
// ArtifactDir/failed/ so the fast-fail is diagnosable without re-spending. The
// fingerprint is NOT poisoned (a transient failure may succeed later).
func TestRunFailedRunPersistsTranscript(t *testing.T) {
	h := newHarness(t, 0.0)
	gate := &spySpendGate{}
	const transcript = "opencode: upstream returned 503 service unavailable; giving up"
	eng := h.engine(gate, fastFailAuthorer{transcript: transcript, exit: 1}, writeValidateStub(t))

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Failed {
		t.Fatalf("expected Failed (nothing committable), got %+v", out)
	}
	// A failed-audit record was written under ArtifactDir/failed/.
	failedDir := filepath.Join(h.artifacts, "failed")
	entries, err := os.ReadDir(failedDir)
	if err != nil {
		t.Fatalf("read failed dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 failed-audit record, got %d", len(entries))
	}
	raw, err := os.ReadFile(filepath.Join(failedDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read failed record: %v", err)
	}
	var rec struct {
		Provenance         Provenance `json:"provenance"`
		Reason             string     `json:"reason"`
		OpencodeExitCode   int        `json:"opencode_exit_code"`
		TranscriptRedacted string     `json:"transcript_redacted"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("decode failed record: %v", err)
	}
	if rec.TranscriptRedacted != transcript {
		t.Errorf("failed record transcript = %q, want %q", rec.TranscriptRedacted, transcript)
	}
	if rec.OpencodeExitCode != 1 {
		t.Errorf("failed record opencode_exit_code = %d, want 1", rec.OpencodeExitCode)
	}
	if !strings.Contains(rec.Reason, "commit authored") {
		t.Errorf("failed record reason = %q, want a commit-authored failure", rec.Reason)
	}
	if rec.Provenance.Fingerprint != testGap().Fingerprint() {
		t.Errorf("failed record fingerprint = %q, want the gap fingerprint", rec.Provenance.Fingerprint)
	}
	// A transient failure must NOT poison the reject set (the gap may succeed later).
	if h.rejects.Has(testGap().Fingerprint()) {
		t.Errorf("a FAILED run poisoned the reject set (should only poison on RED)")
	}
	// No reviewable proposal was emitted.
	if out.ArtifactPath != "" {
		t.Errorf("a FAILED run emitted a proposal artifact %q", out.ArtifactPath)
	}
	// The subkey was still revoked on teardown.
	assertRevoked(t, h)
}

// ---- tests -------------------------------------------------------------------

// TestRunPositive: a clean stub authors an allow-list-clean detector, the gate
// GREENLIGHTs, an artifact is written, the subkey is revoked, and Record logs
// success with the measured cost.
func TestRunPositive(t *testing.T) {
	h := newHarness(t, 0.02)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "clean")), writeValidateStub(t))

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !out.Proposed {
		t.Fatalf("expected Proposed, got %+v", out)
	}
	if out.Gate == nil || !out.Gate.Passed {
		t.Fatalf("expected GREEN GateResult, got %+v", out.Gate)
	}
	// (Authorize-strictly-before-CreateKey ordering is a DonutSession property,
	// proven against the real Forge in internal/selfext/integration.)
	// Artifact written with the reviewable patch.
	if out.ArtifactPath == "" {
		t.Fatalf("no artifact path on GREEN")
	}
	if _, err := os.Stat(filepath.Join(out.ArtifactPath, "proposal.patch")); err != nil {
		t.Errorf("proposal.patch missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out.ArtifactPath, "gate.json")); err != nil {
		t.Errorf("gate.json missing: %v", err)
	}
	// Subkey revoked by full sha256 hash.
	assertRevoked(t, h)
	// Cost recorded with success=true.
	rec := gate.lastRecord(t)
	if !rec.success {
		t.Errorf("Record success=false, want true")
	}
	if rec.cost != 0.02 {
		t.Errorf("Record cost=%v, want 0.02", rec.cost)
	}
	if out.CostUSD != 0.02 {
		t.Errorf("Outcome cost=%v, want 0.02", out.CostUSD)
	}
	// The fingerprint is NOT poisoned on GREEN.
	if h.rejects.Has(testGap().Fingerprint()) {
		t.Errorf("GREEN run poisoned the reject set")
	}
}

// TestRunProvenanceRecordsResolvedOverrideModel is the regression for rd
// when Adapter.Model overrides Lane (the
// code-authoring override), provenance.json's "model" field must record the
// resolved literal catalog model id actually requested/billed — e.g.
// claude-haiku-4-5 — NOT the bare "<provider>/<lane>" string (e.g.
// "forge/heal"). Without this, a qwen3-32b run and a claude-haiku-4-5 run are
// indistinguishable in provenance without cross-checking /v1/usage by
// timestamp.
func TestRunProvenanceRecordsResolvedOverrideModel(t *testing.T) {
	h := newHarness(t, 0.02)
	gate := &spySpendGate{}
	adapter := realAdapter(writeOpencodeStub(t, "clean"))
	adapter.Model = "claude-haiku-4-5"
	eng := h.engine(gate, adapter, writeValidateStub(t))

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Proposed || out.ArtifactPath == "" {
		t.Fatalf("expected Proposed with an artifact, got %+v", out)
	}

	data, rerr := os.ReadFile(filepath.Join(out.ArtifactPath, "provenance.json"))
	if rerr != nil {
		t.Fatalf("read provenance.json: %v", rerr)
	}
	var prov Provenance
	if uerr := json.Unmarshal(data, &prov); uerr != nil {
		t.Fatalf("unmarshal provenance.json: %v", uerr)
	}
	if prov.Model != "claude-haiku-4-5" {
		t.Errorf("provenance.json model = %q, want the resolved literal catalog id %q (not the lane string)", prov.Model, "claude-haiku-4-5")
	}
	if prov.Lane != "heal" {
		t.Errorf("provenance.json lane = %q, want %q (lane is still recorded separately)", prov.Lane, "heal")
	}
}

// TestRunProvenanceRecordsProviderLaneWhenNoOverride proves the unoverridden
// path is unchanged by the fix: with no Adapter.Model override,
// provenance.json's "model" field still records "<provider>/<lane>" — the bare
// lane is genuinely all that was requested (Forge resolves it internally), so
// there is no more specific literal id to record.
func TestRunProvenanceRecordsProviderLaneWhenNoOverride(t *testing.T) {
	h := newHarness(t, 0.02)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "clean")), writeValidateStub(t))

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Proposed || out.ArtifactPath == "" {
		t.Fatalf("expected Proposed with an artifact, got %+v", out)
	}

	data, rerr := os.ReadFile(filepath.Join(out.ArtifactPath, "provenance.json"))
	if rerr != nil {
		t.Fatalf("read provenance.json: %v", rerr)
	}
	var prov Provenance
	if uerr := json.Unmarshal(data, &prov); uerr != nil {
		t.Fatalf("unmarshal provenance.json: %v", uerr)
	}
	want := sandbox.ProviderName + "/heal"
	if prov.Model != want {
		t.Errorf("provenance.json model = %q, want %q", prov.Model, want)
	}
}

// TestRunProposedOnCustomerShapedTargetRepoWithExamRepo proves Engine.ExamRepo
// reaches the gate subprocess end-to-end: h.repo (the
// standard fixture — no cmd/mallcop of its own, i.e. already customer-shaped)
// gates GREEN once Engine.ExamRepo names a real directory, because
// writeValidateStubRequiringExamRepo's fake gate only succeeds when it
// actually receives `--exam-repo <that directory>` in its argv. This is the
// engine-side proof the GateResult JSON contract stays unchanged while the
// customer-tree wiring takes effect (mirrors core/selfgate's own
// TestValidateProposal_CustomerTreeExamAcceptsPassingDetector on the mallcop
// side of the process boundary).
func TestRunProposedOnCustomerShapedTargetRepoWithExamRepo(t *testing.T) {
	h := newHarness(t, 0.02)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "clean")), writeValidateStubRequiringExamRepo(t))
	eng.ExamRepo = t.TempDir() // a real directory — the stub only accepts a real one

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Proposed {
		t.Fatalf("expected Proposed (the stub gate only greenlights WITH --exam-repo present), got %+v", out)
	}
	if out.Gate == nil || !out.Gate.Passed {
		t.Fatalf("expected a GREEN GateResult, got %+v", out.Gate)
	}
}

// TestRunFailsLoudlyOnCustomerShapedTargetRepoWithoutExamRepo is the negative
// half of the proof above: the SAME customer-shaped h.repo, the SAME stub
// gate, but Engine.ExamRepo left unset (the zero value — no engine
// misconfiguration). The gate never sees `--exam-repo`, so the stub (mirroring
// the real gate's own loud, actionable error) exits 2, and the engine surfaces
// this as an OPERATIONAL Failed outcome — never a Rejected/poisoned-fingerprint
// verdict, since a misconfigured reference tree is not a property of the
// authored proposal.
func TestRunFailsLoudlyOnCustomerShapedTargetRepoWithoutExamRepo(t *testing.T) {
	h := newHarness(t, 0.0)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "clean")), writeValidateStubRequiringExamRepo(t))
	// eng.ExamRepo left at its zero value ("").

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Failed {
		t.Fatalf("expected an operational Failed outcome (no --exam-repo reached the gate), got %+v", out)
	}
	if out.Rejected {
		t.Fatalf("a missing --exam-repo is an ENGINE/config problem, not a proposal defect — must never poison the fingerprint: %+v", out)
	}
	if !strings.Contains(out.Reason, "exam-repo") {
		t.Fatalf("Reason should surface the gate's own --exam-repo error, got %q", out.Reason)
	}
	if h.rejects.Has(testGap().Fingerprint()) {
		t.Errorf("an operational gate failure must NOT poison the reject set")
	}
}

// TestRunNegative: a narrowing stub authors a detector importing os/exec, the
// gate REJECTS, NO artifact is emitted, the fingerprint is poisoned, the subkey
// is STILL revoked, and Record logs failure.
func TestRunNegative(t *testing.T) {
	h := newHarness(t, 0.05)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "narrowing")), writeValidateStub(t))

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !out.Rejected {
		t.Fatalf("expected Rejected, got %+v", out)
	}
	if out.Gate == nil || out.Gate.Passed {
		t.Fatalf("expected RED GateResult, got %+v", out.Gate)
	}
	if out.ArtifactPath != "" {
		t.Errorf("RED run must not emit a reviewable artifact, got %q", out.ArtifactPath)
	}
	// No proposal-* directory was created.
	entries, _ := os.ReadDir(h.artifacts)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "proposal-") {
			t.Errorf("RED run emitted a proposal dir %q", e.Name())
		}
	}
	// Fingerprint poisoned.
	if !h.rejects.Has(testGap().Fingerprint()) {
		t.Errorf("RED run did not poison the reject set")
	}
	// Subkey STILL revoked (defer proven under a RED verdict).
	assertRevoked(t, h)
	// Record logged failure.
	if rec := gate.lastRecord(t); rec.success {
		t.Errorf("Record success=true, want false on RED")
	}
}

// TestRunRevokeOnPanic: an adapter that panics mid-Invoke must not leave a live
// subkey — the deferred revoke still fires.
func TestRunRevokeOnPanic(t *testing.T) {
	h := newHarness(t, 0.0)
	gate := &spySpendGate{}
	eng := h.engine(gate, panicAuthorer{}, writeValidateStub(t))

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run returned error instead of recovering panic: %v", err)
	}
	if !out.Failed {
		t.Fatalf("expected Failed outcome after panic, got %+v", out)
	}
	// A key WAS minted (Authorize precedes Invoke) and MUST have been revoked.
	if h.session.mints != 1 {
		t.Fatalf("expected exactly one mint before the panic, got %d", h.session.mints)
	}
	assertRevoked(t, h)
}

// TestRunAntiThrash: a pre-seeded reject fingerprint short-circuits BEFORE any
// spend or Forge call.
func TestRunAntiThrash(t *testing.T) {
	h := newHarness(t, 0.0)
	fp := testGap().Fingerprint()
	if err := h.rejects.Add(fp); err != nil {
		t.Fatalf("seed reject set: %v", err)
	}
	gate := &spySpendGate{}
	counter := &countingAuthorer{}
	eng := h.engine(gate, counter, writeValidateStub(t))

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Skipped {
		t.Fatalf("expected Skipped, got %+v", out)
	}
	// Zero mint, zero Authorize, opencode never invoked.
	if h.session.mints != 0 {
		t.Errorf("anti-thrash minted %d subkeys, want 0", h.session.mints)
	}
	if gate.authorizeCalls != 0 {
		t.Errorf("anti-thrash called Authorize %d times, want 0", gate.authorizeCalls)
	}
	if counter.invoked != 0 {
		t.Errorf("anti-thrash invoked opencode %d times, want 0", counter.invoked)
	}
}

// TestRunRefusalSpendGateDenies: when the Session's Authorize refuses (a benign
// *session.RefusalError — on the donut rail a spend-cap denial), the engine
// produces Outcome{Refused}, mints nothing, never invokes opencode, and — since
// teardown is deferred only AFTER a successful Authorize — never calls Close. The
// REAL spendcap over-cap wiring that PRODUCES this refusal (a $5-over-$1-cap gate
// wrapped by DonutSession) is exercised end to end in internal/selfext/integration
// (TestEngineRun_RealSpendGate_Refuses); here we prove the engine's OWN refusal
// handling through the fake seam.
func TestRunRefusalSpendGateDenies(t *testing.T) {
	h := newHarness(t, 0.0)
	gate := &spySpendGate{denyErr: errors.New("cap exceeded ($5 spent > $1 cap)")}
	counter := &countingAuthorer{}
	eng := h.engine(gate, counter, writeValidateStub(t))

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Refused {
		t.Fatalf("expected Refused, got %+v", out)
	}
	if h.session.mints != 0 {
		t.Errorf("refused run minted a subkey (mints=%d)", h.session.mints)
	}
	if counter.invoked != 0 {
		t.Errorf("refused run invoked opencode %d times, want 0", counter.invoked)
	}
	if h.session.closeCalls != 0 {
		t.Errorf("refused run tore down a session it never opened (closeCalls=%d)", h.session.closeCalls)
	}
}

// TestRunBYOIEndToEndStubGate proves the BYOI rail keeps EVERY safety rail while
// dropping only billing: the worktree jail is opened and cleaned up, the USER's
// own key (not a minted subkey) flows through the adapter, the validate-proposal
// gate runs, a GREEN verdict yields a REVIEWABLE artifact (code is NEVER
// auto-merged), provenance records the endpoint but NEVER the key, and CostUSD is
// 0. A BYOISession holds no Gate/Minter/Forge handle, so there is no Forge server
// in this test at all — zero Forge billing calls is structural.
//
// NAME NOTE (from the b2d veracity audit): this is "EndToEnd"
// for the BYOI billing/credential rail ONLY — ValidateBin here is
// writeValidateStub, a shell script standing in for `mallcop validate-proposal`,
// so it does NOT exercise the real selfgate.GateResult wire contract across the
// process boundary. That binding is proven separately, against the REAL mallcop
// binary built from the sibling checkout, by realgate_test.go
// (TestRunValidateProposal_RealGate_RejectsProtectedPath and
// TestRun_RealGate_RejectsProtectedPath).
func TestRunBYOIEndToEndStubGate(t *testing.T) {
	repo := initFixtureRepo(t)
	rejects, err := LoadRejectSet(t.TempDir())
	if err != nil {
		t.Fatalf("LoadRejectSet: %v", err)
	}
	artifacts := t.TempDir()

	const userKey = "sk-ant-api03-USERKEY-neverbilled-0123456789"
	authorer := &keyCapturingAuthorer{}
	eng := &Engine{
		Session:       &session.BYOISession{BaseURL: "http://fake", Key: userKey},
		Jail:          &sandbox.Jail{TargetRepo: repo, BaseRef: "main"},
		Adapter:       authorer,
		Fingerprints:  rejects,
		ValidateBin:   writeValidateStub(t),
		ArtifactDir:   artifacts,
		Class:         "selfext-author",
		AuthoringLane: "heal",
		Sovereignty:   "open",
		BudgetUSD:     2.00,
	}

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Proposed {
		t.Fatalf("want Proposed on a BYOI GREEN run, got %+v", out)
	}
	if out.Gate == nil || !out.Gate.Passed {
		t.Fatalf("expected the validate-proposal gate to run GREEN, got %+v", out.Gate)
	}
	if out.CostUSD != 0 {
		t.Errorf("BYOI CostUSD = %v, want 0 (no donut ledger decrement)", out.CostUSD)
	}
	// The user's OWN key flowed to the adapter — not a minted subkey.
	if authorer.gotKey != userKey {
		t.Errorf("adapter got key %q, want the BYOI user key", authorer.gotKey)
	}
	// GREEN → a reviewable artifact. Code is NEVER auto-merged: the ONLY output is
	// a proposal directory with a patch a human reviews.
	if out.ArtifactPath == "" {
		t.Fatalf("no artifact path on a GREEN BYOI run")
	}
	if _, err := os.Stat(filepath.Join(out.ArtifactPath, "proposal.patch")); err != nil {
		t.Errorf("proposal.patch missing (nothing to review): %v", err)
	}
	// Provenance records the endpoint (billed-to) but NEVER the key.
	provRaw, err := os.ReadFile(filepath.Join(out.ArtifactPath, "provenance.json"))
	if err != nil {
		t.Fatalf("read provenance.json: %v", err)
	}
	var prov Provenance
	if err := json.Unmarshal(provRaw, &prov); err != nil {
		t.Fatalf("decode provenance: %v", err)
	}
	if prov.Endpoint != "http://fake" {
		t.Errorf("provenance Endpoint = %q, want the BYOI endpoint", prov.Endpoint)
	}
	if strings.Contains(string(provRaw), "sk-ant") || strings.Contains(string(provRaw), userKey) {
		t.Errorf("provenance leaked the BYOI key:\n%s", provRaw)
	}
	// The worktree jail was opened AND cleaned up: only the main worktree remains.
	assertNoLeftoverWorktrees(t, repo)
}

// assertNoLeftoverWorktrees confirms Run cleaned up its jail: only the main
// worktree remains registered on the fixture repo.
func assertNoLeftoverWorktrees(t *testing.T, repo string) {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "worktree", "list", "--porcelain")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git worktree list: %v\n%s", err, out)
	}
	if c := strings.Count(string(out), "worktree "); c != 1 {
		t.Errorf("expected exactly 1 (main) worktree after Run, found %d:\n%s", c, out)
	}
}

// plantedTokenAuthorer authors a clean, allow-list-safe detector but plants an
// UNRELATED sk-ant-* style token in the authored source — simulating opencode
// echoing a leaked SIBLING key (not the run's own subkey) into a worktree
// file. It proves the GREEN proposal.patch artifact is redacted, not just the
// transcript.
const plantedToken = "sk-ant-PLANTEDSIBLINGTOKEN0123456789ABCDEF"

type plantedTokenAuthorer struct{}

func (plantedTokenAuthorer) BuildTaskPrompt(opencode.TrustedGap, bool) string { return "prompt" }
func (plantedTokenAuthorer) Invoke(_ context.Context, wt *sandbox.Worktree, _ string, _ string) (opencode.Result, error) {
	dir := filepath.Join(wt.Dir, "core/detect/authored/deployburst")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return opencode.Result{}, err
	}
	body := "package deployburst\n\n// planted sibling token leak: " + plantedToken + "\nfunc Name() string { return \"authored-deploy-burst\" }\n"
	if err := os.WriteFile(filepath.Join(dir, "deployburst.go"), []byte(body), 0o644); err != nil {
		return opencode.Result{}, err
	}
	return opencode.Result{TranscriptRedacted: []byte("transcript (already redacted upstream)")}, nil
}

// TestRunProposalArtifactRedacted proves the GREEN proposal.patch artifact is
// run through redact.Redact before it is written: a planted sk-ant-* sibling
// token that lands in the authored diff must NOT survive into the artifact on
// disk, and the redaction marker must appear in its place.
func TestRunProposalArtifactRedacted(t *testing.T) {
	h := newHarness(t, 0.01)
	gate := &spySpendGate{}
	eng := h.engine(gate, plantedTokenAuthorer{}, writeValidateStub(t))

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Proposed {
		t.Fatalf("expected Proposed, got %+v", out)
	}
	if out.ArtifactPath == "" {
		t.Fatalf("no artifact path on GREEN")
	}
	patch, err := os.ReadFile(filepath.Join(out.ArtifactPath, "proposal.patch"))
	if err != nil {
		t.Fatalf("read proposal.patch: %v", err)
	}
	if strings.Contains(string(patch), plantedToken) || strings.Contains(string(patch), "sk-ant") {
		t.Errorf("proposal.patch leaked the planted sibling token:\n%s", patch)
	}
	if !strings.Contains(string(patch), "***REDACTED***") {
		t.Errorf("proposal.patch missing the redaction marker:\n%s", patch)
	}
}

// TestRunValidateProposalEnvIsAllowlisted proves the validate-proposal gate
// subprocess sees ONLY the explicit env allowlist (gateEnvAllowlist), not the
// parent process's full environment. Credentials set in the test process
// (Forge admin key, a GitHub token, an AWS key, and a var no denylist would
// know to strip) must never reach the subprocess.
func TestRunValidateProposalEnvIsAllowlisted(t *testing.T) {
	t.Setenv("FORGE_API_KEY", "leak-me-not-forge")
	t.Setenv("GH_TOKEN", "leak-me-not-gh")
	t.Setenv("AWS_ACCESS_KEY_ID", "leak-me-not-aws")
	t.Setenv("SOME_FUTURE_OPERATOR_SECRET", "leak-me-not-future")

	envFile := filepath.Join(t.TempDir(), "gate-env.txt")
	script := "#!/bin/sh\n" +
		"env > " + envFile + "\n" +
		"cat <<'EOF'\n" +
		`{"schema_version":1,"tier":"free","passed":true,"base_sha":"BASE","head_sha":"HEAD","stages":[],"coverage_plus":0,"new_firings":[]}` + "\n" +
		"EOF\n" +
		"exit 0\n"
	bin := writeScript(t, "gate-env-dump.sh", script)

	repo := initFixtureRepo(t)
	if _, _, err := runValidateProposal(context.Background(), bin, repo, "HEAD", ""); err != nil {
		t.Fatalf("runValidateProposal: %v", err)
	}

	raw, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read captured gate env: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		key, _, _ := strings.Cut(line, "=")
		// PWD is not part of cmd.Env at all — /bin/sh sets it itself on start from
		// the process's actual cwd (cmd.Dir), which we already pass explicitly and
		// which carries no secret. Every OTHER var must be in the allowlist.
		if key == "PWD" {
			continue
		}
		if !gateEnvAllowlist[key] {
			t.Errorf("gate subprocess saw non-allowlisted env var %q", key)
		}
	}
	for _, leaked := range []string{"leak-me-not-forge", "leak-me-not-gh", "leak-me-not-aws", "leak-me-not-future"} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("gate subprocess env leaked a credential value %q:\n%s", leaked, raw)
		}
	}
}

// assertRevoked confirms the engine's teardown fired: Session.Close (on the donut
// rail, the subkey revoke) was called exactly once. The forge-free engine can only
// observe that Close was driven; the REAL revoke-by-exact-sha256-hash of the minted
// subkey is proven in internal/selfext/integration (recordingForge.assertRevoked).
func assertRevoked(t *testing.T, h *harness) {
	t.Helper()
	if h.session.closeCalls != 1 {
		t.Errorf("session Close (subkey revoke) called %d times, want exactly 1", h.session.closeCalls)
	}
}

// ---- autonomy dial matrix — CODE lane --------------------
//
// Engine.Autonomy decides ONLY whether a gate-GREEN authored change is ALSO
// merge-automated (a local branch force-update in the TARGET repo — see
// sandbox.Worktree.MergeToTargetBranch). Below: for non/semi/fully, one test
// proving what the dial ALLOWS and one proving what it REJECTS, against the
// real Run() decision path (real git, the real gate-stub process boundary) —
// not a stub of the merge step itself.

// branchExists reports whether branch exists in repo, and its target SHA.
func branchExists(t *testing.T, repo, branch string) (sha string, exists bool) {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "rev-parse", "--verify", "refs/heads/"+branch)
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// --- non: propose-only. Code never auto-applies. ---

// ALLOW (non): the run still reaches a normal GREEN Proposed outcome — the
// dial withholding auto-apply does not break the artifact-only path.
func TestRunAutonomyNonAllowsProposedArtifact(t *testing.T) {
	h := newHarness(t, 0.02)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "clean")), writeValidateStub(t))
	eng.Autonomy = autonomy.NonAutonomy

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Proposed || out.ArtifactPath == "" {
		t.Fatalf("autonomy=non GREEN run: expected Proposed with an artifact, got %+v", out)
	}
}

// REJECT (non): the SAME GREEN run does NOT merge-automate — Applied is false,
// no branch is created in the target repo.
func TestRunAutonomyNonRejectsMergeAutomation(t *testing.T) {
	h := newHarness(t, 0.02)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "clean")), writeValidateStub(t))
	eng.Autonomy = autonomy.NonAutonomy

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Applied || out.AppliedBranch != "" {
		t.Fatalf("autonomy=non must never merge-automate, got Applied=%v AppliedBranch=%q", out.Applied, out.AppliedBranch)
	}
	if _, exists := branchExists(t, h.repo, eng.autoApplyBranch(testGap().DetectorID)); exists {
		t.Errorf("autonomy=non: merge-automation branch exists in target repo despite propose-only dial")
	}
}

// --- semi: DATA auto-applies (router), CODE still waits for a human. ---

// ALLOW (semi): the run still reaches Proposed with an artifact — a human
// reviews and merges it by hand, exactly like non.
func TestRunAutonomySemiAllowsProposedArtifact(t *testing.T) {
	h := newHarness(t, 0.02)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "clean")), writeValidateStub(t))
	eng.Autonomy = autonomy.SemiAutonomy

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Proposed || out.ArtifactPath == "" {
		t.Fatalf("autonomy=semi GREEN run: expected Proposed with an artifact, got %+v", out)
	}
}

// REJECT (semi): CODE still does NOT auto-apply at semi — only DATA does (that
// half of the matrix is proven in router_test.go). No branch is created.
func TestRunAutonomySemiRejectsMergeAutomation(t *testing.T) {
	h := newHarness(t, 0.02)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "clean")), writeValidateStub(t))
	eng.Autonomy = autonomy.SemiAutonomy

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Applied || out.AppliedBranch != "" {
		t.Fatalf("autonomy=semi must not merge-automate CODE, got Applied=%v AppliedBranch=%q", out.Applied, out.AppliedBranch)
	}
	if _, exists := branchExists(t, h.repo, eng.autoApplyBranch(testGap().DetectorID)); exists {
		t.Errorf("autonomy=semi: merge-automation branch exists in target repo")
	}
}

// TestE2E_SemiDial_CodeWaitsEvidence is the e2e proof of the
// CODE half of the SEMI-autonomy contrast: the REAL Engine.Run() pipeline
// (real sandbox.Jail/Worktree against a real target git repo, real spend-gate
// authorize/record round trip against an httptest Forge, real opencode.Adapter
// Go orchestration; only the two subprocess BOUNDARIES — the opencode CLI and
// `mallcop validate-proposal` binaries — are deterministic stub scripts
// standing in for the external processes Engine always shells out to) is run
// at Autonomy=SemiAutonomy on a GREEN gate, and the Outcome is logged verbatim
// (JSON) so the e2e report quotes the ENGINE's own output. Companion:
// router package's TestE2E_SemiDial_DataAutoAppliesEvidence proves the DATA
// half (Destination=tenant_overlay, auto-written) on the same dial position.
func TestE2E_SemiDial_CodeWaitsEvidence(t *testing.T) {
	h := newHarness(t, 0.02)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "clean")), writeValidateStub(t))
	eng.Autonomy = autonomy.SemiAutonomy

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	outJSON, _ := json.MarshalIndent(out, "", "  ")
	t.Logf("SEMI/CODE real Outcome:\n%s", outJSON)

	if !out.Proposed || out.ArtifactPath == "" {
		t.Fatalf("SEMI/CODE: expected Proposed with an artifact (GREEN gate, reviewable), got %+v", out)
	}
	if out.Applied {
		t.Fatalf("SEMI/CODE: Applied = true, want false — code must wait for a human at semi")
	}
	if out.AppliedBranch != "" {
		t.Fatalf("SEMI/CODE: AppliedBranch = %q, want empty — no merge automation at semi", out.AppliedBranch)
	}
	branch := eng.autoApplyBranch(testGap().DetectorID)
	if sha, exists := branchExists(t, h.repo, branch); exists {
		t.Fatalf("SEMI/CODE: merge-automation branch %q exists in target repo at sha %q — code auto-applied despite semi dial", branch, sha)
	}
	t.Logf("SEMI/CODE confirmed: no branch %q in target repo %s (git branch --list empty)", branch, h.repo)
}

// --- fully: DATA and CODE both auto-apply. ---

// ALLOW (fully): a GREEN run merge-automates — Applied is true, and the target
// repo's local branch is force-updated to point at the authored HEAD SHA
// (proven against the REAL target repo via git rev-parse, not a stub).
func TestRunAutonomyFullyAppliesMergeAutomation(t *testing.T) {
	h := newHarness(t, 0.02)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "clean")), writeValidateStub(t))
	eng.Autonomy = autonomy.FullyAutonomy

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Proposed || !out.Applied {
		t.Fatalf("autonomy=fully GREEN run: expected Proposed AND Applied, got %+v", out)
	}
	wantBranch := eng.autoApplyBranch(testGap().DetectorID)
	if out.AppliedBranch != wantBranch {
		t.Fatalf("AppliedBranch = %q, want %q", out.AppliedBranch, wantBranch)
	}
	sha, exists := branchExists(t, h.repo, wantBranch)
	if !exists {
		t.Fatalf("autonomy=fully: merge-automation branch %q not found in target repo", wantBranch)
	}
	if sha != out.Gate.HeadSHA && sha == "" {
		t.Fatalf("merge-automation branch resolved to empty SHA")
	}
	// The branch must point at a real, present commit that carries the authored
	// file — not a dangling/empty ref.
	catFile := exec.Command("git", "-C", h.repo, "show", wantBranch+":core/detect/authored/deployburst/deployburst.go")
	if out, err := catFile.CombinedOutput(); err != nil {
		t.Fatalf("merge-automation branch does not carry the authored file: %v: %s", err, out)
	}
}

// REJECT (fully): NovelGap forces human review — even a gate-GREEN run with
// coverage+1 and zero regressions never merge-automates at "fully" when the
// gate flags NovelGap (BOTH ruling, part B): the customer
// detector's declared family has zero labeled must_fire rows in the reference
// corpus, so the corpus cannot independently grade it. This mirrors the SAME
// dial-independent hard line the engine has no code-lane equivalent for with
// OSS contribute-back (that's router-only) — NovelGap is the CODE-lane
// analogue, proven here against the real Run() path (real git, the real
// gate-stub process boundary), at the most permissive dial for the strongest
// possible guarantee. The proposal is still Proposed (a reviewable artifact),
// only Applied/merge-automation is withheld.
func TestRunAutonomyFullyNovelGapWithholdsMergeAutomation(t *testing.T) {
	h := newHarness(t, 0.02)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "clean")), writeValidateStubNovelGap(t))
	eng.Autonomy = autonomy.FullyAutonomy

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Proposed || out.ArtifactPath == "" {
		t.Fatalf("autonomy=fully NovelGap=true GREEN run: expected Proposed with an artifact, got %+v", out)
	}
	if out.Applied || out.AppliedBranch != "" {
		t.Fatalf("autonomy=fully NovelGap=true must NOT merge-automate, got Applied=%v AppliedBranch=%q", out.Applied, out.AppliedBranch)
	}
	if _, exists := branchExists(t, h.repo, eng.autoApplyBranch(testGap().DetectorID)); exists {
		t.Errorf("autonomy=fully NovelGap=true: merge-automation branch exists in target repo despite the novel-gap human-review requirement")
	}
	if out.Gate == nil || !out.Gate.NovelGap {
		t.Fatalf("expected out.Gate.NovelGap=true to have reached the engine, got %+v", out.Gate)
	}
}

// REJECT (fully): a NON-GREEN (RED) run — even at maximum autonomy — never
// merge-automates. Auto-apply is gated on gate.Passed FIRST, autonomy SECOND;
// proving this at "fully" (the most permissive dial) is the strongest possible
// proof that a RED gate is never bypassed by the dial.
func TestRunAutonomyFullyRejectsMergeAutomationOnRedGate(t *testing.T) {
	h := newHarness(t, 0.05)
	gate := &spySpendGate{}
	eng := h.engine(gate, realAdapter(writeOpencodeStub(t, "narrowing")), writeValidateStub(t))
	eng.Autonomy = autonomy.FullyAutonomy

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !out.Rejected {
		t.Fatalf("expected RED/Rejected, got %+v", out)
	}
	if out.Applied || out.AppliedBranch != "" {
		t.Fatalf("autonomy=fully must not merge-automate a RED gate, got Applied=%v AppliedBranch=%q", out.Applied, out.AppliedBranch)
	}
	if _, exists := branchExists(t, h.repo, eng.autoApplyBranch(testGap().DetectorID)); exists {
		t.Errorf("autonomy=fully: merge-automation branch exists despite a RED gate")
	}
}

// ---- customer-shaped authoring lane ---------------------

// initThinCustomerRepo creates a git repo shaped like a REAL `mallcop init
// --create-repo` THIN-EMBED customer deployment: no cmd/mallcop of its own
// (hasCmdMallcop is the SAME signal the gate already uses) and — critically —
// NO core/detect/authored/ tree and NO registry.go anywhere in its history
// (cli/deployrepo.go's real scaffold never creates one). This is the exact
// repro shape of the 7ee7 live-leg bug: the OLD unconditional registry step
// tried `git checkout <base> -- core/detect/authored/registry.go` against a
// repo where that pathspec never existed, and failed loud.
func initThinCustomerRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-b", "main")
	run("config", "user.email", "fixture@example.com")
	run("config", "user.name", "Fixture")
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module example.com/customer-fixture\n\ngo 1.25.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("customer deployment repo (THIN-EMBED fixture)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-m", "base: THIN-EMBED scaffold, no cmd/mallcop, no core/detect/authored")
	return repo
}

// sidecarFixtureMainSrc is a known-good customer-tree SIDECAR detector,
// mirroring mallcop core/selfgate/customergate_test.go's ground-truth
// customerFixtureDetectorMainSrc fixture: package main, a package-local
// Detector impl (no core/detect import), one func main() whose only
// statement is os.Exit(detectorhost.Run(<local value>{})).
const sidecarFixtureMainSrc = `package main

import (
	"os"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

type widgetLeakDetector struct{}

func (widgetLeakDetector) Name() string { return "widget-leak" }

func (widgetLeakDetector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type == "widget-secret-exposed" {
			out = append(out, finding.Finding{
				ID:     "finding-" + ev.ID + "-widgetleak",
				Source: "detector:widget-leak",
				Type:   "widget-leak",
				Actor:  ev.Actor,
			})
		}
	}
	return out
}

func main() { os.Exit(detectorhost.Run(widgetLeakDetector{})) }
`

// sidecarStubAuthorer stands in for opencode having ALREADY authored a
// known-good customer-tree sidecar — the PROOF fixture calls
// for (no live inference): a pre-baked authored file placed exactly where a
// real customer-tree opencode run would place it, at detectors/<name>/main.go.
type sidecarStubAuthorer struct{}

func (sidecarStubAuthorer) BuildTaskPrompt(opencode.TrustedGap, bool) string { return "prompt" }

func (sidecarStubAuthorer) Invoke(_ context.Context, wt *sandbox.Worktree, _, _ string) (opencode.Result, error) {
	dir := filepath.Join(wt.Dir, "detectors", "widgetleak")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return opencode.Result{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(sidecarFixtureMainSrc), 0o644); err != nil {
		return opencode.Result{}, err
	}
	return opencode.Result{TranscriptRedacted: []byte("stubbed sidecar authoring (fixture)")}, nil
}

// TestRun_CustomerShapedTarget_AuthorsSidecarSkipsRegistryReachesGateVerdict is
// the PROOF fixture (no live inference): a customer-shaped THIN
// target repo (no cmd/mallcop, no core/detect/authored/ at all) plus a
// stubbed "opencode already authored a known-good sidecar" Authorer. It
// asserts all three things the item's PROOF section calls for:
//
//   - (a) the sidecar lands at detectors/widgetleak/main.go under HEAD — the
//     customer-tree location a real deployment discovers — never under
//     core/detect/authored/.
//   - (b) the registry-linkage step is NEVER invoked. Before this fix, Run
//     would try `git checkout <base> -- core/detect/authored/registry.go`
//     against a repo where that pathspec never existed and fail loud with
//     the EXACT 7ee7 live-leg error ("pathspec ... did not match any
//     file(s) known to git"). This fixture repo has NO such path anywhere in
//     its history, so a regression here reproduces that exact Failed
//     outcome — a GREEN Proposed outcome is only reachable if that step
//     never ran.
//   - (c) the gate reached a REAL verdict through the
//     customer-tree (--exam-repo) path: writeValidateStubRequiringExamRepo's
//     fake gate only returns GREEN when it actually receives
//     `--exam-repo <dir>` in its own argv — the same mechanism
//     TestRunProposedOnCustomerShapedTargetRepoWithExamRepo already proves
//     for the gate side, now proven end-to-end from a stubbed authored
//     sidecar file.
func TestRun_CustomerShapedTarget_AuthorsSidecarSkipsRegistryReachesGateVerdict(t *testing.T) {
	h := newHarness(t, 0.02)
	gate := &spySpendGate{}
	eng := h.engine(gate, sidecarStubAuthorer{}, writeValidateStubRequiringExamRepo(t))
	thinRepo := initThinCustomerRepo(t)
	eng.Jail = &sandbox.Jail{TargetRepo: thinRepo, BaseRef: "main"}
	eng.ExamRepo = t.TempDir() // a real directory — the stub gate only accepts a real one

	out, err := eng.Run(context.Background(), testGap())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// (b) FIRST: the registry-linkage step must never have run.
	if out.Failed {
		t.Fatalf("Run FAILED — reproduces the 7ee7 live-leg bug if this is the registry step: %+v", out)
	}
	if strings.Contains(out.Reason, "register authored package") || strings.Contains(out.Reason, "pathspec") {
		t.Fatalf("registry-linkage step ran against a customer-shaped target (must be skipped): %+v", out)
	}

	// (c) the gate reached a REAL verdict through the customer-tree (--exam-repo) path.
	if !out.Proposed {
		t.Fatalf("expected Proposed (the stub gate only greenlights WITH --exam-repo present), got %+v", out)
	}
	if out.Gate == nil || !out.Gate.Passed {
		t.Fatalf("expected a GREEN GateResult via the customer-tree path, got %+v", out.Gate)
	}

	// (a) the sidecar landed at the customer-tree location, never
	// core/detect/authored/. At autonomy=non (the default here) the authored
	// commit lives only in the disposable worktree jail (force-removed on
	// teardown, never merged into thinRepo's own branches) — the artifact's
	// proposal.patch is the durable record of what was authored and where.
	if out.ArtifactPath == "" {
		t.Fatalf("GREEN proposal has no artifact path")
	}
	patch, err := os.ReadFile(filepath.Join(out.ArtifactPath, "proposal.patch"))
	if err != nil {
		t.Fatalf("read proposal.patch: %v", err)
	}
	if !strings.Contains(string(patch), "detectors/widgetleak/main.go") {
		t.Errorf("proposal.patch must add detectors/widgetleak/main.go (the customer-tree sidecar location):\n%s", patch)
	}
	if strings.Contains(string(patch), "core/detect/authored") {
		t.Errorf("proposal.patch must NOT touch anything under core/detect/authored/ for a customer-shaped target:\n%s", patch)
	}
}
