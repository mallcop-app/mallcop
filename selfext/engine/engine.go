// Package engine is the orchestration loop for mallcop's self-extension
// code-authoring engine. It composes the runtime credential/billing SEAM
// (session), the worktree jail (sandbox), and the opencode adapter (opencode)
// into one serialized, destructive-safe build:
//
//	anti-thrash → session.Authorize → open jail → author (opencode) →
//	commit → gate (mallcop validate-proposal) → measure cost → session.Record →
//	GREEN: emit a human-review ARTIFACT / RED: poison the fingerprint →
//	teardown (session.Close, remove worktree) — ALWAYS.
//
// # Two rails, one safety surface
//
// The session seam hides exactly ONE axis of variation: where inference is
// billed. A donut.DonutSession (commercial, in internal/donut) runs the Forge
// spend-cap + subkey lifecycle (authorize → mint → usage-delta → revoke); a
// session.BYOISession points at
// an OSS user's OWN endpoint+key with NO cap and NO subkey. The seam is the
// ONLY difference between the rails — EVERY safety rail below is byte-identical
// on both, and a BYOISession holds no Gate/Minter/Forge handle so a BYOI build
// makes zero Forge billing calls by construction.
//
// # Safety invariants (identical on both rails)
//
//   - A known-reject fingerprint is SKIPPED before the session is even
//     consulted — zero Authorize, zero mint, zero inference, on EITHER rail.
//   - On the donut rail the spend gate is consulted BEFORE a subkey exists; a
//     refusal spends nothing (no network call to inference is possible without
//     a key). session.Close is deferred immediately after Authorize and fires
//     regardless of success, gate verdict, or a panic — on the donut rail this
//     revokes the per-build subkey (the load-bearing teardown step).
//   - The engine NEVER pushes to a remote or opens a PR, at ANY autonomy
//     setting — that requires operator credentials the worktree's scrubbed env
//     never carries (see sandbox's package doc). A GREEN gate always produces a
//     reviewable proposal artifact (diff + GateResult + provenance) in a
//     human-review directory. ADDITIONALLY, when Engine.Autonomy is "fully"
//     (the operator-owned autonomy dial — see package
//     autonomy), a GREEN proposal is ALSO merge-automated: a local branch ref in
//     the TARGET repo (never origin/main, never a push) is force-updated to the
//     authored HEAD, so the operator's own tooling can act on it immediately.
//     At "non"/"semi" this step never runs — a human always merges authored
//     code by hand. Contribute-back to the shared OSS pool has no code-lane
//     equivalent at all: it is a router (DATA lane) concept, and there it is
//     NEVER auto-merged regardless of dial — that hard
//     line is untouched by anything in this package. ADDITIONALLY (BOTH ruling,
//     part B), a GREEN gate with GateResult.NovelGap==true —
//     the customer-tree gate's declared family has ZERO labeled must_fire rows
//     in the reference corpus, so the corpus cannot independently grade it —
//     ALSO withholds merge automation at "fully", the same dial-independent
//     forced-human-review treatment as OSS contribute-back. The proposal is
//     still emitted as a reviewable artifact; it is simply never merged.
//   - The authoring prompt is built from TRUSTED structural signals only.
//
// # Process boundary
//
// The gate runs as a separate trusted binary (`mallcop validate-proposal`);
// its versioned JSON GateResult is the seam (see gate.go). mallcop-pro does not
// import the mallcop module.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/selfext/autonomy"
	"github.com/mallcop-app/mallcop/selfext/opencode"
	"github.com/mallcop-app/mallcop/selfext/redact"
	"github.com/mallcop-app/mallcop/selfext/sandbox"
	"github.com/mallcop-app/mallcop/selfext/session"
)

// SpendController is the spend-cap surface the engine needs. It is a type ALIAS
// to session.SpendController so the donut session, the engine, and the proposer
// all share ONE definition (a reviewer confirms the spend-cap surface in a
// single place). *spendcap.SpendGate satisfies it; tests inject a spy.
type SpendController = session.SpendController

// Authorer is the code-authoring surface the engine needs. *opencode.Adapter
// satisfies it; tests inject a fake stub (including one that panics, to prove
// deferred teardown still fires). The Adapter's inference endpoint is bound at
// CLI wiring (donut: the Forge URL; BYOI: the user's URL); only the run's key
// flows through Invoke — the donut subkey OR the BYOI user key, from
// session.Credentials.
type Authorer interface {
	Invoke(ctx context.Context, wt *sandbox.Worktree, apiKey, task string) (opencode.Result, error)
	// BuildTaskPrompt builds the authoring instruction. customerShaped is the
	// SAME trusted signal the gate itself uses (hasCmdMallcop on the worktree
	// jail's own TargetRepo — see Run's customerShaped computation and
	// runValidateProposal) — never anything derived from untrusted proposal
	// content. true routes the prompt (and, in Run, the post-authoring
	// registry step) onto the customer-tree SIDECAR shape instead of the
	// in-tree own-package shape.
	BuildTaskPrompt(gap opencode.TrustedGap, customerShaped bool) string
}

// jailOpener opens worktree jails. *sandbox.Jail satisfies it.
type jailOpener interface {
	Open(ctx context.Context) (*sandbox.Worktree, error)
}

// Engine orchestrates one authoring build per Run. All fields are set once;
// Run is serialized by the caller (one build at a time).
type Engine struct {
	// Session is the runtime seam that supplies inference credentials and, on the
	// donut rail, the spend-cap + subkey lifecycle. A donut.DonutSession
	// reproduces the Forge billing preamble (authorize → mint → usage-delta →
	// revoke); a session.BYOISession points at the user's OWN endpoint+key with
	// NO cap and NO subkey. Required. It is the ONLY place billing differs between
	// the two rails — every safety rail below is identical.
	Session session.Session
	// Jail opens the target-repo worktree write jail. Required.
	Jail jailOpener
	// Adapter drives headless opencode. Its endpoint is bound at wiring; the run's
	// key flows through Invoke via session.Credentials. Required.
	Adapter Authorer
	// Fingerprints is the anti-thrash reject set. Required.
	Fingerprints *RejectSet

	// ValidateBin is the mallcop binary that runs `validate-proposal`. When set
	// it is trusted verbatim (operator/test-injected configuration). Empty →
	// "mallcop" is resolved from PATH and then VERSION-PROBED (see
	// resolveValidateBin/probeGoMallcopBinary) before the engine ever trusts
	// it as the gate — a bare, unverified PATH lookup can silently resolve to
	// an unrelated or stale "mallcop" (e.g. the deprecated python-legacy shim
	// some machines still have on PATH), which then fails opaquely mid-run
	// instead of never being invoked. The gate itself builds per-tree binaries.
	ValidateBin string
	// ExamRepo is the path to a REFERENCE mallcop tree (has
	// its own cmd/mallcop + pinned exam corpus) the gate uses to grade a
	// CUSTOMER-SHAPED TargetRepo — one with no cmd/mallcop of its own (the
	// THIN-EMBED shape: go.mod pins mallcop, detectors/<name>/ carries the
	// authored detector). It is passed to the gate as `--exam-repo` ONLY when
	// the worktree jail's TargetRepo lacks cmd/mallcop (see gate.go's
	// hasCmdMallcop); when TargetRepo already has its own cmd/mallcop (the
	// existing "author into the mallcop repo itself" lane), ExamRepo is
	// ignored and the gate runs its unchanged in-tree lane. Empty is the
	// fail-safe default — a misconfigured customer-tree build then surfaces
	// the gate's own loud, actionable error (it names --exam-repo) rather than
	// silently building nothing. ExamRepo is caller-owned configuration, NEVER
	// derived from the untrusted target repo's own contents (the trust
	// boundary core/selfgate's package doc establishes on the mallcop side).
	ExamRepo string
	// ArtifactDir is the human-review lane directory GREEN proposals land in.
	// Required.
	ArtifactDir string
	// Class is the stable spendcap class string recorded in provenance for
	// self-ext authoring. Empty → "selfext-author". The spend attribution class
	// itself lives on the DonutSession.
	Class string
	// AuthoringLane is the lane the subkey is scoped to and opencode authors
	// under (e.g. "heal"). Required.
	AuthoringLane string
	// Sovereignty is recorded in provenance (the account's sovereignty tier).
	Sovereignty string
	// BudgetUSD is the per-build spend estimate handed to session.Authorize.
	// On the donut rail it is the spend-cap estimate and pool ceiling; BYOI
	// ignores it. Required (> 0).
	BudgetUSD float64

	// Autonomy is the operator-owned dial. ONLY "fully"
	// merge-automates a GREEN proposal (see AutoApplyBranchPrefix); "non" and
	// "semi" both always leave it as an artifact for a human to review and
	// merge by hand. Zero value normalizes to autonomy.NonAutonomy (fail-safe:
	// an unconfigured Engine never auto-applies) via autonomy.Dial.Normalized.
	Autonomy autonomy.Dial
	// AutoApplyBranchPrefix is the local branch prefix "fully" autonomy merge
	// automation force-updates in the TARGET repo: <prefix>/<detector-id>.
	// Empty -> "selfext/applied". Never origin/main, never a push.
	AutoApplyBranchPrefix string

	// Logger receives non-secret lifecycle events. Nil → discard.
	Logger *slog.Logger
	// Now is the clock, for tests. Nil → time.Now.
	Now func() time.Time
}

// defaultClass is the spendcap class for self-ext authoring runs.
const defaultClass = "selfext-author"

// defaultValidateBin is the gate binary name resolved from PATH when
// Engine.ValidateBin is unset. It is never trusted on name alone — see
// resolveValidateBin, which version-probes whatever this resolves to before
// the engine execs it as the trusted gate.
const defaultValidateBin = "mallcop"

// Outcome is the terminal state of one Run. Exactly one of Skipped / Refused /
// Proposed / Rejected / Failed is true. Skipped and Refused spend nothing.
type Outcome struct {
	Skipped  bool // anti-thrash: known-reject fingerprint; spent nothing
	Refused  bool // spend gate denied; spent nothing
	Proposed bool // GREEN gate: reviewable artifact written
	Rejected bool // RED gate: findings; fingerprint poisoned
	Failed   bool // operational/authoring failure (transient; no fingerprint)

	Reason       string      // human-readable cause (denial reason, error, ...)
	Fingerprint  string      // the gap fingerprint
	ArtifactPath string      // GREEN: path to the proposal artifact directory
	CostUSD      float64     // measured spend for this run
	Gate         *GateResult // parsed gate verdict when the gate ran

	// Applied is true ONLY when Engine.Autonomy is "fully" AND the gate was
	// GREEN: the authored change was ALSO merge-automated (see AppliedBranch).
	// At "non"/"semi" this is always false — Proposed alone means "artifact
	// only, a human must merge it by hand".
	Applied bool
	// AppliedBranch is the local target-repo branch merge automation
	// force-updated to the authored HEAD, set only when Applied is true.
	AppliedBranch string
}

// Provenance is the auditable record emitted alongside every artifact.
type Provenance struct {
	Fingerprint string `json:"fingerprint"`
	DetectorID  string `json:"detector_id"`
	EventType   string `json:"event_type"`
	Lane        string `json:"lane"`
	Model       string `json:"model"`
	// Endpoint is the inference base URL this build was billed to (the Forge URL
	// on the donut rail, the user's URL on BYOI). It is recorded from
	// session.Credentials for an auditable "billed-to" record. It is the base URL
	// only — NEVER the key.
	Endpoint    string    `json:"endpoint"`
	Sovereignty string    `json:"sovereignty"`
	Class       string    `json:"class"`
	CostUSD     float64   `json:"cost_usd"`
	BaseSHA     string    `json:"base_sha"`
	HeadSHA     string    `json:"head_sha"`
	GatePassed  bool      `json:"gate_passed"`
	Timestamp   time.Time `json:"timestamp"`
	// Applied/AppliedBranch mirror Outcome.Applied/AppliedBranch — recorded in
	// the artifact's provenance.json for an auditable "was this auto-merged"
	// trail, distinct from GatePassed (GREEN but NOT applied happens at
	// "non"/"semi").
	Applied       bool   `json:"applied"`
	AppliedBranch string `json:"applied_branch,omitempty"`
}

func (e *Engine) class() string {
	if e.Class != "" {
		return e.Class
	}
	return defaultClass
}

// resolveValidateBin returns the mallcop binary the gate execs.
// Engine.ValidateBin, when set, is trusted verbatim — operator or test
// configuration, the caller's explicit choice. When empty, "mallcop" is
// resolved from PATH and then VERSION-PROBED (probeGoMallcopBinary) before
// being trusted: a bare, unverified `exec.LookPath("mallcop")` can silently
// resolve to an unrelated or stale "mallcop" on the machine's PATH (e.g. the
// deprecated python-legacy shim, ModuleNotFoundError on invoke) — a confusing
// operational failure unrelated to the actual gate outcome. A resolution or
// probe failure here is a configuration error, not a gap-specific outcome, so
// Run surfaces it as a hard error BEFORE the spend gate is consulted or any
// subkey is minted (see Run's ordering: resolved right after the anti-thrash
// skip, before Authorize).
func (e *Engine) resolveValidateBin(ctx context.Context) (string, error) {
	if e.ValidateBin != "" {
		return e.ValidateBin, nil
	}
	bin, lerr := exec.LookPath(defaultValidateBin)
	if lerr != nil {
		return "", fmt.Errorf(
			"selfext: %q not found on PATH (%w); pass -validate-bin to point at the mallcop Go binary this build validates against",
			defaultValidateBin, lerr)
	}
	if perr := probeGoMallcopBinary(ctx, bin); perr != nil {
		return "", perr
	}
	return bin, nil
}

func (e *Engine) logger() *slog.Logger {
	if e.Logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return e.Logger
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// autonomyDial normalizes e.Autonomy — a zero value (an Engine literal that
// never set the field) is treated as autonomy.NonAutonomy, the fail-safe.
func (e *Engine) autonomyDial() autonomy.Dial {
	return e.Autonomy.Normalized()
}

// defaultAutoApplyBranchPrefix is the local branch prefix "fully" autonomy
// merge automation writes to when Engine.AutoApplyBranchPrefix is empty.
const defaultAutoApplyBranchPrefix = "selfext/applied"

// autoApplyBranch returns the local target-repo branch name merge automation
// force-updates for detectorID: "<prefix>/<detector-id>".
func (e *Engine) autoApplyBranch(detectorID string) string {
	prefix := e.AutoApplyBranchPrefix
	if prefix == "" {
		prefix = defaultAutoApplyBranchPrefix
	}
	return prefix + "/" + detectorID
}

// validate checks the required fields are set before a run touches inference.
// The billing preconditions (spend gate, minter, account id, Forge URL) now
// live inside the donut Session, so the Engine only guards its rail-agnostic
// invariants.
func (e *Engine) validate() error {
	switch {
	case e.Session == nil:
		return errors.New("selfext: Engine.Session is nil")
	case e.Jail == nil:
		return errors.New("selfext: Engine.Jail is nil")
	case e.Adapter == nil:
		return errors.New("selfext: Engine.Adapter is nil")
	case e.Fingerprints == nil:
		return errors.New("selfext: Engine.Fingerprints is nil")
	case e.ArtifactDir == "":
		return errors.New("selfext: Engine.ArtifactDir is empty")
	case e.AuthoringLane == "":
		return errors.New("selfext: Engine.AuthoringLane is empty")
	case e.BudgetUSD <= 0:
		return errors.New("selfext: Engine.BudgetUSD must be > 0")
	}
	return nil
}

// Run executes one authoring build for gap. It returns an Outcome describing
// the terminal state; the error return is reserved for engine-infrastructure
// failures (bad config, unwritable artifact dir) — expected terminal states
// (skipped/refused/rejected/failed) are Outcomes with a nil error.
//
// Named returns let the deferred panic-guard convert a panic in opencode or the
// gate into Outcome{Failed} while the deferred teardown (revoke, worktree
// remove) still fires.
func (e *Engine) Run(ctx context.Context, gap opencode.TrustedGap) (out Outcome, err error) {
	if verr := e.validate(); verr != nil {
		return Outcome{}, verr
	}

	fp := gap.Fingerprint()
	out.Fingerprint = fp
	log := e.logger().With("fingerprint", fp, "detector_id", gap.DetectorID)

	// 1) Anti-thrash: a known reject is skipped BEFORE anything is spent or
	//    minted. Zero Forge calls.
	if e.Fingerprints.Has(fp) {
		log.Info("selfext: skipping known-reject gap")
		return Outcome{Skipped: true, Reason: "known-reject fingerprint", Fingerprint: fp}, nil
	}

	// 1.5) Resolve + version-probe the gate binary. This is a configuration
	//      precondition (like validate() above), not a gap-specific outcome, so
	//      it fails loudly here — BEFORE the spend gate is consulted or a
	//      subkey minted — rather than surfacing as an opaque exec failure
	//      deep inside the gate step after money has already moved.
	validateBin, vberr := e.resolveValidateBin(ctx)
	if vberr != nil {
		return Outcome{}, vberr
	}

	// 2) Authorize. Donut: spend gate (consulted BEFORE any subkey exists — a
	//    refusal spends nothing) + mint the capped, lane-scoped subkey. BYOI: a
	//    no-op that always succeeds. A benign cap refusal is a *RefusalError
	//    (Refused, spent nothing); a mint/resolver failure surfaces as a hard error.
	if aerr := e.Session.Authorize(ctx, e.BudgetUSD); aerr != nil {
		if refusal, ok := session.AsRefusal(aerr); ok {
			log.Info("selfext: spend gate refused", "err", refusal)
			return Outcome{Refused: true, Reason: refusal.Error(), Fingerprint: fp}, nil
		}
		return Outcome{}, aerr
	}

	// 3) Teardown is unconditional (defer) — success, failure, or panic. Donut:
	//    revoke the subkey + drain the pool. BYOI: a no-op.
	defer func() {
		if cerr := e.Session.Close(); cerr != nil {
			log.Error("selfext: session close failed (teardown)", "err", cerr)
		}
	}()

	// 4) Open the worktree jail on the target repo. Force-removed on teardown.
	wt, werr := e.Jail.Open(ctx)
	if werr != nil {
		return Outcome{}, fmt.Errorf("selfext: open worktree jail: %w", werr)
	}
	defer func() {
		if cerr := wt.Close(); cerr != nil {
			log.Error("selfext: worktree close failed (teardown)", "err", cerr)
		}
	}()

	// Panic guard registered LAST → runs FIRST during unwind, converting a
	// panic in opencode/the gate into a Failed outcome; the teardown defers
	// (registered earlier) then still run, so session.Close always fires.
	defer func() {
		if r := recover(); r != nil {
			err = nil
			out = Outcome{Failed: true, Reason: fmt.Sprintf("panic during authoring/gate: %v", r), Fingerprint: fp}
			log.Error("selfext: recovered panic during run", "panic", r)
		}
	}()

	model := providerLaneModel(e.Adapter, e.AuthoringLane)

	// customerShaped is the SAME trusted signal
	// runValidateProposal/hasCmdMallcop uses to route the GATE: a target repo
	// with no cmd/mallcop of its own is a customer-shaped THIN-EMBED deployment
	// repo (`mallcop init --create-repo`'s scaffold) whose detectors are
	// wasip1.wasm SIDECARS under detectors/<name>/,
	// not the in-tree core/detect/authored/<name>/ own-package shape. It is
	// derived here from the TRUSTED worktree jail's own TargetRepo checkout —
	// never from anything the untrusted proposal content could set — exactly
	// like gate.go's own routing, so the authoring lane and the gate that
	// grades it always agree on which shape is in play.
	customerShaped := !hasCmdMallcop(wt.Dir)

	// 5) Resolve inference credentials (donut subkey OR BYOI user key) and author
	//    with opencode. Credentials marks the usage-measurement window start (the
	//    moment just before inference) and returns the base URL for provenance —
	//    never the key. The Adapter's endpoint was bound at wiring (donut: Forge
	//    URL; BYOI: user URL); only the key flows through Invoke.
	baseURL, key, credErr := e.Session.Credentials(ctx)
	if credErr != nil {
		return Outcome{}, fmt.Errorf("selfext: resolve inference credentials: %w", credErr)
	}
	res, ierr := e.Adapter.Invoke(ctx, wt, key, e.Adapter.BuildTaskPrompt(gap, customerShaped))
	if ierr != nil {
		return e.failWithTranscript(ctx, log, gap, model, baseURL, "opencode invoke: "+ierr.Error(), res), nil
	}

	// 5.5) Register the authored package DETERMINISTICALLY — IN-TREE LANE ONLY
	//    (customerShaped SKIPS this entirely). In the in-tree
	//    lane the model authors the detector package + scenarios but must NOT
	//    touch the aggregator registry (a guard-protected append-only seam it
	//    reliably botches — it overwrote it with a bare fragment):
	//    the engine restores the base registry and appends exactly one blank
	//    import — trusted, guaranteed the append-only shape the guard permits.
	//    A customer-shaped THIN-EMBED target repo has NO core/detect/authored/
	//    tree and NO registry.go at all (cli/deployrepo.go's scaffold never
	//    creates one) — under the sidecar model the detectors/<name>/ directory
	//    IS the registration, so this step must never run for it. Before this
	//    fix it ran unconditionally and reproduced the exact 7ee7 live-leg bug:
	//    `git checkout <base> -- core/detect/authored/registry.go` fails with
	//    "pathspec ... did not match any file(s) known to git" because that path
	//    never existed in the repo's history. Skipped (in either lane) when the
	//    model authored nothing (empty worktree → the commit step reports the
	//    fast-fail).
	if !customerShaped {
		if authored, _ := worktreeAuthored(ctx, wt.Dir); authored {
			if regErr := registerAuthoredPackage(ctx, wt, gap.PackageName()); regErr != nil {
				return e.failWithTranscript(ctx, log, gap, model, baseURL, "register authored package: "+regErr.Error(), res), nil
			}
			// 5b) Regenerate the exam corpus integrity pin — a TRUSTED step, like
			//     the registry append above. The authored scenarios change the
			//     corpus count + digest, but a model cannot compute the sha256
			//     manifest by hand (it leaves corpus.pin stale, so exam-detect
			//     fails "count N != pinned M — nothing runs"). The engine owns the
			//     pin so it always matches the authored corpus.
			if pErr := regenerateCorpusPin(wt.Dir); pErr != nil {
				return e.failWithTranscript(ctx, log, gap, model, baseURL, "regenerate corpus pin: "+pErr.Error(), res), nil
			}
		}
	}

	// 6) Commit whatever was authored so HEAD is a ref the gate can diff. If
	//    nothing was authored (empty diff), commit fails — a transient authoring
	//    failure, not a permanent reject (do NOT poison the fingerprint). This is
	//    the common live fast-fail (opencode gave up), so its transcript is
	//    persisted for diagnosis (see failWithTranscript).
	headSHA, cerr := wt.CommitAuthored(ctx, "selfext: author "+gap.DetectorID)
	if cerr != nil {
		return e.failWithTranscript(ctx, log, gap, model, baseURL, "commit authored: "+cerr.Error(), res), nil
	}

	// 7) Gate: exec the trusted mallcop validate-proposal over base..HEAD.
	gate, exitCode, gerr := runValidateProposal(ctx, validateBin, wt.Dir, wt.BaseSHA, e.ExamRepo)
	if gerr != nil {
		// Operational gate failure (exit 2, unparseable JSON, spawn failure):
		// not a proposal property — do NOT poison the fingerprint.
		log.Error("selfext: gate operational failure", "err", gerr, "exit", exitCode)
		return e.failWithTranscript(ctx, log, gap, model, baseURL, "gate: "+gerr.Error(), res), nil
	}
	out.Gate = &gate

	// 8) Measure real spend (donut: Forge usage delta + ledger; BYOI: $0) and
	//    record it.
	cost := e.record(ctx, log, gate.Passed)
	out.CostUSD = cost

	prov := Provenance{
		Fingerprint: fp,
		DetectorID:  gap.DetectorID,
		EventType:   gap.EventType,
		Lane:        e.AuthoringLane,
		Model:       model,
		Endpoint:    baseURL,
		Sovereignty: e.Sovereignty,
		Class:       e.class(),
		CostUSD:     cost,
		BaseSHA:     wt.BaseSHA,
		HeadSHA:     headSHA,
		GatePassed:  gate.Passed,
		Timestamp:   e.now().UTC(),
	}

	// 9) GREEN → emit a reviewable artifact for the human-review lane (always),
	//    then — ONLY at autonomy=fully — ALSO merge-automate:
	//    force-update a local branch in the TARGET repo to the authored HEAD.
	//    Never a push, never a PR, at any autonomy setting.
	if gate.Passed {
		diff, derr := wt.Diff(ctx)
		if derr != nil {
			return Outcome{}, fmt.Errorf("selfext: diff green proposal: %w", derr)
		}

		if e.autonomyDial().AutoAppliesCode() && !gate.NovelGap {
			branch := e.autoApplyBranch(gap.DetectorID)
			if merr := wt.MergeToTargetBranch(ctx, branch); merr != nil {
				return Outcome{}, fmt.Errorf("selfext: autonomy=fully merge automation: %w", merr)
			}
			out.Applied = true
			out.AppliedBranch = branch
			prov.Applied = true
			prov.AppliedBranch = branch
			log.Info("selfext: autonomy=fully — merge automation applied",
				"branch", branch, "head_sha", headSHA)
		} else if e.autonomyDial().AutoAppliesCode() && gate.NovelGap {
			// NovelGap FORCES a human review regardless of the autonomy dial
			// (BOTH ruling, part B) — mirroring the existing
			// dial-independent hard line already applied to OSS
			// contribute-back (see internal/selfext/autonomy's package doc).
			// The gate-GREEN proposal is still emitted as a reviewable
			// artifact below; it is simply never merge-automated.
			log.Info("selfext: autonomy=fully but NovelGap=true — merge automation withheld, human review required",
				"novel_gap_families", gate.NovelGapFamilies, "head_sha", headSHA)
		}

		artifactPath, aerr := e.writeProposalArtifact(prov, gate, diff, res.TranscriptRedacted, key)
		if aerr != nil {
			return Outcome{}, aerr
		}
		log.Info("selfext: GREEN proposal emitted for human review",
			"artifact", artifactPath, "coverage_plus", gate.CoveragePlus, "cost_usd", cost, "applied", out.Applied)
		out.Proposed = true
		out.ArtifactPath = artifactPath
		return out, nil
	}

	// 10) RED → poison the fingerprint, write a rejected-audit record (NOT a
	//     reviewable proposal), discard the worktree via defer.
	if aerr := e.Fingerprints.Add(fp); aerr != nil {
		log.Error("selfext: persist rejected fingerprint failed", "err", aerr)
	}
	if werr := e.writeRejectedRecord(prov, gate, res.TranscriptRedacted); werr != nil {
		log.Error("selfext: write rejected-audit record failed", "err", werr)
	}
	log.Info("selfext: RED gate — proposal rejected", "cost_usd", cost, "stages", len(gate.Stages))
	out.Rejected = true
	out.Reason = rejectionReason(gate)
	return out, nil
}

// record folds the run's measured spend into the Session ledger and returns the
// cost. On the donut rail the Session sums the Forge usage delta since
// Credentials and calls Gate.Record; on the BYOI rail it returns 0 and records
// nothing (never a ledger decrement). A record failure is non-fatal (logged,
// not returned) so the attempt/freeze machinery still advances.
func (e *Engine) record(ctx context.Context, log *slog.Logger, gatePassed bool) float64 {
	cost, rerr := e.Session.Record(ctx, gatePassed, e.BudgetUSD)
	if rerr != nil {
		log.Error("selfext: session record failed", "err", rerr)
	}
	return cost
}

// authoredRegistryPath is the aggregator the engine appends the authored
// package's blank import to. Kept in one place so the path can't drift.
const authoredRegistryPath = "core/detect/authored/registry.go"

// worktreeAuthored reports whether opencode left any change in the worktree
// (staged or unstaged). A clean tree means the model authored nothing, so the
// engine skips the registry append and lets the commit step report the fast-fail.
func worktreeAuthored(ctx context.Context, dir string) (bool, error) {
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "status", "--porcelain").Output()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) != "", nil
}

// registerAuthoredPackage deterministically links the authored detector package
// into the aggregator registry so the MODEL never touches that file. The model
// reliably botches the append (it overwrote registry.go with a bare, unparseable
// fragment), so the engine owns it: restore the base registry
// (discarding any stray model edit), then insert exactly one blank import inside
// the import block — the append-only shape the guard permits. The result is
// re-parsed fail-closed. Idempotent: a package already registered is a no-op.
func registerAuthoredPackage(ctx context.Context, wt *sandbox.Worktree, pkg string) error {
	if pkg == "" {
		return errors.New("registry: empty package name")
	}
	// The engine owns this file — discard whatever the model may have written.
	restore := exec.CommandContext(ctx, "git", "-C", wt.Dir, "checkout", wt.BaseSHA, "--", authoredRegistryPath)
	if out, err := restore.CombinedOutput(); err != nil {
		return fmt.Errorf("restore base registry: %v: %s", err, strings.TrimSpace(string(out)))
	}
	path := filepath.Join(wt.Dir, authoredRegistryPath)
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read registry: %w", err)
	}
	importPath := "github.com/mallcop-app/mallcop/core/detect/authored/" + pkg
	if strings.Contains(string(src), `"`+importPath+`"`) {
		return nil // already registered
	}
	lines := strings.Split(string(src), "\n")
	insertAt, inImport := -1, false
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "import ("):
			inImport = true
		case inImport && t == ")":
			insertAt = i
		}
		if insertAt >= 0 {
			break
		}
	}
	if insertAt < 0 {
		return errors.New("registry: no `import (` block to append into")
	}
	newLine := "\t_ \"" + importPath + "\""
	out := append(append(append([]string{}, lines[:insertAt]...), newLine), lines[insertAt:]...)
	blob := []byte(strings.Join(out, "\n"))
	if _, perr := parser.ParseFile(token.NewFileSet(), path, blob, parser.ImportsOnly); perr != nil {
		return fmt.Errorf("registry would be unparseable after append: %w", perr)
	}
	return os.WriteFile(path, blob, 0o644)
}

// writeProposalArtifact writes the GREEN reviewable proposal (diff + GateResult
// + provenance + redacted transcript) into a fresh directory under ArtifactDir
// and returns its path. This is the engine's ONLY output — a human reviews it;
// nothing is pushed or merged.
//
// key is the run's inference credential (donut subkey OR BYOI user key,
// resolved via session.Credentials). The diff is a raw `git diff` of whatever
// opencode authored in the worktree — untrusted output — so it is run through
// redact.Redact BEFORE it is written to disk, exactly like the transcript
// (adapter.go) and any surfaced authoring error (proposer.go): if opencode
// ever echoed the key back into a file, the patch artifact must not carry it.
func (e *Engine) writeProposalArtifact(prov Provenance, gate GateResult, diff, transcript []byte, key string) (string, error) {
	dir := filepath.Join(e.ArtifactDir, "proposal-"+shortFP(prov.Fingerprint)+"-"+prov.Timestamp.Format("20060102-150405"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("selfext: create artifact dir: %w", err)
	}
	redactedDiff := redact.Redact(string(diff), key)
	if err := os.WriteFile(filepath.Join(dir, "proposal.patch"), []byte(redactedDiff), 0o644); err != nil {
		return "", fmt.Errorf("selfext: write proposal.patch: %w", err)
	}
	if err := writeJSONFile(filepath.Join(dir, "gate.json"), gate); err != nil {
		return "", err
	}
	if err := writeJSONFile(filepath.Join(dir, "provenance.json"), prov); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "transcript.txt"), transcript, 0o644); err != nil {
		return "", fmt.Errorf("selfext: write transcript: %w", err)
	}
	return dir, nil
}

// writeRejectedRecord writes a RED audit record under ArtifactDir/rejected/.
// It is NOT a reviewable proposal (no patch to merge) — just provenance + the
// gate findings, for observability.
func (e *Engine) writeRejectedRecord(prov Provenance, gate GateResult, transcript []byte) error {
	dir := filepath.Join(e.ArtifactDir, "rejected")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("selfext: create rejected dir: %w", err)
	}
	rec := struct {
		Provenance         Provenance `json:"provenance"`
		Gate               GateResult `json:"gate"`
		TranscriptRedacted string     `json:"transcript_redacted"`
	}{prov, gate, string(transcript)}
	path := filepath.Join(dir, shortFP(prov.Fingerprint)+"-"+prov.Timestamp.Format("20060102-150405")+".json")
	return writeJSONFile(path, rec)
}

// failWithTranscript is the shared terminal for an operational FAILURE that is
// NOT a proposal property (opencode invoke error, nothing committable authored,
// or a gate operational failure). It measures the run's spend, persists a
// redacted FAILED-run audit record (partial provenance + the opencode
// transcript) under ArtifactDir/failed/, and returns the Failed Outcome.
//
// This closes the debuggability gap: before, only REJECTED runs left a
// transcript on disk, so a fast-fail (opencode exiting non-zero in a few seconds
// with a tiny transcript on a transient upstream error) was invisible after
// teardown — the only way to see what happened was to re-run and re-spend. Now
// the transcript is captured for EVERY failed run. A persist failure is logged,
// never fatal: a failed run must still tear down cleanly.
func (e *Engine) failWithTranscript(ctx context.Context, log *slog.Logger, gap opencode.TrustedGap, model, baseURL, reason string, res opencode.Result) Outcome {
	fp := gap.Fingerprint()
	cost := e.record(ctx, log, false)
	prov := Provenance{
		Fingerprint: fp,
		DetectorID:  gap.DetectorID,
		EventType:   gap.EventType,
		Lane:        e.AuthoringLane,
		Model:       model,
		Endpoint:    baseURL,
		Sovereignty: e.Sovereignty,
		Class:       e.class(),
		CostUSD:     cost,
		GatePassed:  false,
		Timestamp:   e.now().UTC(),
	}
	if werr := e.writeFailedRecord(prov, reason, res.ExitCode, res.TranscriptRedacted); werr != nil {
		log.Error("selfext: write failed-audit record failed", "err", werr)
	}
	log.Error("selfext: authoring run FAILED (audit persisted)",
		"reason", reason, "opencode_exit", res.ExitCode, "cost_usd", cost,
		"transcript_bytes", len(res.TranscriptRedacted))
	return Outcome{Failed: true, Reason: reason, Fingerprint: fp, CostUSD: cost}
}

// writeFailedRecord writes an operational-FAILURE audit record under
// ArtifactDir/failed/: partial provenance, the failure reason, opencode's exit
// code, and the redacted transcript. Unlike a RED rejection it is NOT a proposal
// property and does NOT poison the fingerprint (the gap may succeed on a later,
// non-transient run) — it exists purely so a fast-fail is DIAGNOSABLE without
// re-spending inference. Mirrors writeRejectedRecord.
func (e *Engine) writeFailedRecord(prov Provenance, reason string, opencodeExit int, transcript []byte) error {
	dir := filepath.Join(e.ArtifactDir, "failed")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("selfext: create failed dir: %w", err)
	}
	rec := struct {
		Provenance         Provenance `json:"provenance"`
		Reason             string     `json:"reason"`
		OpencodeExitCode   int        `json:"opencode_exit_code"`
		TranscriptRedacted string     `json:"transcript_redacted"`
	}{prov, reason, opencodeExit, string(transcript)}
	path := filepath.Join(dir, shortFP(prov.Fingerprint)+"-"+prov.Timestamp.Format("20060102-150405")+".json")
	return writeJSONFile(path, rec)
}

// writeJSONFile marshals v (indented) and writes it to path.
func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("selfext: marshal %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("selfext: write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// shortFP is the first 12 hex chars of a fingerprint, for filenames.
func shortFP(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}

// rejectionReason summarizes the failing stage of a RED gate for the Outcome.
func rejectionReason(gate GateResult) string {
	if len(gate.Stages) == 0 {
		return "gate rejected (no stage detail)"
	}
	last := gate.Stages[len(gate.Stages)-1]
	if len(last.Findings) == 0 {
		return fmt.Sprintf("gate rejected at stage %q", last.Name)
	}
	f := last.Findings[0]
	return fmt.Sprintf("gate rejected at stage %q: %s/%s: %s", last.Name, last.Name, f.Rule, f.Detail)
}

// providerLaneModel returns the model string recorded in provenance.json's
// "model" field. Ordinarily (no code-authoring override)
// that is "<provider>/<lane>": the bare lane is all that was actually
// requested, Forge resolves it internally. But when Adapter.Model overrides
// the lane, providerLaneModel records THAT literal resolved catalog model id
// verbatim instead — otherwise a qwen3-32b run (unoverridden
// "heal" lane) and a claude-haiku-4-5 run (overridden) are indistinguishable in
// provenance without cross-checking /v1/usage by timestamp. Non-opencode
// adapters (e.g. test doubles) record the lane alone.
func providerLaneModel(a Authorer, lane string) string {
	if oc, ok := a.(*opencode.Adapter); ok {
		if model, overridden := oc.RequestedModel(); overridden {
			return model
		}
		p := oc.Provider
		if p == "" {
			p = sandbox.ProviderName
		}
		return p + "/" + lane
	}
	return lane
}

// corpusScenariosRel is the corpus root relative to the target-repo root. It
// mirrors mallcop core/eval's scenariosRelPath — the two MUST agree or the pin
// the engine writes will not match the digest the gate's loader recomputes.
const corpusScenariosRel = "exams/scenarios"

// regenerateCorpusPin deterministically rewrites exams/scenarios/corpus.pin so it
// matches the authored corpus. It is a TRUSTED engine step (never the model): the
// integrity pin is a sha256 of a canonical manifest, which no coder can compute by
// hand — leaving it stale fails exam-detect with "count N != pinned M". This
// replicates mallcop core/eval's scanCorpus manifest EXACTLY: every *.yaml/*.yml
// under exams/scenarios (leading-underscore files AND directories skipped at any
// depth), one "<forward-slash relpath><two spaces><lowercase-hex sha256(file)>\n"
// line, sorted by relpath; the pin is "count <N>\nsha256 <sha256(manifest)>\n".
//
// It is a no-op when the target repo has no corpus.pin (an unpinned corpus is not
// integrity-checked, so there is nothing to keep in sync).
func regenerateCorpusPin(repoDir string) error {
	root := filepath.Join(repoDir, corpusScenariosRel)
	pinPath := filepath.Join(root, "corpus.pin")
	if _, err := os.Stat(pinPath); err != nil {
		return nil // no pin => corpus is not integrity-pinned; nothing to do.
	}

	type entry struct{ rel, sha string }
	var entries []entry
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		// Leading-underscore skip — files AND directories, any depth (prune subtrees).
		for _, part := range strings.Split(rel, "/") {
			if strings.HasPrefix(part, "_") {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".yaml") && !strings.HasSuffix(d.Name(), ".yml") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return fmt.Errorf("read scenario %s: %w", rel, rerr)
		}
		sum := sha256.Sum256(data)
		entries = append(entries, entry{rel: rel, sha: hex.EncodeToString(sum[:])})
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("scan corpus: %w", walkErr)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })

	var mb strings.Builder
	for _, e := range entries {
		mb.WriteString(e.rel)
		mb.WriteString("  ") // two-space separator (manifest contract)
		mb.WriteString(e.sha)
		mb.WriteByte('\n')
	}
	digest := sha256.Sum256([]byte(mb.String()))
	pin := fmt.Sprintf("count %d\nsha256 %s\n", len(entries), hex.EncodeToString(digest[:]))
	if err := os.WriteFile(pinPath, []byte(pin), 0o644); err != nil {
		return fmt.Errorf("write corpus pin: %w", err)
	}
	return nil
}
