package router

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/mallcop-app/mallcop/selfext/autonomy"
	"github.com/mallcop-app/mallcop/selfext/engine"
	"github.com/mallcop-app/mallcop/selfext/proposer"
	"github.com/mallcop-app/mallcop/selfext/session"
)

// The router is part of the forge-free BYOK surface slated to relocate to the
// public MIT mallcop repo, so its TEST layer must reach NEITHER
// internal/forge NOR internal/donut NOR internal/selfext/subkey NOR internal/spendcap.
// This deterministic collect→propose→route e2e drives the proposer through a
// library-pure fakeSession (below); the real DonutSession over a Forge server is
// out of scope here (the e2e proves ROUTING, not billing) and is covered in
// internal/selfext/integration.

// goldenCollectJSON is a `mallcop collect --json` envelope: one high-count
// unmapped github repo.rename gap whose closed vocabulary includes config_change
// (a KnownEventTypes member on the mallcop side). This is the proposer's process
// boundary — the deterministic e2e decodes it exactly as the operator pipeline
// would.
const goldenCollectJSON = `{
  "schema_version": 1,
  "mapping_gaps": [
    {
      "source": "github",
      "raw_action": "repo.rename",
      "count": 5,
      "sample_event_ids": ["evt_a", "evt_b"],
      "suggested_vocabulary": ["config_change", "login", "push"]
    }
  ],
  "gap_candidates": []
}`

// ---- inline proposer harness (fake inference + fake session + spy gate) ----

type e2eFake struct {
	resp  proposer.MessagesResponse
	err   error
	calls int
}

func (f *e2eFake) Messages(_ context.Context, _ proposer.MessagesRequest) (proposer.MessagesResponse, error) {
	f.calls++
	return f.resp, f.err
}

type e2eGate struct {
	denyErr error
	records int
}

func (g *e2eGate) Authorize(context.Context, string, float64) error { return g.denyErr }
func (g *e2eGate) Record(string, float64, bool) error               { g.records++; return nil }
func (g *e2eGate) CapUSD() float64                                  { return 25.0 }

// fakeSession is a library-pure session.Session backing the proposer in this e2e:
// it wraps the e2eGate spend-cap surface, counts "mints" (a successful Authorize —
// the donut rail mints its subkey iff the gate grants), wraps a denial in
// *session.RefusalError exactly as DonutSession does, and hands back a fixed
// (baseURL, key). No Forge server, no subkey, no ledger — the router e2e asserts
// ROUTING; the real DonutSession billing lifecycle is proven in
// internal/selfext/integration.
type fakeSession struct {
	gate    *e2eGate
	baseURL string
	mints   int
}

var _ session.Session = (*fakeSession)(nil)

func (s *fakeSession) Authorize(ctx context.Context, estUSD float64) error {
	if err := s.gate.Authorize(ctx, "selfext-propose", estUSD); err != nil {
		return &session.RefusalError{Err: err}
	}
	s.mints++
	return nil
}

func (s *fakeSession) Credentials(context.Context) (string, string, error) {
	return s.baseURL, "mallcop-sk-fake-subkey", nil
}

func (s *fakeSession) Record(_ context.Context, success bool, _ float64) (float64, error) {
	_ = s.gate.Record("selfext-propose", 0.02, success)
	return 0.02, nil
}

func (s *fakeSession) Close() error { return nil }

// e2eSetup builds a proposer + router that SHARE one reject set (proving the
// shared anti-thrash), the proposer driven by a library-pure fakeSession.
func e2eSetup(t *testing.T, fake *e2eFake, gate *e2eGate) (*proposer.Proposer, *Router, *fakeSession) {
	t.Helper()
	rejects, err := engine.LoadRejectSet(t.TempDir())
	if err != nil {
		t.Fatalf("LoadRejectSet: %v", err)
	}
	sess := &fakeSession{gate: gate, baseURL: "https://forge.fake.local"}
	p := &proposer.Proposer{
		Session:      sess,
		Fingerprints: rejects,
		NewClient:    func(_, _ string) proposer.InferenceClient { return fake },
		Lane:         "investigate",
		BudgetUSD:    2.0,
	}
	base := t.TempDir()
	r := &Router{
		KnownEventTypes: map[string]bool{"config_change": true, "login": true, "push": true},
		OverlayDir:      base + "/overlay",
		ArtifactDir:     base + "/oss",
		ProvenanceDir:   base + "/prov",
		Fingerprints:    rejects, // SHARED with the proposer
		GitSHA:          "gitsha-e2e",
		// This e2e predates the autonomy dial and asserts the
		// auto-apply-data behavior — see newRouter's comment in router_test.go.
		Autonomy: autonomy.SemiAutonomy,
	}
	return p, r, sess
}

func e2eMappingReply() proposer.MessagesResponse {
	return proposer.MessagesResponse{
		StopReason: "tool_use",
		Content: []proposer.ContentBlock{{
			Type: "tool_use", Name: "propose_mapping",
			Input: map[string]any{"source": "github", "raw_action": "repo.rename", "event_type": "config_change"},
		}},
	}
}

func decodeGap(t *testing.T) proposer.MappingGap {
	t.Helper()
	env, err := proposer.DecodeCollectEnvelope([]byte(goldenCollectJSON))
	if err != nil {
		t.Fatalf("DecodeCollectEnvelope: %v", err)
	}
	if env.SchemaVersion != 1 || len(env.MappingGaps) != 1 {
		t.Fatalf("unexpected envelope: %+v", env)
	}
	return env.MappingGaps[0]
}

// TestE2E_CollectProposeRoute_TenantOverlay is the deterministic end-to-end proof
// of the happy path (TEST PLAN case i): golden collect JSON → proposer(FAKE
// inference) → router(STUB GREEN gate) → TenantOverlay + overlay written +
// provenance recorded.
func TestE2E_CollectProposeRoute_TenantOverlay(t *testing.T) {
	fake := &e2eFake{resp: e2eMappingReply()}
	gate := &e2eGate{}
	p, r, _ := e2eSetup(t, fake, gate)

	out, err := p.Propose(context.Background(), decodeGap(t))
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Proposed || out.Proposal == nil {
		t.Fatalf("want Proposed, got %+v", out)
	}
	if fake.calls != 1 {
		t.Errorf("inference calls = %d, want 1", fake.calls)
	}

	dec, err := r.Route(*out.Proposal, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("destination = %q, want tenant_overlay", dec.Destination)
	}
	if readMappings(t, dec.OverlayPath)["github"]["repo.rename"] != "config_change" {
		t.Errorf("overlay not written correctly")
	}
	if provenanceCount(t, r.ProvenanceDir) != 1 {
		t.Errorf("provenance not recorded")
	}
}

// TestE2E_SemiDial_DataAutoAppliesEvidence is the e2e proof of
// the DATA half of the SEMI-autonomy contrast: the REAL proposer (FAKE
// inference client, real strict-parse) hands a real Proposal to the REAL
// Router.Route at Autonomy=SemiAutonomy (e2eSetup's default — see its
// comment), and the decision is captured and logged verbatim (Decision JSON +
// the actual overlay file bytes on disk) so the e2e report quotes the ENGINE's
// own output, not a re-derived expectation. Companion: engine_test.go's
// TestE2E_SemiDial_CodeWaitsEvidence proves the CODE half (Applied=false) on
// the same dial position.
func TestE2E_SemiDial_DataAutoAppliesEvidence(t *testing.T) {
	fake := &e2eFake{resp: e2eMappingReply()}
	gate := &e2eGate{}
	p, r, _ := e2eSetup(t, fake, gate)
	if r.Autonomy != autonomy.SemiAutonomy {
		t.Fatalf("harness precondition: r.Autonomy = %q, want semi", r.Autonomy)
	}

	out, err := p.Propose(context.Background(), decodeGap(t))
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Proposed || out.Proposal == nil {
		t.Fatalf("want Proposed, got %+v", out)
	}

	dec, err := r.Route(*out.Proposal, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	decJSON, _ := json.MarshalIndent(dec, "", "  ")
	t.Logf("SEMI/DATA real Decision:\n%s", decJSON)

	if dec.Destination != DestTenantOverlay {
		t.Fatalf("SEMI/DATA: destination = %q, want tenant_overlay (auto-apply)", dec.Destination)
	}
	if dec.OverlayPath == "" {
		t.Fatalf("SEMI/DATA: OverlayPath empty — nothing auto-written")
	}
	raw, err := os.ReadFile(dec.OverlayPath)
	if err != nil {
		t.Fatalf("read overlay file %q: %v", dec.OverlayPath, err)
	}
	t.Logf("SEMI/DATA real overlay file %s contents:\n%s", dec.OverlayPath, raw)
	if readMappings(t, dec.OverlayPath)["github"]["repo.rename"] != "config_change" {
		t.Errorf("overlay not auto-written correctly")
	}
	if dec.Provenance.Destination != string(DestTenantOverlay) {
		t.Errorf("provenance destination = %q, want tenant_overlay", dec.Provenance.Destination)
	}
}

// TestE2E_ConsentGatesOSS (case ii): the SAME clean widen stays overlay-only
// without consent, and additionally emits an OSS-PR artifact (never auto-merged)
// with consent.
func TestE2E_ConsentGatesOSS(t *testing.T) {
	fake := &e2eFake{resp: e2eMappingReply()}
	p, r, _ := e2eSetup(t, fake, &e2eGate{})
	out, err := p.Propose(context.Background(), decodeGap(t))
	if err != nil || !out.Proposed {
		t.Fatalf("Propose: %v out=%+v", err, out)
	}

	noConsent, err := r.Route(*out.Proposal, greenGate(), false)
	if err != nil {
		t.Fatalf("Route(no consent): %v", err)
	}
	if noConsent.Destination != DestTenantOverlay || noConsent.ArtifactPath != "" {
		t.Fatalf("no-consent must be overlay-only, got %q artifact=%q", noConsent.Destination, noConsent.ArtifactPath)
	}

	withConsent, err := r.Route(*out.Proposal, greenGate(), true)
	if err != nil {
		t.Fatalf("Route(consent): %v", err)
	}
	if withConsent.Destination != DestOSSContribBack || withConsent.ArtifactPath == "" {
		t.Fatalf("consent must emit an OSS-PR artifact, got %q artifact=%q", withConsent.Destination, withConsent.ArtifactPath)
	}
}

// TestE2E_KnownRejectSkips (case v): a fingerprint already in the SHARED reject
// set short-circuits the proposer to Skipped with ZERO Authorize and ZERO
// inference — the proposer and router share one anti-thrash ledger.
func TestE2E_KnownRejectSkips(t *testing.T) {
	fake := &e2eFake{resp: e2eMappingReply()}
	gate := &e2eGate{}
	p, r, sess := e2eSetup(t, fake, gate)
	gap := decodeGap(t)

	// Poison the gap via the router's shared reject set (as a Forbidden route
	// would), then the proposer must skip it.
	forbidden := proposer.Proposal{Kind: proposer.KindConsensusBypass, BypassReason: "narrowing", Fingerprint: mustFingerprint(t, p, gap)}
	if _, err := r.Route(forbidden, greenGate(), false); err != nil {
		t.Fatalf("Route(forbidden): %v", err)
	}

	out, err := p.Propose(context.Background(), gap)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Skipped {
		t.Fatalf("want Skipped on shared-reject fingerprint, got %+v", out)
	}
	if fake.calls != 0 || gate.records != 0 || sess.mints != 0 {
		t.Errorf("known-reject spent: inference=%d records=%d mint=%d", fake.calls, gate.records, sess.mints)
	}
}

// TestE2E_OverCapRefuses (case vi): a denying spend gate refuses the proposer
// before any subkey exists — ZERO inference, ZERO mint.
func TestE2E_OverCapRefuses(t *testing.T) {
	fake := &e2eFake{resp: e2eMappingReply()}
	gate := &e2eGate{denyErr: errors.New("cap exceeded")}
	p, _, sess := e2eSetup(t, fake, gate)

	out, err := p.Propose(context.Background(), decodeGap(t))
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Refused {
		t.Fatalf("want Refused, got %+v", out)
	}
	if fake.calls != 0 || sess.mints != 0 {
		t.Errorf("over-cap spent: inference=%d mint=%d", fake.calls, sess.mints)
	}
}

// mustFingerprint recovers the gap fingerprint the proposer would compute, by
// running one Propose against a fake that records nothing and reading the
// Outcome fingerprint. It uses a fresh proposer so it does not perturb the
// caller's ledgers.
func mustFingerprint(t *testing.T, _ *proposer.Proposer, gap proposer.MappingGap) string {
	t.Helper()
	// The proposer's mapping fingerprint is deterministic over (source, raw_action);
	// recover it via a throwaway Propose whose gate refuses (no spend, no mint).
	fake := &e2eFake{resp: e2eMappingReply()}
	throwaway, _, _ := e2eSetup(t, fake, &e2eGate{denyErr: errors.New("cap exceeded")})
	out, err := throwaway.Propose(context.Background(), gap)
	if err != nil {
		t.Fatalf("recover fingerprint: %v", err)
	}
	if out.Fingerprint == "" {
		t.Fatalf("no fingerprint recovered")
	}
	return out.Fingerprint
}
