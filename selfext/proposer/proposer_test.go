package proposer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/mallcop-app/mallcop/selfext/engine"
	"github.com/mallcop-app/mallcop/selfext/session"
)

// The proposer is part of the BYOK-pure surface of the public MIT mallcop repo,
// so its TEST layer — like its
// production code — must reach NO commercial billing internals. These tests
// drive the proposer through its OWN seam (session.Session + session.SpendController)
// using the library-pure fakeSession below; the real commercial billing wiring (cost via
// the provider usage delta, run-key revoke, endpoint stamping) is proven with the
// commercial layer.

// ---- library-pure fake session ----------------------------------------------

// fakeSession is a library-pure session.Session that models the metered credential/
// billing lifecycle's OBSERVABLE behavior WITHOUT importing any commercial billing
// internals. Authorize delegates
// to the spy gate (and counts a "mint" on success, wrapping a denial as
// *session.RefusalError exactly as a commercial billing session does); Credentials hands back the
// run's (baseURL, key); Record delegates the ledger fold to the gate and returns the
// canned cost (the provider usage-delta analogue); Close counts the revoke.
type fakeSession struct {
	gate    engine.SpendController
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

// ---- spy spend gate (satisfies engine.SpendController) ----------------------

type spySpendGate struct {
	denyErr error

	mu             sync.Mutex
	authorizeCalls int
	records        []recordCall
}

type recordCall struct {
	class   string
	cost    float64
	success bool
}

func (s *spySpendGate) Authorize(_ context.Context, _ string, _ float64) error {
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

var _ engine.SpendController = (*spySpendGate)(nil)

// ---- fake inference client --------------------------------------------------

type fakeInference struct {
	resp     MessagesResponse
	err      error
	panicMsg string

	mu    sync.Mutex
	calls int
}

func (f *fakeInference) Messages(_ context.Context, _ MessagesRequest) (MessagesResponse, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.panicMsg != "" {
		panic(f.panicMsg)
	}
	return f.resp, f.err
}

func (f *fakeInference) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// ---- harness ----------------------------------------------------------------

type harness struct {
	session *fakeSession
	gate    *spySpendGate
	fake    *fakeInference
	rejects *engine.RejectSet
	prop    *Proposer
}

func newHarness(t *testing.T, fake *fakeInference, gate *spySpendGate, usageCost float64) *harness {
	t.Helper()
	rejects, err := engine.LoadRejectSet(t.TempDir())
	if err != nil {
		t.Fatalf("LoadRejectSet: %v", err)
	}

	// METERED rail behind a library-pure fakeSession: the spy gate is the spend-cap
	// surface, usageCost is the provider usage-delta the session Records, and Close
	// counts the run-key revoke. The REAL commercial billing session over a live
	// inference endpoint is proven with the commercial layer.
	sess := &fakeSession{
		gate:    gate,
		class:   "selfext-propose",
		baseURL: "https://forge.fake.local",
		key:     "mallcop-sk-fake-subkey",
		cost:    usageCost,
	}
	p := &Proposer{
		Session:      sess,
		Fingerprints: rejects,
		NewClient:    func(_, _ string) InferenceClient { return fake },
		Lane:         "investigate",
		BudgetUSD:    2.0,
	}
	return &harness{session: sess, gate: gate, fake: fake, rejects: rejects, prop: p}
}

func sampleGap() MappingGap {
	return MappingGap{
		Source:              "github",
		RawAction:           "repo.rename",
		Count:               7,
		SampleEventIDs:      []string{"evt_a", "evt_b"},
		SuggestedVocabulary: []string{"config_change", "login", "push"},
	}
}

func mappingResponse(source, rawAction, eventType string) MessagesResponse {
	return MessagesResponse{
		StopReason: "tool_use",
		Content: []ContentBlock{{
			Type:  "tool_use",
			ID:    "toolu_1",
			Name:  "propose_mapping",
			Input: map[string]any{"source": source, "raw_action": rawAction, "event_type": eventType},
		}},
	}
}

// ---- tests ------------------------------------------------------------------

// TestProposeValidMapping: a valid mapping tool_use yields Proposed, cost is
// Recorded via the usage delta, exactly ONE inference call is made, and the
// run key is revoked on teardown.
func TestProposeValidMapping(t *testing.T) {
	fake := &fakeInference{resp: mappingResponse("github", "repo.rename", "config_change")}
	h := newHarness(t, fake, &spySpendGate{}, 0.0123)

	out, err := h.prop.Propose(context.Background(), sampleGap())
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Proposed {
		t.Fatalf("want Proposed, got %+v", out)
	}
	if out.Proposal == nil || out.Proposal.Kind != KindMapping {
		t.Fatalf("want a mapping proposal, got %+v", out.Proposal)
	}
	if got := out.Proposal.Mapping.EventType; got != "config_change" {
		t.Errorf("event_type = %q, want config_change", got)
	}
	if out.Proposal.Fingerprint == "" {
		t.Errorf("proposal fingerprint not set")
	}
	if out.Proposal.Endpoint != h.session.baseURL {
		t.Errorf("proposal endpoint = %q, want session base URL %q", out.Proposal.Endpoint, h.session.baseURL)
	}
	if fake.callCount() != 1 {
		t.Errorf("inference calls = %d, want exactly 1", fake.callCount())
	}
	rec := h.gate.lastRecord(t)
	if rec.cost != 0.0123 || !rec.success {
		t.Errorf("Record = %+v, want cost 0.0123 success true", rec)
	}
	if h.session.closeCalls != 1 {
		t.Errorf("subkey not revoked (Session.Close called %d times, want 1)", h.session.closeCalls)
	}
}

// TestProposeRejectUnknownVocab: a tool_use whose event_type is outside the
// closed vocabulary is REJECTED, the fingerprint is poisoned, and there is NO
// retry (exactly one inference call).
func TestProposeRejectUnknownVocab(t *testing.T) {
	fake := &fakeInference{resp: mappingResponse("github", "repo.rename", "totally_new_type")}
	h := newHarness(t, fake, &spySpendGate{}, 0.004)

	out, err := h.prop.Propose(context.Background(), sampleGap())
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Rejected {
		t.Fatalf("want Rejected, got %+v", out)
	}
	if fake.callCount() != 1 {
		t.Errorf("inference calls = %d, want exactly 1 (NO retry)", fake.callCount())
	}
	if !h.rejects.Has(out.Fingerprint) {
		t.Errorf("fingerprint %q not poisoned into the reject set", out.Fingerprint)
	}
	// Cost of the rejected call is still recorded (we spent the inference).
	if rec := h.gate.lastRecord(t); rec.cost != 0.004 || rec.success {
		t.Errorf("Record = %+v, want cost 0.004 success false", rec)
	}
	if h.session.closeCalls != 1 {
		t.Errorf("subkey not revoked on reject (Session.Close called %d times, want 1)", h.session.closeCalls)
	}
}

// TestProposeRejectProse: a prose-only reply (no tool_use, not pure JSON) is
// REJECTED and poisoned.
func TestProposeRejectProse(t *testing.T) {
	fake := &fakeInference{resp: MessagesResponse{
		StopReason: "end_turn",
		Content:    []ContentBlock{{Type: "text", Text: "I think repo.rename maps to config_change, probably."}},
	}}
	h := newHarness(t, fake, &spySpendGate{}, 0.001)

	out, err := h.prop.Propose(context.Background(), sampleGap())
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Rejected {
		t.Fatalf("want Rejected on prose-only reply, got %+v", out)
	}
	if !h.rejects.Has(out.Fingerprint) {
		t.Errorf("prose reply fingerprint not poisoned")
	}
}

// TestProposeRejectNarrowingMultiBlock: two proposal blocks (a narrowing attempt
// smuggled alongside a valid one) is REJECTED — exactly one add-only proposal is
// allowed.
func TestProposeRejectMultiBlock(t *testing.T) {
	fake := &fakeInference{resp: MessagesResponse{
		StopReason: "tool_use",
		Content: []ContentBlock{
			{Type: "tool_use", Name: "propose_mapping", Input: map[string]any{"source": "github", "raw_action": "repo.rename", "event_type": "config_change"}},
			{Type: "tool_use", Name: "propose_mapping", Input: map[string]any{"source": "github", "raw_action": "repo.rename", "event_type": "push"}},
		},
	}}
	h := newHarness(t, fake, &spySpendGate{}, 0.001)

	out, err := h.prop.Propose(context.Background(), sampleGap())
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Rejected {
		t.Fatalf("want Rejected on multi-block reply, got %+v", out)
	}
}

// TestProposeOverCap: when Authorize denies (the commercial billing session wraps
// the spend-cap denial in *session.RefusalError), the run is Refused with ZERO
// inference calls and ZERO mint (the run key never exists). The REAL spend-cap
// denial → Refused path over a live inference endpoint is proven with the
// commercial layer.
func TestProposeOverCap(t *testing.T) {
	fake := &fakeInference{resp: mappingResponse("github", "repo.rename", "config_change")}
	gate := &spySpendGate{denyErr: errors.New("cap exceeded")}
	h := newHarness(t, fake, gate, 0.01)

	out, err := h.prop.Propose(context.Background(), sampleGap())
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Refused {
		t.Fatalf("want Refused, got %+v", out)
	}
	if fake.callCount() != 0 {
		t.Errorf("inference calls = %d, want 0 on refusal", fake.callCount())
	}
	if h.session.mints != 0 {
		t.Errorf("mint calls = %d, want 0 on refusal (no subkey should exist)", h.session.mints)
	}
	if len(gate.records) != 0 {
		t.Errorf("Record called on refusal (should spend nothing): %+v", gate.records)
	}
}

// TestProposeKnownReject: a pre-poisoned fingerprint short-circuits to Skipped
// with ZERO Authorize, ZERO mint, ZERO inference.
func TestProposeKnownReject(t *testing.T) {
	fake := &fakeInference{resp: mappingResponse("github", "repo.rename", "config_change")}
	gate := &spySpendGate{}
	h := newHarness(t, fake, gate, 0.01)

	fp := mappingFingerprint(sampleGap())
	if err := h.rejects.Add(fp); err != nil {
		t.Fatalf("seed reject set: %v", err)
	}

	out, err := h.prop.Propose(context.Background(), sampleGap())
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Skipped {
		t.Fatalf("want Skipped, got %+v", out)
	}
	if gate.authorizeCalls != 0 {
		t.Errorf("Authorize called = %d, want 0 on known-reject", gate.authorizeCalls)
	}
	if fake.callCount() != 0 {
		t.Errorf("inference calls = %d, want 0 on known-reject", fake.callCount())
	}
	if h.session.mints != 0 {
		t.Errorf("mint calls = %d, want 0 on known-reject", h.session.mints)
	}
}

// TestProposeRevokeOnPanic: a panicking inference client is converted to a Failed
// outcome while the deferred run-key revoke still fires.
func TestProposeRevokeOnPanic(t *testing.T) {
	fake := &fakeInference{panicMsg: "boom in the fake client"}
	h := newHarness(t, fake, &spySpendGate{}, 0.0)

	out, err := h.prop.Propose(context.Background(), sampleGap())
	if err != nil {
		t.Fatalf("Propose returned an error on panic (want Failed outcome): %v", err)
	}
	if !out.Failed {
		t.Fatalf("want Failed on panic, got %+v", out)
	}
	if h.session.closeCalls != 1 {
		t.Errorf("subkey NOT revoked after panic (Session.Close called %d times, want 1)", h.session.closeCalls)
	}
}

// ---- BYOI (Bring-Your-Own-Inference) rail -----------------------------------

func freshRejects(t *testing.T) *engine.RejectSet {
	t.Helper()
	rejects, err := engine.LoadRejectSet(t.TempDir())
	if err != nil {
		t.Fatalf("LoadRejectSet: %v", err)
	}
	return rejects
}

// TestProposeBYOIEndToEnd: on the BYOI rail the SAME anti-thrash → Credentials →
// strict add-only parse runs, but inference is billed to the USER's endpoint+key
// (no metered billing). The fake client must receive the user's (url, key); the outcome is
// Proposed with CostUSD == 0. There is no billing server in this test at all — a
// BYOISession holds no Gate/Minter/billing handle, so Authorize/Mint/Revoke/
// GetUsage cannot be called by construction.
func TestProposeBYOIEndToEnd(t *testing.T) {
	fake := &fakeInference{resp: mappingResponse("github", "repo.rename", "config_change")}
	var gotURL, gotKey string
	p := &Proposer{
		Session:      &session.BYOISession{BaseURL: "http://user.endpoint", Key: "sk-ant-USERKEY"},
		Fingerprints: freshRejects(t),
		NewClient: func(url, key string) InferenceClient {
			gotURL, gotKey = url, key
			return fake
		},
		Lane:      "investigate",
		BudgetUSD: 2.0,
	}

	out, err := p.Propose(context.Background(), sampleGap())
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Proposed || out.Proposal == nil || out.Proposal.Kind != KindMapping {
		t.Fatalf("want a mapping proposal, got %+v", out)
	}
	if out.Proposal.Mapping.EventType != "config_change" {
		t.Errorf("event_type = %q, want config_change", out.Proposal.Mapping.EventType)
	}
	if gotURL != "http://user.endpoint" || gotKey != "sk-ant-USERKEY" {
		t.Errorf("inference client got (%q,%q), want the user's own URL+key", gotURL, gotKey)
	}
	if out.Proposal.Endpoint != "http://user.endpoint" {
		t.Errorf("proposal endpoint = %q, want the BYOI base URL (never the key)", out.Proposal.Endpoint)
	}
	if fake.callCount() != 1 {
		t.Errorf("inference calls = %d, want exactly 1", fake.callCount())
	}
	if out.CostUSD != 0 {
		t.Errorf("BYOI CostUSD = %v, want 0 (no donut cap decrement)", out.CostUSD)
	}
}

// TestProposeBYOIKnownReject: the anti-thrash short-circuit runs on the BYOI rail
// too — a known-reject fingerprint spends ZERO inference on the user's dime.
func TestProposeBYOIKnownReject(t *testing.T) {
	fake := &fakeInference{resp: mappingResponse("github", "repo.rename", "config_change")}
	rejects := freshRejects(t)
	if err := rejects.Add(mappingFingerprint(sampleGap())); err != nil {
		t.Fatalf("seed reject set: %v", err)
	}
	p := &Proposer{
		Session:      &session.BYOISession{BaseURL: "http://user.endpoint", Key: "sk-ant-USERKEY"},
		Fingerprints: rejects,
		NewClient:    func(_, _ string) InferenceClient { return fake },
		Lane:         "investigate",
		BudgetUSD:    2.0,
	}

	out, err := p.Propose(context.Background(), sampleGap())
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Skipped {
		t.Fatalf("want Skipped on a known-reject fingerprint, got %+v", out)
	}
	if fake.callCount() != 0 {
		t.Errorf("inference calls = %d, want 0 on a known reject (BYOI)", fake.callCount())
	}
}

// TestProposeBYOIRedactsKeyInError: an inference error carrying the user's
// vendor key is scrubbed from the Outcome.Reason AND from every log line — the
// exact-string redaction pass catches an "sk-ant-..." key that the mallcop-sk-*
// regex would miss.
func TestProposeBYOIRedactsKeyInError(t *testing.T) {
	const key = "sk-ant-api03-LEAKED-SECRET-abcdefghijklmnop"
	fake := &fakeInference{err: fmt.Errorf("upstream 401 unauthorized: bad key %q in Authorization header", key)}

	var logbuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logbuf, nil))
	p := &Proposer{
		Session:      &session.BYOISession{BaseURL: "http://user.endpoint", Key: key, Logger: log},
		Fingerprints: freshRejects(t),
		NewClient:    func(_, _ string) InferenceClient { return fake },
		Lane:         "investigate",
		BudgetUSD:    2.0,
		Logger:       log,
	}

	out, err := p.Propose(context.Background(), sampleGap())
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Failed {
		t.Fatalf("want Failed on an inference error, got %+v", out)
	}
	if strings.Contains(out.Reason, key) || strings.Contains(out.Reason, "sk-ant") {
		t.Errorf("Outcome.Reason leaked the BYOI key: %q", out.Reason)
	}
	if strings.Contains(logbuf.String(), key) {
		t.Errorf("a log line leaked the raw BYOI key: %q", logbuf.String())
	}
}
