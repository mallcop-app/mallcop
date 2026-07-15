package investigate

// serve_seed_test.go — the mallcoppro-010 reproduce-then-fix test. It replays the
// real prod-chat failure: a critical `new-external-access` / `forge-proxy` finding
// is on the operator's screen, they ask "give me the details on the external
// access from forge please", and the live analyst must GROUND on that finding
// rather than reverse-engineering an actor="forge" filter from the prose, coming
// up empty, and interrogating the operator for data already on their screen.
//
// The LLM transport is the only stub (same boundary as investigate_test.go). The
// scripted "model" branches on whether the loop actually delivered the on-screen
// finding into its FIRST request: given the finding it grounds (search_findings by
// the finding's real source, then search_events by the finding's event_ids, then a
// grounded answer); starved of it, it does what the real model did in prod — guess
// actor="forge", get nothing, and punt. So the test is a genuine red→green: with
// the seed seam removed (browser record.findings not threaded through serve) it
// takes the punt branch and fails; with the fix it grounds and passes.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// seedExternalAccessStore opens a real git-backed store holding the north-star
// finding (find-ext-001, new-external-access, source forge-proxy, critical) plus
// the two REAL events it was built from (evt-ext-1/evt-ext-2, source forge-proxy)
// and a decoy event for a different actor — so grounding on the finding's
// event_ids and chaining to search_events genuinely filters rather than echoing
// the whole stream.
func seedExternalAccessStore(t *testing.T) *store.Store {
	t.Helper()
	dir := initRepo(t)
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	events := []event.Event{
		{
			ID:        "evt-ext-1",
			Source:    "forge-proxy",
			Type:      "external-access-grant",
			Actor:     "svc-forge",
			Timestamp: time.Date(2026, 7, 14, 2, 0, 0, 0, time.UTC),
			Org:       "acme",
			Payload:   json.RawMessage(`{"target":"prod-db","action":"grant","port":"5432"}`),
		},
		{
			ID:        "evt-ext-2",
			Source:    "forge-proxy",
			Type:      "external-access-grant",
			Actor:     "svc-forge",
			Timestamp: time.Date(2026, 7, 14, 2, 1, 0, 0, time.UTC),
			Org:       "acme",
			Payload:   json.RawMessage(`{"target":"prod-db","action":"open","port":"6379"}`),
		},
		{
			ID:        "evt-decoy-1",
			Source:    "github",
			Type:      "push",
			Actor:     "alice",
			Timestamp: time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC),
			Org:       "acme",
			Payload:   json.RawMessage(`{"target":"repo","action":"push"}`),
		},
	}
	for _, ev := range events {
		if _, err := st.Append(store.KindEvents, ev); err != nil {
			t.Fatalf("seed event %s: %v", ev.ID, err)
		}
	}

	f := finding.Finding{
		ID:        "find-ext-001",
		Source:    "forge-proxy",
		Severity:  "critical",
		Type:      "new-external-access",
		Actor:     "svc-forge",
		Timestamp: time.Date(2026, 7, 14, 2, 1, 0, 0, time.UTC),
		Reason:    "new external access grant to prod-db from forge-proxy",
	}
	if _, err := st.Append(store.KindFindings, f); err != nil {
		t.Fatalf("seed finding %s: %v", f.ID, err)
	}
	return st
}

// groundOrPuntServer is the scripted LLM transport for the reproduce-then-fix
// test. It decides ONCE, from the loop's first request, whether the on-screen
// finding context was delivered, and then plays either the grounded analyst or the
// prod-failure punt. The grounded arm proves the whole north-star chain:
// search_findings (by the finding's real source, not a prose guess) → search_events
// by the finding's event_ids → an answer citing the real finding + events.
func groundOrPuntServer(t *testing.T) (*httptest.Server, *[]string, *bool) {
	t.Helper()
	var bodies []string
	grounded := false

	toolUse := func(w http.ResponseWriter, id, name string, input map[string]any) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "message", "role": "assistant", "stop_reason": "tool_use",
			"content": []map[string]any{{"type": "tool_use", "id": id, "name": name, "input": input}},
		})
	}
	text := func(w http.ResponseWriter, s string) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "message", "role": "assistant", "stop_reason": "end_turn",
			"content": []map[string]any{{"type": "text", "text": s}},
		})
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		body := string(buf)
		bodies = append(bodies, body)
		w.Header().Set("Content-Type", "application/json")

		if len(bodies) == 1 {
			// A real model grounds when it can see the finding, and guesses from
			// prose when it cannot. Decide the arm from whether the loop delivered
			// the finding's identifying fields into this first request.
			grounded = strings.Contains(body, "find-ext-001") &&
				strings.Contains(body, "forge-proxy") &&
				strings.Contains(body, "evt-ext-1")
		}

		if grounded {
			switch len(bodies) {
			case 1:
				// Prefer search_findings, filtered by the finding's REAL source —
				// never a prose-guessed actor.
				toolUse(w, "toolu_sf", "search_findings", map[string]any{"source": "forge-proxy"})
			case 2:
				if !strings.Contains(body, "find-ext-001") {
					t.Errorf("grounded turn 2 request did not carry the real search_findings tool_result (want find-ext-001):\n%s", body)
				}
				// Chain to the finding's event_ids via the new search_events ids filter.
				toolUse(w, "toolu_se", "search_events", map[string]any{"ids": []string{"evt-ext-1", "evt-ext-2"}})
			default:
				if !strings.Contains(body, "evt-ext-1") {
					t.Errorf("grounded turn 3 request did not carry the chained search_events tool_result (want evt-ext-1):\n%s", body)
				}
				text(w, "The external access from forge is finding find-ext-001 (critical, new-external-access, source forge-proxy). It was built from events evt-ext-1 and evt-ext-2 — grants to prod-db on ports 5432 and 6379.")
			}
			return
		}

		// Punt arm — the prod failure: no finding context, so guess actor from the
		// word "forge", find nothing, and ask the operator for what is already on
		// their screen.
		switch len(bodies) {
		case 1:
			toolUse(w, "toolu_guess", "search_events", map[string]any{"actor": "forge"})
		default:
			text(w, "I couldn't find any events for actor \"forge\". Which finding are you referring to? Please provide the finding ID, its source, and the port numbers involved.")
		}
	}))
	return srv, &bodies, &grounded
}

// TestServe_GroundsOnSeededOnScreenFinding is the mallcoppro-010 reproduce-then-fix
// test. It writes the operator's question WITH the on-screen finding attached (the
// browser seam this fix adds — chat_page.go sendLive → inbox record.findings),
// drives the real serve loop, and asserts the analyst grounded on the finding,
// chained to its event_ids, and never punted for on-screen data.
//
// Before the fix (serve does not thread record.findings into the loop): the first
// model request carries no finding context, the scripted model takes the punt arm,
// and this test FAILS on the grounding assertion — reproducing the prod bug. After
// the fix it grounds and passes.
func TestServe_GroundsOnSeededOnScreenFinding(t *testing.T) {
	st := seedExternalAccessStore(t)
	srv, bodies, grounded := groundOrPuntServer(t)
	defer srv.Close()

	dir := t.TempDir()
	inboxPath := filepath.Join(dir, "inbox.jsonl")
	outboxPath := filepath.Join(dir, "outbox.jsonl")

	// The browser writes the on-screen finding into the question record. event_ids
	// come from the browser's findings.json row; they are what the analyst chains on.
	question := map[string]any{
		"type": "question", "seq": 1, "id": "q_1",
		"text": "give me the details on the external access from forge please",
		"findings": []map[string]any{{
			"id": "find-ext-001", "type": "new-external-access",
			"source": "forge-proxy", "actor": "svc-forge", "severity": "critical",
			"reason":    "new external access grant to prod-db from forge-proxy",
			"event_ids": []string{"evt-ext-1", "evt-ext-2"},
		}},
	}
	line, _ := json.Marshal(question)
	if err := os.WriteFile(inboxPath, append(line, '\n'), 0o644); err != nil {
		t.Fatalf("write inbox: %v", err)
	}

	client := &inference.DirectClient{BaseURL: srv.URL, Model: "test-model"}
	opts := ServeOptions{
		Options:         Options{Client: client, Model: "test-model", Store: st},
		InboxPath:       inboxPath,
		OutboxPath:      outboxPath,
		IdleTimeout:     150 * time.Millisecond,
		PollInterval:    20 * time.Millisecond,
		HeartbeatPeriod: time.Hour,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Serve(ctx, opts); err != nil {
		t.Fatalf("Serve: unexpected error: %v", err)
	}

	// --- DEFECT 1: the loop must have delivered the on-screen finding into the
	// model's first request. Without it, the analyst starts blind. ---
	if !*grounded {
		first := ""
		if len(*bodies) > 0 {
			first = (*bodies)[0]
		}
		t.Fatalf("DEFECT 1 not fixed: the runner did NOT seed the on-screen finding into the model's first request, so the analyst had to guess a filter from the operator's prose. First request:\n%s", first)
	}

	raw, err := os.ReadFile(outboxPath)
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	out := string(raw)

	// --- the answer grounds on the real finding and chains to its events ---
	if !strings.Contains(out, "find-ext-001") {
		t.Fatalf("answer never cites the seeded finding find-ext-001:\n%s", out)
	}
	if !strings.Contains(out, "evt-ext-1") {
		t.Fatalf("answer never chains to the finding's event_ids (want evt-ext-1):\n%s", out)
	}

	// --- DEFECT 2: never interrogate the operator for on-screen data ---
	for _, punt := range []string{"Which finding", "provide the finding", "port numbers involved", "referring to"} {
		if strings.Contains(out, punt) {
			t.Fatalf("DEFECT 2 not fixed: the analyst punted back to the operator for data already on their screen (matched %q):\n%s", punt, out)
		}
	}

	// --- a decoy event for a different actor never leaked into the answer, proving
	// the event_ids chain genuinely filtered (a blind loop had no basis to) ---
	if strings.Contains(out, "evt-decoy-1") {
		t.Fatalf("answer leaked a decoy event — the event_ids chain did not filter:\n%s", out)
	}
}
