// toolrun_test.go — standalone unit tests for the PRODUCTION ToolRunner over a
// REAL git-backed core/store fixture (no eval seam, no model, no network). These
// prove the runner's own behavior end-to-end: the per-tier toolset, the boxed
// per-tool transcript fields, the ToolEmpty fail-safe, the FIX-2 new-actor
// fallback, and the three observable force-escalate predicates — computed over a
// store the test seeds by hand (the same git-backed source of truth production
// reads). The cross-runner byte-equality proof lives in core/eval/parity_test.go.
package toolrun

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// seedStore builds a fresh git-backed store under a temp dir and appends the given
// events. It mirrors the hermetic git discipline core/store + the eval harness use
// so the fixture is reproducible regardless of the operator's git environment.
func seedStore(t *testing.T, events []event) *store.Store {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	for i, e := range events {
		if _, err := st.Append(store.KindEvents, e.record(t)); err != nil {
			t.Fatalf("append event[%d]: %v", i, err)
		}
	}
	return st
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=toolrun-test", "GIT_AUTHOR_EMAIL=test@mallcop.app",
		"GIT_COMMITTER_NAME=toolrun-test", "GIT_COMMITTER_EMAIL=test@mallcop.app",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
}

// event is a compact test fixture event projected into the on-disk event.Event the
// store persists (action/target/metadata ride in Payload, as production records do).
type event struct {
	id, source, etype, actor, action, target string
	ts                                       string
	meta                                     map[string]string
}

func (e event) record(t *testing.T) any {
	t.Helper()
	payload := map[string]any{"action": e.action, "target": e.target}
	if len(e.meta) > 0 {
		payload["metadata"] = e.meta
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	ts := time.Time{}
	if e.ts != "" {
		if parsed, err := time.Parse(time.RFC3339, e.ts); err == nil {
			ts = parsed.UTC()
		}
	}
	return map[string]any{
		"id": e.id, "source": e.source, "type": e.etype, "actor": e.actor,
		"timestamp": ts, "payload": json.RawMessage(raw),
	}
}

func findingFor(actor, source, etype string) finding.Finding {
	evid, _ := json.Marshal(map[string]any{"source": source, "event_type": etype})
	return finding.Finding{
		ID: "f-1", Actor: actor, Source: "detector:" + source, Type: etype, Evidence: evid,
	}
}

// TestRunner_TriageToolset proves the triage tier runs search-events + check-baseline
// (2 calls, 2 distinct tools), boxes each into its own per-tool field, and reports a
// non-empty read when the actor's events are present.
func TestRunner_TriageToolset(t *testing.T) {
	st := seedStore(t, []event{
		{id: "evt_001", source: "azure", etype: "storage_access", actor: "batch-proc",
			action: "read_blob", target: "acct/containers/reports", ts: "2026-03-01T01:00:00Z"},
	})
	r := &Runner{Store: st, Baseline: &baseline.Baseline{
		KnownActors:     []string{"batch-proc"},
		FrequencyTables: map[string]int{"azure:storage_access": 50},
	}}
	ev, err := r.RunTools(context.Background(), "triage", findingFor("batch-proc", "azure", "storage_access"))
	if err != nil {
		t.Fatalf("RunTools: %v", err)
	}
	if ev.ToolCalls != 2 || ev.DistinctTools != 2 {
		t.Fatalf("triage toolset: calls=%d distinct=%d want 2/2", ev.ToolCalls, ev.DistinctTools)
	}
	if ev.ToolEmpty {
		t.Fatalf("read had events; ToolEmpty must be false")
	}
	if ev.FindingsText != "" {
		t.Fatalf("triage must NOT run search-findings; got FindingsText=%q", ev.FindingsText)
	}
	if !strings.Contains(ev.EventsText, "evt_001") {
		t.Fatalf("EventsText must carry the surfaced event; got %q", ev.EventsText)
	}
	if !strings.Contains(ev.BaselineText, "check-baseline") {
		t.Fatalf("BaselineText must carry the check-baseline result; got %q", ev.BaselineText)
	}
}

// TestRunner_InvestigateAddsSearchFindings proves the investigate tier adds the
// deeper search-findings sweep (3 calls, 3 distinct tools, FindingsText populated).
func TestRunner_InvestigateAddsSearchFindings(t *testing.T) {
	st := seedStore(t, []event{
		{id: "evt_001", source: "azure", etype: "storage_access", actor: "batch-proc",
			action: "read_blob", target: "acct/containers/reports", ts: "2026-03-01T01:00:00Z"},
	})
	r := &Runner{Store: st, Baseline: &baseline.Baseline{KnownActors: []string{"batch-proc"}}}
	ev, err := r.RunTools(context.Background(), "investigate", findingFor("batch-proc", "azure", "storage_access"))
	if err != nil {
		t.Fatalf("RunTools: %v", err)
	}
	if ev.ToolCalls != 3 || ev.DistinctTools != 3 {
		t.Fatalf("investigate toolset: calls=%d distinct=%d want 3/3", ev.ToolCalls, ev.DistinctTools)
	}
	if !strings.Contains(ev.FindingsText, "search-findings") {
		t.Fatalf("investigate must run search-findings; got FindingsText=%q", ev.FindingsText)
	}
}

// TestRunner_ToolEmptyForeignActor proves the fail-safe: a finding about an actor
// with NO events (and no naming events to fall back to) reports ToolEmpty=true.
func TestRunner_ToolEmptyForeignActor(t *testing.T) {
	st := seedStore(t, []event{
		{id: "evt_001", source: "azure", etype: "storage_access", actor: "batch-proc",
			action: "read_blob", target: "acct/x", ts: "2026-03-01T01:00:00Z"},
	})
	r := &Runner{Store: st, Baseline: &baseline.Baseline{}}
	ev, err := r.RunTools(context.Background(), "triage", findingFor("ghost-actor", "azure", "storage_access"))
	if err != nil {
		t.Fatalf("RunTools: %v", err)
	}
	if !ev.ToolEmpty {
		t.Fatalf("foreign actor with no events must report ToolEmpty=true; events=%q", ev.EventsText)
	}
}

// TestRunner_Fix2NewActorFallback proves the FIX-2 fallback: a finding about a NEW
// actor whose creation event is AUTHORED by a different principal (the new actor is
// the event target) surfaces that event via the naming fallback, so ToolEmpty=false.
func TestRunner_Fix2NewActorFallback(t *testing.T) {
	st := seedStore(t, []event{
		{id: "evt_001", source: "azure", etype: "role_assignment", actor: "admin-user",
			action: "create_principal", target: "principals/deploy-svc-new", ts: "2026-03-01T01:00:00Z",
			meta: map[string]string{"principal_id": "deploy-svc-new"}},
	})
	r := &Runner{Store: st, Baseline: &baseline.Baseline{}}
	ev, err := r.RunTools(context.Background(), "triage", findingFor("deploy-svc-new", "azure", "role_assignment"))
	if err != nil {
		t.Fatalf("RunTools: %v", err)
	}
	if ev.ToolEmpty {
		t.Fatalf("FIX-2: the creation event naming the new actor must surface so ToolEmpty=false; events=%q", ev.EventsText)
	}
	if !strings.Contains(ev.EventsText, "deploy-svc-new") {
		t.Fatalf("FIX-2: the naming event must reach the transcript; got %q", ev.EventsText)
	}
	// The new actor performed no grant itself (admin-user authored it), so the
	// role-grant force must NOT fire on the finding actor.
	if ev.RoleGrantByActor {
		t.Fatalf("RoleGrantByActor must be false (grant authored by admin-user, not deploy-svc-new); detail=%q", ev.RoleGrantDetail)
	}
}

// TestRunner_BulkExportNoJustification_Fires proves the action-keyed bulk-export
// force fires on a high-volume export with no justification companion.
func TestRunner_BulkExportNoJustification_Fires(t *testing.T) {
	st := seedStore(t, []event{
		{id: "evt_001", source: "pg", etype: "database_access", actor: "admin",
			action: "pg_dump", target: "db/prod", ts: "2026-03-01T02:00:00Z",
			meta: map[string]string{"rows_affected": "15000"}},
	})
	r := &Runner{Store: st, Baseline: &baseline.Baseline{}}
	ev, err := r.RunTools(context.Background(), "triage", findingFor("admin", "pg", "database_access"))
	if err != nil {
		t.Fatalf("RunTools: %v", err)
	}
	if !ev.BulkExportNoJustification {
		t.Fatalf("a 15,000-row unjustified pg_dump must trip the bulk-export force; events=%q", ev.EventsText)
	}
}

// TestRunner_BulkExportJustified_DoesNotFire proves the justification exclusion: the
// SAME high-volume export with a job_id/schedule companion does NOT trip the force.
func TestRunner_BulkExportJustified_DoesNotFire(t *testing.T) {
	st := seedStore(t, []event{
		{id: "evt_001", source: "pg", etype: "database_access", actor: "batch",
			action: "pg_dump", target: "db/prod", ts: "2026-03-01T02:00:00Z",
			meta: map[string]string{"rows_affected": "15000", "job_id": "nightly-report", "scheduled": "true"}},
	})
	r := &Runner{Store: st, Baseline: &baseline.Baseline{}}
	ev, err := r.RunTools(context.Background(), "triage", findingFor("batch", "pg", "database_access"))
	if err != nil {
		t.Fatalf("RunTools: %v", err)
	}
	if ev.BulkExportNoJustification {
		t.Fatalf("a justified scheduled export must NOT trip the force; detail=%q", ev.BulkExportDetail)
	}
}

// TestRunner_ZeroHistoryAccess proves the zero-history force fires when the actor
// accesses a target absent from its relationship history, and does NOT fire when the
// target is covered by an established relationship.
func TestRunner_ZeroHistoryAccess(t *testing.T) {
	mkStore := func(target string) *store.Store {
		return seedStore(t, []event{
			{id: "evt_001", source: "azure", etype: "storage_access", actor: "ci-bot",
				action: "read_blob", target: target, ts: "2026-03-01T01:00:00Z"},
		})
	}
	bl := &baseline.Baseline{Relationships: map[string]baseline.Relationship{
		"ci-bot:registry/atom-images": {Count: 200},
	}}

	// Zero-history: ci-bot reads a storage target it has never touched.
	r := &Runner{Store: mkStore("storage/atomstore01/financial"), Baseline: bl}
	ev, _ := r.RunTools(context.Background(), "triage", findingFor("ci-bot", "azure", "storage_access"))
	if !ev.ZeroHistoryAccess {
		t.Fatalf("access to an unrelated target must trip zero-history; detail=%q", ev.ZeroHistoryDetail)
	}

	// Established: ci-bot reads a sub-path of a target it already has history with.
	r2 := &Runner{Store: mkStore("registry/atom-images/tag-v2"), Baseline: bl}
	ev2, _ := r2.RunTools(context.Background(), "triage", findingFor("ci-bot", "azure", "storage_access"))
	if ev2.ZeroHistoryAccess {
		t.Fatalf("access to a sub-path of an established relationship must NOT trip zero-history; detail=%q", ev2.ZeroHistoryDetail)
	}
}

// TestRunner_NilBaselineSafe proves the runner degrades safely with a nil baseline:
// no panic, predicates fall to false, search-events still runs.
func TestRunner_NilBaselineSafe(t *testing.T) {
	st := seedStore(t, []event{
		{id: "evt_001", source: "azure", etype: "login", actor: "user", action: "login", ts: "2026-03-01T01:00:00Z"},
	})
	r := &Runner{Store: st, Baseline: nil}
	ev, err := r.RunTools(context.Background(), "triage", findingFor("user", "azure", "login"))
	if err != nil {
		t.Fatalf("RunTools with nil baseline: %v", err)
	}
	if ev.ZeroHistoryAccess || ev.RoleGrantByActor {
		t.Fatalf("nil baseline must yield no relationship/role forces")
	}
	if !strings.Contains(ev.EventsText, "evt_001") {
		t.Fatalf("search-events must still run with a nil baseline; got %q", ev.EventsText)
	}
}
