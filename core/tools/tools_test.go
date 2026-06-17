package tools

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// repoRoot resolves the repository root from this test file's location. core/tools
// is two directories below the repo root, so the shipped fixtures
// (agents/rules/operator-decisions.yaml, test/fixtures/baseline.json) are at
// ../../ relative to this file. Resolving via runtime.Caller makes the tests run
// from any working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "agents", "rules", "operator-decisions.yaml")); err != nil {
		t.Fatalf("repo root %q missing shipped rule corpus: %v", root, err)
	}
	return root
}

// ---- lookup-rules ----------------------------------------------------------

// TestLookupRules drives the lookup-rules tool against the REAL shipped rule
// corpus at agents/rules/operator-decisions.yaml. Each case asserts which rule
// ids match a given family + metadata predicate.
func TestLookupRules(t *testing.T) {
	root := repoRoot(t)

	cases := []struct {
		name      string
		input     LookupRulesInput
		wantRules []string // rule ids, in corpus order
		wantErr   bool
	}{
		{
			name: "unusual-timing + maintenance_window matches R-001",
			input: LookupRulesInput{
				FindingID:         "f-1",
				FindingFamily:     "unusual-timing",
				MaintenanceWindow: "true",
			},
			wantRules: []string{"R-001"},
		},
		{
			name: "unusual-timing + location_change matches R-005",
			input: LookupRulesInput{
				FindingID:      "f-2",
				FindingFamily:  "unusual-timing",
				LocationChange: "true",
			},
			wantRules: []string{"R-005"},
		},
		{
			name: "volume-anomaly + scheduled matches R-002 only",
			input: LookupRulesInput{
				FindingID:     "f-3",
				FindingFamily: "volume-anomaly",
				Scheduled:     "true",
			},
			wantRules: []string{"R-002"},
		},
		{
			name: "volume-anomaly + deploy_release matches R-008 only",
			input: LookupRulesInput{
				FindingID:     "f-4",
				FindingFamily: "volume-anomaly",
				DeployRelease: "true",
			},
			wantRules: []string{"R-008"},
		},
		{
			name: "auth-failure-burst + login_success matches R-003",
			input: LookupRulesInput{
				FindingID:       "f-5",
				FindingFamily:   "auth-failure-burst",
				ResolutionEvent: "login_success",
			},
			wantRules: []string{"R-003"},
		},
		{
			name: "new-actor + terraform provenance matches R-007 (via legacy map)",
			input: LookupRulesInput{
				FindingID:       "f-6",
				FindingFamily:   "new-actor",
				FindingMetadata: map[string]string{"automation_provenance": "terraform"},
			},
			wantRules: []string{"R-007"},
		},
		{
			name: "case-insensitive family + metadata value",
			input: LookupRulesInput{
				FindingID:         "f-7",
				FindingFamily:     "UNUSUAL-TIMING",
				MaintenanceWindow: "TRUE",
			},
			wantRules: []string{"R-001"},
		},
		{
			name: "family match but predicate absent yields no rules",
			input: LookupRulesInput{
				FindingID:     "f-8",
				FindingFamily: "unusual-timing",
				// no maintenance_window / location_change flag
			},
			wantRules: []string{},
		},
		{
			name: "unknown family yields empty (not error)",
			input: LookupRulesInput{
				FindingID:         "f-9",
				FindingFamily:     "no-such-family",
				MaintenanceWindow: "true",
			},
			wantRules: []string{},
		},
		{
			name:    "missing finding_id errors",
			input:   LookupRulesInput{FindingFamily: "unusual-timing"},
			wantErr: true,
		},
		{
			name:    "missing finding_family errors",
			input:   LookupRulesInput{FindingID: "f-10"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := LookupRules(root, tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (out=%+v)", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if out.FindingID != tc.input.FindingID {
				t.Errorf("finding_id: got %q want %q", out.FindingID, tc.input.FindingID)
			}
			got := make([]string, 0, len(out.Rules))
			for _, r := range out.Rules {
				got = append(got, r.ID)
			}
			if !equalStrings(got, tc.wantRules) {
				t.Errorf("rules: got %v want %v", got, tc.wantRules)
			}
			// Rules slice is never nil (empty slice on no match).
			if out.Rules == nil {
				t.Error("Rules must be non-nil empty slice on no match")
			}
		})
	}
}

// TestLookupRulesMissingCorpus confirms a repo root with no corpus loads zero
// rules (missing file == "no pre-seeded rules", not an error).
func TestLookupRulesMissingCorpus(t *testing.T) {
	empty := t.TempDir()
	out, err := LookupRules(empty, LookupRulesInput{FindingID: "f", FindingFamily: "unusual-timing", MaintenanceWindow: "true"})
	if err != nil {
		t.Fatalf("missing corpus should not error: %v", err)
	}
	if len(out.Rules) != 0 {
		t.Errorf("missing corpus should yield 0 rules, got %d", len(out.Rules))
	}
}

// ---- check-baseline --------------------------------------------------------

// TestCheckBaseline drives check-baseline against the REAL shipped fixture at
// test/fixtures/baseline.json plus a constructed typed baseline exercising
// frequency / roles / known-actor paths.
func TestCheckBaseline(t *testing.T) {
	root := repoRoot(t)

	// Real fixture: known_users baron + ci-bot, with geos and last_seen.
	real, err := baseline.Load(filepath.Join(root, "test", "fixtures", "baseline.json"))
	if err != nil {
		t.Fatalf("load real baseline fixture: %v", err)
	}

	// Constructed baseline exercising frequency tables, known actors, roles.
	rich := &baseline.Baseline{
		KnownActors: []string{"deploy-svc"},
		FrequencyTables: map[string]int{
			"azure:container_restart:deploy-svc": 40,
			"azure:image_push:deploy-svc":        2,
			"time:02:deploy-svc":                 10, // must NOT bucket as event type
			"github:push:someone-else":           99, // must NOT match deploy-svc
		},
		ActorRoles: map[string][]string{
			"deploy-svc": {"deployer", "restarter"},
		},
	}

	cases := []struct {
		name  string
		base  *baseline.Baseline
		input CheckBaselineInput
		want  CheckBaselineResult
	}{
		{
			name:  "known user from real fixture",
			base:  real,
			input: CheckBaselineInput{Entity: "baron"},
			want: CheckBaselineResult{
				Known:           true,
				LastSeen:        "2026-04-09T12:00:00Z",
				FrequencyByType: map[string]int{},
				Roles:           []string{},
			},
		},
		{
			name:  "known user case-insensitive",
			base:  real,
			input: CheckBaselineInput{Entity: "CI-BOT"},
			want: CheckBaselineResult{
				Known:           true,
				LastSeen:        "2026-04-10T00:00:00Z",
				FrequencyByType: map[string]int{},
				Roles:           []string{},
			},
		},
		{
			name:  "unknown entity from real fixture",
			base:  real,
			input: CheckBaselineInput{Entity: "mallory"},
			want: CheckBaselineResult{
				Known:           false,
				FrequencyByType: map[string]int{},
				Roles:           []string{},
			},
		},
		{
			name:  "known source (geo) keeps known true",
			base:  real,
			input: CheckBaselineInput{Entity: "baron", Source: "US"},
			want: CheckBaselineResult{
				Known:           true,
				LastSeen:        "2026-04-09T12:00:00Z",
				FrequencyByType: map[string]int{},
				Roles:           []string{},
			},
		},
		{
			name:  "unknown source (geo) downgrades known",
			base:  real,
			input: CheckBaselineInput{Entity: "ci-bot", Source: "FR"},
			want: CheckBaselineResult{
				Known:           false,
				LastSeen:        "2026-04-10T00:00:00Z",
				FrequencyByType: map[string]int{},
				Roles:           []string{},
			},
		},
		{
			name:  "frequency sums compound keys + buckets by type, roles populated",
			base:  rich,
			input: CheckBaselineInput{Entity: "deploy-svc", EventType: "container_restart"},
			want: CheckBaselineResult{
				Known:            true,
				Frequency:        52, // 40 + 2 + 10 (time bucket counted in aggregate)
				FrequencyByType:  map[string]int{"container_restart": 40, "image_push": 2},
				FrequencyForType: 40,
				EventType:        "container_restart",
				Roles:            []string{"deployer", "restarter"},
			},
		},
		{
			name:  "nil baseline → unknown, no error",
			base:  nil,
			input: CheckBaselineInput{Entity: "anyone"},
			want: CheckBaselineResult{
				Known:           false,
				FrequencyByType: map[string]int{},
				Roles:           []string{},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CheckBaseline(tc.base, tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(tc.want)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("result mismatch\n got: %s\nwant: %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestCheckBaselineRequiresEntity(t *testing.T) {
	if _, err := CheckBaseline(&baseline.Baseline{}, CheckBaselineInput{}); err == nil {
		t.Fatal("expected error for empty entity")
	}
}

// ---- search-events ---------------------------------------------------------

// TestSearchEvents drives search-events against a REAL core/store temp repo:
// events are appended via store.Append, then read back through SearchEvents.
func TestSearchEvents(t *testing.T) {
	s := newTempStore(t)

	base := time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC)
	seed := []event.Event{
		{ID: "e1", Source: "github", Type: "push", Actor: "baron", Timestamp: base},
		{ID: "e2", Source: "github", Type: "push", Actor: "ci-bot", Timestamp: base.Add(1 * time.Hour)},
		{ID: "e3", Source: "azure", Type: "container_restart", Actor: "deploy-svc", Timestamp: base.Add(2 * time.Hour)},
		{ID: "e4", Source: "github", Type: "delete", Actor: "baron", Timestamp: base.Add(3 * time.Hour)},
	}
	for _, ev := range seed {
		if _, err := s.Append(store.KindEvents, ev); err != nil {
			t.Fatalf("append event %s: %v", ev.ID, err)
		}
	}

	cases := []struct {
		name        string
		input       SearchEventsInput
		wantIDs     []string
		wantFellBck bool
	}{
		{
			name:    "no filter returns all in order",
			input:   SearchEventsInput{},
			wantIDs: []string{"e1", "e2", "e3", "e4"},
		},
		{
			name:    "actor filter case-insensitive",
			input:   SearchEventsInput{Actor: "BARON"},
			wantIDs: []string{"e1", "e4"},
		},
		{
			name:    "source filter",
			input:   SearchEventsInput{Source: "azure"},
			wantIDs: []string{"e3"},
		},
		{
			name:    "type filter",
			input:   SearchEventsInput{Type: "push"},
			wantIDs: []string{"e1", "e2"},
		},
		{
			name:    "combined actor + type",
			input:   SearchEventsInput{Actor: "baron", Type: "delete"},
			wantIDs: []string{"e4"},
		},
		{
			name:    "time window selects subset",
			input:   SearchEventsInput{Since: base.Add(90 * time.Minute), Until: base.Add(150 * time.Minute)},
			wantIDs: []string{"e3"},
		},
		{
			name:        "all-excluding window falls back to non-time set",
			input:       SearchEventsInput{Actor: "baron", Since: base.Add(100 * time.Hour)},
			wantIDs:     []string{"e1", "e4"},
			wantFellBck: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, fellBack, err := SearchEvents(s, tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			ids := make([]string, 0, len(got))
			for _, ev := range got {
				ids = append(ids, ev.ID)
			}
			if !equalStrings(ids, tc.wantIDs) {
				t.Errorf("ids: got %v want %v", ids, tc.wantIDs)
			}
			if fellBack != tc.wantFellBck {
				t.Errorf("fellBack: got %v want %v", fellBack, tc.wantFellBck)
			}
		})
	}
}

func TestSearchEventsEmptyStore(t *testing.T) {
	s := newTempStore(t)
	got, fellBack, err := SearchEvents(s, SearchEventsInput{Actor: "nobody"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 || fellBack {
		t.Errorf("empty store: got %d events fellBack=%v, want 0 / false", len(got), fellBack)
	}
}

func TestSearchEventsNilStore(t *testing.T) {
	if _, _, err := SearchEvents(nil, SearchEventsInput{}); err == nil {
		t.Fatal("expected error for nil store")
	}
}

// ---- search-findings -------------------------------------------------------

// TestSearchFindings drives search-findings against a REAL core/store temp repo.
func TestSearchFindings(t *testing.T) {
	s := newTempStore(t)

	base := time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC)
	seed := []finding.Finding{
		{ID: "f1", Source: "detector:unusual-login", Severity: "high", Type: "unusual-login", Actor: "baron", Timestamp: base},
		{ID: "f2", Source: "detector:new-actor", Severity: "medium", Type: "new-actor", Actor: "ci-bot", Timestamp: base.Add(1 * time.Hour)},
		{ID: "f3", Source: "detector:unusual-login", Severity: "low", Type: "unusual-login", Actor: "baron", Timestamp: base.Add(2 * time.Hour)},
	}
	for _, f := range seed {
		if _, err := s.Append(store.KindFindings, f); err != nil {
			t.Fatalf("append finding %s: %v", f.ID, err)
		}
	}

	cases := []struct {
		name    string
		input   SearchFindingsInput
		wantIDs []string
	}{
		{
			name:    "no filter returns all in order",
			input:   SearchFindingsInput{},
			wantIDs: []string{"f1", "f2", "f3"},
		},
		{
			name:    "actor filter case-insensitive",
			input:   SearchFindingsInput{Actor: "BARON"},
			wantIDs: []string{"f1", "f3"},
		},
		{
			name:    "source filter",
			input:   SearchFindingsInput{Source: "detector:new-actor"},
			wantIDs: []string{"f2"},
		},
		{
			name:    "since lower bound inclusive",
			input:   SearchFindingsInput{Since: base.Add(1 * time.Hour)},
			wantIDs: []string{"f2", "f3"},
		},
		{
			name:    "actor + since combined",
			input:   SearchFindingsInput{Actor: "baron", Since: base.Add(1 * time.Hour)},
			wantIDs: []string{"f3"},
		},
		{
			name:    "no match yields empty",
			input:   SearchFindingsInput{Actor: "nobody"},
			wantIDs: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SearchFindings(s, tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			ids := make([]string, 0, len(got))
			for _, f := range got {
				ids = append(ids, f.ID)
			}
			if !equalStrings(ids, tc.wantIDs) {
				t.Errorf("ids: got %v want %v", ids, tc.wantIDs)
			}
		})
	}
}

func TestSearchFindingsEmptyStore(t *testing.T) {
	s := newTempStore(t)
	got, err := SearchFindings(s, SearchFindingsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty store: got %d findings, want 0", len(got))
	}
}

func TestSearchFindingsNilStore(t *testing.T) {
	if _, err := SearchFindings(nil, SearchFindingsInput{}); err == nil {
		t.Fatal("expected error for nil store")
	}
}

// ---- helpers ---------------------------------------------------------------

// newTempStore git-inits a temp repo (with a root commit so HEAD resolves) and
// opens a real core/store over it. Mirrors core/store/store_test.go's initRepo.
func newTempStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "test"},
		{"config", "user.email", "test@example.com"},
		{"config", "commit.gpgsign", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	seed := exec.Command("git", "commit", "-q", "--allow-empty", "-m", "root")
	seed.Dir = dir
	seed.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed commit: %v\n%s", err, out)
	}
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return s
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
