// builtindisable_test.go — proofs for cfg-8 (rd mallcoppro-06a): the loop can
// never write detectors.builtin.disable in mallcop.yaml, only a human/owner
// can. Two layers, mirroring the rest of this package's test style:
//
//   - unit tests on checkBuiltinDisableOwnerOnly directly (no git needed);
//   - end-to-end Guard() tests over a real fixture repo, using the ACTUAL
//     product marshaller (config.Marshal) to generate the base/head
//     mallcop.yaml content rather than fabricated YAML text — so the proof is
//     anchored to what `mallcop init` / config.WriteConfigAtomic actually
//     produce, not a strawman.
package selfgate

import (
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/config"
)

// ---- unit tests: checkBuiltinDisableOwnerOnly --------------------------------

func TestCheckBuiltinDisableOwnerOnly(t *testing.T) {
	base := []byte(`
detectors:
  builtin:
    enabled: true
    disable: []
`)

	tests := []struct {
		name    string
		base    []byte // nil means "use the shared base above"
		head    string
		wantOK  bool
		wantSub string
	}{
		{
			name:   "identical (both empty) passes",
			head:   "detectors:\n  builtin:\n    enabled: true\n    disable: []\n",
			wantOK: true,
		},
		{
			name:   "reordering an unchanged set passes",
			base:   []byte("detectors:\n  builtin:\n    disable: [\"priv_escalation\", \"secret_exposure\"]\n"),
			head:   "detectors:\n  builtin:\n    disable: [\"secret_exposure\", \"priv_escalation\"]\n",
			wantOK: true,
		},
		{
			name:    "loop-authored addition to an empty list is rejected",
			head:    "detectors:\n  builtin:\n    enabled: true\n    disable: [\"priv_escalation\"]\n",
			wantOK:  false,
			wantSub: "owner discretion",
		},
		{
			name:    "loop-authored addition to a non-empty list is rejected",
			base:    []byte("detectors:\n  builtin:\n    disable: [\"priv_escalation\"]\n"),
			head:    "detectors:\n  builtin:\n    disable: [\"priv_escalation\", \"secret_exposure\"]\n",
			wantOK:  false,
			wantSub: "owner discretion",
		},
		{
			name:    "loop-authored removal is rejected (still a write, not owner's to make)",
			base:    []byte("detectors:\n  builtin:\n    disable: [\"priv_escalation\"]\n"),
			head:    "detectors:\n  builtin:\n    disable: []\n",
			wantOK:  false,
			wantSub: "owner discretion",
		},
		{
			name:    "setting it for the first time on a brand-new file (base=nil) is rejected",
			base:    nil,
			head:    "detectors:\n  builtin:\n    disable: [\"priv_escalation\"]\n",
			wantOK:  false,
			wantSub: "owner discretion",
		},
		{
			name:    "unparseable head fails closed",
			head:    "\tthis: : is: not: yaml",
			wantOK:  false,
			wantSub: "fail closed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := base
			if tc.base != nil {
				b = tc.base
			}
			findings := checkBuiltinDisableOwnerOnly("mallcop.yaml", b, []byte(tc.head))
			if tc.wantOK {
				if len(findings) != 0 {
					t.Fatalf("want pass, got findings: %+v", findings)
				}
				return
			}
			if len(findings) == 0 {
				t.Fatalf("want rejection, got pass")
			}
			for _, f := range findings {
				if f.Rule != RuleBuiltinDisableOwnerOnly {
					t.Errorf("finding rule = %q, want %q", f.Rule, RuleBuiltinDisableOwnerOnly)
				}
			}
			joined := ""
			for _, f := range findings {
				joined += f.Detail + "\n"
			}
			if !strings.Contains(joined, tc.wantSub) {
				t.Errorf("findings %q missing %q", joined, tc.wantSub)
			}
		})
	}
}

// ---- end-to-end Guard() proofs -----------------------------------------------

// marshalCfg is a small test helper around the REAL product marshaller so
// fixture content is never hand-fabricated YAML.
func marshalCfg(t *testing.T, cfg config.Config) string {
	t.Helper()
	data, err := config.Marshal(cfg)
	if err != nil {
		t.Fatalf("config.Marshal: %v", err)
	}
	return string(data)
}

// TestGuard_RejectsLoopAuthoredBuiltinDisableAddition proves the full wiring:
// a proposal diff that adds a detector to detectors.builtin.disable in an
// EXISTING mallcop.yaml (the 'M' case) is rejected via Guard(), the same entry
// point ValidateProposal calls for every self-extension proposal.
func TestGuard_RejectsLoopAuthoredBuiltinDisableAddition(t *testing.T) {
	f := newFixture(t)
	f.write("mallcop.yaml", marshalCfg(t, config.Defaults()))
	base := f.commit("base: mallcop init")

	next := config.Defaults()
	next.Detectors.Builtin.Disable = []string{"priv_escalation"}
	f.write("mallcop.yaml", marshalCfg(t, next))
	head := f.commit("proposal: quiet a noisy built-in detector")

	requireRejected(t, f.guard(base, head), RuleBuiltinDisableOwnerOnly, "mallcop.yaml")
}

// TestGuard_RejectsBuiltinDisableSetOnBrandNewConfig proves the 'A' case: a
// proposal that ADDS mallcop.yaml (no prior file in the diff's base) with a
// non-empty disable list is rejected identically — "setting it for the first
// time" is still a write the loop may not make.
func TestGuard_RejectsBuiltinDisableSetOnBrandNewConfig(t *testing.T) {
	f := newFixture(t)
	f.write(".gitkeep", "")
	base := f.commit("base: empty repo, no config yet")

	cfg := config.Defaults()
	cfg.Detectors.Builtin.Disable = []string{"secret_exposure"}
	f.write("mallcop.yaml", marshalCfg(t, cfg))
	head := f.commit("proposal: add mallcop.yaml with a detector pre-disabled")

	requireRejected(t, f.guard(base, head), RuleBuiltinDisableOwnerOnly, "mallcop.yaml")
}

// TestGuard_AllowsMallcopYamlChangeThatLeavesDisableUntouched proves the rule
// is scoped to exactly the disable field (per cfg-8's directive: the loop can
// still propose ordinary config data widens — e.g. a new connector, or
// raising a budget — just never touch detectors.builtin.disable). This is the
// "owner edit is allowed" side: a change that never writes disable never
// trips RuleBuiltinDisableOwnerOnly.
func TestGuard_AllowsMallcopYamlChangeThatLeavesDisableUntouched(t *testing.T) {
	f := newFixture(t)
	f.write("mallcop.yaml", marshalCfg(t, config.Defaults()))
	base := f.commit("base: mallcop init")

	next := config.Defaults()
	next.Budgets.MaxFindings = 50 // unrelated widen; disable list untouched
	f.write("mallcop.yaml", marshalCfg(t, next))
	head := f.commit("owner: raise the findings budget")

	findings := f.guard(base, head)
	for _, finding := range findings {
		if finding.Rule == RuleBuiltinDisableOwnerOnly {
			t.Fatalf("unrelated config change tripped the disable-owner rule: %+v", finding)
		}
	}
}

// TestGuard_AllowsDeletingMallcopYaml proves the 'D' arm: deleting the config
// resets everything (including disable) to config.Defaults()'s empty list at
// load time, so it can never SET or WIDEN disable — this rule has nothing to
// reject for a deletion.
func TestGuard_AllowsDeletingMallcopYaml(t *testing.T) {
	f := newFixture(t)
	f.write("mallcop.yaml", marshalCfg(t, config.Defaults()))
	base := f.commit("base: mallcop init")

	f.remove("mallcop.yaml")
	head := f.commit("delete mallcop.yaml")

	findings := f.guard(base, head)
	for _, finding := range findings {
		if finding.Rule == RuleBuiltinDisableOwnerOnly {
			t.Fatalf("deletion tripped the disable-owner rule: %+v", finding)
		}
	}
}
