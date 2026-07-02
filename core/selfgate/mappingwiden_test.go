package selfgate

import (
	"strings"
	"testing"
)

// TestCheckMappingWidenOnly exercises the learned_mappings.yaml widen checker
// directly (the real checker, no git needed): additive changes pass; removals,
// retargets, and unparseable documents are rejected.
func TestCheckMappingWidenOnly(t *testing.T) {
	base := []byte(`
github:
  repo.rename: config_change
  repo.transfer: config_change
`)

	tests := []struct {
		name    string
		head    string
		wantOK  bool
		wantSub string
	}{
		{
			name: "identical passes",
			head: `
github:
  repo.rename: config_change
  repo.transfer: config_change
`,
			wantOK: true,
		},
		{
			name: "new action key is a widen",
			head: `
github:
  repo.rename: config_change
  repo.transfer: config_change
  repo.archive: config_change
`,
			wantOK: true,
		},
		{
			name: "new source is a widen",
			head: `
github:
  repo.rename: config_change
  repo.transfer: config_change
gitlab:
  project.rename: config_change
`,
			wantOK: true,
		},
		{
			name: "removed action rejected",
			head: `
github:
  repo.rename: config_change
`,
			wantOK:  false,
			wantSub: "removed",
		},
		{
			name: "retargeted action rejected",
			head: `
github:
  repo.rename: role_assignment
  repo.transfer: config_change
`,
			wantOK:  false,
			wantSub: "retargeted",
		},
		{
			name: "removed source rejected",
			head: `
gitlab:
  project.rename: config_change
`,
			wantOK:  false,
			wantSub: "removed",
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
			findings := checkMappingWidenOnly("detectors/learned_mappings.yaml", base, []byte(tc.head))
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
				if f.Rule != RuleDetectorDataWidenOnly {
					t.Errorf("finding rule = %q, want %q", f.Rule, RuleDetectorDataWidenOnly)
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
