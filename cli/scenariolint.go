// scenariolint.go — `mallcop scenario lint`: validates the operator's own
// scenarios/ directory and nudges toward the BENIGN-TWIN authoring
// discipline.
//
// Two checks:
//
//  1. HARD (blocking): every scenarios/*.yaml file must parse via
//     internal/exam.Load — the IDENTICAL loader 'mallcop eval' feeds through
//     eval.LoadExtraScenarios (this command reuses that exact function, so a
//     scenario that lints clean is GUARANTEED to load cleanly for eval too).
//     A malformed scenario returns an error (non-zero exit) — an operator's
//     local corpus must not silently degrade to "one file quietly ignored".
//
//  2. SOFT (a WARNING, never a block): every LOCALLY-CAPTURED
//     (provenance: captured) must_fire family should have at least one
//     must_not_fire TWIN scenario somewhere in the directory. This
//     generalizes core/selfgate's L4c mandatory-twin gate
//     (benigntwins_test.go) from GATE time — where a missing twin blocks a
//     self-extension proposal from merging — to AUTHORING time, where it is
//     just a nudge while the operator is still building out their local
//     corpus. Blocking here would punish an operator for capturing a single
//     real attack before they've had a chance to also capture its benign
//     look-alike; 'mallcop eval' itself already treats every local scenario
//     as report-only (see cli/eval.go), and this command follows the same
//     philosophy.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/internal/exam"
)

// scenarioMissingTwin is one entry in the WARNING list: a captured must_fire
// family with no must_not_fire twin anywhere in the linted directory.
type scenarioMissingTwin struct {
	Family     string `json:"family"`
	ScenarioID string `json:"scenario_id"`
}

// scenarioLintReport is the --json wire shape.
type scenarioLintReport struct {
	Dir             string                `json:"dir"`
	ScenariosLinted int                   `json:"scenarios_linted"`
	MissingTwins    []scenarioMissingTwin `json:"missing_twins"`
}

// runScenarioLint implements `mallcop scenario lint`.
func runScenarioLint(args []string) error {
	fs := flag.NewFlagSet("scenario lint", flag.ContinueOnError)
	scenariosDir := fs.String("scenarios-dir", "", "Directory of scenario YAML files to lint (default: <repo-root>/scenarios, repo-root via eval.RepoRoot())")
	asJSON := fs.Bool("json", false, "Output the lint result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	dir := strings.TrimSpace(*scenariosDir)
	if dir == "" {
		root, err := eval.RepoRoot()
		if err != nil {
			return fmt.Errorf("scenario lint: resolving deploy repo root (for the default scenarios/ directory; pass --scenarios-dir to override): %w", err)
		}
		dir = filepath.Join(root, "scenarios")
	}

	if fi, statErr := os.Stat(dir); statErr != nil || !fi.IsDir() {
		// Mirrors cli/eval.go's default-dir handling: an absent scenarios/
		// directory (a brand-new deploy repo, nothing captured yet) is not an
		// error -- there is simply nothing to lint.
		if *asJSON {
			return encodeScenarioLintJSON(scenarioLintReport{Dir: dir})
		}
		fmt.Printf("scenario lint: %s does not exist yet -- nothing to lint (empty local corpus)\n", dir)
		return nil
	}

	scenarios, err := eval.LoadExtraScenarios(dir)
	if err != nil {
		return fmt.Errorf("scenario lint: %w", err)
	}

	missingTwins := findMissingBenignTwins(scenarios)

	if *asJSON {
		return encodeScenarioLintJSON(scenarioLintReport{
			Dir:             dir,
			ScenariosLinted: len(scenarios),
			MissingTwins:    missingTwins,
		})
	}

	fmt.Printf("Linted %d scenario(s) in %s -- all parsed via internal/exam.Load.\n", len(scenarios), dir)
	if len(missingTwins) == 0 {
		fmt.Println("Benign-twin discipline: every captured must_fire family has at least one must_not_fire twin.")
		return nil
	}
	fmt.Println("WARNING: missing benign twins (authoring-time nudge, not a block):")
	for _, m := range missingTwins {
		fmt.Printf("  - %-30s missing must_not_fire twin (captured by %s)\n", m.Family, m.ScenarioID)
		fmt.Printf("      recipe: capture the closest legitimate version of this activity --\n")
		fmt.Printf("              mallcop scenario capture --store <dir> --actor <benign-actor> --window <w> --must-not-fire %s\n", m.Family)
	}
	return nil
}

func encodeScenarioLintJSON(report scenarioLintReport) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// findMissingBenignTwins returns, for every LOCALLY-CAPTURED scenario's
// must_fire family with no must_not_fire twin ANYWHERE in scenarios (any
// provenance qualifies as a twin -- an operator-authored must_not_fire
// scenario for the same family satisfies a captured must_fire just as well as
// a captured one would), one entry naming the family and the first captured
// scenario that asserted it. Each distinct family is reported at most once,
// in deterministic family-sorted order.
func findMissingBenignTwins(scenarios []eval.LoadedScenario) []scenarioMissingTwin {
	haveTwin := map[string]bool{}
	for _, ls := range scenarios {
		s := ls.Scenario
		if s.ExpectedDetection == nil {
			continue
		}
		for _, f := range s.ExpectedDetection.MustNotFire {
			haveTwin[normalizeLintFamily(f)] = true
		}
	}

	reported := map[string]bool{}
	var out []scenarioMissingTwin
	for _, ls := range scenarios {
		s := ls.Scenario
		if s.EffectiveProvenance() != exam.ProvenanceCaptured {
			continue
		}
		if s.ExpectedDetection == nil {
			continue
		}
		for _, f := range s.ExpectedDetection.MustFire {
			fam := normalizeLintFamily(f)
			if fam == "" || haveTwin[fam] || reported[fam] {
				continue
			}
			reported[fam] = true
			out = append(out, scenarioMissingTwin{Family: fam, ScenarioID: s.ID})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Family < out[j].Family })
	return out
}

// normalizeLintFamily mirrors core/eval/examdetect.go's unexported
// normalizeFamilyToken (lowercase, trimmed) -- duplicated here for the same
// no-cross-package-reach reason cli/investigate.go's loadPersistedBaseline
// doc explains.
func normalizeLintFamily(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
