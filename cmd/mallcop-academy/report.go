// report.go — aggregate report writer for mallcop-academy.
//
// After all scenarios complete, writeAggregateReport produces
// docs/academy/<run-id>/report.md with:
//
//   - Per-failure-mode tag pass rate (KA/AE/CS/NE/VN/TT etc, parsed from
//     scenario tags).
//   - Category pass rate (access/auth/behavioral/...).
//   - Top failure modes by structural axis (e.g. "reasoning_must_mention
//     failed on 7 KA scenarios").
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/thirdiv/mallcop-legion/internal/exam"
)

// scenarioPassResult summarises one scenario's pass/fail status for the
// aggregate report.
type scenarioPassResult struct {
	ScenarioID   string
	FailureMode  string           // from scenario.FailureMode (KA, AE, CS, etc.)
	Category     string           // from scenario.Category (access, auth, behavioral, ...)
	Tags         []string         // from scenario.Tags
	TerminalPass bool             // chain_action == pass
	Structural   *StructuralGrade // nil if no expected: block
	RubricScore  int              // investigation_thoroughness, 0 if unavailable
}

// axisFailureCount counts how many scenarios failed a given structural axis.
type axisFailureCount struct {
	Axis     string
	Count    int
	Examples []string // up to 3 scenario IDs
}

// tagPassRate holds pass-rate stats for a tag bucket (failure mode or category).
type tagPassRate struct {
	Tag   string
	Total int
	Pass  int
	Rate  float64
}

// aggregateReportData is passed to the report template.
type aggregateReportData struct {
	RunID       string
	GeneratedAt string
	Total       int
	Passed      int
	Failed      int
	PassRate    float64

	ByFailureMode []tagPassRate
	ByCategory    []tagPassRate
	TopAxisFails  []axisFailureCount
}

const reportTemplate = `# Academy Run Report: {{.RunID}}

Generated: {{.GeneratedAt}}

## Overall

| Metric | Value |
|--------|-------|
| Total scenarios | {{.Total}} |
| Passed | {{.Passed}} |
| Failed | {{.Failed}} |
| Pass rate | {{printf "%.1f" .PassRate}}% |

## Pass Rate by Failure Mode

| Failure Mode | Pass/Total | Rate |
|---|---|---|
{{- range .ByFailureMode}}
| {{.Tag}} | {{.Pass}}/{{.Total}} | {{printf "%.1f" .Rate}}% |
{{- end}}

## Pass Rate by Category

| Category | Pass/Total | Rate |
|---|---|---|
{{- range .ByCategory}}
| {{.Tag}} | {{.Pass}}/{{.Total}} | {{printf "%.1f" .Rate}}% |
{{- end}}

## Top Structural Axis Failures

{{- if .TopAxisFails}}
| Axis | Failures | Example Scenarios |
|---|---|---|
{{- range .TopAxisFails}}
| {{.Axis}} | {{.Count}} | {{joinStrings .Examples}} |
{{- end}}
{{- else}}
No structural axis failures recorded.
{{- end}}
`

// writeAggregateReport produces report.md in outputDir based on all scenario
// records.
func writeAggregateReport(runID, outputDir string, scenarios []*exam.Scenario, tracked map[string]*trackedScenario) error {
	results := buildResults(scenarios, tracked)

	data := aggregateReportData{
		RunID:       runID,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Overall pass rate: chain_action == pass counts as passed.
	for _, r := range results {
		data.Total++
		if r.TerminalPass {
			data.Passed++
		} else {
			data.Failed++
		}
	}
	if data.Total > 0 {
		data.PassRate = float64(data.Passed) / float64(data.Total) * 100.0
	}

	// By failure mode.
	data.ByFailureMode = computeTagRates(results, func(r scenarioPassResult) string {
		return r.FailureMode
	})

	// By category.
	data.ByCategory = computeTagRates(results, func(r scenarioPassResult) string {
		return r.Category
	})

	// Top axis failures.
	data.TopAxisFails = computeAxisFails(results)

	// Render template.
	funcMap := template.FuncMap{
		"joinStrings": func(ss []string) string { return strings.Join(ss, ", ") },
		"printf":      fmt.Sprintf,
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("parse report template: %w", err)
	}

	f, err := os.Create(filepath.Join(outputDir, "report.md"))
	if err != nil {
		return fmt.Errorf("create report.md: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

// buildResults converts tracked scenarios into scenarioPassResult list.
func buildResults(scenarios []*exam.Scenario, tracked map[string]*trackedScenario) []scenarioPassResult {
	results := make([]scenarioPassResult, 0, len(scenarios))
	for _, s := range scenarios {
		ts, ok := tracked[s.ID]
		if !ok {
			continue
		}
		ts.mu.Lock()

		// Compute structural grade using same logic as writeScenarioRecord.
		var sg *StructuralGrade
		if s.ExpectedResolution != nil {
			rubricScore := 0
			judgeRan := false
			if ts.judgeResult != nil {
				judgeRan = true
				rubricScore = ts.judgeResult.Rubric.InvestigationThoroughness
			}
			grade := computeStructuralGrade(
				s.ExpectedResolution,
				ts.terminalAction,
				ts.terminalReason,
				ts.triageCloseAction,
				ts.toolsUsedInInvest,
				ts.maxInvestIterations,
				rubricScore,
				judgeRan,
			)
			sg = &grade
		}

		terminalPass := sg != nil && sg.ChainAction == AxisPass

		r := scenarioPassResult{
			ScenarioID:   s.ID,
			FailureMode:  s.FailureMode,
			Category:     s.Category,
			Tags:         s.Tags,
			TerminalPass: terminalPass,
			Structural:   sg,
		}
		if ts.judgeResult != nil {
			r.RubricScore = ts.judgeResult.Rubric.InvestigationThoroughness
		}
		ts.mu.Unlock()
		results = append(results, r)
	}
	return results
}

// computeTagRates groups results by tag (using tagFn) and computes pass rates.
func computeTagRates(results []scenarioPassResult, tagFn func(scenarioPassResult) string) []tagPassRate {
	byTag := make(map[string]*tagPassRate)
	for _, r := range results {
		tag := tagFn(r)
		if tag == "" {
			tag = "unknown"
		}
		if _, ok := byTag[tag]; !ok {
			byTag[tag] = &tagPassRate{Tag: tag}
		}
		byTag[tag].Total++
		if r.TerminalPass {
			byTag[tag].Pass++
		}
	}
	out := make([]tagPassRate, 0, len(byTag))
	for _, pr := range byTag {
		if pr.Total > 0 {
			pr.Rate = float64(pr.Pass) / float64(pr.Total) * 100.0
		}
		out = append(out, *pr)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Total != out[j].Total {
			return out[i].Total > out[j].Total
		}
		return out[i].Tag < out[j].Tag
	})
	return out
}

// computeAxisFails builds the list of structural axes that failed, sorted by
// failure count descending, with up to 3 example scenario IDs.
func computeAxisFails(results []scenarioPassResult) []axisFailureCount {
	type axisEntry struct {
		count    int
		examples []string
	}
	axes := map[string]*axisEntry{
		"chain_action":  {},
		"triage_action": {},
		"mentions":      {},
		"no_mentions":   {},
		"tools_used":    {},
		"iterations":    {},
		"quality_floor": {},
	}
	for _, r := range results {
		if r.Structural == nil {
			continue
		}
		check := func(name, val string) {
			if val == AxisFail {
				ac := axes[name]
				ac.count++
				if len(ac.examples) < 3 {
					ac.examples = append(ac.examples, r.ScenarioID)
				}
			}
		}
		check("chain_action", r.Structural.ChainAction)
		check("triage_action", r.Structural.TriageAction)
		check("mentions", r.Structural.Mentions)
		check("no_mentions", r.Structural.NoMentions)
		check("tools_used", r.Structural.ToolsUsed)
		check("iterations", r.Structural.Iterations)
		check("quality_floor", r.Structural.QualityFloor)
	}

	out := make([]axisFailureCount, 0, len(axes))
	for name, ac := range axes {
		if ac.count > 0 {
			out = append(out, axisFailureCount{
				Axis:     name,
				Count:    ac.count,
				Examples: ac.examples,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Count > out[j].Count
	})
	return out
}
