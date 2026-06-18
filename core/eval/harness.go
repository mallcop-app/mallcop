// harness.go — the end-to-end eval driver: load (SHA+count gate) → run the corpus
// N times → grade deterministically → report MEDIAN chain_action pass-rate with
// the §4.6 8pp noise band → classify failures (§4.8). MEDIAN-OF-N is mandatory:
// "single-run results lie" (§4.6) — a single run can swing ±10 pp on identical
// code, so the harness NEVER gates on one run.
package eval

import (
	"context"
	"fmt"
	"sort"

	"github.com/mallcop-app/mallcop/core/agent"
)

// RunConfig configures one harness invocation.
type RunConfig struct {
	// Mode selects the backend: ModeCanned (merge-gate, golden responses) or
	// ModeReal (parity, live model). ModeReal requires creds (RealClientFromEnv).
	Mode Mode
	// N is the number of full-corpus passes for the median (§4.6). Default 3 when
	// <= 0 — single-run gating is forbidden.
	N int
	// Opts carries per-tier model ids + the (optional) live ToolRunner. The
	// merge-gate runs with a nil ToolRunner (golden responses need no live tools).
	Opts agent.CascadeOptions
	// RealClient is the live client for ModeReal. Ignored in ModeCanned (a fresh
	// golden cannedbackend is started per scenario). Must be non-nil for ModeReal.
	RealClient agent.Client
}

// RunResult is one full corpus pass: the graded per-scenario results + the
// chain_action pass-rate for the pass.
type RunResult struct {
	Index    int              `json:"index"`
	Results  []ScenarioResult `json:"results"`
	Passed   int              `json:"passed"`
	Total    int              `json:"total"`
	PassRate float64          `json:"pass_rate"`
	// Transcripts maps scenario id → the full captured transcript for this pass
	// (§4.7). Carried on the run so artifacts derive from a single source.
	Transcripts map[string][]TranscriptEntry `json:"-"`
}

// HarnessReport is the harness's full output: the corpus integrity facts, every
// run, the MEDIAN pass-rate + noise band, and the classifier summary.
type HarnessReport struct {
	Mode           Mode              `json:"mode"`
	CorpusCount    int               `json:"corpus_count"`
	CorpusSHA      string            `json:"corpus_sha256"`
	Runs           []RunResult       `json:"runs"`
	MedianPassRate float64           `json:"median_pass_rate"`
	NoiseBandPP    float64           `json:"noise_band_pp"`
	WithinBand     bool              `json:"runs_within_band"`
	Classifier     ClassifierSummary `json:"classifier"`
	// Note states, in the report itself, what the number means — so a reader can
	// never mistake the merge-gate's 100% for the accuracy number (§4.4).
	Note string `json:"note"`
}

// noiseBandPP is the §4.6 band: treat any single-run delta < 8 pp as noise.
const noiseBandPP = 8.0

// Run executes the harness: load → N passes → grade → median → classify.
//
// The corpus integrity gate (count + SHA) runs FIRST via Load. A tampered or
// drifted corpus HARD-FAILS here and NOTHING runs (the eval interlock).
func Run(ctx context.Context, cfg RunConfig) (HarnessReport, error) {
	root, err := RepoRoot()
	if err != nil {
		return HarnessReport{}, err
	}
	corpus, err := Load(root) // count + SHA interlock
	if err != nil {
		return HarnessReport{}, err
	}

	n := cfg.N
	if n <= 0 {
		n = 3 // median-of-N default; single-run gating forbidden (§4.6)
	}

	report := HarnessReport{
		Mode:        cfg.Mode,
		CorpusCount: corpus.Count,
		CorpusSHA:   corpus.SHA,
		NoiseBandPP: noiseBandPP,
	}
	switch cfg.Mode {
	case ModeCanned:
		report.Note = "MERGE-GATE (golden responses): proves the harness+grader pipeline, NOT the model's accuracy. The real accuracy number comes only from ModeReal."
	case ModeReal:
		report.Note = "REAL-MODEL parity run: this IS the accuracy number (the model decided each verdict)."
	}

	var passRates []float64
	for i := 0; i < n; i++ {
		rr, err := runOnce(ctx, cfg, corpus, i)
		if err != nil {
			return HarnessReport{}, err
		}
		report.Runs = append(report.Runs, rr)
		passRates = append(passRates, rr.PassRate)
	}

	report.MedianPassRate = median(passRates)
	report.WithinBand = spread(passRates) <= noiseBandPP/100.0
	report.Classifier = Classify(report.Runs)
	return report, nil
}

// runOnce runs the full corpus once and grades it.
func runOnce(ctx context.Context, cfg RunConfig, corpus Corpus, index int) (RunResult, error) {
	results := make([]ScenarioResult, 0, corpus.Count)
	transcripts := make(map[string][]TranscriptEntry, corpus.Count)
	passed := 0

	for _, ls := range corpus.Scenarios {
		var client agent.Client
		var stop func()

		switch cfg.Mode {
		case ModeCanned:
			c, s, err := newCannedClient(ls.Scenario)
			if err != nil {
				return RunResult{}, err
			}
			client, stop = c, s
		case ModeReal:
			if cfg.RealClient == nil {
				return RunResult{}, fmt.Errorf("ModeReal requires a non-nil RealClient (RealClientFromEnv); refusing to run")
			}
			client, stop = cfg.RealClient, func() {}
		default:
			return RunResult{}, fmt.Errorf("unknown mode %q", cfg.Mode)
		}

		// ModeReal wires the per-scenario live ToolRunner (real core/tools over the
		// scenario's events+baseline) so the agent actually investigates. ModeCanned
		// (merge-gate) runs tool-free: golden responses prove the grader pipeline,
		// not tool use, and the live ToolEmpty fail-safe would distort that.
		run := RunScenario(ctx, client, ls, cfg.Opts, cfg.Mode == ModeReal)
		stop()

		res := Grade(run)
		if res.Pass {
			passed++
		}
		results = append(results, res)
		transcripts[res.ScenarioID] = run.Transcript
	}

	rr := RunResult{
		Index:       index,
		Results:     results,
		Passed:      passed,
		Total:       len(results),
		PassRate:    rate(passed, len(results)),
		Transcripts: transcripts,
	}
	return rr, nil
}

func rate(passed, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(passed) / float64(total)
}

// median returns the median of xs (sorted copy; mean of the two middles for even
// n). Median, NOT max — the headline "100%" is best-of-N; the median is honest
// (§4.6).
func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := make([]float64, len(xs))
	copy(s, xs)
	sort.Float64s(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}

// spread is max−min of xs: the observed run-to-run swing, compared to the band.
func spread(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	mn, mx := xs[0], xs[0]
	for _, x := range xs {
		if x < mn {
			mn = x
		}
		if x > mx {
			mx = x
		}
	}
	return mx - mn
}
