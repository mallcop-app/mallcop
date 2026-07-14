// Command mallcop-eval runs the portable eval harness over the SHA-pinned
// scenario corpus and prints the report as JSON.
//
//	mallcop-eval -mode canned          # creds-free merge-gate (golden responses)
//	mallcop-eval -mode real -n 3       # parity run vs a live model (needs creds)
//	mallcop-eval -mode e2e  -n 3       # END-TO-END: raw events → core/detect → cascade
//
// ModeReal AND ModeE2E read MALLCOP_INFERENCE_URL + MALLCOP_API_KEY (see core/eval
// RealClientFromEnv). The per-tier lane defaults (triage glm-4.7-flash,
// investigate/deep glm-5) come from the cascade; no model flag is needed.
//
// -mode e2e drives the SAME pipeline.Run `mallcop scan` calls, so the scenario's
// raw events flow through the PROD detector fleet. Its headline output is the
// detect_fidelity block (reproduction_rate + end_to_end_pass_rate) — the honest
// "does live scan get the right answer from raw events" number.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mallcop-app/mallcop/core/eval"
)

func main() {
	mode := flag.String("mode", "canned", "canned | real | e2e")
	n := flag.Int("n", 3, "number of full-corpus passes for the median")
	// consensus selects the number of ADDITIONAL committee re-runs the consensus
	// gate makes on every RESOLVE (default 3). 0 turns the gate OFF: the harness
	// coerces a literal 0 to 3 (the median-of-N default), so passing 0 here maps to
	// ConsensusRuns = -1, which the harness leaves untouched and the cascade treats
	// as "gate disabled" (it gates only on ConsensusRuns > 0). This is the lever the
	// validation bakeoff uses to measure the cascade WITHOUT the consensus gate.
	consensus := flag.Int("consensus", 3, "additional consensus re-runs per resolve (0 = gate OFF)")
	// consensusTemp overrides the sampling temperature forced on every consensus
	// re-run (agent.consensusTemperature, built-in default 1.0 — see consensus.go).
	// 0 (the flag default) leaves the built-in default untouched: CascadeOptions
	// .ConsensusTemperature == 0 is the "unset" sentinel the gate coerces to 1.0
	// (consensus.go: "if reRunOpts.ConsensusTemperature == 0"). This is a TUNING
	// KNOB for the mallcoppro-9dd detection-coverage loop: 1.0 is high-variance
	// sampling, which can inject a spurious dissenting vote (pure sampling noise,
	// not a genuine second opinion) into an otherwise-unanimous benign resolve and
	// flip it to escalate via any-escalate-wins. Lowering the temperature narrows
	// that noise band while keeping the re-runs non-deterministic (STOCHASTICITY IS
	// MANDATORY per consensus.go — pass a value in (0, 1.0], never 0, or the gate
	// silently reverts to the built-in 1.0 default).
	consensusTemp := flag.Float64("consensus-temp", 0, "override the consensus re-run sampling temperature (0 = built-in default 1.0; must be >0 if set)")
	dumpTranscripts := flag.String("dump-transcripts", "", "directory to write per-scenario transcripts of run 0 (<sid>.txt)")
	flag.Parse()

	cfg := eval.RunConfig{N: *n}
	// Map the consensus flag onto Opts.ConsensusRuns. A literal 0 must become -1 so
	// the harness's 0->3 coercion does not silently re-enable the gate.
	if *consensus == 0 {
		cfg.Opts.ConsensusRuns = -1
	} else {
		cfg.Opts.ConsensusRuns = *consensus
	}
	if *consensusTemp != 0 {
		cfg.Opts.ConsensusTemperature = *consensusTemp
	}
	switch *mode {
	case "canned":
		cfg.Mode = eval.ModeCanned
	case "real":
		cfg.Mode = eval.ModeReal
		client, err := eval.RealClientFromEnv()
		if err != nil {
			fmt.Fprintf(os.Stderr, "mallcop-eval: %v\n", err)
			os.Exit(2)
		}
		cfg.RealClient = client
	case "e2e":
		cfg.Mode = eval.ModeE2E
		client, err := eval.RealClientFromEnv()
		if err != nil {
			fmt.Fprintf(os.Stderr, "mallcop-eval: %v\n", err)
			os.Exit(2)
		}
		cfg.RealClient = client
	default:
		fmt.Fprintf(os.Stderr, "mallcop-eval: unknown -mode %q (want canned|real|e2e)\n", *mode)
		os.Exit(2)
	}

	report, err := eval.Run(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mallcop-eval: %v\n", err)
		os.Exit(1)
	}

	if *dumpTranscripts != "" {
		if err := dumpRun0Transcripts(*dumpTranscripts, report); err != nil {
			fmt.Fprintf(os.Stderr, "mallcop-eval: dump transcripts: %v\n", err)
			os.Exit(1)
		}
	}

	// Print the recall/precision split ABOVE the blended report JSON that follows
	// (report.MedianPassRate mixes attacks and benigns into one number — see
	// harness.go's Note). Named, honest counts before the blended headline, the
	// same discipline #180 established for exam-detect's --recall view.
	printRecallPrecisionSummary(report)

	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mallcop-eval: marshal report: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}

// printRecallPrecisionSummary prints the recall-first split (mallcoppro C2) —
// named ATTACKS MISSED / BENIGN FALSE-ALARMS counts, median-of-N — mirroring the
// recall-first report #180 added to exam-detect, applied here to the harness's
// agent-reasoning ScenarioResult.Pass instead of exam-detect's must_fire/
// must_not_fire labels. Reads only the already-graded per-run Attacks/
// AttacksPassed/Benigns/BenignsPassed fields Run() partitioned — it re-runs no
// scenario and changes no grading. No-op when the report has no runs (e.g. a
// ModeReal refusal error path never reaches here, but defensive all the same).
func printRecallPrecisionSummary(report eval.HarnessReport) {
	if len(report.Runs) == 0 {
		return
	}
	attacksTotal := report.Runs[0].Attacks
	benignsTotal := report.Runs[0].Benigns
	missed := make([]int, len(report.Runs))
	falseAlarms := make([]int, len(report.Runs))
	for i, rr := range report.Runs {
		missed[i] = rr.Attacks - rr.AttacksPassed
		falseAlarms[i] = rr.Benigns - rr.BenignsPassed
	}
	fmt.Printf("ATTACKS MISSED (median):      %d of %d  (recall %.1f%%)\n",
		medianInt(missed), attacksTotal, report.MedianRecallRate*100)
	fmt.Printf("BENIGN FALSE-ALARMS (median): %d of %d  (precision %.1f%%)\n",
		medianInt(falseAlarms), benignsTotal, report.MedianPrecisionRate*100)
	if report.DetectFidelity != nil {
		fmt.Printf("e2e recall (live scan, all attacks):    %.1f%%\n", report.DetectFidelity.E2ERecall*100)
		fmt.Printf("e2e precision (live scan, all benigns):  %.1f%%\n", report.DetectFidelity.E2EPrecision*100)
	}
	fmt.Printf("(blended median_pass_rate: %.1f%% — see report.note)\n", report.MedianPassRate*100)
}

// medianInt returns the median of xs (sorted copy; rounded average of the two
// middles for even n — a count must be an integer). Mirrors eval.median's
// median-of-N discipline (§4.6: single-run counts are noise) for integer counts.
func medianInt(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	s := make([]int, len(xs))
	copy(s, xs)
	sort.Ints(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return int(math.Round(float64(s[mid-1]+s[mid]) / 2))
}

// dumpRun0Transcripts renders run 0's per-scenario transcripts to dir/<sid>.txt.
// Each file lists every TranscriptEntry (one model exchange) with its Seq, Model,
// advertised Tools, System prompt, boxed UserPrompt, model Reply, and any Err — the
// human-readable §4.7 audit the validation bakeoff reads to see what the model saw.
func dumpRun0Transcripts(dir string, report eval.HarnessReport) error {
	if len(report.Runs) == 0 {
		return fmt.Errorf("report has no runs")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	for sid, tr := range report.Runs[0].Transcripts {
		var b strings.Builder
		fmt.Fprintf(&b, "scenario: %s\n", sid)
		for _, e := range tr {
			b.WriteString(strings.Repeat("=", 72) + "\n")
			fmt.Fprintf(&b, "seq:    %d\n", e.Seq)
			fmt.Fprintf(&b, "model:  %s\n", e.Model)
			fmt.Fprintf(&b, "tools:  %s\n", strings.Join(e.Tools, ", "))
			fmt.Fprintf(&b, "--- system ---\n%s\n", e.System)
			fmt.Fprintf(&b, "--- user_prompt ---\n%s\n", e.UserPrompt)
			fmt.Fprintf(&b, "--- reply ---\n%s\n", e.Reply)
			if e.Err != "" {
				fmt.Fprintf(&b, "--- err ---\n%s\n", e.Err)
			}
		}
		path := filepath.Join(dir, sid+".txt")
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}
