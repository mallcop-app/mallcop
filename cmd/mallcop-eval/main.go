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
	"os"
	"path/filepath"
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

	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mallcop-eval: marshal report: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
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
