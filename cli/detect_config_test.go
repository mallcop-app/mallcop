package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/mallcop-app/mallcop/core/detect"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// syntheticTuning is the widen-only knob that closes the SYNTHETIC gap-close
// demo (exams/synthetic/): it ADDS "mallcopsyntheticelevated" to the
// priv-escalation elevated-keyword set so the MallcopSyntheticElevatedRole grant
// reads as an escalation. Using the synthetic pair instead of PE-08/poweruser
// decouples these tests from every REAL corpus scenario, so PE-08 / IP-01 / etc.
// are free to be fixed (rd mallcoppro-a07 / S1). core/detect/synthdemo_invariant_test.go
// guarantees the keyword can never become a built-in.
const syntheticTuning = "priv_escalation:\n  extra_elevated_keywords:\n    - mallcopsyntheticelevated\n"

// syntheticElevatedEvent is a MallcopSyntheticElevatedRole grant on the stdin
// (pkg/event) wire shape. priv-escalation fires on it ONLY once the synthetic
// keyword is applied — the role carries none of the built-in elevation
// vocabulary (admin/owner/write/...), so it is the ideal probe for "was the
// tuning applied".
const syntheticElevatedEvent = `{"id":"se1","source":"synthetic","type":"role_assignment","actor":"synth-actor","payload":{"role_name":"MallcopSyntheticElevatedRole","target_user":"svc-synth"}}` + "\n"

// synthMustFireID is the synthetic must-fire scenario id (SYNTH-PE-01).
const synthMustFireID = "SYNTH-PE-01-elevated-must-fire"

// cliRecomputeCorpusPin replicates core/eval/corpus.go's canonical manifest
// digest (one "<relpath><two-spaces><sha256(file)>\n" line per included
// scenario, sorted; leading-underscore paths excluded), the same replication the
// core/selfgate tests anchor against the committed pin.
func cliRecomputeCorpusPin(t *testing.T, root string) (int, string) {
	t.Helper()
	scenRoot := filepath.Join(root, "exams", "scenarios")
	type entry struct{ rel, fileSHA string }
	var entries []entry
	err := filepath.WalkDir(scenRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(scenRoot, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		for _, part := range strings.Split(rel, "/") {
			if strings.HasPrefix(part, "_") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() || (!strings.HasSuffix(d.Name(), ".yaml") && !strings.HasSuffix(d.Name(), ".yml")) {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(data)
		entries = append(entries, entry{rel: rel, fileSHA: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		t.Fatalf("recompute corpus pin: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	var manifest strings.Builder
	for _, e := range entries {
		manifest.WriteString(e.rel)
		manifest.WriteString("  ")
		manifest.WriteString(e.fileSHA)
		manifest.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(manifest.String()))
	return len(entries), hex.EncodeToString(sum[:])
}

// injectSyntheticCorpus builds a throwaway repo root whose pinned corpus is a
// copy of the real one PLUS the synthetic gap-close pair (exams/synthetic/)
// injected under exams/scenarios/synthetic/, with corpus.pin regenerated so the
// injected corpus verifies. Returns the temp root (usable as MALLCOP_REPO_ROOT).
func injectSyntheticCorpus(t *testing.T) string {
	t.Helper()
	src := cliRepoUnderTest(t)
	root := t.TempDir()
	srcScen := filepath.Join(src, "exams", "scenarios")
	dstScen := filepath.Join(root, "exams", "scenarios")
	if err := filepath.WalkDir(srcScen, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(srcScen, path)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dstScen, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(target, data, 0o644)
	}); err != nil {
		t.Fatalf("copy corpus: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dstScen, "synthetic"), 0o755); err != nil {
		t.Fatalf("mkdir synthetic: %v", err)
	}
	for _, name := range []string{"SYNTH-PE-01-elevated-must-fire.yaml", "SYNTH-PE-02-baseline-benign-twin.yaml"} {
		data, err := os.ReadFile(filepath.Join(src, "exams", "synthetic", name))
		if err != nil {
			t.Fatalf("read synthetic fixture %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dstScen, "synthetic", name), data, 0o644); err != nil {
			t.Fatalf("inject %s: %v", name, err)
		}
	}
	count, sha := cliRecomputeCorpusPin(t, root)
	if err := os.WriteFile(filepath.Join(dstScen, "corpus.pin"),
		[]byte(fmt.Sprintf("# fixture pin (synthetic gap-close injection)\ncount %d\nsha256 %s\n", count, sha)), 0o644); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	return root
}

// detectFiredPrivEscalation reports whether the detect JSONL output contains a
// priv-escalation finding.
func detectFiredPrivEscalation(t *testing.T, out string) bool {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var f finding.Finding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("detect output line is not a valid Finding: %v\nline: %s", err, line)
		}
		if f.Type == "priv-escalation" {
			return true
		}
	}
	return false
}

// writeConfig writes a mallcop.yaml with the given body under dir and returns
// its path.
func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "mallcop.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// TestRunDetect_AppliesConfigTuningNoFlag is the core cfg-7 proof: with a
// mallcop.yaml declaring learning.dir and a tuning.yaml under it, `mallcop
// detect < events.jsonl` applies the widen-only tuning with NO --tuning flag —
// the deferred tuning auto-discovery is now resolved by explicit config. The
// stdin events contract is exercised end-to-end (events read from stdin only).
func TestRunDetect_AppliesConfigTuningNoFlag(t *testing.T) {
	tmp := t.TempDir()
	ldir := filepath.Join(tmp, "detectors")
	if err := os.MkdirAll(ldir, 0o755); err != nil {
		t.Fatalf("mkdir learning dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ldir, "tuning.yaml"), []byte(syntheticTuning), 0o644); err != nil {
		t.Fatalf("write tuning: %v", err)
	}
	cfgPath := writeConfig(t, tmp, "version: 1\nlearning:\n  dir: detectors\n")
	t.Setenv("MALLCOP_CONFIG", cfgPath)
	t.Setenv("MALLCOP_DECL_RULES", "")

	out, err := withStdio(t, syntheticElevatedEvent, func() error { return runDetect(nil) })
	if err != nil && !isFindingsError(err) {
		t.Fatalf("unexpected detect error: %v\nout:\n%s", err, out)
	}
	if !detectFiredPrivEscalation(t, out) {
		t.Fatalf("priv-escalation did NOT fire from config-declared tuning (no --tuning flag)\nout:\n%s", out)
	}
}

// TestRunDetect_TuningFlagOverridesConfig proves the flag still wins over the
// config: the config's learning.dir has NO tuning.yaml, yet an explicit --tuning
// file is honored.
func TestRunDetect_TuningFlagOverridesConfig(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "empty"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfgPath := writeConfig(t, tmp, "version: 1\nlearning:\n  dir: empty\n")
	t.Setenv("MALLCOP_CONFIG", cfgPath)
	t.Setenv("MALLCOP_DECL_RULES", "")

	flagTuning := filepath.Join(tmp, "flag-tuning.yaml")
	if err := os.WriteFile(flagTuning, []byte(syntheticTuning), 0o644); err != nil {
		t.Fatalf("write flag tuning: %v", err)
	}

	out, err := withStdio(t, syntheticElevatedEvent, func() error {
		return runDetect([]string{"--tuning", flagTuning})
	})
	if err != nil && !isFindingsError(err) {
		t.Fatalf("unexpected detect error: %v\nout:\n%s", err, out)
	}
	if !detectFiredPrivEscalation(t, out) {
		t.Fatalf("--tuning flag was not applied (config learning.dir had no tuning.yaml)\nout:\n%s", out)
	}
}

// TestResolveTuningPath_Precedence covers flag > config > default(none) purely,
// with no global detector-state mutation. The "absent config → no tuning"
// branch is the invariant that keeps existing flag-only usage unchanged.
func TestResolveTuningPath_Precedence(t *testing.T) {
	// Flag wins — no config is even consulted.
	if got, err := resolveTuningPath("/explicit/tuning.yaml"); err != nil || got != "/explicit/tuning.yaml" {
		t.Fatalf("flag should win: got %q err %v", got, err)
	}

	// Absent config → "" (no auto-discovery; today's flag-only behavior).
	t.Chdir(t.TempDir())
	t.Setenv("MALLCOP_CONFIG", "")
	if got, err := resolveTuningPath(""); err != nil || got != "" {
		t.Fatalf("absent config should yield no tuning: got %q err %v", got, err)
	}

	// Config present → learning.dir/tuning.yaml, resolved against the config dir.
	tmp := t.TempDir()
	cfgPath := writeConfig(t, tmp, "version: 1\nlearning:\n  dir: mydir\n")
	t.Setenv("MALLCOP_CONFIG", cfgPath)
	want := filepath.Join(tmp, "mydir", "tuning.yaml")
	if got, err := resolveTuningPath(""); err != nil || got != want {
		t.Fatalf("config tuning path: got %q want %q err %v", got, want, err)
	}
}

// TestResolveBaselinePath_Precedence covers flag > config store.baseline >
// default(empty).
func TestResolveBaselinePath_Precedence(t *testing.T) {
	if got, err := resolveBaselinePath("/flag/baseline.json"); err != nil || got != "/flag/baseline.json" {
		t.Fatalf("flag should win: got %q err %v", got, err)
	}

	t.Chdir(t.TempDir())
	t.Setenv("MALLCOP_CONFIG", "")
	if got, err := resolveBaselinePath(""); err != nil || got != "" {
		t.Fatalf("absent config should yield empty baseline: got %q err %v", got, err)
	}

	tmp := t.TempDir()
	cfgPath := writeConfig(t, tmp, "version: 1\nstore:\n  baseline: base.json\n")
	t.Setenv("MALLCOP_CONFIG", cfgPath)
	want := filepath.Join(tmp, "base.json")
	if got, err := resolveBaselinePath(""); err != nil || got != want {
		t.Fatalf("config baseline path: got %q want %q err %v", got, want, err)
	}
}

// TestRunExamDetect_ConfigTuningClosesPE proves exam-detect GREEN on the
// SYNTHETIC gap using config-only tuning (no --tuning flag): a discovered
// mallcop.yaml whose learning.dir carries the synthetic knob flips the labeled
// SYNTH-PE-01 gap RED->GREEN in the REAL grader — the same mechanism that lets
// the self-extension loop's tuning proposal grade through the exam-detect stage,
// driven by config instead of the flag, and decoupled from every real scenario.
func TestRunExamDetect_ConfigTuningClosesPE(t *testing.T) {
	// This test publishes a priv-escalation widening into process-global detector
	// state; restore the pristine snapshot afterward so it cannot leak into a
	// sibling test that asserts an untuned grade (e.g. the free-tier default proof).
	t.Cleanup(detect.ResetTuning)
	root := injectSyntheticCorpus(t)
	t.Setenv("MALLCOP_REPO_ROOT", root)

	// A learning dir holding ONLY the synthetic knob, discovered via config.
	ldir := filepath.Join(t.TempDir(), "learn")
	if err := os.MkdirAll(ldir, 0o755); err != nil {
		t.Fatalf("mkdir learn dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ldir, "tuning.yaml"), []byte(syntheticTuning), 0o644); err != nil {
		t.Fatalf("write tuning: %v", err)
	}
	tmp := t.TempDir()
	cfgPath := writeConfig(t, tmp, "version: 1\nlearning:\n  dir: "+ldir+"\n")
	t.Setenv("MALLCOP_CONFIG", cfgPath)
	t.Setenv("MALLCOP_DECL_RULES", "")

	out, _ := withStdio(t, "", func() error { return runExamDetect([]string{"--json"}) })

	var report struct {
		Rows []struct {
			ScenarioID string   `json:"scenario_id"`
			Emitted    []string `json:"emitted"`
			Pass       bool     `json:"pass"`
		} `json:"rows"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("exam-detect --json is not valid JSON: %v\nout:\n%s", err, out)
	}

	var found, pass bool
	var emitted []string
	for _, r := range report.Rows {
		if r.ScenarioID == synthMustFireID {
			found, pass, emitted = true, r.Pass, r.Emitted
		}
	}
	if !found {
		t.Fatalf("no %s row in exam-detect output", synthMustFireID)
	}
	if !pass {
		t.Fatalf("%s still RED with config-only synthetic tuning applied (emitted: %v)", synthMustFireID, emitted)
	}
}
