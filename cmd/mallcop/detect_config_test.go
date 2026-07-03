package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// powerUserTuning is the widen-only knob that closes the PE-08 data-only false
// negative: it ADDS "poweruser" to the priv-escalation elevated-keyword set so a
// PowerUserAccess grant reads as an escalation. It is the exact shape of the
// committed detectors/tuning.yaml.
const powerUserTuning = "priv_escalation:\n  extra_elevated_keywords:\n    - poweruser\n"

// powerUserEvent is an AWS PowerUserAccess role grant on the stdin (pkg/event)
// wire shape. priv-escalation fires on it ONLY once the poweruser tuning knob is
// applied — PowerUserAccess carries none of the built-in elevation vocabulary
// (admin/owner/write/...), so it is the ideal probe for "was the tuning applied".
const powerUserEvent = `{"id":"pe1","source":"aws","type":"role_assignment","actor":"ops","payload":{"role_name":"PowerUserAccess","target_user":"svc-batch"}}` + "\n"

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
	if err := os.WriteFile(filepath.Join(ldir, "tuning.yaml"), []byte(powerUserTuning), 0o644); err != nil {
		t.Fatalf("write tuning: %v", err)
	}
	cfgPath := writeConfig(t, tmp, "version: 1\nlearning:\n  dir: detectors\n")
	t.Setenv("MALLCOP_CONFIG", cfgPath)
	t.Setenv("MALLCOP_DECL_RULES", "")

	out, err := withStdio(t, powerUserEvent, func() error { return runDetect(nil) })
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
	if err := os.WriteFile(flagTuning, []byte(powerUserTuning), 0o644); err != nil {
		t.Fatalf("write flag tuning: %v", err)
	}

	out, err := withStdio(t, powerUserEvent, func() error {
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

// TestResolveDeclRulesPath_ConfigBeatsRoot proves the precedence flag >
// $MALLCOP_DECL_RULES > config learning.dir/rules.yaml > legacy repo-root guess.
// The config path REPLACES the repo-root auto-discovery, which is wrong outside
// a repo; the legacy guess survives only when NO config is present.
func TestResolveDeclRulesPath_ConfigBeatsRoot(t *testing.T) {
	// Absent config → legacy <root>/detectors/rules.yaml (today's behavior).
	t.Chdir(t.TempDir())
	t.Setenv("MALLCOP_CONFIG", "")
	t.Setenv("MALLCOP_DECL_RULES", "")
	if got := resolveDeclRulesPath("", "/repo"); got != filepath.Join("/repo", "detectors", "rules.yaml") {
		t.Fatalf("absent config: got %q, want the legacy repo-root guess", got)
	}

	// Config present → learning.dir/rules.yaml (the repo-root guess is ignored).
	tmp := t.TempDir()
	cfgPath := writeConfig(t, tmp, "version: 1\nlearning:\n  dir: ld\n")
	t.Setenv("MALLCOP_CONFIG", cfgPath)
	want := filepath.Join(tmp, "ld", "rules.yaml")
	if got := resolveDeclRulesPath("", "/repo"); got != want {
		t.Fatalf("config present: got %q want %q (config must beat the repo-root guess)", got, want)
	}

	// $MALLCOP_DECL_RULES beats config.
	t.Setenv("MALLCOP_DECL_RULES", "/env/rules.yaml")
	if got := resolveDeclRulesPath("", "/repo"); got != "/env/rules.yaml" {
		t.Fatalf("env should beat config: got %q", got)
	}

	// The --rules flag beats everything.
	if got := resolveDeclRulesPath("/flag/rules.yaml", "/repo"); got != "/flag/rules.yaml" {
		t.Fatalf("flag should win: got %q", got)
	}
}

// TestRunExamDetect_ConfigTuningClosesPE proves exam-detect GREEN on the PE-08
// case using config-only tuning (no --tuning flag): a discovered mallcop.yaml
// whose learning.dir points at the committed detectors/ applies the poweruser
// knob, flipping the labeled PE-08 gap RED→GREEN in the REAL grader — the same
// mechanism that lets the self-extension loop's tuning proposal grade through
// the exam-detect stage, now driven by config instead of the flag.
func TestRunExamDetect_ConfigTuningClosesPE(t *testing.T) {
	root := repoRootForExamTest(t)
	t.Setenv("MALLCOP_REPO_ROOT", root)

	tmp := t.TempDir()
	body := "version: 1\nlearning:\n  dir: " + filepath.Join(root, "detectors") + "\n"
	cfgPath := writeConfig(t, tmp, body)
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
		if r.ScenarioID == "PE-08-aws-poweruser-grant" {
			found, pass, emitted = true, r.Pass, r.Emitted
		}
	}
	if !found {
		t.Fatal("no PE-08-aws-poweruser-grant row in exam-detect output")
	}
	if !pass {
		t.Fatalf("PE-08 still RED with config-only tuning applied (emitted: %v)", emitted)
	}
}
