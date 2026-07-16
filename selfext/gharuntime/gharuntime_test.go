package gharuntime

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// update regenerates the golden testdata from the emitted templates. Run
// `go test ./internal/selfext/gharuntime/ -update` after an intentional template
// change, then commit the regenerated testdata/golden tree.
var update = flag.Bool("update", false, "regenerate golden testdata from the emitted templates")

// TestScaffoldGolden asserts the emitted CODE-lane template set is byte-stable:
// Scaffold writes exactly the canonical file set, at the canonical RelPaths, with
// bytes identical to testdata/golden. Any drift in a template (or in the scaffold
// path mapping) fails here until the golden is regenerated with -update.
func TestScaffoldGolden(t *testing.T) {
	out := t.TempDir()
	written, err := Scaffold(out)
	if err != nil {
		t.Fatalf("Scaffold: %v", err)
	}

	wantPaths := []string{
		".github/workflows/mallcop-selfext-code.yml",
		".github/workflows/selfext-code-reusable.yml",
		".github/CODEOWNERS",
		".github/MALLCOP_SELFEXT_SETUP.md",
	}
	if strings.Join(written, ",") != strings.Join(wantPaths, ",") {
		t.Fatalf("Scaffold wrote %v, want %v (order matters)", written, wantPaths)
	}

	goldenRoot := filepath.Join("testdata", "golden")
	for _, rel := range wantPaths {
		got, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read emitted %s: %v", rel, err)
		}
		goldenPath := filepath.Join(goldenRoot, filepath.FromSlash(rel))
		if *update {
			if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
				t.Fatalf("mkdir golden for %s: %v", rel, err)
			}
			if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
				t.Fatalf("write golden %s: %v", rel, err)
			}
			continue
		}
		want, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatalf("read golden %s: %v (run with -update to seed)", rel, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s drifted from golden. Re-run with -update if the change is intentional.", rel)
		}
	}
}

// TestScaffoldIdempotent asserts a second Scaffold over the same dir is a no-op in
// effect: it overwrites in place with identical bytes and reports the same set.
func TestScaffoldIdempotent(t *testing.T) {
	out := t.TempDir()
	first, err := Scaffold(out)
	if err != nil {
		t.Fatalf("first Scaffold: %v", err)
	}
	second, err := Scaffold(out)
	if err != nil {
		t.Fatalf("second Scaffold: %v", err)
	}
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("Scaffold not idempotent: first=%v second=%v", first, second)
	}
	for _, rel := range second {
		emitted, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		embedded, err := Content(rel)
		if err != nil {
			t.Fatalf("Content %s: %v", rel, err)
		}
		if string(emitted) != string(embedded) {
			t.Errorf("%s on disk differs from embedded source", rel)
		}
	}
}

var (
	// usesLine matches a GitHub Actions `uses:` directive and captures the ref
	// after the final @, up to whitespace or an inline comment.
	usesLine = regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s*\S+@(\S+)`)
	// sha40 is a full 40-char lowercase-hex commit SHA (the only allowed pin form).
	sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// TestTemplatesLint is the static safety gate on the templates (design §7 E9/E11):
//   - no template ever uses pull_request_target (would run authored code with base
//     secrets);
//   - every `uses:` ref is a full 40-hex commit SHA, or its line/preceding TODO
//     marks it as an as-yet-unpinned placeholder;
//   - the author-bearing workflows grant only contents:write + pull-requests:write.
func TestTemplatesLint(t *testing.T) {
	for _, f := range Files {
		body, err := templatesFS.ReadFile(f.src)
		if err != nil {
			t.Fatalf("read %s: %v", f.src, err)
		}
		src := string(body)

		if strings.Contains(src, "pull_request_target") {
			t.Errorf("%s uses pull_request_target — forbidden (E11: never run authored code with base secrets)", f.RelPath)
		}

		lines := strings.Split(src, "\n")
		for _, m := range usesLine.FindAllStringSubmatchIndex(src, -1) {
			ref := src[m[2]:m[3]]
			fullLine := lineContaining(src, m[0])
			todo := strings.Contains(fullLine, "TODO") || precedingLineHasTODO(lines, fullLine)
			if !sha40.MatchString(ref) && !todo {
				t.Errorf("%s: uses ref %q is neither a 40-hex SHA nor a TODO placeholder", f.RelPath, ref)
			}
		}

		if strings.HasSuffix(f.RelPath, ".yml") {
			assertMinimalPermissions(t, f.RelPath, src)
		}
	}
}

// assertMinimalPermissions checks that a workflow's top-level permissions block
// grants only contents:write + pull-requests:write and nothing broader — the only
// elevated scopes the author lane is allowed (design §2.4).
func assertMinimalPermissions(t *testing.T, relPath, src string) {
	t.Helper()
	lines := strings.Split(src, "\n")
	in := false
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(ln, "permissions:") {
			in = true
			continue
		}
		if in {
			// The block ends at the next unindented (column-0) key.
			if !strings.HasPrefix(ln, " ") && !strings.HasPrefix(ln, "\t") {
				break
			}
			key := strings.TrimSpace(strings.SplitN(trimmed, ":", 2)[0])
			val := strings.TrimSpace(strings.TrimPrefix(trimmed, key+":"))
			switch key {
			case "contents", "pull-requests":
				if val != "write" {
					t.Errorf("%s: permissions.%s = %q, want write", relPath, key, val)
				}
			default:
				t.Errorf("%s: permissions grants unexpected scope %q (only contents+pull-requests allowed)", relPath, key)
			}
		}
	}
}

// TestAutonomyDialIsConfigFileNotWorkflowInput is the security invariant behind
// R3: the fully-autonomy auto-merge path must be controllable
// ONLY from the operator's own CODEOWNERS/guard-protected mallcop.yaml, and
// NEVER from a workflow input. A dial that could arrive as a workflow_dispatch /
// workflow_call input (or as a `with:` forwarded from the thin caller) would let
// a web-lane dispatch — which forwards only its own declared inputs — escalate
// autonomy, defeating "the operator owns their own blast radius".
//
// This test walks the YAML of BOTH shipped workflow templates and proves:
//   - no trigger input (workflow_dispatch.inputs / workflow_call.inputs), no
//     workflow_call.secrets key, and no thin-caller `with:` key names autonomy
//     or a dial in any casing; and
//   - the reusable workflow DOES read the dial from mallcop.yaml (the positive
//     side — the dial has a source, and that source is the config file).
//
// yaml.Node walking (not struct unmarshalling) is deliberate: GitHub's `on:`
// key resolves to the boolean true under YAML 1.1, so a typed decode would lose
// the trigger block entirely. Node.Value preserves the literal key text.
func TestAutonomyDialIsConfigFileNotWorkflowInput(t *testing.T) {
	dialRe := regexp.MustCompile(`(?i)autonomy|dial`)

	caller, err := Content(".github/workflows/mallcop-selfext-code.yml")
	if err != nil {
		t.Fatalf("read caller template: %v", err)
	}
	reusable, err := Content(".github/workflows/selfext-code-reusable.yml")
	if err != nil {
		t.Fatalf("read reusable template: %v", err)
	}

	// --- negative: no input surface may carry the dial -----------------------
	callerRoot := docRoot(t, caller)
	reusableRoot := docRoot(t, reusable)

	callerOn := mapGet(mapGet(callerRoot, "on"), "workflow_dispatch")
	for _, k := range mapKeys(mapGet(callerOn, "inputs")) {
		if dialRe.MatchString(k) {
			t.Errorf("caller workflow_dispatch input %q names the dial — a web/CLI dispatch could then escalate autonomy", k)
		}
	}

	reusableCall := mapGet(mapGet(reusableRoot, "on"), "workflow_call")
	for _, k := range mapKeys(mapGet(reusableCall, "inputs")) {
		if dialRe.MatchString(k) {
			t.Errorf("reusable workflow_call input %q names the dial — the dial must come from mallcop.yaml, not an input", k)
		}
	}
	for _, k := range mapKeys(mapGet(reusableCall, "secrets")) {
		if dialRe.MatchString(k) {
			t.Errorf("reusable workflow_call secret %q names the dial", k)
		}
	}

	// The thin caller must not FORWARD a dial into the reusable workflow either.
	callerJob := mapGet(mapGet(callerRoot, "jobs"), "selfext")
	for _, k := range mapKeys(mapGet(callerJob, "with")) {
		if dialRe.MatchString(k) {
			t.Errorf("caller forwards %q into the reusable workflow's `with:` — the dial must not travel as an input", k)
		}
	}
	for _, k := range mapKeys(mapGet(callerJob, "secrets")) {
		if dialRe.MatchString(k) {
			t.Errorf("caller forwards secret %q into the reusable workflow — the dial must not travel as a secret", k)
		}
	}

	// --- positive: the reusable workflow reads the dial from the config file --
	if !strings.Contains(string(reusable), "mallcop.yaml") {
		t.Error("reusable workflow never reads mallcop.yaml — the autonomy dial has no config-file source")
	}
	if !strings.Contains(string(reusable), "autonomy:") {
		t.Error("reusable workflow never parses learning.autonomy from mallcop.yaml")
	}
}

// TestContributeBackJobNeverMerges is the CODE-lane contribute-back hard line
// (design R3): the contribute_back job opens a REVIEW PR to the
// shared OSS repo under the operator's OWN token and NEVER merges it — the OSS
// repo's own exam.yml + CODEOWNERS review gate the merge, categorically outside
// this job's hands at every autonomy dial. This walks the reusable workflow YAML,
// isolates the contribute_back job, and asserts NO run step in it invokes any
// `gh pr merge` (the author job legitimately may — the DATA/dial auto-merge step —
// so the assertion is scoped to the contribute_back job, not the whole file).
//
// It mirrors TestAutonomyDialIsConfigFileNotWorkflowInput's node-walk style
// (yaml.Node, minding the YAML-1.1 on:->true trap).
func TestContributeBackJobNeverMerges(t *testing.T) {
	reusable, err := Content(".github/workflows/selfext-code-reusable.yml")
	if err != nil {
		t.Fatalf("read reusable template: %v", err)
	}
	root := docRoot(t, reusable)
	job := mapGet(mapGet(root, "jobs"), "contribute_back")
	if job == nil {
		t.Fatal("reusable workflow has no contribute_back job — the CODE-lane contribute-back path is missing")
	}
	steps := mapGet(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode || len(steps.Content) == 0 {
		t.Fatal("contribute_back job has no steps")
	}
	var sawConsentGate, sawOSSOpen bool
	for _, step := range steps.Content {
		run := mapGet(step, "run")
		if run == nil {
			continue
		}
		body := run.Value
		// Scan only executable shell — strip full-line `#` comments so an
		// explanatory "calls NO `gh pr merge`" comment is not a false positive; a
		// real invocation is never on a comment line.
		if strings.Contains(stripShellComments(body), "gh pr merge") {
			name := ""
			if n := mapGet(step, "name"); n != nil {
				name = n.Value
			}
			t.Errorf("contribute_back step %q calls `gh pr merge` — the CODE-lane hard line forbids merging at any dial (R3)", name)
		}
		if strings.Contains(body, "mallcop.yaml") && strings.Contains(body, "contribute_back") {
			sawConsentGate = true
		}
		if strings.Contains(body, "open-contribback-code-pr.sh") {
			sawOSSOpen = true
		}
	}
	// Positive: the job DOES gate on the config-file consent and DOES open an OSS PR.
	if !sawConsentGate {
		t.Error("contribute_back job never reads learning.contribute_back from mallcop.yaml — consent has no config-file source")
	}
	if !sawOSSOpen {
		t.Error("contribute_back job never opens the upstream OSS PR")
	}
}

// TestContributeBackConsentIsConfigFileNotWorkflowInput is the consent-escalation
// invariant for the CODE lane (R3 + R5): the contribute-back
// CONSENT knob (learning.contribute_back) must be controllable ONLY from the
// operator's own guard-protected mallcop.yaml, NEVER from a workflow input, so a
// web-lane dispatch cannot turn it on. (promote_detector / oss_repo inputs are
// fine — they select WHICH detector to promote, not WHETHER contribute-back is
// consented; the regex targets the consent knob's name, not those.)
func TestContributeBackConsentIsConfigFileNotWorkflowInput(t *testing.T) {
	consentRe := regexp.MustCompile(`(?i)contribute[_-]?back`)

	caller, err := Content(".github/workflows/mallcop-selfext-code.yml")
	if err != nil {
		t.Fatalf("read caller template: %v", err)
	}
	reusable, err := Content(".github/workflows/selfext-code-reusable.yml")
	if err != nil {
		t.Fatalf("read reusable template: %v", err)
	}
	callerRoot := docRoot(t, caller)
	reusableRoot := docRoot(t, reusable)

	callerOn := mapGet(mapGet(callerRoot, "on"), "workflow_dispatch")
	for _, k := range mapKeys(mapGet(callerOn, "inputs")) {
		if consentRe.MatchString(k) {
			t.Errorf("caller workflow_dispatch input %q names the contribute-back consent knob — a dispatch could then turn it on (R3/R5)", k)
		}
	}
	reusableCall := mapGet(mapGet(reusableRoot, "on"), "workflow_call")
	for _, k := range mapKeys(mapGet(reusableCall, "inputs")) {
		if consentRe.MatchString(k) {
			t.Errorf("reusable workflow_call input %q names the contribute-back consent knob — consent must come from mallcop.yaml, not an input", k)
		}
	}
	callerJob := mapGet(mapGet(callerRoot, "jobs"), "selfext")
	for _, k := range mapKeys(mapGet(callerJob, "with")) {
		if consentRe.MatchString(k) {
			t.Errorf("caller forwards %q into the reusable workflow's `with:` — the consent knob must not travel as an input", k)
		}
	}
	// Positive: the reusable workflow reads the consent knob from the config file.
	if !strings.Contains(string(reusable), "learning.contribute_back") && !strings.Contains(string(reusable), "contribute_back:") {
		t.Error("reusable workflow never parses learning.contribute_back from mallcop.yaml — the consent knob has no config-file source")
	}
}

// stripShellComments removes full-line `#` comments from a shell script body so a
// static scan sees only executable lines. It does not attempt to parse inline
// comments after a command (those would still be flagged), which is the safe
// direction: a real `gh pr merge` command is never buried in a trailing comment.
func stripShellComments(body string) string {
	var b strings.Builder
	for _, ln := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	return b.String()
}

// docRoot parses src and returns the top-level mapping node.
func docRoot(t *testing.T, src []byte) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		t.Fatalf("parse workflow YAML: %v", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		t.Fatalf("workflow YAML root is not a mapping")
	}
	return doc.Content[0]
}

// mapGet returns the value node for literal key in mapping m, or nil. It matches
// on Node.Value so the YAML-1.1 `on:` → true key resolution cannot hide a block.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mapKeys returns the literal key strings of mapping m (empty for a nil/non-map).
func mapKeys(m *yaml.Node) []string {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	var keys []string
	for i := 0; i+1 < len(m.Content); i += 2 {
		keys = append(keys, m.Content[i].Value)
	}
	return keys
}

// lineContaining returns the full source line containing byte offset off.
func lineContaining(src string, off int) string {
	start := strings.LastIndexByte(src[:off], '\n') + 1
	end := strings.IndexByte(src[off:], '\n')
	if end < 0 {
		return src[start:]
	}
	return src[start : off+end]
}

// precedingLineHasTODO reports whether the line immediately before target (in the
// same file) carries a TODO — the templates put the TODO on a comment line above
// the `uses:` directive.
func precedingLineHasTODO(lines []string, target string) bool {
	for i, ln := range lines {
		if ln == target && i > 0 {
			return strings.Contains(lines[i-1], "TODO")
		}
	}
	return false
}
