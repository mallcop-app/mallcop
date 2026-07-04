//go:build docdemo

// Package docdemo is the doc-test harness for mallcop-pro item mallcoppro-cec:
// "every terminal-text demo on site+docs is DOC-TESTED to real commands+output."
//
// It builds the REAL mallcop binary from this checkout and runs the commands
// shown in README.md and docs/demo/e2e-scan.md against it in a clean temp dir,
// asserting the captured stdout matches the output shown in the doc after a
// documented, narrow normalization (see normalize.go). No demo's "expected"
// text is hand-typed without having actually been produced by a real run here.
//
// SCOPE / registry: README.md and docs/demo/e2e-scan.md contain 13 ```bash
// fenced blocks in total (verified by TestDemoRegistry_NoSilentExclusions,
// which recounts them on every run so a doc edit that adds/removes a block
// cannot silently escape this harness). Every one of those 13 is accounted for
// in the `registry` table below with an explicit disposition:
//
//   - full-output : run against the real binary; stdout/stderr/exit code
//     compared byte-for-byte against the doc's shown output, after
//     normalization. This is the actual "demo is doc-tested" proof.
//   - smoke       : run against the real binary (proves the command doesn't
//     error), but the doc shows no distinct output block to compare against —
//     there is nothing to assert byte-for-byte.
//   - out-of-reach: NOT run. Requires a live GitHub org, a live inference
//     endpoint, or a real credential this harness must not use (per this
//     item's NO-LIVE-INFERENCE constraint). Listed explicitly, with the reason,
//     rather than silently skipped.
//
// The mallcop-pro marketing site (site/*.html) is a SEPARATE repo with its own
// harness at site/docs/_doctest (mallcop-pro's test/docdemo) — this package
// only covers the docs that live in the mallcop repo.
package docdemo

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Registry: every ```bash block in README.md + docs/demo/e2e-scan.md,
// accounted for. See TestDemoRegistry_NoSilentExclusions.
// ---------------------------------------------------------------------------

type disposition string

const (
	fullOutput disposition = "full-output"
	smoke      disposition = "smoke"
	outOfReach disposition = "out-of-reach"
)

type registryEntry struct {
	doc         string // README.md | docs/demo/e2e-scan.md
	firstLine   string // first non-comment line of the block, for identification
	disposition disposition
	reason      string // required for smoke/out-of-reach
	testFunc    string // Go test function that exercises it, if any
}

// registry enumerates all 13 ```bash blocks found by TestDemoRegistry_NoSilentExclusions.
var registry = []registryEntry{
	{"README.md", "curl -fsSL https://mallcop.app/install.sh | sh", outOfReach,
		"network install of a hosted script; no shown output to assert against", ""},
	{"README.md", "go install github.com/mallcop-app/mallcop/cmd/mallcop@latest", outOfReach,
		"network go install; no shown output — equivalent local build already exercised by buildMallcop()", ""},
	{"README.md", "mallcop init", fullOutput, "", "TestDemo_Init"},
	{"README.md", "mallcop scan", fullOutput, "", "TestDemo_Scan"},
	{"README.md", "mallcop config set connector --kind=github --id=my-org --org=my-org", smoke,
		"doc shows no output block for this command", "TestDemo_ConfigSetConnector_Smoke"},
	{"README.md", "mallcop init --pro / export MALLCOP_API_KEY=... / mallcop scan", outOfReach,
		"the exported MALLCOP_API_KEY is an illustrative placeholder; running `scan` with it configured "+
			"would attempt a LIVE network call to the donut rail (api.mallcop.app) — forbidden by this "+
			"item's no-live-inference constraint. `mallcop init --pro` itself (writing the config) is "+
			"covered structurally by TestDemo_Init's config-writing path.", ""},
	{"README.md", "mallcop status --store store", fullOutput, "", "TestDemo_Scan"},
	{"README.md", "export MALLCOP_GITHUB_TOKEN=... / mallcop init --create-repo ...", outOfReach,
		"creates+pushes a real GitHub repo — live network + real credentials", ""},
	{"README.md", "mallcop config set autonomy semi", smoke,
		"doc shows no output block for this command", "TestDemo_ConfigSetAutonomy_Smoke"},
	{"README.md", "mallcop validate-proposal --base <ref> --head <ref> --json", outOfReach,
		"<ref> is a literal placeholder token in the doc (illustrating flag syntax), not a resolvable "+
			"git ref, and no output block is shown to compare against. The equivalent WORKING command "+
			"shape (validate-proposal --guard-only --json against real refs) is proven end-to-end by the "+
			"mallcop-pro site harness's self-improvement.html demo coverage.", ""},
	{"README.md", "mallcop scan (zero-flag) / mallcop scan --events events.jsonl --store store / mallcop scan --connector github ...", smoke,
		"doc shows no output block for this 3-variant illustration; the zero-flag and file-connector " +
			"forms are the same command already exercised byte-for-byte by TestDemo_Scan. The --connector " +
			"github variant needs a live GitHub org (out-of-reach; not run).", "TestDemo_ScanVariants_Smoke"},
	{"README.md", "go install .../mallcop-connectors/cmd/aws@latest / mallcop-connector-aws --since ... | mallcop scan --events - --store store", outOfReach,
		"network go install of a third-party connector binary + a real AWS CloudTrail source — live network", ""},
	{"docs/demo/e2e-scan.md", "export MALLCOP_INFERENCE_URL=... / mallcop scan --events docs/demo/events.jsonl --baseline docs/demo/baseline.json --store ... --json", fullOutput,
		"the three exports point at a placeholder BYOK endpoint (forge.example) that is not a real host; " +
			"this harness runs the underlying `mallcop scan --events ... --baseline ... --store ... --json` " +
			"WITHOUT those exports set — the OSS fail-safe (no inference client configured => force-escalate) " +
			"produces the identical shown JSON summary offline, which is exactly the property the doc's own " +
			"prose calls out (\"the fail-safe...runs end to end with zero credentials\").", "TestDemo_E2EScan"},
	{"docs/demo/e2e-scan.md", "git -C /tmp/mallcop-demo-store show HEAD:resolutions.jsonl", fullOutput, "", "TestDemo_E2EScan"},
}

// TestDemoRegistry_NoSilentExclusions recounts every ```bash fenced block in
// README.md and docs/demo/e2e-scan.md and asserts the count equals len(registry).
// This is the "no silent exclusions" proof: a demo added to either doc without
// a corresponding registry entry (and, if full-output, a TestDemo_* case) makes
// this fail instead of quietly passing.
func TestDemoRegistry_NoSilentExclusions(t *testing.T) {
	total := 0
	counts := map[string]int{}
	for _, rel := range []string{"README.md", "docs/demo/e2e-scan.md"} {
		doc := readDoc(t, rel)
		n := countBashBlocks(doc)
		counts[rel] = n
		total += n
	}
	full, sm, oor := 0, 0, 0
	for _, e := range registry {
		switch e.disposition {
		case fullOutput:
			full++
		case smoke:
			sm++
		case outOfReach:
			oor++
		}
	}
	t.Logf("demo blocks found: README.md=%d docs/demo/e2e-scan.md=%d total=%d | registry: full-output=%d smoke=%d out-of-reach=%d total=%d",
		counts["README.md"], counts["docs/demo/e2e-scan.md"], total, full, sm, oor, len(registry))
	if total != len(registry) {
		t.Fatalf("found %d ```bash blocks across README.md + docs/demo/e2e-scan.md but the registry "+
			"in test/docdemo/demo_test.go accounts for %d — a demo block was added or removed without "+
			"updating the registry. Every block must be registered as full-output (run+asserted), "+
			"smoke (run, no output to assert), or out-of-reach (documented reason, not run).",
			total, len(registry))
	}
	for _, e := range registry {
		if e.disposition != fullOutput && e.reason == "" {
			t.Fatalf("registry entry %q (%s) has disposition %s but no reason", e.firstLine, e.doc, e.disposition)
		}
	}
}

func countBashBlocks(doc string) int {
	count := 0
	inBash := false
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "```bash":
			inBash = true
		case trimmed == "```" && inBash:
			inBash = false
			count++
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	if err != nil {
		t.Fatalf("abs repo root: %v", err)
	}
	return root
}

func buildMallcop(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "mallcop")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/mallcop")
	cmd.Dir = repoRoot(t)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build mallcop: %v", err)
	}
	return bin
}

func readDoc(t *testing.T, relPath string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), relPath))
	if err != nil {
		t.Fatalf("read %s: %v (doc moved/renamed? update this harness)", relPath, err)
	}
	return string(b)
}

func mustContain(t *testing.T, docPath, doc, snippet, label string) {
	t.Helper()
	if !strings.Contains(doc, snippet) {
		t.Fatalf("%s: shown %s snippet no longer found verbatim in the doc — it changed; "+
			"update this test's expected output to match:\n--- snippet ---\n%s\n---------------",
			docPath, label, snippet)
	}
}

// run executes bin with args in dir. env supplies KEY=VALUE overrides; any
// ambient MALLCOP_/GITHUB_/inference-shaped env var is stripped from the
// inherited environment first, so a demo asserted to run "offline" cannot
// accidentally pass because the CI/dev environment happens to export a real
// key — the offline claim is enforced, not incidental.
func run(t *testing.T, dir, bin string, env []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	base := os.Environ()
	filtered := make([]string, 0, len(base))
	for _, kv := range base {
		key := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			key = kv[:i]
		}
		switch {
		case strings.HasPrefix(key, "MALLCOP_"),
			strings.HasPrefix(key, "GITHUB_APP_"),
			key == "GITHUB_INSTALLATION_ID",
			key == "GITHUB_TOKEN":
			continue // stripped: demos must prove their offline claim, not inherit a real credential
		}
		filtered = append(filtered, kv)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(filtered, env...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %s %v: %v", bin, args, err)
		}
	}
	return outBuf.String(), errBuf.String(), code
}
