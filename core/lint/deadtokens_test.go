package lint

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// deadTokens are machine tokens for subsystems that were REMOVED from the product
// and must never reappear in impl/config/CI. Unlike bannedImportSubstrings (which
// is import-path-scoped to core/), this gate scans the WHOLE repo's implementation
// files for the tokens' literal presence — the "so it stops coming back" merge gate
// for the legion-runtime teardown (bin/we, charts, mallcop-academy, the heal
// claude-code spawner, the legion boot/deploy scripts).
//
// Each token, and why it is dead:
//   - "3dl-dev/legion"      — the legion (ClankerOS) automaton engine import path.
//                             The product is the one-shot cmd/mallcop CLI; it links
//                             no orchestrator. (core/lint/imports_test.go already
//                             bans this as an IMPORT under core/; this extends the
//                             ban repo-wide, to config/CI/scripts too.)
//   - ".we-version"         — pin file for the legion `we` binary. Gone.
//   - "we-linux-amd64"      — the downloaded legion binary artifact. Gone.
//   - "spawn-claude-code-fix" — the heal worker's Claude Code subprocess spawner
//                             tool (excised, mallcop #121). The product embeds no
//                             proprietary agent runtime.
//   - "start-mallcop.sh"    — legion boot script. Gone; the product is a CLI.
//   - "bootstrap-deploy.sh" — legion deploy bootstrap. Gone.
//
// If this test fails, someone reintroduced a removed subsystem — delete the
// reference, do not relax the token list. To retire a token (a subsystem genuinely
// coming back by design), remove it here in the same change that revives it.
var deadTokens = []string{
	"3dl-dev/legion",
	".we-version",
	"we-linux-amd64",
	"spawn-claude-code-fix",
	"start-mallcop.sh",
	"bootstrap-deploy.sh",
}

// scannedExts are implementation surfaces where a dead token is a real regression:
// source, config, CI workflows, scripts, container/build files. Prose (.md) is
// excluded — docs carry legitimate historical/provenance mentions of removed
// subsystems, and this gate protects impl, not history.
var scannedExts = map[string]bool{
	".go": true, ".yml": true, ".yaml": true, ".toml": true, ".sh": true,
}

// deadTokenAllowlist are files that legitimately contain a dead token as data:
// the ban-tests (which name the tokens they forbid) and this gate itself.
func deadTokenAllowed(rel string) bool {
	base := filepath.Base(rel)
	if base == "deadtokens_test.go" {
		return true
	}
	// *imports_test.go files carry banned import paths (incl. "3dl-dev/legion")
	// as the literal deny-list / negative-control examples.
	return strings.HasSuffix(base, "imports_test.go")
}

// repoRoot locates the module root by walking up to the go.mod marker — the same
// self-locating discipline coreRoot() uses, but rooted at the repo, not core/.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to filesystem root without finding go.mod")
		}
		dir = parent
	}
}

// TestNoDeadTokensAcrossRepo walks every implementation file in the repo and fails
// if any contains a removed-subsystem token. This is the merge gate that keeps the
// legion/we/heal-spawn teardown from silently regressing.
func TestNoDeadTokensAcrossRepo(t *testing.T) {
	root := repoRoot(t)
	skipDirs := map[string]bool{
		".git": true, "mallcop-python-legacy": true, "node_modules": true,
		"vendor": true, ".ready": true, ".campfire": true,
	}
	checked := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !scannedExts[filepath.Ext(d.Name())] {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if deadTokenAllowed(rel) {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		checked++
		content := string(b)
		for _, tok := range deadTokens {
			if strings.Contains(content, tok) {
				t.Errorf("%s contains removed-subsystem token %q — the legion/we/heal-spawn "+
					"runtime was torn down; the product is the one-shot cmd/mallcop CLI. Remove "+
					"the reference, do not relax the ban.", rel, tok)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if checked == 0 {
		t.Fatal("dead-token lint scanned 0 implementation files; layout changed?")
	}
	t.Logf("dead-token lint scanned %d implementation files repo-wide", checked)
}

// TestDeadTokenNegativeControl proves the gate fires: a planted token is caught,
// clean content is not. Runs the same Contains match the live scan uses.
func TestDeadTokenNegativeControl(t *testing.T) {
	for _, tok := range deadTokens {
		tok := tok
		t.Run(tok, func(t *testing.T) {
			planted := "package x\n// uses " + tok + " somewhere\n"
			hit := false
			for _, d := range deadTokens {
				if strings.Contains(planted, d) {
					hit = true
				}
			}
			if !hit {
				t.Fatalf("negative control did not fire for %q — the gate would miss it", tok)
			}
			clean := "package x\n// entirely clean content\n"
			for _, d := range deadTokens {
				if strings.Contains(clean, d) {
					t.Fatalf("false positive: clean content matched %q", d)
				}
			}
		})
	}
}
