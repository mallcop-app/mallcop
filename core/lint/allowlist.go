package lint

// allowlist.go is the L2 purity gate for the AUTHORED detector tree — the
// detectors the in-product self-extension loop writes as code under
// detectors/ (canonical authoredRel = "detectors"). It is PRODUCTION code:
// the K4 validate_proposal step calls CheckAuthoredDetectorTree to reject a
// proposed detector whose import graph reaches outside the sandbox, and
// allowlist_test.go runs the same checker as a repo CI gate.
//
// Posture: ALLOW-list, exact match, fail closed. Where imports_test.go is a
// DENY gate over core/ (ban known framework/SDK families, allow everything
// else), authored detector code is held to the inverse and much stricter
// standard: an import is legal only if it is (a) on the small exact-match
// stdlib allow list, (b) exactly one of the four framework surface packages,
// or (c) another authored helper under the same authored tree — which is then
// checked transitively, so contraband cannot be smuggled through a helper
// package. Everything else — os, os/exec, net/http, io, reflect, unsafe,
// plugin, syscall, cgo, any third-party module, any other in-module package —
// is a Violation.
//
// Division of labor (why framework imports are TERMINAL): the four framework
// packages (pkg/event, pkg/finding, pkg/baseline, core/detect) are
// human-written, reviewed product code. pkg/baseline legitimately imports os
// (it persists baselines); recursing into the framework would force the
// authored-code allow list onto packages it was never meant to govern. The
// framework itself is guarded by being human-authored, PR-reviewed product
// code behind the self-extension invariant guard's protected paths (note:
// the core-wide deny gate in imports_test.go walks core/ only — pkg/event,
// pkg/finding and pkg/baseline are OUTSIDE its scope, and it is a
// framework/SDK substring denylist, not an os/net gate) — so the checker
// treats an exact framework import as OK and does NOT recurse.
//
// Consensus-not-rules invariant: this gate only constrains what authored
// detector CODE may link. The allow list is fixed in this file — there is no
// configuration surface, no per-detector override, and no mechanism by which
// a proposal could narrow what the committee sees. Widening the list is a
// human code change reviewed like any other.

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// allowedStdlib is the EXACT-match set of standard-library import paths an
// authored detector may use. Pure computation and encoding only — nothing on
// this list can touch the filesystem, the network, the process table, or the
// runtime's type system. Matching is exact: "os" is not "sort", and
// "encoding/json" does not admit "encoding/gob".
var allowedStdlib = map[string]bool{
	"fmt":             true,
	"sort":            true,
	"strings":         true,
	"strconv":         true,
	"time":            true,
	"math":            true,
	"unicode":         true,
	"unicode/utf8":    true,
	"regexp":          true,
	"encoding/json":   true,
	"encoding/base64": true,
}

// frameworkSurface returns the EXACT-match set of in-module packages that form
// the detector framework surface: the event/finding/baseline types a detector
// consumes and produces, and the detect registry it plugs into. These are
// terminal — see the division-of-labor note in the file comment.
func frameworkSurface(modulePath string) map[string]bool {
	return map[string]bool{
		modulePath + "/pkg/event":    true,
		modulePath + "/pkg/finding":  true,
		modulePath + "/pkg/baseline": true,
		modulePath + "/core/detect":  true,
	}
}

// Violation is one illegal import found in the authored detector tree.
type Violation struct {
	// File is the repo-root-relative (slash-separated) path of the file that
	// literally contains the offending import.
	File string
	// Import is the offending import path as written in the source.
	Import string
	// Reason explains which rule the import broke.
	Reason string
	// Via names the smuggling path for a TRANSITIVE hit: the root authored
	// file that was being checked, followed by each in-module authored-helper
	// import traversed to reach File. Nil for a direct hit in the root file
	// itself.
	Via []string
}

// ModulePath parses the module path from repoRoot/go.mod. Callers of
// CheckAuthoredDetectorTree use it so MODULE is always the real module
// identity, never a hardcoded guess.
func ModulePath(repoRoot string) (string, error) {
	path := filepath.Join(repoRoot, "go.mod")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "module"); ok {
			mod := strings.Trim(strings.TrimSpace(rest), `"`)
			if mod != "" {
				return mod, nil
			}
		}
	}
	return "", fmt.Errorf("no module directive in %s", path)
}

// CheckAuthoredDetectorTree walks every non-test .go file under
// repoRoot/authoredRel and returns a Violation for each import that is not on
// the allow list. modulePath is the module identity from go.mod (see
// ModulePath); authoredRel is the repo-relative authored tree root (canonical:
// "detectors").
//
// Classification, per import path p:
//   - exact allowedStdlib match          -> OK
//   - exact framework surface match      -> OK, TERMINAL (no recursion)
//   - in-module under MODULE/authoredRel -> authored helper: resolve to its
//     directory and check it transitively (visited set breaks cycles), so a
//     helper cannot smuggle contraband for its importers
//   - any OTHER in-module path           -> Violation (e.g. MODULE/core/agent)
//   - anything else                      -> Violation (os, net/http, unsafe,
//     "C", third-party, ...)
//
// If the authored root does not exist the walk error (wrapping fs.ErrNotExist)
// is returned; callers that treat an empty authored tree as trivially green
// check for that.
func CheckAuthoredDetectorTree(repoRoot, modulePath, authoredRel string) ([]Violation, error) {
	fset := token.NewFileSet()
	framework := frameworkSurface(modulePath)
	root := filepath.Join(repoRoot, filepath.FromSlash(authoredRel))

	var violations []Violation
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isProductionGoFile(d.Name()) {
			return nil
		}
		// Each root file gets its own visited set: the transitive check is a
		// property of that file's import graph, and the set breaks helper
		// import cycles.
		visited := map[string]bool{}
		vs, cerr := checkAuthoredFile(fset, repoRoot, modulePath, authoredRel, path, nil, visited, framework)
		if cerr != nil {
			return cerr
		}
		violations = append(violations, vs...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return violations, nil
}

// checkAuthoredFile classifies every import of one authored file, recursing
// into authored-helper imports. via is the smuggling path accumulated so far
// (nil when filePath is the root file being checked).
func checkAuthoredFile(fset *token.FileSet, repoRoot, modulePath, authoredRel, filePath string, via []string, visited map[string]bool, framework map[string]bool) ([]Violation, error) {
	relFile := repoRelative(repoRoot, filePath)
	f, err := parser.ParseFile(fset, filePath, nil, parser.ImportsOnly)
	if err != nil {
		return nil, fmt.Errorf("parse authored file %s: %w", relFile, err)
	}

	authoredPkgPrefix := modulePath + "/" + authoredRel
	var violations []Violation
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		switch {
		case allowedStdlib[p]:
			// OK: exact stdlib allow-list match.

		case framework[p]:
			// OK, terminal: the framework surface is human-written code
			// covered by the repo's own gates (see file comment) — do not
			// recurse into it.

		case p == authoredPkgPrefix || strings.HasPrefix(p, authoredPkgPrefix+"/"):
			// Authored helper: check it transitively so it cannot smuggle.
			dir := filepath.Join(repoRoot, filepath.FromSlash(strings.TrimPrefix(p, modulePath+"/")))
			if visited[dir] {
				continue
			}
			visited[dir] = true
			childVia := via
			if len(childVia) == 0 {
				childVia = []string{relFile}
			}
			childVia = append(append([]string{}, childVia...), p)
			vs, err := checkAuthoredDir(fset, repoRoot, modulePath, authoredRel, dir, childVia, visited, framework)
			if err != nil {
				// Fail closed: an authored-helper import that cannot be
				// resolved and verified is itself a violation.
				violations = append(violations, Violation{
					File:   relFile,
					Import: p,
					Reason: fmt.Sprintf("authored-helper import cannot be resolved for transitive checking: %v", err),
					Via:    via,
				})
				continue
			}
			violations = append(violations, vs...)

		case p == modulePath || strings.HasPrefix(p, modulePath+"/"):
			violations = append(violations, Violation{
				File:   relFile,
				Import: p,
				Reason: "in-module import outside the framework surface (pkg/event, pkg/finding, pkg/baseline, core/detect) and the authored tree",
				Via:    via,
			})

		default:
			violations = append(violations, Violation{
				File:   relFile,
				Import: p,
				Reason: "import is not on the authored-detector allow list (exact stdlib set + framework surface + authored helpers only)",
				Via:    via,
			})
		}
	}
	return violations, nil
}

// checkAuthoredDir checks every non-test .go file in one authored-helper
// package directory (non-recursive over subdirectories: a Go package is one
// directory; sub-packages are reached via their own import paths).
func checkAuthoredDir(fset *token.FileSet, repoRoot, modulePath, authoredRel, dir string, via []string, visited map[string]bool, framework map[string]bool) ([]Violation, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var violations []Violation
	for _, e := range entries {
		if e.IsDir() || !isProductionGoFile(e.Name()) {
			continue
		}
		vs, err := checkAuthoredFile(fset, repoRoot, modulePath, authoredRel, filepath.Join(dir, e.Name()), via, visited, framework)
		if err != nil {
			return nil, err
		}
		violations = append(violations, vs...)
	}
	return violations, nil
}

// isProductionGoFile reports whether name is a non-test Go source file.
func isProductionGoFile(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}

// repoRelative returns path relative to repoRoot, slash-separated, for stable
// Violation.File values.
func repoRelative(repoRoot, path string) string {
	rel, err := filepath.Rel(repoRoot, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
