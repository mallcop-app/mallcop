// Package gharuntime holds the embedded GitHub Actions templates that make up the
// mallcop self-extension CODE-lane runtime, plus the scaffolder that writes them
// into an operator's fork of mallcop-app/mallcop.
//
// The CODE-lane runtime is deliberately thin: it is the `mallcop-ops selfext`
// binary run inside an ephemeral GitHub Actions job (see docs/gha-selfext-runtime.md).
// This package owns only the three static files that turn a fork into a runtime:
//
//   - the thin CALLER workflow (.github/workflows/mallcop-selfext-code.yml) that a
//     fork owns and that forwards a dispatch to the pinned reusable workflow;
//   - the REUSABLE workflow (selfext-code-reusable.yml) that carries all the
//     orchestration logic and runs the binary verbatim;
//   - a CODEOWNERS belt that freezes .github/ and the committee/grader/guard paths.
//
// Every `uses:` in the templates is pinned to a full 40-hex commit SHA. The v1
// placeholders are all-zero on purpose, each with a TODO, so the static lint
// (TestTemplatesLint) flags them as unpinned until an operator or Dependabot bumps
// them to a real release commit.
package gharuntime

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed templates/mallcop-selfext-code.yml templates/selfext-code-reusable.yml templates/CODEOWNERS templates/MALLCOP_SELFEXT_SETUP.md
var templatesFS embed.FS

// setupGuideSrc is the embedded source of the persistent operator setup guide. It
// is the SINGLE source of truth for the post-scaffold steps: Scaffold writes it into
// the repo (durable) and OperatorChecklist prints it (ephemeral) — same bytes.
const setupGuideSrc = "templates/MALLCOP_SELFEXT_SETUP.md"

// File is one emitted template: its embedded source and where it lands relative
// to the scaffold out dir (an operator's mallcop fork checkout).
type File struct {
	// src is the path under templates/ in the embedded FS.
	src string
	// RelPath is the destination path relative to the scaffold out dir, using
	// forward slashes (converted to the OS separator on write).
	RelPath string
}

// Files is the ORDERED, canonical set the CODE-lane runtime emits. The order is
// stable so the golden test and the printed manifest are deterministic.
//
// Note the reusable workflow is normally hosted centrally in mallcop-app/selfext
// and referenced by SHA from the caller; it is emitted here too so an operator can
// audit it and, if they wish, self-host it. The caller is what actually runs in a
// fork.
var Files = []File{
	{src: "templates/mallcop-selfext-code.yml", RelPath: ".github/workflows/mallcop-selfext-code.yml"},
	{src: "templates/selfext-code-reusable.yml", RelPath: ".github/workflows/selfext-code-reusable.yml"},
	{src: "templates/CODEOWNERS", RelPath: ".github/CODEOWNERS"},
	// A durable, version-controlled copy of the operator setup steps — the secrets,
	// branch protection, and contribute-back token GitHub won't let a scaffold set.
	// It lands in the repo so the guidance survives the terminal.
	{src: setupGuideSrc, RelPath: ".github/MALLCOP_SELFEXT_SETUP.md"},
}

// Content returns the embedded bytes for one template by its RelPath.
func Content(relPath string) ([]byte, error) {
	for _, f := range Files {
		if f.RelPath == relPath {
			return templatesFS.ReadFile(f.src)
		}
	}
	return nil, fmt.Errorf("gharuntime: no template for %q", relPath)
}

// Scaffold writes the CODE-lane templates into outDir, creating parent dirs as
// needed, and returns the RelPaths written in canonical order. It is idempotent:
// an existing file is overwritten with the current template bytes, so re-running
// upgrades in place.
func Scaffold(outDir string) ([]string, error) {
	if outDir == "" {
		return nil, fmt.Errorf("gharuntime: out dir is required")
	}
	var written []string
	for _, f := range Files {
		b, err := templatesFS.ReadFile(f.src)
		if err != nil {
			return written, fmt.Errorf("gharuntime: read embedded %s: %w", f.src, err)
		}
		dst := filepath.Join(outDir, filepath.FromSlash(f.RelPath))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return written, fmt.Errorf("gharuntime: mkdir for %s: %w", f.RelPath, err)
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			return written, fmt.Errorf("gharuntime: write %s: %w", f.RelPath, err)
		}
		written = append(written, f.RelPath)
	}
	return written, nil
}

// OperatorChecklist returns the post-scaffold steps an operator must run by hand —
// GitHub cannot set repo secrets or branch protection from inside a scaffold. It
// returns the SAME bytes Scaffold writes to .github/MALLCOP_SELFEXT_SETUP.md, so the
// printed steps and the committed copy can never drift (single source of truth). The
// caller prints this after scaffolding; the committed file is what survives the
// terminal.
func OperatorChecklist() string {
	b, err := templatesFS.ReadFile(setupGuideSrc)
	if err != nil {
		// Unreachable: the guide is embedded, so the read cannot fail at runtime.
		return ""
	}
	return "\n" + string(b)
}
