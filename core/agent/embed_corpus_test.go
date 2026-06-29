package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TestEmbedFallback_ResolutionFailureUsesBakedRoutes is the core fix for the
// /tmp standalone-binary symptom. When the repo-root resolver FAILS (rootErr !=
// nil, as a /tmp binary with MALLCOP_REPO_ROOT unset hits), checkHardConstraints
// must NO LONGER fail-safe-escalate every finding with "cannot locate
// escalate-route corpus". Instead it loads the EMBEDDED routes and behaves
// exactly as in-repo:
//   - a dangerous family still force-escalates (matched a real embedded route),
//     and the reason is the route's reason, NOT a resolution-failure message;
//   - a benign family proceeds (forceEscalate=false) — proving the floor is the
//     real baked-in policy, not escalate-everything.
func TestEmbedFallback_ResolutionFailureUsesBakedRoutes(t *testing.T) {
	invalidateRoutesCache()
	t.Cleanup(invalidateRoutesCache)

	rootErr := errors.New("resolveRepoRoot: no project marker found, MALLCOP_REPO_ROOT unset")

	// Dangerous family: the embedded corpus has an escalate route for it, so the
	// floor force-escalates with the ROUTE's reason, not a resolution-failure.
	feDanger, resDanger := checkHardConstraints("", rootErr, finding.Finding{ID: "d", Type: "injection-probe"})
	if !feDanger {
		t.Fatal("embed fallback: a dangerous family must still force-escalate from the embedded corpus")
	}
	if strings.Contains(resDanger.Reason, "cannot locate escalate-route corpus") {
		t.Fatalf("embed fallback regressed: still reporting the resolution-failure fail-safe reason: %q", resDanger.Reason)
	}
	if resDanger.RouteID == "" {
		t.Fatalf("embed fallback: escalation must cite an embedded route id, got %+v", resDanger)
	}

	// Benign family: proceeds. This proves the embed loaded REAL routes (a
	// fail-safe-escalate-everything path would have escalated this too).
	feBenign, _ := checkHardConstraints("", rootErr, finding.Finding{ID: "b", Type: "unusual-login"})
	if feBenign {
		t.Fatal("embed fallback: a benign family must proceed (forceEscalate=false), not escalate-everything")
	}
}

// TestEmbedDisabled_ResolutionFailureEmptyFloor proves the
// MALLCOP_RULES_EMBED_DISABLE escape hatch for the floor: with it set, a
// resolution failure yields an EMPTY floor (no routes, no error), so a benign
// AND a dangerous family both proceed at THIS gate (the downstream resolve
// fail-safe still covers the dangerous case). This pins the on-disk-only branch
// so the embed cannot become mandatory.
func TestEmbedDisabled_ResolutionFailureEmptyFloor(t *testing.T) {
	t.Setenv("MALLCOP_RULES_EMBED_DISABLE", "1")
	invalidateRoutesCache()
	t.Cleanup(invalidateRoutesCache)

	routes, err := loadEscalateRoutes("", errors.New("resolver failed"))
	if err != nil {
		t.Fatalf("embed disabled + resolution failure should be empty floor, not error: %v", err)
	}
	if routes == nil || len(routes.routes) != 0 {
		t.Fatalf("embed disabled: expected empty floor (0 routes), got %+v", routes)
	}
}

// TestDiskWinsOverEmbed_Floor is the footgun guard for the floor: a PRESENT
// on-disk corpus must be read, never shadowed by the embed. It writes a temp
// corpus with a single sentinel route whose family is absent from the embedded
// corpus, then asserts that exact route fires — proving the disk bytes were used.
func TestDiskWinsOverEmbed_Floor(t *testing.T) {
	invalidateRoutesCache()
	t.Cleanup(invalidateRoutesCache)

	root := t.TempDir()
	dir := filepath.Join(root, "agents", "rules")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const sentinel = "escalate_routes:\n  - id: \"E-DISK-SENTINEL\"\n    family: \"disk-only-family\"\n    reason: \"from disk, not embed\"\nrules: []\n"
	if err := os.WriteFile(filepath.Join(dir, "operator-decisions.yaml"), []byte(sentinel), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}

	// rootErr=nil → on-disk read; the sentinel family must fire from disk bytes.
	fe, res := checkHardConstraints(root, nil, finding.Finding{ID: "s", Type: "disk-only-family"})
	if !fe || res.RouteID != "E-DISK-SENTINEL" {
		t.Fatalf("disk corpus must win over embed; expected E-DISK-SENTINEL to fire, got fe=%v res=%+v", fe, res)
	}
}
