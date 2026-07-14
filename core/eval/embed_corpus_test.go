// embed_corpus_test.go — proves the embedded corpus (LoadEmbedded,
// mallcop.ScenariosFS) is a faithful, integrity-verified stand-in for the
// on-disk corpus (Load), mirroring core/tools/embed_corpus_test.go's
// embed==disk pattern for the operator-decisions corpus. This is the
// prerequisite for C4 (per-operator local eval in a customer deploy repo that
// carries no exams/scenarios directory on disk).
package eval

import (
	"strings"
	"testing"
)

// TestLoadEmbedded_Succeeds proves the shipped embed passes its OWN pin
// verification: LoadEmbedded scans mallcop.ScenariosFS, reads the embedded
// corpus.pin, and the count+SHA gate must be green — exactly like Load(root)
// is for the on-disk tree. A failure here means the embed and corpus.pin have
// drifted (a scenario changed without go:embed picking up the new bytes, which
// should never happen since //go:embed always bakes the checked-out tree at
// build time — but this is the interlock that would catch it).
func TestLoadEmbedded_Succeeds(t *testing.T) {
	c, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if c.Count == 0 {
		t.Fatal("embedded corpus loaded 0 scenarios")
	}
}

// TestLoadEmbedded_MatchesDiskCorpus is the embed==disk parity test: the
// embedded corpus and the on-disk corpus (loaded from the SAME checked-out
// tree LoadEmbedded was built from) must agree on count, digest, and the exact
// set of RelPath+FileSHA pairs. Because //go:embed copies file bytes verbatim,
// any divergence here means the checked-out tree changed since the test binary
// was built (a normal `go test` recompiles first, so this should never
// legitimately fail) or the embed pattern in corpusembed.go stopped matching
// what the disk walker walks.
func TestLoadEmbedded_MatchesDiskCorpus(t *testing.T) {
	root := repoRoot(t)

	disk, err := Load(root)
	if err != nil {
		t.Fatalf("Load(disk): %v", err)
	}
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	if disk.Count != embedded.Count {
		t.Fatalf("count mismatch: disk=%d embedded=%d", disk.Count, embedded.Count)
	}
	if disk.SHA != embedded.SHA {
		t.Fatalf("digest mismatch: disk=%s embedded=%s", disk.SHA, embedded.SHA)
	}
	if disk.Manifest() != embedded.Manifest() {
		t.Fatal("manifest mismatch: disk and embedded corpora disagree on relpath/filesha pairs despite equal count+SHA (should be unreachable)")
	}

	// Spot-check parsed content, not just hashes: the first and last scenario
	// (by RelPath, both sorted identically) must carry the SAME scenario ID
	// through both loaders — proving loadScenarioFromBytes' temp-file bridge
	// parses the embedded bytes exactly as exam.Load parses the on-disk file.
	if len(disk.Scenarios) == 0 {
		t.Fatal("no scenarios loaded")
	}
	for _, i := range []int{0, len(disk.Scenarios) - 1} {
		d, e := disk.Scenarios[i], embedded.Scenarios[i]
		if d.RelPath != e.RelPath {
			t.Fatalf("relpath[%d] mismatch: disk=%s embedded=%s", i, d.RelPath, e.RelPath)
		}
		if d.FileSHA != e.FileSHA {
			t.Fatalf("filesha[%d] mismatch for %s: disk=%s embedded=%s", i, d.RelPath, d.FileSHA, e.FileSHA)
		}
		if d.Scenario.ID != e.Scenario.ID {
			t.Fatalf("parsed scenario ID[%d] mismatch for %s: disk=%s embedded=%s", i, d.RelPath, d.Scenario.ID, e.Scenario.ID)
		}
	}
}

// TestLoadEmbedded_SkipsLeadingUnderscorePaths mirrors
// TestCorpus_SkipsLeadingUnderscorePaths (harness_test.go) for the embedded
// corpus: go:embed's own directory-embed default excludes "_"/"."-prefixed
// files and dirs (verified empirically against exams/scenarios/_schema.yaml
// and exams/scenarios/_test/), so no scenario in the embedded set may carry an
// underscore path component.
func TestLoadEmbedded_SkipsLeadingUnderscorePaths(t *testing.T) {
	c, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	for _, s := range c.Scenarios {
		if hasUnderscoreComponent(s.RelPath) {
			t.Fatalf("underscore path leaked into embedded corpus: %s", s.RelPath)
		}
		if strings.Contains(s.RelPath, "_schema") || strings.HasPrefix(s.RelPath, "_test/") {
			t.Fatalf("forbidden underscore path included in embedded corpus: %s", s.RelPath)
		}
	}
}

// TestLoad_ErrorsWhenCorpusRootMissing proves the exact failure mode
// LoadEmbedded exists to route around: a resolved repo root (e.g. a customer
// deploy repo with its own go.mod/.git marker) that carries NO
// exams/scenarios directory on disk. Load must fail clearly rather than
// silently falling back to the embed — LoadEmbedded is an explicit,
// separately-named entry point a caller opts into, never an implicit shadow of
// Load.
func TestLoad_ErrorsWhenCorpusRootMissing(t *testing.T) {
	_, err := Load(t.TempDir())
	if err == nil {
		t.Fatal("expected Load to fail on a root with no exams/scenarios directory")
	}
	if !strings.Contains(err.Error(), "corpus root not found") {
		t.Fatalf("expected a 'corpus root not found' error, got: %v", err)
	}
}

// TestLoadEmbedded_TamperedPinHardFails proves the embedded path enforces the
// SAME hard-fail interlock the disk path does: verifyPin rejects a count or
// SHA mismatch regardless of which fs.FS the corpus was scanned from. This
// exercises the shared loadFromFS/verifyPin code directly (constructing a
// deliberately wrong pin) rather than mutating the embedded corpus.pin itself
// (which is immutable at runtime by construction).
func TestLoadEmbedded_TamperedPinHardFails(t *testing.T) {
	c, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	if err := verifyPin(c, CorpusPin{Count: c.Count + 1, SHA: c.SHA}); err == nil {
		t.Fatal("expected a count mismatch to hard-fail verifyPin")
	}
	if err := verifyPin(c, CorpusPin{Count: c.Count, SHA: "deadbeef"}); err == nil {
		t.Fatal("expected a sha mismatch to hard-fail verifyPin")
	}
	if err := verifyPin(c, CorpusPin{Count: c.Count, SHA: c.SHA}); err != nil {
		t.Fatalf("matching pin should not fail: %v", err)
	}
}
