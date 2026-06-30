package mallcop_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop"
)

// corpusRelPath is the repo-relative location of the operator-decisions corpus,
// the same file //go:embed bakes into mallcop.OperatorDecisionsYAML.
var corpusRelPath = filepath.Join("agents", "rules", "operator-decisions.yaml")

// TestEmbedEqualsOnDisk asserts the embedded corpus is byte-for-byte identical
// to the on-disk agents/rules/operator-decisions.yaml. //go:embed already
// guarantees this at BUILD time (it copies the exact file), but this test makes
// the invariant explicit at TEST time: if someone edits the corpus and a stale
// build artifact is reused, or a duplicate copy is ever introduced, this fails
// loudly. The root package's test working directory IS the repo root, so the
// relative path resolves directly.
func TestEmbedEqualsOnDisk(t *testing.T) {
	disk, err := os.ReadFile(corpusRelPath)
	if err != nil {
		t.Fatalf("read on-disk corpus %s: %v", corpusRelPath, err)
	}
	if len(mallcop.OperatorDecisionsYAML) == 0 {
		t.Fatal("embedded OperatorDecisionsYAML is empty; //go:embed directive not wired")
	}
	if !bytes.Equal(disk, mallcop.OperatorDecisionsYAML) {
		t.Fatalf("embedded corpus differs from on-disk %s: disk=%d bytes embed=%d bytes — "+
			"the binary would carry a corpus that disagrees with the file the SHA pin describes",
			corpusRelPath, len(disk), len(mallcop.OperatorDecisionsYAML))
	}
}
