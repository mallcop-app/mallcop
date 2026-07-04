// corpus.go — the SHA-PINNED, PROVENANCE-SAFE scenario corpus loader.
//
// This is the self-extension FOUNDATION (portable-agent-architecture.md §4.1,
// §4.9): the eval is an INTERLOCK. Before any scenario runs, the loader asserts
// two integrity gates that a self-extension loop (an agent that appends new
// scenarios) MUST clear:
//
//  1. COUNT  — the corpus has exactly the expected number of scenarios.
//  2. SHA    — the corpus content hashes to the exact pinned digest.
//
// A mismatch on EITHER is a HARD FAIL (Load returns an error; nothing runs). The
// pin lives in a committed file (corpus.pin) the loader verifies on every run.
// An agent that adds or edits a scenario MUST also update the pin in the same
// change — so a tampered or drifted corpus cannot silently change the accuracy
// number. This is the eval-as-interlock property the closed loop depends on.
//
// THE LEADING-UNDERSCORE FOOTGUN (§4.10): the walker SKIPS every path component
// that begins with "_" — both FILES (`_schema.yaml`) and DIRECTORIES (`_test/`).
// exams/scenarios/ ships `_schema.yaml` (the schema, not a scenario) and a
// `_test/` directory (harness probes, not graded scenarios). Including either
// would inflate the count, corrupt the hash, and feed non-scenarios to the
// grader. The skip is on ANY component, at ANY depth — `a/_b/c.yaml` is skipped.
//
// THE CANONICAL MANIFEST (the hashed artifact): the corpus SHA is NOT a hash of a
// tarball or a directory listing (both are order/zip/timestamp-sensitive). It is
// the SHA-256 of a CANONICAL MANIFEST: for each included scenario, one line
//
//	<forward-slash relpath><two spaces><lowercase hex sha256 of file bytes>\n
//
// lines sorted lexicographically by relpath, concatenated. This is reproducible
// across OSes (forward slashes), independent of walk order (sorted), and
// independent of file mtime/permissions (content hash only). The Go loader is the
// SOURCE OF TRUTH for the format; corpus.pin holds the digest the loader emits.
package eval

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mallcop-app/mallcop/internal/exam"
)

// scenariosRelPath is the corpus root relative to the repo root.
const scenariosRelPath = "exams/scenarios"

// pinRelPath is the committed pin file the loader verifies before running.
// It lives BESIDE the corpus so a scenario change and its pin update land
// together in one diff (the self-extension contract).
const pinRelPath = scenariosRelPath + "/corpus.pin"

// LoadedScenario pairs a parsed scenario with its provenance: the corpus-relative
// path (stable id used in result filenames + the manifest) and the per-file
// content hash that fed the corpus digest.
type LoadedScenario struct {
	// RelPath is the forward-slash path under exams/scenarios (e.g.
	// "auth/AF-01-fat-finger-benign.yaml"). Stable across OSes; used in the
	// manifest and as a provenance key.
	RelPath string
	// FileSHA is the lowercase-hex sha256 of the scenario file's bytes.
	FileSHA string
	// Scenario is the parsed, validated scenario (exam.Load).
	Scenario *exam.Scenario
}

// Corpus is the loaded, integrity-verified scenario set.
type Corpus struct {
	// Scenarios are sorted lexicographically by RelPath — deterministic order so
	// the runner, the grader, and the manifest all agree.
	Scenarios []LoadedScenario
	// SHA is the corpus digest: sha256 of the canonical manifest. It equals the
	// pinned digest (Load fails otherwise).
	SHA string
	// Count is len(Scenarios) — equals the pinned count (Load fails otherwise).
	Count int
}

// CorpusPin is the committed integrity pin: the expected count + digest. A
// mismatch between the loaded corpus and this pin HARD-FAILS the run.
type CorpusPin struct {
	Count int
	SHA   string
}

// Manifest returns the canonical manifest (the exact bytes that get hashed):
// one "<relpath><two spaces><filesha>\n" line per scenario, sorted by relpath.
// Exposed so the pin-regeneration helper and tests can recompute the digest
// from the same source of truth the loader uses.
func (c Corpus) Manifest() string {
	var b strings.Builder
	for _, s := range c.Scenarios {
		b.WriteString(s.RelPath)
		b.WriteString("  ") // two-space separator (manifest contract)
		b.WriteString(s.FileSHA)
		b.WriteByte('\n')
	}
	return b.String()
}

// computeManifestSHA hashes a manifest string to its lowercase-hex sha256.
func computeManifestSHA(manifest string) string {
	sum := sha256.Sum256([]byte(manifest))
	return hex.EncodeToString(sum[:])
}

// hasUnderscoreComponent reports whether any path component of rel (forward-slash
// separated) begins with "_". This is the leading-underscore skip applied to
// BOTH files and directories at ANY depth — the _schema.yaml / _test/ footgun.
func hasUnderscoreComponent(rel string) bool {
	for _, part := range strings.Split(rel, "/") {
		if strings.HasPrefix(part, "_") {
			return true
		}
	}
	return false
}

// scanCorpus walks scenariosRoot, parses every included scenario, and returns the
// loaded set + digest. It applies the leading-underscore skip and computes each
// file's content hash. It does NOT verify the pin — that is Load's job (so tests
// can scan a tampered tree and observe the digest BEFORE the gate rejects it).
func scanCorpus(scenariosRoot string) (Corpus, error) {
	var loaded []LoadedScenario

	err := filepath.WalkDir(scenariosRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(scenariosRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		// Skip the root itself.
		if rel == "." {
			return nil
		}

		// LEADING-UNDERSCORE SKIP — files AND directories, any depth. On a
		// directory we return SkipDir so the whole subtree (e.g. _test/) is
		// pruned, not just the dir entry.
		if hasUnderscoreComponent(rel) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".yaml") && !strings.HasSuffix(d.Name(), ".yml") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read scenario %s: %w", rel, err)
		}
		sum := sha256.Sum256(data)
		fileSHA := hex.EncodeToString(sum[:])

		sc, err := exam.Load(path)
		if err != nil {
			return fmt.Errorf("parse scenario %s: %w", rel, err)
		}

		loaded = append(loaded, LoadedScenario{
			RelPath:  rel,
			FileSHA:  fileSHA,
			Scenario: sc,
		})
		return nil
	})
	if err != nil {
		return Corpus{}, err
	}

	sort.Slice(loaded, func(i, j int) bool { return loaded[i].RelPath < loaded[j].RelPath })

	c := Corpus{Scenarios: loaded, Count: len(loaded)}
	c.SHA = computeManifestSHA(c.Manifest())
	return c, nil
}

// readPin parses the committed pin file. Format (two lines, order-free, '#'
// comments and blank lines ignored):
//
//	count <N>
//	sha256 <hex>
func readPin(pinPath string) (CorpusPin, error) {
	f, err := os.Open(pinPath)
	if err != nil {
		return CorpusPin{}, fmt.Errorf("open corpus pin %s: %w (the eval interlock requires a committed pin)", pinPath, err)
	}
	defer func() { _ = f.Close() }()

	var pin CorpusPin
	var sawCount, sawSHA bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return CorpusPin{}, fmt.Errorf("corpus pin %s: malformed line %q (want '<key> <value>')", pinPath, line)
		}
		switch fields[0] {
		case "count":
			n, perr := parseCount(fields[1])
			if perr != nil {
				return CorpusPin{}, fmt.Errorf("corpus pin %s: bad count %q: %w", pinPath, fields[1], perr)
			}
			pin.Count = n
			sawCount = true
		case "sha256":
			pin.SHA = strings.ToLower(fields[1])
			sawSHA = true
		default:
			return CorpusPin{}, fmt.Errorf("corpus pin %s: unknown key %q", pinPath, fields[0])
		}
	}
	if err := sc.Err(); err != nil {
		return CorpusPin{}, fmt.Errorf("read corpus pin %s: %w", pinPath, err)
	}
	if !sawCount || !sawSHA {
		return CorpusPin{}, fmt.Errorf("corpus pin %s: must declare both 'count' and 'sha256'", pinPath)
	}
	return pin, nil
}

// parseCount parses a non-negative decimal integer.
func parseCount(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("non-digit %q", string(r))
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

// LoadExtraScenarios scans dir (any directory — e.g. a customer detector's
// own co-located detectors/<name>/scenarios/ sidecar, mallcoppro-f95) for
// scenario YAML files using the SAME leading-underscore skip and exam.Load
// parser scanCorpus applies to the pinned corpus, but performs NO pin
// verification and contributes NOTHING to any corpus.pin digest or count —
// this is the UNIONED, UNPINNED efficacy set RunExamDetectExtra grades
// alongside the reference corpus. It is never part of the reference corpus
// and never mutates it.
//
// dir == "" (no extra scenarios shipped) returns (nil, nil) — the caller's
// union is then just the reference corpus, unchanged.
func LoadExtraScenarios(dir string) ([]LoadedScenario, error) {
	if dir == "" {
		return nil, nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("extra scenarios dir %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("extra scenarios dir %s: not a directory", dir)
	}
	c, err := scanCorpus(dir)
	if err != nil {
		return nil, err
	}
	return c.Scenarios, nil
}

// Load scans the corpus under repoRoot, then HARD-VERIFIES it against the
// committed pin. This is the integrity interlock: a count OR sha mismatch returns
// an error and NOTHING runs. Both halves of the gate are reported in the error so
// a self-extension agent knows exactly what drifted.
//
// repoRoot is the directory holding exams/scenarios (the repo root). Callers
// resolve it via RepoRoot (walk up from the binary) or pin it in tests via
// SetRepoRootForTest — the same self-locating discipline §3.5 prescribes.
func Load(repoRoot string) (Corpus, error) {
	scenariosRoot := filepath.Join(repoRoot, scenariosRelPath)
	if fi, err := os.Stat(scenariosRoot); err != nil || !fi.IsDir() {
		return Corpus{}, fmt.Errorf("corpus root not found at %s: %w", scenariosRoot, err)
	}

	c, err := scanCorpus(scenariosRoot)
	if err != nil {
		return Corpus{}, err
	}

	pin, err := readPin(filepath.Join(repoRoot, pinRelPath))
	if err != nil {
		return Corpus{}, err
	}

	// HARD-FAIL the run on a count mismatch.
	if c.Count != pin.Count {
		return Corpus{}, fmt.Errorf(
			"CORPUS INTEGRITY FAIL: scenario count %d != pinned %d — a scenario was added/removed without updating %s; nothing runs (eval interlock)",
			c.Count, pin.Count, pinRelPath)
	}
	// HARD-FAIL the run on a digest mismatch.
	if c.SHA != pin.SHA {
		return Corpus{}, fmt.Errorf(
			"CORPUS INTEGRITY FAIL: corpus sha256 %s != pinned %s — a scenario's CONTENT changed without updating %s; nothing runs (eval interlock)",
			c.SHA, pin.SHA, pinRelPath)
	}

	return c, nil
}
