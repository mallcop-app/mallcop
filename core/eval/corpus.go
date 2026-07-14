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
// go:embed's own directory-embed default applies the IDENTICAL skip (files and
// dirs named "_*" or ".*" are excluded, recursively) — verified empirically and
// documented on corpusembed.go's ScenariosFS — so the embedded corpus (below)
// and the on-disk corpus always agree on which files are "in".
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
//
// # Disk-first / embed-last precedence
//
// scanCorpus and readPin operate over io/fs.FS rather than raw os calls, so the
// SAME walking, hashing, and pin-verification logic runs against either source:
//
//   - Load(repoRoot)  — os.DirFS(repoRoot): the on-disk corpus. This is what dev
//     and CI use, and it is what preserves edit-and-reload — a scenario edited on
//     disk is picked up on the next Load, no rebuild required.
//   - LoadEmbedded()  — mallcop.ScenariosFS (corpusembed.go, repo root): the
//     corpus baked into the binary at build time. This is the fallback for a
//     SHIPPED binary running in a customer deploy repo that has no
//     exams/scenarios directory on disk at all — RepoRoot() still resolves (the
//     customer repo has its own go.mod/.git marker), but Load(repoRoot) then
//     fails to find exams/scenarios under it. LoadEmbedded lets `mallcop eval` /
//     exam-detect run from the shipped reference corpus in that case.
//
// On-disk ALWAYS wins when present — callers that want the fallback behavior
// call Load first and fall back to LoadEmbedded only on a "corpus root not
// found" failure, never the other way around. Neither function silently
// prefers the embed; each is an explicit, separately-named entry point.
package eval

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/mallcop-app/mallcop"
	"github.com/mallcop-app/mallcop/internal/exam"
)

// scenariosRelPath is the corpus root relative to the repo root (disk) or the
// embed root (embedded) — identical in both cases because corpusembed.go embeds
// "exams/scenarios" from the repo root, the same relative path os.DirFS(repoRoot)
// resolves against on disk.
const scenariosRelPath = "exams/scenarios"

// pinRelPath is the committed pin file the loader verifies before running.
// It lives BESIDE the corpus so a scenario change and its pin update land
// together in one diff (the self-extension contract). It does not start with
// "_", so it is included in the embed exactly like any other corpus file.
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

// loadScenarioFromBytes parses scenario YAML bytes using the SAME parser and
// validation exam.Load applies to an on-disk file (ErrMissingID, ErrMissingFinding,
// etc.). exam.Load reads its own bytes from a filesystem path — it has no
// bytes-based entry point — so this bridges an fs.FS byte source (disk OR the
// embedded corpus, scanCorpus does not care which) into exam.Load via a
// short-lived scratch file. The bytes hit the EXACT SAME validation path
// scanCorpus has always used; there is no duplicated parse/validate logic here
// that could drift from internal/exam's rules.
func loadScenarioFromBytes(rel string, data []byte) (*exam.Scenario, error) {
	tmp, err := os.CreateTemp("", "mallcop-scenario-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("scratch file for %s: %w", rel, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("write scratch file for %s: %w", rel, err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close scratch file for %s: %w", rel, err)
	}

	sc, err := exam.Load(tmpPath)
	if err != nil {
		// exam.Load's error embeds tmpPath (a meaningless scratch location) —
		// wrap with rel so the operator sees the real corpus-relative path.
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	return sc, nil
}

// scanCorpus walks scenariosRoot under fsys, parses every included scenario, and
// returns the loaded set + digest. It applies the leading-underscore skip and
// computes each file's content hash. It does NOT verify the pin — that is
// loadFromFS's job (so tests can scan a tampered tree and observe the digest
// BEFORE the gate rejects it).
//
// fsys is either os.DirFS(repoRoot) (the on-disk corpus) or
// mallcop.ScenariosFS (the embedded corpus) — the walking, skip, and hashing
// logic is identical either way; only the byte source differs.
func scanCorpus(fsys fs.FS, scenariosRoot string) (Corpus, error) {
	var loaded []LoadedScenario

	err := fs.WalkDir(fsys, scenariosRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		// Skip the root itself.
		if p == scenariosRoot {
			return nil
		}
		// rel is p relative to scenariosRoot. scenariosRoot == "." (the
		// LoadExtraScenarios case, an arbitrary directory scanned via
		// os.DirFS(dir)) is the fs.FS convention for "the fsys root" — fs.FS
		// paths under it carry no "./" prefix to strip, so rel is just p.
		rel := p
		if scenariosRoot != "." {
			rel = strings.TrimPrefix(p, scenariosRoot+"/")
		}

		// LEADING-UNDERSCORE SKIP — files AND directories, any depth. On a
		// directory we return SkipDir so the whole subtree (e.g. _test/) is
		// pruned, not just the dir entry. (go:embed already prunes these from
		// the embedded fsys itself; this guard is a no-op there and the sole
		// enforcement point on disk.)
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

		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return fmt.Errorf("read scenario %s: %w", rel, err)
		}
		sum := sha256.Sum256(data)
		fileSHA := hex.EncodeToString(sum[:])

		sc, err := loadScenarioFromBytes(rel, data)
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

// readPin parses the committed pin file out of fsys. Format (two lines,
// order-free, '#' comments and blank lines ignored):
//
//	count <N>
//	sha256 <hex>
func readPin(fsys fs.FS, pinPath string) (CorpusPin, error) {
	data, err := fs.ReadFile(fsys, pinPath)
	if err != nil {
		return CorpusPin{}, fmt.Errorf("open corpus pin %s: %w (the eval interlock requires a committed pin)", pinPath, err)
	}

	var pin CorpusPin
	var sawCount, sawSHA bool
	sc := bufio.NewScanner(bytes.NewReader(data))
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
	// dir is an arbitrary absolute/relative OS path outside any repo-root-
	// relative fsys, so scan it directly via os.DirFS(dir) with an empty
	// (root) scenariosRoot.
	c, err := scanCorpus(os.DirFS(dir), ".")
	if err != nil {
		return nil, err
	}
	return c.Scenarios, nil
}

// verifyPin HARD-FAILS when the loaded corpus disagrees with the committed pin
// on either count or digest. Both halves of the gate are checked (and reported
// independently) so a self-extension agent knows exactly what drifted.
func verifyPin(c Corpus, pin CorpusPin) error {
	if c.Count != pin.Count {
		return fmt.Errorf(
			"CORPUS INTEGRITY FAIL: scenario count %d != pinned %d — a scenario was added/removed without updating %s; nothing runs (eval interlock)",
			c.Count, pin.Count, pinRelPath)
	}
	if c.SHA != pin.SHA {
		return fmt.Errorf(
			"CORPUS INTEGRITY FAIL: corpus sha256 %s != pinned %s — a scenario's CONTENT changed without updating %s; nothing runs (eval interlock)",
			c.SHA, pin.SHA, pinRelPath)
	}
	return nil
}

// loadFromFS is the shared implementation behind Load and LoadEmbedded: locate
// scenariosRelPath under fsys, scan it, read the pin, and verify. label is used
// only to make a "corpus root not found" error legible about WHICH source
// (a repo root path, or "embedded corpus") was consulted.
func loadFromFS(fsys fs.FS, label string) (Corpus, error) {
	if fi, err := fs.Stat(fsys, scenariosRelPath); err != nil || !fi.IsDir() {
		return Corpus{}, fmt.Errorf("corpus root not found under %s at %s: %w", label, scenariosRelPath, err)
	}

	c, err := scanCorpus(fsys, scenariosRelPath)
	if err != nil {
		return Corpus{}, err
	}

	pin, err := readPin(fsys, pinRelPath)
	if err != nil {
		return Corpus{}, err
	}

	if err := verifyPin(c, pin); err != nil {
		return Corpus{}, err
	}

	return c, nil
}

// Load scans the on-disk corpus under repoRoot, then HARD-VERIFIES it against
// the committed pin. This is the PRIMARY, disk-first entry point: dev and CI
// always resolve here, and an on-disk corpus always wins over the embed —
// editing a scenario on disk is picked up on the very next Load call, no
// rebuild required.
//
// repoRoot is the directory holding exams/scenarios (the repo root). Callers
// resolve it via RepoRoot (walk up from the binary) or pin it in tests via
// SetRepoRootForTest — the same self-locating discipline §3.5 prescribes.
//
// A repoRoot that resolves (a valid go.mod/.git marker) but carries no
// exams/scenarios directory — the shipped-binary-in-a-customer-repo case —
// returns a "corpus root not found" error; callers that want the embedded
// fallback in that case call LoadEmbedded explicitly (see LoadEmbedded's doc).
func Load(repoRoot string) (Corpus, error) {
	c, err := loadFromFS(os.DirFS(repoRoot), repoRoot)
	if err != nil {
		return Corpus{}, err
	}
	return c, nil
}

// LoadEmbedded scans the corpus baked into the binary at build time
// (mallcop.ScenariosFS, corpusembed.go at the repo root) and HARD-VERIFIES it
// against the SAME committed pin Load checks — the embedded corpus.pin is
// byte-identical to the on-disk one (both are produced by the same //go:embed
// exams/scenarios directive, which embeds corpus.pin alongside the scenario
// files since "corpus.pin" does not begin with "_").
//
// This is the FALLBACK entry point for a shipped mallcop binary running `eval` /
// exam-detect inside a customer deploy repo that has no exams/scenarios
// directory on disk at all: RepoRoot() still resolves there (the customer repo
// has its own go.mod or .git marker), so Load(repoRoot) fails with "corpus root
// not found" rather than an unresolvable-root error. LoadEmbedded lets that
// failure mode still produce a working eval, from the exact reference corpus
// the binary shipped with.
//
// LoadEmbedded never reads the filesystem — it is unaffected by
// MALLCOP_REPO_ROOT and cannot pick up an edited on-disk scenario. Callers that
// want disk-first-with-embedded-fallback semantics call Load first and use
// LoadEmbedded only when Load fails to locate the corpus root — never the
// reverse, so dev edit-and-reload is always preserved.
func LoadEmbedded() (Corpus, error) {
	c, err := loadFromFS(mallcop.ScenariosFS, "embedded corpus")
	if err != nil {
		return Corpus{}, fmt.Errorf("load embedded corpus: %w", err)
	}
	return c, nil
}
