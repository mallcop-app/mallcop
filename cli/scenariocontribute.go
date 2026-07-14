// scenariocontribute.go — `mallcop scenario contribute` (mallcoppro-c78, corpus-
// expansion axis iii): the OPT-IN commons. An operator who captured (or hand-
// authored) a valuable scenario in their own LOCAL scenarios/ directory can
// offer it to the shared, shipped reference corpus. This mirrors the detector
// contribute-back shape (sandbox -> gate -> PR -> review): sanitize locally,
// show the operator exactly what would leave the machine, and — only on
// explicit confirmation — open a normal, REVIEWED pull request. NOTHING here
// auto-merges; OSS review is the gate at every autonomy-dial setting (mallcop-
// pro d70 ruling: contribute-back stays reviewed).
//
// Multi-pass sanitize (deterministic — the SAME input file always produces
// the SAME sanitized output, so re-running `contribute` on an unchanged file
// is idempotent). Pass ORDER is load-bearing:
//
//  0. RAW STRIP + SECRET pass: every event's raw: payload is dropped
//     wholesale, and secret-shaped metadata values (credentials, tokens,
//     connection strings) are scrubbed by REUSING scenariocapture.go's
//     scrubPayloadMap — the same helper that survived two adversarial review
//     rounds in C5 (#190); it is not forked. Runs FIRST so no later pass
//     ever handles (or accidentally preserves spans of) a live credential.
//  1. IDENTITY pass: every distinct actor value found anywhere in the
//     scenario (events, finding metadata, actor_chain, baseline known_entities/
//     actor_roles/actor_hours/relationships) is renamed to a canonical corpus-
//     style token (ci-bot, admin-user, deploy-svc, ... — the SAME flavor of
//     token the shipped corpus already uses, e.g. exams/scenarios/behavioral/
//     VA-03-data-exfil.yaml), in FIRST-SEEN document order so the mapping is
//     reproducible. The rename also runs as a substring pass over prose
//     fields (trap_description, trap_resolved_means, finding.title,
//     reasoning_must_mention/not_mention, event targets) AND over EVERY
//     metadata string value and map key at ANY nesting depth (event metadata,
//     finding metadata, connector_tool returns) — capture copies event
//     payloads WHOLESALE into metadata, so an actor name inside a payload
//     field must not survive just because it wasn't in a structured field.
//  2. IDENTIFIER pass: residual identifier-shaped substrings — UUIDs, email
//     addresses, hostnames/FQDNs, IPv4 addresses, and long all-hex/digit
//     runs (subscription ids, cloud account ids) — in event/actor-chain
//     targets, baseline relationship keys, prose fields, and EVERY metadata
//     string value (and map key) at ANY nesting depth are replaced with a
//     deterministic content-hash token (sub-<hash8>, id-<hash8>,
//     host-<hash8>.example, ip-<hash8>, user-<hash8>@example.com). ONE hash
//     cache spans the whole document, so the SAME original identifier always
//     maps to the SAME token everywhere — a subscription UUID in an event
//     target and that same UUID in metadata.tenant agree (VA-03's
//     "sub-169efd95" convention). A metadata value under an identifier-
//     carrying KEY (email, ip, host, tenant, account, ...) that matches no
//     shape pattern is tokenized WHOLESALE — the same never-leak key-net
//     safety idea scrubPayloadMap applies to credential-shaped keys.
//
// TRANSMIT-TIME RESIDUE CHECK: after the sanitized YAML and the PR body are
// assembled, every ORIGINAL value in the redaction ledger is grep-verified
// ABSENT from both artifacts (verifyLedgerResidue). A hit hard-fails plan
// assembly — nothing is shown as safe, nothing can be sent. The PR body's
// "raw values never left" statement is generated from this check passing,
// never merely asserted. Over-redaction bias throughout: for a shared corpus
// fixture, a false-positive redaction is always preferable to a leak.
//
// Timestamps are shifted by a single constant so every relative delta in the
// document — fine-grained event spacing AND baseline relationship first_seen/
// last_seen history — is preserved exactly, while the earliest event lands on
// the corpus's canonical 2026-03 window (anchored at VA-03's own start,
// 2026-03-10T08:00:00Z). Timing/volume detectors grade on these deltas, not
// absolute wall-clock time, so this is a lossless transform for grading
// purposes.
//
// R2/R9-equivalent constraint: contribution is a COPY. The operator's local
// scenario file is never written to — sanitize operates on an in-memory deep
// copy (via a yaml marshal/unmarshal round trip), and the raw bytes never
// leave the machine until (and unless) the operator passes --yes.
package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/internal/exam"
)

// contributeDefaultRepo is the target OSS repo `mallcop scenario contribute`
// opens a PR against when --repo is not given.
const contributeDefaultRepo = "mallcop-app/mallcop"

// scenariosRelPathPrefix turns a corpus-manifest-relative path (e.g.
// "behavioral/CONTRIB-....yaml" — the exact convention
// core/eval.LoadedScenario.RelPath uses) into the FULL repo-relative path
// used for file placement and display.
const scenariosRelPathPrefix = "exams/scenarios/"

// contributeAnchorTime is the corpus's canonical window anchor — the earliest
// event timestamp in a contributed scenario is shifted to land exactly here,
// matching exams/scenarios/behavioral/VA-03-data-exfil.yaml's own start.
const contributeAnchorTime = "2026-03-10T08:00:00Z"

// contributeCanonicalActorPool: canonical, corpus-flavored actor tokens,
// assigned in FIRST-SEEN order to the distinct actor values found in a
// contributed scenario. Drawn from the actor vocabulary already present
// across exams/scenarios/*/*.yaml (ci-bot, admin-user, deploy-svc,
// tf-automation, ...) so a contributed scenario reads like a hand-curated one.
var contributeCanonicalActorPool = []string{
	"ci-bot", "admin-user", "deploy-svc", "tf-automation", "ops-engineer",
	"sre-engineer", "infra-admin", "contrib-user", "report-svc", "batch-processor",
	"on-call-system", "org-owner", "dev-user", "svc-account", "integration-bot",
	"backup-svc", "audit-bot", "release-bot", "support-agent", "vendor-user",
}

// contributeFamilyCategory is a best-effort detector-family -> corpus
// directory map, built from the family/category pairing already observed
// across the shipped corpus. A family not listed here (or a scenario that
// legitimately spans several families) falls back to contributeDefaultCategory
// — "cross_cutting" is already the corpus's own catch-all for exactly that
// case (see exams/scenarios/cross_cutting/*.yaml).
var contributeFamilyCategory = map[string]string{
	"new-external-access":     "access",
	"auth-failure-burst":      "auth",
	"unusual-resource-access": "behavioral",
	"unusual-timing":          "behavioral",
	"unusual-login":           "behavioral",
	"volume-anomaly":          "behavioral",
	"rate-anomaly":            "behavioral",
	"exfil-pattern":           "behavioral",
	"new-actor":               "identity",
	"priv-escalation":         "privilege",
	"injection-probe":         "signature",
	"malicious-skill":         "signature",
	"secrets-exposure":        "signature",
	"log-format-drift":        "structural",
	"config-drift":            "structural",
	"dependency-tamper":       "structural",
	"git-oops":                "structural",
}

// contributeDefaultCategory is the fallback corpus directory for a family not
// present in contributeFamilyCategory.
const contributeDefaultCategory = "cross_cutting"

// --- identifier scrub patterns -----------------------------------------------
//
// Shape patterns for identifiers that must never leave the machine. Bias
// matches scenariocapture.go's scrub: over-redaction of an occasional benign
// token (a dotted filename that reads like an FQDN, a long numeric run that
// happens not to be an account id) beats residue — for a shared corpus
// fixture, a false-positive redaction is always preferable to a leak.
var (
	contributeUUIDRE           = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	contributeEmailRE          = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	contributeSubPrefixedHexRE = regexp.MustCompile(`(?i)\bsub-[0-9a-fA-F]{8}\b`)
	contributeHexRunRE         = regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`)
	// Hostname/FQDN: two or more dot-separated labels with an ALPHABETIC final
	// label (so version strings like "2.55.0" never match). Candidates whose
	// final label is a common file extension are filtered out in code
	// (contributeFilenameExtensions) since RE2 has no negative lookahead.
	contributeHostnameRE = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
	// IPv4, including private/internal addresses. Documentation-range
	// addresses (RFC 5737) are scrubbed too — over-redaction bias.
	contributeIPv4RE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

// contributeFilenameExtensions: a hostname-pattern candidate whose FINAL label
// is one of these is a dotted filename, not an FQDN — skipped so metadata like
// "policy.json" or "backup.tar.gz" isn't shredded. Anything not listed here
// still gets scrubbed (over-redaction bias — an exotic real TLD beats a leak).
var contributeFilenameExtensions = map[string]bool{
	"json": true, "yaml": true, "yml": true, "txt": true, "log": true, "md": true,
	"csv": true, "xml": true, "html": true, "htm": true, "js": true, "mjs": true,
	"ts": true, "tsx": true, "jsx": true, "py": true, "go": true, "rb": true,
	"sh": true, "exe": true, "dll": true, "gz": true, "tar": true, "zip": true,
	"tgz": true, "pdf": true, "png": true, "jpg": true, "jpeg": true, "gif": true,
	"svg": true, "ico": true, "css": true, "lock": true, "toml": true, "ini": true,
	"cfg": true, "conf": true, "bak": true, "tmp": true, "sql": true, "db": true,
	"pem": true, "crt": true, "key": true, "pub": true, "jar": true, "war": true,
	"sock": true, "service": true, "timer": true, "rs": true, "c": true, "h": true,
	"cpp": true, "java": true, "php": true, "wasm": true, "bin": true,
}

// contributeIdentifierKeyTokens: a metadata KEY whose underscore/dash-split
// tokens include any of these carries an identifying value — the value is
// tokenized WHOLESALE when no shape pattern recognized it (and numeric values,
// which shape patterns can't see, are tokenized too). The metadata twin of
// scrubPayloadMap's captureSensitiveKeySubstrings net, but emitting a
// deterministic equality-preserving token instead of [REDACTED] so
// cross-event correlation survives.
var contributeIdentifierKeyTokens = map[string]bool{
	"email": true, "mail": true, "ip": true, "ipaddr": true, "ipaddress": true,
	"host": true, "hostname": true, "fqdn": true, "domain": true, "tenant": true,
	"subscription": true, "account": true, "actor": true, "username": true,
	"collaborator": true, "peer": true, "principal": true,
}

// contributeIdentifierKeyExcludeTokens: a key containing one of these tokens
// is a MEASUREMENT over an identifier, not the identifier itself
// ("peer_count", "login_hours") — tokenizing its (numeric) value would corrupt
// exactly the frequency/timing data detectors grade on, so the key net skips
// it. Shape patterns still apply to its string values.
var contributeIdentifierKeyExcludeTokens = map[string]bool{
	"count": true, "total": true, "num": true, "ratio": true, "hours": true,
	"window": true, "size": true, "duration": true, "len": true, "agent": true,
}

// runScenarioContribute implements `mallcop scenario contribute`. Flags MUST
// precede the positional scenario file path (the same convention `mallcop
// improve` uses for its free-text argument): the standard library flag
// package stops parsing at the first non-flag argument.
func runScenarioContribute(args []string) error {
	fs := flag.NewFlagSet("scenario contribute", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "Confirm: open the PR after showing the redaction diff (required unless --dry-run)")
	dryRun := fs.Bool("dry-run", false, "Assemble and print the redaction diff + would-be PR content; NEVER opens a PR or touches the network, regardless of --yes")
	allowAuthored := fs.Bool("allow-authored", false, "Allow contributing a provenance:authored scenario (refused by default — author-independence)")
	repo := fs.String("repo", contributeDefaultRepo, "owner/name of the target GitHub repo")
	referenceRepo := fs.String("reference-repo", "", "Path to a local checkout of the target repo, used as the base corpus for pin regen (default: this binary's own embedded reference corpus)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	posArgs := fs.Args()
	if len(posArgs) != 1 {
		return fmt.Errorf("scenario contribute: usage: mallcop scenario contribute [--yes] [--dry-run] [--allow-authored] [--repo owner/name] [--reference-repo <path>] <scenarios/file.yaml>")
	}
	srcPath := posArgs[0]

	if _, _, ok := splitOwnerRepo(*repo); !ok {
		return fmt.Errorf("scenario contribute: --repo must be \"owner/name\", got %q", *repo)
	}

	sc, err := exam.Load(srcPath)
	if err != nil {
		return fmt.Errorf("scenario contribute: %w", err)
	}
	// Literal check against the raw field (NOT EffectiveProvenance): an empty
	// provenance defaults to "reference" for the shipped corpus's own
	// historical scenarios, which is not what a local operator file usually
	// means and is not what the spec asks this gate to catch. Only an
	// EXPLICIT provenance: authored is refused.
	if sc.Provenance == exam.ProvenanceAuthored && !*allowAuthored {
		return fmt.Errorf("scenario contribute: %s has provenance:authored -- refused by default (the commons should predominantly grow from operator/captured ground truth, not detector-author fixtures); pass --allow-authored to override", sc.ID)
	}

	plan, err := buildContributePlan(sc, srcPath, *repo, *referenceRepo)
	if err != nil {
		return fmt.Errorf("scenario contribute: %w", err)
	}

	printContributePlan(plan)

	if *dryRun {
		fmt.Println()
		fmt.Println("--dry-run: no PR opened, nothing left this machine.")
		return nil
	}
	if !*yes {
		fmt.Println()
		fmt.Println("Re-run with --yes to open a PR with the content shown above, or --dry-run to preview without confirming.")
		return nil
	}

	return openContributePR(plan)
}

// --- plan assembly ------------------------------------------------------------

// contributeRename is one entry in the local review diff: an original value
// and the canonical token it was replaced with.
type contributeRename struct {
	Original  string
	Canonical string
}

// contributeDiff is the REDACTION LEDGER — the full local-review summary,
// shown to the operator on stdout BEFORE anything leaves the machine, and the
// input to verifyLedgerResidue (the transmit-time guarantee that no Original
// value survives in anything that would be sent). Every rename/redaction the
// sanitizer performs is enumerated here — the consent surface must never
// under-report what leaves. The PR body (renderContributePRBody) carries only
// COUNTS derived from this struct (len of the slices), never the Original
// values, since the PR body does leave the machine.
type contributeDiff struct {
	// ActorRenames: every actor original -> canonical corpus token (identity
	// mappings excluded — nothing changed, nothing to consent to).
	ActorRenames []contributeRename
	// IdentifierRenames: every identifier original -> deterministic token,
	// from EVERY scrubbed surface: targets, relationship keys, prose, and all
	// metadata values/keys at any nesting depth.
	IdentifierRenames []contributeRename
	// SecretPaths: the document path of every metadata value the C5 secret
	// scrub redacted (e.g. "events[0].metadata.github_token"). Paths, not
	// values — the diff must never display a live credential.
	SecretPaths       []string
	TimestampsShifted int
	ShiftDuration     time.Duration
}

// contributePinDiff is the corpus.pin delta a contribution would produce.
type contributePinDiff struct {
	OldCount int
	NewCount int
	OldSHA   string
	NewSHA   string
	NewLine  string // the new manifest line: "<relpath>  <filesha>"
}

// contributePlan is the fully-assembled, ready-to-review-or-open contribution.
type contributePlan struct {
	SourcePath     string
	ScenarioID     string // the operator's original local id
	NewID          string // the canonical contributed id
	RelPath        string // exams/scenarios/<category>/<id>.yaml
	Repo           string
	Branch         string
	SanitizedYAML  []byte
	Diff           contributeDiff
	Pin            contributePinDiff
	PRTitle        string
	PRBody         string
	AttackScenario bool
	Family         string
}

// buildContributePlan sanitizes sc, resolves its target corpus location,
// regenerates the corpus.pin delta against the base corpus (a live checkout
// via referenceRepo, or this binary's own embedded reference corpus when
// referenceRepo is ""), and assembles the PR title/body. It performs NO I/O
// beyond reading the base corpus — no network, no writes.
func buildContributePlan(sc *exam.Scenario, srcPath, repo, referenceRepo string) (*contributePlan, error) {
	family, isAttack := contributePrimaryFamily(sc)
	if family == "" {
		return nil, fmt.Errorf("scenario %s has no expected_detection must_fire/must_not_fire family -- nothing to contribute", sc.ID)
	}

	sanitized, diff, err := sanitizeScenarioForContribution(sc)
	if err != nil {
		return nil, fmt.Errorf("sanitizing %s: %w", sc.ID, err)
	}
	sanitized.Provenance = exam.ProvenanceContributed
	category := categoryForFamily(family)
	sanitized.Category = category

	// Content-hash the sanitized doc (BEFORE stamping its own id, so the id
	// doesn't feed its own hash) to derive a stable, collision-resistant id.
	prelim, err := yaml.Marshal(sanitized)
	if err != nil {
		return nil, fmt.Errorf("marshal sanitized scenario: %w", err)
	}
	hash8 := contentHashToken(string(prelim), 8)
	newID := fmt.Sprintf("CONTRIB-%s-%s", slugifyCaptureToken(family), hash8)
	sanitized.ID = newID
	if sanitized.Finding != nil {
		sanitized.Finding.ID = newID + "-finding"
	}

	out, err := yaml.Marshal(sanitized)
	if err != nil {
		return nil, fmt.Errorf("marshal final sanitized scenario: %w", err)
	}
	// The header deliberately does NOT cite the operator's original local
	// scenario id: this file leaves the machine, and a local id can itself
	// carry identifying content (an actor name in a hand-chosen --id). The
	// old->new id mapping is shown locally by printContributePlan instead.
	header := "# Contributed via `mallcop scenario contribute` from an operator's local corpus.\n" +
		"# Sanitized: actors/targets/identifiers canonicalized (including every metadata\n" +
		"# value at any depth), secret-shaped metadata redacted, raw payloads stripped,\n" +
		"# timestamps shifted onto the corpus's 2026-03 window preserving relative\n" +
		"# deltas. See the PR body for the redaction summary.\n"
	sanitizedBytes := append([]byte(header), out...)

	// manifestPath is relative to exams/scenarios/ (e.g. "behavioral/CONTRIB-
	// ....yaml") -- the EXACT convention core/eval/corpus.go's
	// LoadedScenario.RelPath uses (see its doc: "the corpus-relative path (e.g.
	// auth/AF-01-fat-finger-benign.yaml)"). This is the string that must feed
	// the manifest/pin math. relpath is the FULL repo-relative path (with the
	// exams/scenarios/ prefix) used for file placement and display.
	manifestPath := fmt.Sprintf("%s/%s.yaml", category, newID)
	relpath := scenariosRelPathPrefix + manifestPath

	base, err := contributeBaseCorpus(referenceRepo)
	if err != nil {
		return nil, fmt.Errorf("loading base corpus for pin regen: %w", err)
	}
	fileSum := sha256.Sum256(sanitizedBytes)
	fileSHA := hex.EncodeToString(fileSum[:])
	pin, err := computeContributePin(base, manifestPath, fileSHA)
	if err != nil {
		return nil, err
	}

	branch := "contribute/" + newID
	title := fmt.Sprintf("scenario: contribute %s (%s)", newID, family)
	body := renderContributePRBody(newID, family, isAttack, relpath, diff, pin)

	// TRANSMIT-TIME RESIDUE CHECK (fail-closed): every original value in the
	// redaction ledger must be absent from BOTH transmit-bound artifacts — the
	// sanitized YAML and the PR body. The PR body's "raw values never left"
	// line is true because this check passed, not because it was asserted.
	if err := verifyLedgerResidue("the sanitized scenario YAML", sanitizedBytes, diff); err != nil {
		return nil, err
	}
	if err := verifyLedgerResidue("the PR body", []byte(body), diff); err != nil {
		return nil, err
	}

	return &contributePlan{
		SourcePath: srcPath, ScenarioID: sc.ID, NewID: newID, RelPath: relpath,
		Repo: repo, Branch: branch, SanitizedYAML: sanitizedBytes, Diff: diff, Pin: pin,
		PRTitle: title, PRBody: body, AttackScenario: isAttack, Family: family,
	}, nil
}

// contributePrimaryFamily returns the scenario's primary detector family
// (must_fire[0], or must_not_fire[0] when there is no must_fire — a pure
// benign-twin contribution) and whether it is an attack (must_fire) label.
func contributePrimaryFamily(sc *exam.Scenario) (family string, isAttack bool) {
	if sc.ExpectedDetection == nil {
		return "", false
	}
	if len(sc.ExpectedDetection.MustFire) > 0 {
		return strings.ToLower(strings.TrimSpace(sc.ExpectedDetection.MustFire[0])), true
	}
	if len(sc.ExpectedDetection.MustNotFire) > 0 {
		return strings.ToLower(strings.TrimSpace(sc.ExpectedDetection.MustNotFire[0])), false
	}
	return "", false
}

// categoryForFamily maps a detector family token to its corpus directory.
func categoryForFamily(family string) string {
	family = strings.ToLower(strings.TrimSpace(family))
	if cat, ok := contributeFamilyCategory[family]; ok {
		return cat
	}
	return contributeDefaultCategory
}

// contributeBaseCorpus loads the corpus a contribution's pin regen is
// computed against: a live checkout at referenceRepo when given, otherwise
// this binary's own embedded reference corpus (mallcop.ScenariosFS via
// eval.LoadEmbedded) — the exact corpus the shipped binary was built from,
// which needs no network access and is always available.
func contributeBaseCorpus(referenceRepo string) (eval.Corpus, error) {
	if strings.TrimSpace(referenceRepo) != "" {
		return eval.Load(referenceRepo)
	}
	return eval.LoadEmbedded()
}

// computeContributePin regenerates the corpus.pin delta a contribution would
// produce: base's manifest plus one new "<relpath>  <filesha>" line,
// re-sorted by RelPath (the IDENTICAL construction core/eval/corpus.go's
// scanCorpus + Manifest use), re-hashed. relpath MUST be manifest-relative
// (relative to exams/scenarios/, e.g. "behavioral/CONTRIB-....yaml") — the
// same convention base.Scenarios[].RelPath already uses; passing a path with
// the exams/scenarios/ prefix would silently compute against the wrong key
// space. Errors if relpath already exists in the base corpus.
func computeContributePin(base eval.Corpus, relpath, fileSHA string) (contributePinDiff, error) {
	for _, s := range base.Scenarios {
		if s.RelPath == relpath {
			return contributePinDiff{}, fmt.Errorf("a scenario already exists at %s in the base corpus -- choose a different id", relpath)
		}
	}

	type entry struct{ RelPath, FileSHA string }
	entries := make([]entry, 0, len(base.Scenarios)+1)
	for _, s := range base.Scenarios {
		entries = append(entries, entry{s.RelPath, s.FileSHA})
	}
	entries = append(entries, entry{relpath, fileSHA})
	sort.Slice(entries, func(i, j int) bool { return entries[i].RelPath < entries[j].RelPath })

	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.RelPath)
		b.WriteString("  ")
		b.WriteString(e.FileSHA)
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))

	return contributePinDiff{
		OldCount: base.Count,
		NewCount: base.Count + 1,
		OldSHA:   base.SHA,
		NewSHA:   hex.EncodeToString(sum[:]),
		NewLine:  relpath + "  " + fileSHA,
	}, nil
}

// contentHashToken returns the first n hex characters of sha256(s) —
// deterministic: the same input always produces the same token.
func contentHashToken(s string, n int) string {
	sum := sha256.Sum256([]byte(s))
	tok := hex.EncodeToString(sum[:])
	if n > len(tok) {
		n = len(tok)
	}
	return tok[:n]
}

// --- sanitize -----------------------------------------------------------------

// deepCopyScenario returns a fully independent copy of sc via a yaml marshal/
// unmarshal round trip, so sanitizing the copy can never mutate sc (and
// therefore can never touch the operator's original file on disk) — R2/R9-
// equivalent: contribution is a COPY.
//
// Every metadata tree in the copy is then NORMALIZED to plain map[string]any/
// []any (normalizeMetadataTree): yaml.v3 propagates a NAMED map type (e.g.
// exam.EventMetadata) to nested mappings it decodes into `any` holes, and a
// `case map[string]any:` type switch does NOT match a named map type — so
// without normalization, every recursive scrubber in the sanitize pipeline
// (the C5 secret scrub's scrubMetadataValue included) would silently SKIP
// nested metadata blocks. Caught by this build's own transmit-time residue
// check on a nested-hostname fixture; the normalization is the fix.
func deepCopyScenario(sc *exam.Scenario) (*exam.Scenario, error) {
	data, err := yaml.Marshal(sc)
	if err != nil {
		return nil, fmt.Errorf("deep-copy marshal: %w", err)
	}
	var cp exam.Scenario
	if err := yaml.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("deep-copy unmarshal: %w", err)
	}

	if cp.Finding != nil && cp.Finding.Metadata != nil {
		cp.Finding.Metadata = normalizeMetadataTree(map[string]any(cp.Finding.Metadata)).(map[string]any)
	}
	for i := range cp.Events {
		if cp.Events[i].Metadata != nil {
			cp.Events[i].Metadata = normalizeMetadataTree(map[string]any(cp.Events[i].Metadata)).(map[string]any)
		}
	}
	for i := range cp.ConnectorTools {
		if cp.ConnectorTools[i].Returns != nil {
			cp.ConnectorTools[i].Returns = normalizeMetadataTree(map[string]any(cp.ConnectorTools[i].Returns)).(map[string]any)
		}
	}
	return &cp, nil
}

// normalizeMetadataTree recursively rebuilds every map (WHATEVER its named Go
// type — reflection on Kind, not a type switch) as a plain map[string]any and
// every slice/array as []any, so downstream `case map[string]any:` /
// `case []any:` type switches reliably reach every nesting level. Scalars
// pass through unchanged.
func normalizeMetadataTree(v any) any {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		out := make(map[string]any, rv.Len())
		for _, k := range rv.MapKeys() {
			out[fmt.Sprint(k.Interface())] = normalizeMetadataTree(rv.MapIndex(k).Interface())
		}
		return out
	case reflect.Slice, reflect.Array:
		out := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out[i] = normalizeMetadataTree(rv.Index(i).Interface())
		}
		return out
	default:
		return v
	}
}

// sanitizeScenarioForContribution returns a sanitized deep copy of sc plus
// the redaction ledger describing every rename/redaction/shift performed. sc
// itself is never mutated. Pass order (see the package doc — load-bearing):
// raw strip + secret scrub FIRST, then actor renames, then identifier scrub,
// then the timestamp shift.
func sanitizeScenarioForContribution(sc *exam.Scenario) (*exam.Scenario, contributeDiff, error) {
	out, err := deepCopyScenario(sc)
	if err != nil {
		return nil, contributeDiff{}, err
	}

	// Pass 0a: strip raw payloads wholesale (C8 spec: "strip raw payloads").
	// The raw block is the unparsed connector payload — it can contain
	// anything, so no pattern scrub is trustworthy on it; drop it entirely.
	for i := range out.Events {
		out.Events[i].Raw = nil
	}

	// Pass 0b: C5 secret scrub over every metadata surface — FIRST, so no
	// later pass ever handles a live credential.
	secretPaths := scrubScenarioMetadata(out)

	// Pass 1: actor canonicalization (structured fields + prose + every
	// metadata string at any depth).
	actorMap := buildContributeActorMap(out)
	var actorRenames []contributeRename
	for orig, canon := range actorMap {
		if orig == canon {
			continue
		}
		actorRenames = append(actorRenames, contributeRename{Original: orig, Canonical: canon})
	}
	sort.Slice(actorRenames, func(i, j int) bool { return actorRenames[i].Original < actorRenames[j].Original })
	applyActorRenames(out, actorMap)

	// Pass 2: identifier scrub. canonActors lets the metadata key-net skip
	// values the actor pass ALREADY canonicalized — re-tokenizing "ci-bot"
	// into id-... would destroy the intentional actor mapping.
	canonActors := make(map[string]bool, len(actorMap))
	for _, canon := range actorMap {
		canonActors[canon] = true
	}
	identifierRenames := applyIdentifierRenames(out, canonActors)

	// Pass 3: timestamp shift onto the canonical corpus window.
	shift, shiftedCount := shiftScenarioTimestamps(out)

	diff := contributeDiff{
		ActorRenames:      actorRenames,
		IdentifierRenames: identifierRenames,
		SecretPaths:       secretPaths,
		TimestampsShifted: shiftedCount,
		ShiftDuration:     shift,
	}
	return out, diff, nil
}

// collectContributeActors returns every distinct, non-empty actor value in
// sc, in a FIXED deterministic order (events in file order, then finding
// metadata, then actor_chain in file order, then baseline actors in file
// order, then actor_roles/actor_hours/relationship-actor keys sorted — map
// keys have no file order, so they are explicitly sorted for reproducibility).
func collectContributeActors(sc *exam.Scenario) []string {
	seen := map[string]bool{}
	var order []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		order = append(order, v)
	}

	for _, ev := range sc.Events {
		add(ev.Actor)
	}
	if sc.Finding != nil && sc.Finding.Metadata != nil {
		if a, ok := sc.Finding.Metadata["actor"].(string); ok {
			add(a)
		}
	}
	for _, ac := range sc.ActorChain {
		add(ac.Actor)
	}
	if sc.Baseline != nil {
		for _, a := range sc.Baseline.KnownEntities.Actors {
			add(a)
		}
		var roleKeys []string
		for k := range sc.Baseline.KnownEntities.ActorRoles {
			roleKeys = append(roleKeys, k)
		}
		sort.Strings(roleKeys)
		for _, k := range roleKeys {
			add(k)
		}

		var hourKeys []string
		for k := range sc.Baseline.KnownEntities.ActorHours {
			hourKeys = append(hourKeys, k)
		}
		sort.Strings(hourKeys)
		for _, k := range hourKeys {
			add(k)
		}

		var relKeys []string
		for k := range sc.Baseline.Relationships {
			relKeys = append(relKeys, k)
		}
		sort.Strings(relKeys)
		for _, k := range relKeys {
			actor, _, ok := strings.Cut(k, ":")
			if ok {
				add(actor)
			}
		}
	}
	return order
}

// buildContributeActorMap assigns each distinct actor a canonical token from
// contributeCanonicalActorPool, in first-seen order; overflow beyond the pool
// falls back to a deterministic content-hash token.
func buildContributeActorMap(sc *exam.Scenario) map[string]string {
	actors := collectContributeActors(sc)
	m := make(map[string]string, len(actors))
	for i, a := range actors {
		if i < len(contributeCanonicalActorPool) {
			m[a] = contributeCanonicalActorPool[i]
		} else {
			m[a] = "actor-" + contentHashToken(a, 6)
		}
	}
	return m
}

// applyActorRenames rewrites every structured actor field via exact-value
// lookup, then does a longest-first substring pass over prose/target fields
// so an actor name mentioned outside a structured field doesn't survive.
func applyActorRenames(sc *exam.Scenario, actorMap map[string]string) {
	rename := func(s string) string {
		if canon, ok := actorMap[s]; ok {
			return canon
		}
		return s
	}

	for i := range sc.Events {
		sc.Events[i].Actor = rename(sc.Events[i].Actor)
	}
	if sc.Finding != nil && sc.Finding.Metadata != nil {
		if a, ok := sc.Finding.Metadata["actor"].(string); ok {
			sc.Finding.Metadata["actor"] = rename(a)
		}
	}
	for i := range sc.ActorChain {
		sc.ActorChain[i].Actor = rename(sc.ActorChain[i].Actor)
	}
	if sc.Baseline != nil {
		for i, a := range sc.Baseline.KnownEntities.Actors {
			sc.Baseline.KnownEntities.Actors[i] = rename(a)
		}
		sc.Baseline.KnownEntities.ActorRoles = renameActorRoleKeys(sc.Baseline.KnownEntities.ActorRoles, actorMap)
		sc.Baseline.KnownEntities.ActorHours = renameActorHourKeys(sc.Baseline.KnownEntities.ActorHours, actorMap)
		sc.Baseline.Relationships = renameRelationshipActorKeys(sc.Baseline.Relationships, actorMap)
	}

	// Longest-original-first substring pass: prevents a short actor value
	// (e.g. "admin") from mangling a longer one that contains it as a
	// substring (e.g. "admin-jane") before the longer one gets its turn.
	origs := make([]string, 0, len(actorMap))
	for o := range actorMap {
		if o != "" {
			origs = append(origs, o)
		}
	}
	sort.Slice(origs, func(i, j int) bool { return len(origs[i]) > len(origs[j]) })
	substProse := func(s string) string {
		for _, o := range origs {
			s = strings.ReplaceAll(s, o, actorMap[o])
		}
		return s
	}

	sc.TrapDescription = substProse(sc.TrapDescription)
	sc.TrapResolvedMeans = substProse(sc.TrapResolvedMeans)
	if sc.Finding != nil {
		sc.Finding.Title = substProse(sc.Finding.Title)
	}
	if sc.ExpectedResolution != nil {
		for i, m := range sc.ExpectedResolution.ReasoningMustMention {
			sc.ExpectedResolution.ReasoningMustMention[i] = substProse(m)
		}
		for i, m := range sc.ExpectedResolution.ReasoningMustNotMention {
			sc.ExpectedResolution.ReasoningMustNotMention[i] = substProse(m)
		}
	}
	for i := range sc.Events {
		sc.Events[i].Target = substProse(sc.Events[i].Target)
	}
	for i := range sc.ActorChain {
		sc.ActorChain[i].Target = substProse(sc.ActorChain[i].Target)
	}

	// Metadata walk: capture copies event payloads WHOLESALE into metadata, so
	// an actor name can sit in ANY payload field (collaborator, granted_by,
	// requested_for, ...) at ANY nesting depth — the substring pass must reach
	// every metadata string VALUE and map KEY (a payload map keyed by actor,
	// e.g. per-actor tallies, is a leak through the key).
	if sc.Finding != nil && len(sc.Finding.Metadata) > 0 {
		sc.Finding.Metadata = renameActorsInAnyValue(map[string]any(sc.Finding.Metadata), substProse).(map[string]any)
	}
	for i := range sc.Events {
		if len(sc.Events[i].Metadata) > 0 {
			sc.Events[i].Metadata = renameActorsInAnyValue(map[string]any(sc.Events[i].Metadata), substProse).(map[string]any)
		}
	}
	for i := range sc.ConnectorTools {
		if len(sc.ConnectorTools[i].Returns) > 0 {
			sc.ConnectorTools[i].Returns = renameActorsInAnyValue(map[string]any(sc.ConnectorTools[i].Returns), substProse).(map[string]any)
		}
	}
}

// renameActorsInAnyValue applies subst to every string it can reach in v —
// scalar strings, map values, map KEYS, and slice elements, recursively.
// Non-string scalars pass through untouched.
func renameActorsInAnyValue(v any, subst func(string) string) any {
	switch val := v.(type) {
	case string:
		return subst(val)
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, vv := range val {
			out[subst(k)] = renameActorsInAnyValue(vv, subst)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, vv := range val {
			out[i] = renameActorsInAnyValue(vv, subst)
		}
		return out
	default:
		return v
	}
}

func renameActorRoleKeys(m map[string][]string, actorMap map[string]string) map[string][]string {
	if m == nil {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		nk := k
		if canon, ok := actorMap[k]; ok {
			nk = canon
		}
		out[nk] = v
	}
	return out
}

func renameActorHourKeys(m map[string][]int, actorMap map[string]string) map[string][]int {
	if m == nil {
		return nil
	}
	out := make(map[string][]int, len(m))
	for k, v := range m {
		nk := k
		if canon, ok := actorMap[k]; ok {
			nk = canon
		}
		out[nk] = v
	}
	return out
}

// renameRelationshipActorKeys rewrites the ACTOR half of every
// "actor:target" relationship key (strings.Cut splits on the FIRST ':' only —
// actor tokens never contain a colon, so this always isolates the actor
// correctly even when the target half itself carries a ':').
func renameRelationshipActorKeys(m map[string]exam.RelationshipEntry, actorMap map[string]string) map[string]exam.RelationshipEntry {
	if m == nil {
		return nil
	}
	out := make(map[string]exam.RelationshipEntry, len(m))
	for k, v := range m {
		actor, rest, ok := strings.Cut(k, ":")
		nk := k
		if ok {
			if canon, exists := actorMap[actor]; exists {
				nk = canon + ":" + rest
			}
		}
		out[nk] = v
	}
	return out
}

// applyIdentifierRenames scrubs residual identifier-shaped substrings (UUIDs,
// emails, hostnames/FQDNs, IPv4 addresses, long all-hex/digit runs — e.g. an
// Azure subscription id or an AWS account id) from event/actor-chain targets,
// baseline relationship keys, the prose fields the actor pass touches, and —
// the C8 review's CRITICAL fix — EVERY metadata string value and map key at
// ANY nesting depth (event metadata, finding metadata, connector_tool
// returns; capture copies event payloads wholesale into metadata). Every
// DISTINCT original substring maps to the SAME deterministic token everywhere
// in the document (shared caches threaded across every field), so a
// subscription id mentioned in a target path, in trap_description, AND in
// metadata.tenant gets the identical replacement.
//
// canonActors is the set of canonical tokens the actor pass emitted — the
// metadata key-net skips values already carrying an intentional actor token.
// Returns the distinct renames performed, sorted for a deterministic diff.
func applyIdentifierRenames(sc *exam.Scenario, canonActors map[string]bool) []contributeRename {
	hashCache := map[string]string{} // raw identifier -> bare hash8 (no prefix)
	renameLog := map[string]string{} // full original span -> full canonical token (WITH prefix), for the diff

	scrub := func(s string) string { return scrubIdentifiersInString(s, hashCache, renameLog) }

	for i := range sc.Events {
		sc.Events[i].Target = scrub(sc.Events[i].Target)
	}
	for i := range sc.ActorChain {
		sc.ActorChain[i].Target = scrub(sc.ActorChain[i].Target)
	}
	if sc.Baseline != nil && sc.Baseline.Relationships != nil {
		renamed := make(map[string]exam.RelationshipEntry, len(sc.Baseline.Relationships))
		for k, v := range sc.Baseline.Relationships {
			renamed[scrub(k)] = v
		}
		sc.Baseline.Relationships = renamed
	}
	sc.TrapDescription = scrub(sc.TrapDescription)
	sc.TrapResolvedMeans = scrub(sc.TrapResolvedMeans)
	if sc.Finding != nil {
		sc.Finding.Title = scrub(sc.Finding.Title)
	}
	if sc.ExpectedResolution != nil {
		for i, m := range sc.ExpectedResolution.ReasoningMustMention {
			sc.ExpectedResolution.ReasoningMustMention[i] = scrub(m)
		}
		for i, m := range sc.ExpectedResolution.ReasoningMustNotMention {
			sc.ExpectedResolution.ReasoningMustNotMention[i] = scrub(m)
		}
	}

	// Metadata walk — values AND keys, any depth.
	if sc.Finding != nil && len(sc.Finding.Metadata) > 0 {
		sc.Finding.Metadata = scrubIdentifiersInAnyValue("", map[string]any(sc.Finding.Metadata), hashCache, renameLog, canonActors).(map[string]any)
	}
	for i := range sc.Events {
		if len(sc.Events[i].Metadata) > 0 {
			sc.Events[i].Metadata = scrubIdentifiersInAnyValue("", map[string]any(sc.Events[i].Metadata), hashCache, renameLog, canonActors).(map[string]any)
		}
	}
	for i := range sc.ConnectorTools {
		if len(sc.ConnectorTools[i].Returns) > 0 {
			sc.ConnectorTools[i].Returns = scrubIdentifiersInAnyValue("", map[string]any(sc.ConnectorTools[i].Returns), hashCache, renameLog, canonActors).(map[string]any)
		}
	}

	origs := make([]string, 0, len(renameLog))
	for o := range renameLog {
		origs = append(origs, o)
	}
	sort.Strings(origs)
	out := make([]contributeRename, 0, len(origs))
	for _, o := range origs {
		out = append(out, contributeRename{Original: o, Canonical: renameLog[o]})
	}
	return out
}

// identifierKeyNet reports whether a metadata key names an identifying value
// (see contributeIdentifierKeyTokens). The key is split into alphanumeric
// tokens ("src_ip" -> [src ip], "peerEmail" is NOT split — snake/kebab only,
// matching the corpus's own key style); an exclude token ("peer_count" ->
// count) always wins, because those keys hold measurements ABOUT an
// identifier, not the identifier.
func identifierKeyNet(key string) bool {
	toks := strings.FieldsFunc(strings.ToLower(key), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	hit := false
	for _, tk := range toks {
		if contributeIdentifierKeyExcludeTokens[tk] {
			return false
		}
		if contributeIdentifierKeyTokens[tk] {
			hit = true
		}
	}
	return hit
}

// scrubIdentifiersInAnyValue applies the identifier scrub to every string it
// can reach in v (values and map keys, any depth), plus the key-net safety
// net: a value under an identifier-carrying key (identifierKeyNet) that no
// shape pattern recognized — including NUMERIC values, which shape patterns
// cannot see at all — is tokenized WHOLESALE with the same deterministic
// hash, so an account id stored as a bare number still never leaves.
// Values already carrying a canonical actor token (canonActors) are left
// alone — the actor pass put them there intentionally.
func scrubIdentifiersInAnyValue(key string, v any, hashCache, renameLog map[string]string, canonActors map[string]bool) any {
	switch val := v.(type) {
	case string:
		if val == "" || val == captureRedactedPlaceholder || canonActors[val] {
			return val
		}
		scrubbed := scrubIdentifiersInString(val, hashCache, renameLog)
		if scrubbed != val {
			return scrubbed
		}
		if identifierKeyNet(key) {
			tok := "id-" + contributeHashFor(val, hashCache)
			recordContributeRename(renameLog, val, tok)
			return tok
		}
		return val
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, vv := range val {
			nk := scrubIdentifiersInString(k, hashCache, renameLog)
			out[nk] = scrubIdentifiersInAnyValue(k, vv, hashCache, renameLog, canonActors)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, vv := range val {
			out[i] = scrubIdentifiersInAnyValue(key, vv, hashCache, renameLog, canonActors)
		}
		return out
	case int, int64, uint64, float64:
		if identifierKeyNet(key) {
			raw := fmt.Sprint(val)
			tok := "id-" + contributeHashFor(raw, hashCache)
			recordContributeRename(renameLog, raw, tok)
			return tok
		}
		return v
	default:
		return v
	}
}

// contributeHashFor returns the cached hash8 for raw, computing and caching it
// on first sight — ONE cache per document, so the same raw identifier always
// yields the same hash everywhere.
func contributeHashFor(raw string, hashCache map[string]string) string {
	if tok, ok := hashCache[raw]; ok {
		return tok
	}
	tok := contentHashToken(raw, 8)
	hashCache[raw] = tok
	return tok
}

// recordContributeRename records an original -> canonical replacement in the
// ledger, first occurrence wins (the mapping is deterministic, so later
// occurrences are identical anyway).
func recordContributeRename(renameLog map[string]string, original, canonical string) {
	if _, ok := renameLog[original]; !ok {
		renameLog[original] = canonical
	}
}

// identMatch is one candidate identifier span found in a string, before
// overlap resolution.
type identMatch struct {
	start, end int
	kind       string // "uuid" | "email" | "subhex" | "hostname" | "ip" | "hexrun"
}

// identMatchPriority ranks candidate kinds when two matches start at the SAME
// position (lower wins): a UUID / an explicit "sub-<hex8>" span is more
// specific than the bare hex-run pattern that would otherwise match part of
// it; an email beats the hostname match on its own domain and the hex-run
// false-positive on its local part (e.g. "deadbeef@example.com"); a hostname
// beats the hex-run match on an all-hex first label ("deadbeef.example.com").
var identMatchPriority = map[string]int{"uuid": 0, "email": 1, "subhex": 2, "hostname": 3, "ip": 4, "hexrun": 5}

// scrubIdentifiersInString replaces every UUID / email / "sub-<hex8>" /
// hostname / IPv4 / long-all-hex-run match in s with a deterministic token,
// in a SINGLE pass over the ORIGINAL string (all patterns are matched against
// s BEFORE any substitution happens, spans are de-overlapped by start
// position + identMatchPriority, then the result is built by walking s once).
// This is deliberately NOT chained ReplaceAllStringFunc calls: an inserted
// hash8 token is itself an 8-character hex string, so a later pass in a chain
// would re-match and re-hash it (turning "sub-<hash>" into
// "sub-sub-<hash-of-hash>"). Building the output from the ORIGINAL string
// exactly once makes that impossible.
//
// hashCache maps a raw matched identifier to its bare hash8 (no prefix) so
// the SAME raw identifier always gets the SAME hash, however many times or
// in whatever prefixed/bare form it appears. renameLog maps the FULL original
// span (prefix included, e.g. "sub-169efd95") to the FULL canonical
// replacement (e.g. "sub-ec0646c8") for the ledger/diff.
//
// Token shapes: hostnames keep an FQDN-ish shape (host-<hash8>.example, RFC
// 2606 reserved TLD) and emails keep an email shape
// (user-<hash8>@example.com) so shape-sensitive detector parsing survives;
// everything else is sub-<hash8> (8-hex, VA-03's convention) or id-<hash8>.
func scrubIdentifiersInString(s string, hashCache, renameLog map[string]string) string {
	var matches []identMatch
	for _, m := range contributeUUIDRE.FindAllStringIndex(s, -1) {
		matches = append(matches, identMatch{m[0], m[1], "uuid"})
	}
	for _, m := range contributeEmailRE.FindAllStringIndex(s, -1) {
		matches = append(matches, identMatch{m[0], m[1], "email"})
	}
	for _, m := range contributeSubPrefixedHexRE.FindAllStringIndex(s, -1) {
		matches = append(matches, identMatch{m[0], m[1], "subhex"})
	}
	for _, m := range contributeHostnameRE.FindAllStringIndex(s, -1) {
		raw := s[m[0]:m[1]]
		lastLabel := strings.ToLower(raw[strings.LastIndex(raw, ".")+1:])
		if contributeFilenameExtensions[lastLabel] {
			continue // "policy.json" is a filename, not an FQDN
		}
		matches = append(matches, identMatch{m[0], m[1], "hostname"})
	}
	for _, m := range contributeIPv4RE.FindAllStringIndex(s, -1) {
		matches = append(matches, identMatch{m[0], m[1], "ip"})
	}
	for _, m := range contributeHexRunRE.FindAllStringIndex(s, -1) {
		matches = append(matches, identMatch{m[0], m[1], "hexrun"})
	}
	if len(matches) == 0 {
		return s
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].start != matches[j].start {
			return matches[i].start < matches[j].start
		}
		return identMatchPriority[matches[i].kind] < identMatchPriority[matches[j].kind]
	})

	var b strings.Builder
	cursor, lastEnd := 0, -1
	for _, m := range matches {
		if m.start < lastEnd {
			continue // overlaps an already-chosen, earlier/higher-priority match
		}
		raw := s[m.start:m.end]
		var canon string
		switch m.kind {
		case "subhex":
			canon = "sub-" + contributeHashFor(raw[len(raw)-8:], hashCache) // strip the literal "sub-"/"SUB-" prefix; hash the hex part only
		case "hexrun":
			prefix := "id-"
			if len(raw) == 8 {
				prefix = "sub-"
			}
			canon = prefix + contributeHashFor(raw, hashCache)
		case "hostname":
			canon = "host-" + contributeHashFor(raw, hashCache) + ".example"
		case "ip":
			canon = "ip-" + contributeHashFor(raw, hashCache)
		case "email":
			canon = "user-" + contributeHashFor(raw, hashCache) + "@example.com"
		default: // "uuid"
			canon = "id-" + contributeHashFor(raw, hashCache)
		}
		recordContributeRename(renameLog, raw, canon)
		b.WriteString(s[cursor:m.start])
		b.WriteString(canon)
		cursor = m.end
		lastEnd = m.end
	}
	b.WriteString(s[cursor:])
	return b.String()
}

// shiftScenarioTimestamps shifts every parseable timestamp in sc (event
// Timestamp/IngestedAt, baseline relationship FirstSeen/LastSeen) by the SAME
// constant duration — the earliest event timestamp becomes
// contributeAnchorTime, and every other timestamp moves by the identical
// amount, so ALL relative deltas (fine event spacing AND baseline history
// offsets) are preserved exactly. Returns the shift applied and the number of
// fields touched; (0, 0) when sc carries no parseable event timestamp.
func shiftScenarioTimestamps(sc *exam.Scenario) (time.Duration, int) {
	var earliest time.Time
	found := false
	for _, ev := range sc.Events {
		for _, s := range []string{ev.Timestamp, ev.IngestedAt} {
			if t, ok := parseContributeTimestamp(s); ok {
				if !found || t.Before(earliest) {
					earliest = t
					found = true
				}
			}
		}
	}
	if !found {
		return 0, 0
	}

	anchor, err := time.Parse(time.RFC3339, contributeAnchorTime)
	if err != nil {
		// contributeAnchorTime is a compile-time constant in a known-good
		// format; a parse failure here would be a programming error, not a
		// runtime condition -- fail loudly rather than silently skip the shift.
		panic(fmt.Sprintf("scenariocontribute: invalid contributeAnchorTime constant: %v", err))
	}
	shift := anchor.Sub(earliest)

	count := 0
	shiftField := func(s string) string {
		t, ok := parseContributeTimestamp(s)
		if !ok {
			return s
		}
		count++
		return formatContributeTimestamp(t.Add(shift), s)
	}

	for i := range sc.Events {
		sc.Events[i].Timestamp = shiftField(sc.Events[i].Timestamp)
		sc.Events[i].IngestedAt = shiftField(sc.Events[i].IngestedAt)
	}
	if sc.Baseline != nil {
		for k, r := range sc.Baseline.Relationships {
			r.FirstSeen = shiftField(r.FirstSeen)
			r.LastSeen = shiftField(r.LastSeen)
			sc.Baseline.Relationships[k] = r
		}
	}
	return shift, count
}

// parseContributeTimestamp tries RFC3339 (event timestamps) then a bare
// YYYY-MM-DD date (relationship first_seen/last_seen).
func parseContributeTimestamp(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// formatContributeTimestamp re-renders t in the SAME layout original was
// written in: date-only stays date-only; RFC3339 stays RFC3339, PRESERVING
// sub-second precision when present (RFC3339Nano — a 30.5s inter-event delta
// must survive as 30.5s; timing detectors grade on exact deltas). A value
// whose fractional part is all zeros re-renders without the fraction — the
// instant is identical, only the textual form normalizes.
func formatContributeTimestamp(t time.Time, original string) string {
	if _, err := time.Parse("2006-01-02", strings.TrimSpace(original)); err == nil {
		return t.UTC().Format("2006-01-02")
	}
	if t.Nanosecond() != 0 {
		return t.UTC().Format(time.RFC3339Nano)
	}
	return t.UTC().Format(time.RFC3339)
}

// scrubScenarioMetadata REUSES scenariocapture.go's scrubPayloadMap (the C5
// helper that survived two adversarial review rounds — not forked) over every
// metadata-shaped block in sc: finding.metadata, each event's metadata, and
// each connector_tool's canned returns. Returns the sorted document path of
// every value carrying the redaction placeholder afterward (the ledger
// entries the consent diff enumerates — paths, never the secret values).
func scrubScenarioMetadata(sc *exam.Scenario) []string {
	var paths []string
	if sc.Finding != nil && sc.Finding.Metadata != nil {
		scrubbed := scrubPayloadMap(sc.Finding.Metadata)
		sc.Finding.Metadata = scrubbed
		paths = append(paths, redactedValuePaths("finding.metadata", scrubbed)...)
	}
	for i := range sc.Events {
		if sc.Events[i].Metadata == nil {
			continue
		}
		scrubbed := scrubPayloadMap(sc.Events[i].Metadata)
		sc.Events[i].Metadata = scrubbed
		paths = append(paths, redactedValuePaths(fmt.Sprintf("events[%d].metadata", i), scrubbed)...)
	}
	for i := range sc.ConnectorTools {
		if sc.ConnectorTools[i].Returns == nil {
			continue
		}
		scrubbed := scrubPayloadMap(sc.ConnectorTools[i].Returns)
		sc.ConnectorTools[i].Returns = scrubbed
		paths = append(paths, redactedValuePaths(fmt.Sprintf("connector_tools[%d].returns", i), scrubbed)...)
	}
	sort.Strings(paths)
	return paths
}

// redactedValuePaths returns the document path of every string value (at any
// nesting depth under prefix) that carries the C5 redaction placeholder —
// e.g. "events[0].metadata.github_token". Paths only, never the values.
func redactedValuePaths(prefix string, m map[string]any) []string {
	var paths []string
	var walk func(p string, v any)
	walk = func(p string, v any) {
		switch val := v.(type) {
		case string:
			if strings.Contains(val, captureRedactedPlaceholder) {
				paths = append(paths, p)
			}
		case map[string]any:
			for k, vv := range val {
				walk(p+"."+k, vv)
			}
		case []any:
			for i, vv := range val {
				walk(fmt.Sprintf("%s[%d]", p, i), vv)
			}
		}
	}
	for k, v := range m {
		walk(prefix+"."+k, v)
	}
	return paths
}

// verifyLedgerResidue is the transmit-time guarantee behind the PR body's
// "raw values never left" statement: every ORIGINAL value in the redaction
// ledger must be ABSENT from the artifact bytes. A hit hard-fails plan
// assembly (fail-closed — nothing is presented as safe, nothing can be
// sent). Originals shorter than 3 bytes are skipped: they cannot be checked
// by substring without false-positiving on every coincidental occurrence
// inside canonical tokens.
func verifyLedgerResidue(artifact string, data []byte, diff contributeDiff) error {
	check := func(kind string, renames []contributeRename) error {
		for _, r := range renames {
			if len(r.Original) < 3 {
				continue
			}
			if strings.Contains(string(data), r.Original) {
				return fmt.Errorf("SANITIZE RESIDUE in %s: %s original %q still present after sanitize -- refusing to proceed (fail-closed; nothing has left this machine)", artifact, kind, r.Original)
			}
		}
		return nil
	}
	if err := check("actor", diff.ActorRenames); err != nil {
		return err
	}
	return check("identifier", diff.IdentifierRenames)
}

// --- rendering / PR content ----------------------------------------------------

// printContributePlan prints the FULL local review: the redaction diff (with
// original values, since this is the operator's OWN data on their OWN
// terminal — nothing here has left the machine), the sanitized YAML that
// would be contributed, and the would-be PR content. This is shown on EVERY
// invocation (--dry-run, no flags, or --yes) so the operator always sees
// exactly what they are about to confirm.
func printContributePlan(p *contributePlan) {
	fmt.Printf("Scenario contribute: %s -> %s\n", p.ScenarioID, p.NewID)
	fmt.Printf("  Source: %s\n", p.SourcePath)
	fmt.Printf("  Target: %s (repo %s, branch %s)\n", p.RelPath, p.Repo, p.Branch)
	fmt.Println()
	fmt.Println("Redaction diff (the FULL ledger -- every replacement that will be transmitted; nothing has left this machine yet):")
	if len(p.Diff.ActorRenames) == 0 {
		fmt.Println("  Actors renamed: 0")
	} else {
		fmt.Printf("  Actors renamed: %d\n", len(p.Diff.ActorRenames))
		for _, r := range p.Diff.ActorRenames {
			fmt.Printf("    %-40s -> %s\n", r.Original, r.Canonical)
		}
	}
	if len(p.Diff.IdentifierRenames) == 0 {
		fmt.Println("  Identifiers redacted (targets, prose, metadata): 0")
	} else {
		fmt.Printf("  Identifiers redacted (targets, prose, metadata): %d\n", len(p.Diff.IdentifierRenames))
		for _, r := range p.Diff.IdentifierRenames {
			fmt.Printf("    %-40s -> %s\n", r.Original, r.Canonical)
		}
	}
	if len(p.Diff.SecretPaths) == 0 {
		fmt.Println("  Secret-shaped metadata values redacted: 0")
	} else {
		fmt.Printf("  Secret-shaped metadata values redacted: %d\n", len(p.Diff.SecretPaths))
		for _, path := range p.Diff.SecretPaths {
			fmt.Printf("    %-40s -> %s\n", path, captureRedactedPlaceholder)
		}
	}
	fmt.Printf("  Timestamps shifted: %d field(s), by %s (relative deltas preserved)\n", p.Diff.TimestampsShifted, p.Diff.ShiftDuration)
	fmt.Println("  Residue check: PASSED -- every original above verified absent from the YAML and PR body below.")
	fmt.Println()
	fmt.Println("Sanitized scenario YAML (this is what would be contributed):")
	fmt.Println("---")
	fmt.Print(string(p.SanitizedYAML))
	fmt.Println("---")
	fmt.Println()
	fmt.Println("Would-be PR:")
	fmt.Printf("  Repo:   %s\n", p.Repo)
	fmt.Printf("  Branch: %s\n", p.Branch)
	fmt.Printf("  File:   %s\n", p.RelPath)
	fmt.Printf("  Pin:    count %d -> %d\n", p.Pin.OldCount, p.Pin.NewCount)
	fmt.Printf("          sha256 %s\n", p.Pin.OldSHA)
	fmt.Printf("              -> %s\n", p.Pin.NewSHA)
	fmt.Printf("  Title:  %s\n", p.PRTitle)
	fmt.Println("  Body:")
	for _, line := range strings.Split(p.PRBody, "\n") {
		fmt.Printf("    %s\n", line)
	}
}

// renderContributePRBody builds the PR body: a SAFE summary whose every count
// is derived from the redaction ledger (len of the diff slices — never a
// separately-maintained number that could drift from what was actually
// redacted), and NEVER the original values themselves (this text leaves the
// machine the moment a PR opens; buildContributePlan residue-checks it
// against the ledger too).
func renderContributePRBody(newID, family string, isAttack bool, relpath string, diff contributeDiff, pin contributePinDiff) string {
	label := "must_not_fire (benign twin)"
	if isAttack {
		label = "must_fire (attack)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Contributed scenario %s for family %s (%s).\n\n", newID, family, label)
	fmt.Fprintf(&b, "Placed at %s. provenance: contributed.\n\n", relpath)
	fmt.Fprintf(&b, "Redaction summary (counts derived from the sanitizer's redaction ledger on the contributor's machine):\n")
	fmt.Fprintf(&b, "- %d actor(s) renamed to canonical corpus tokens\n", len(diff.ActorRenames))
	fmt.Fprintf(&b, "- %d identifier(s) (targets, prose, metadata values/keys at any depth) redacted to deterministic tokens\n", len(diff.IdentifierRenames))
	fmt.Fprintf(&b, "- %d secret-shaped metadata value(s) redacted\n", len(diff.SecretPaths))
	fmt.Fprintf(&b, "- %d timestamp field(s) shifted onto the corpus's 2026-03 window (relative deltas preserved)\n\n", diff.TimestampsShifted)
	fmt.Fprintf(&b, "Transmit-time residue check: PASSED -- every original value in the redaction ledger was verified absent from the contributed file and from this PR body before anything left the contributor's machine.\n\n")
	fmt.Fprintf(&b, "corpus.pin regen (exams/scenarios/corpus.pin):\n")
	fmt.Fprintf(&b, "  count:  %d -> %d\n", pin.OldCount, pin.NewCount)
	fmt.Fprintf(&b, "  sha256: %s\n", pin.OldSHA)
	fmt.Fprintf(&b, "      ->  %s\n", pin.NewSHA)
	fmt.Fprintf(&b, "  new manifest line: %s\n\n", pin.NewLine)
	fmt.Fprintf(&b, "Nothing here auto-merges -- this is a normal reviewed PR (mallcop-pro d70 ruling: contribute-back stays reviewed).\n")
	return b.String()
}

// --- opening the real PR -------------------------------------------------------

// contributeLookupGH resolves the gh binary. A package-level seam so the
// command-construction test can force the gh-present path without requiring
// gh on the test machine's PATH.
var contributeLookupGH = func() (string, error) { return exec.LookPath("gh") }

// contributeRunCommand executes one external command in dir (""" = inherit
// cwd) and returns its combined output. A package-level seam so the
// command-construction test can record the EXACT argv sequence without ever
// executing git/gh or touching the network (the review's MED finding was a
// misconstructed `gh repo fork` argv that no test could have caught — this
// seam makes the construction testable while the never-open-a-real-PR safety
// constraint stands).
var contributeRunCommand = func(dir, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	return cmd.CombinedOutput()
}

// openContributePR is the ONLY function in this file that touches git/gh or
// the network (via the contributeRunCommand seam). It is reachable
// exclusively from the non-dry-run, --yes branch of runScenarioContribute —
// tests of this package must never call it with the REAL seams (see
// scenariocontribute_test.go's package doc note: opening a real PR against
// mallcop-app/mallcop from a test would spam the OSS repo; the construction
// test swaps both seams for recorders first).
//
// Flow: resolve the caller's GitHub login; when the login is not the target
// repo's owner, ensure a fork exists (gh repo fork --clone=false — the fork
// and clone are SEPARATE commands: `gh repo fork <repo> --clone <dir>` does
// not exist as an argv shape, the review's MED finding) and clone THE FORK;
// an owner clones the target repo directly (you cannot fork your own repo).
// Then branch, place the file, regen the pin, commit, push to origin (the
// clone's origin is whichever repo was cloned), and open the PR with an
// owner-qualified --head when contributing from a fork.
//
// If `gh` is not on PATH, prints exact manual instructions instead of
// failing — the operator can still contribute by hand.
func openContributePR(p *contributePlan) error {
	ghPath, err := contributeLookupGH()
	if err != nil {
		printManualContributeInstructions(p)
		return nil
	}

	loginOut, err := contributeRunCommand("", ghPath, "api", "user", "--jq", ".login")
	if err != nil {
		return fmt.Errorf("gh api user (resolving your GitHub login): %w\n%s", err, loginOut)
	}
	login := strings.TrimSpace(string(loginOut))
	if login == "" {
		return fmt.Errorf("gh api user returned an empty login -- is gh authenticated? (gh auth status)")
	}

	owner, repoName, _ := splitOwnerRepo(p.Repo)
	cloneTarget := p.Repo
	head := p.Branch
	if login != owner {
		// Contributor path: fork (idempotent when the fork already exists),
		// then clone the FORK — pushes go to the fork, and the PR head names
		// it explicitly.
		if out, err := contributeRunCommand("", ghPath, "repo", "fork", p.Repo, "--clone=false"); err != nil {
			return fmt.Errorf("gh repo fork %s: %w\n%s", p.Repo, err, out)
		}
		cloneTarget = login + "/" + repoName
		head = login + ":" + p.Branch
	}

	tmpDir, err := os.MkdirTemp("", "mallcop-contribute-*")
	if err != nil {
		return fmt.Errorf("scratch dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if out, err := contributeRunCommand("", ghPath, "repo", "clone", cloneTarget, tmpDir); err != nil {
		return fmt.Errorf("gh repo clone %s: %w\n%s", cloneTarget, err, out)
	}

	run := func(name string, args ...string) error {
		out, err := contributeRunCommand(tmpDir, name, args...)
		if err != nil {
			return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out)
		}
		return nil
	}

	if err := run("git", "checkout", "-b", p.Branch); err != nil {
		return err
	}

	targetPath := filepath.Join(tmpDir, p.RelPath)
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(targetPath), err)
	}
	if err := os.WriteFile(targetPath, p.SanitizedYAML, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", targetPath, err)
	}

	pinPath := filepath.Join(tmpDir, "exams", "scenarios", "corpus.pin")
	if err := updateContributePinFile(pinPath, p.Pin); err != nil {
		return err
	}

	if err := run("git", "add", p.RelPath, "exams/scenarios/corpus.pin"); err != nil {
		return err
	}

	msgFile := filepath.Join(tmpDir, ".contribute-commit-msg")
	commitMsg := fmt.Sprintf("%s\n\n%s\n", p.PRTitle, p.PRBody)
	if err := os.WriteFile(msgFile, []byte(commitMsg), 0o644); err != nil {
		return fmt.Errorf("write commit message: %w", err)
	}
	if err := run("git", "commit", "-F", ".contribute-commit-msg"); err != nil {
		return err
	}
	if err := run("git", "push", "origin", p.Branch); err != nil {
		return err
	}

	bodyFile := filepath.Join(tmpDir, ".contribute-pr-body")
	if err := os.WriteFile(bodyFile, []byte(p.PRBody), 0o644); err != nil {
		return fmt.Errorf("write PR body: %w", err)
	}

	out, err := contributeRunCommand(tmpDir, ghPath, "pr", "create", "--repo", p.Repo, "--title", p.PRTitle, "--body-file", bodyFile, "--head", head)
	if err != nil {
		return fmt.Errorf("gh pr create: %w\n%s", err, out)
	}
	fmt.Print(string(out))
	return nil
}

// updateContributePinFile rewrites ONLY the count/sha256 value lines of an
// existing corpus.pin file, preserving its header comment verbatim.
func updateContributePinFile(path string, pin contributePinDiff) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "count "):
			lines[i] = fmt.Sprintf("count %d", pin.NewCount)
		case strings.HasPrefix(trimmed, "sha256 "):
			lines[i] = fmt.Sprintf("sha256 %s", pin.NewSHA)
		}
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}

// printManualContributeInstructions is the fallback when `gh` is not on PATH:
// exact by-hand instructions using the already-printed diff/PR content.
func printManualContributeInstructions(p *contributePlan) {
	fmt.Println("`gh` not found on PATH -- open the PR by hand:")
	fmt.Printf("  1. Fork and clone %s\n", p.Repo)
	fmt.Printf("  2. git checkout -b %s\n", p.Branch)
	fmt.Printf("  3. Write the sanitized YAML shown above to %s\n", p.RelPath)
	fmt.Printf("  4. Update exams/scenarios/corpus.pin to: count %d, sha256 %s\n", p.Pin.NewCount, p.Pin.NewSHA)
	fmt.Println("  5. git add, commit, and push the branch")
	fmt.Printf("  6. Open a PR against %s with the title and body shown above\n", p.Repo)
}
