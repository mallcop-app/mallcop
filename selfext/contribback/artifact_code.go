package contribback

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ossAuthoredDest is the OSS repository subtree authored detectors are promoted
// into (design R6/R7: authored detectors live under core/detect/authored/<name>/).
const ossAuthoredDest = "core/detect/authored"

// codeArtifactFile mirrors the on-disk JSON a CODE-lane contribute-back artifact
// carries: a merged authored detector (its source + scenario files, provenance,
// and the tenant-consent fact) proposed for promotion into the shared OSS corpus.
// We decode only the fields this package needs; unknown fields are ignored. Like
// the DATA-lane artifact, this file is emitted ONLY when the customer consented to
// contribute-back for the build the detector came from — loading one implies that
// fact, recorded explicitly on the returned Artifact.
type codeArtifactFile struct {
	// Kind must be "authored_detector" — a guard so a DATA-lane oss-pr-*.json is
	// never mistaken for a code-lane one (and vice versa).
	Kind     string `json:"kind"`
	Detector struct {
		Name string `json:"name"`
		// Files are the detector's files as customer-repo-relative paths under
		// detectors/<name>/ (source, tests, and scenarios). Each is promoted to
		// core/detect/authored/<name>/... (dest derived deterministically).
		Files []string `json:"files"`
	} `json:"detector"`
	Provenance struct {
		// Fingerprint of the originating coverage gap — names the idempotent head
		// branch (contribback/<fp>) so a re-run reuses the same PR.
		Fingerprint string `json:"fingerprint"`
		// GateRef is the gate result reference (head SHA / gate id) that
		// GREEN-certified the authored detector, for the PR body's audit trail.
		GateRef string `json:"gate_ref"`
	} `json:"provenance"`
}

// LoadCodeArtifact reads a CODE-lane contribute-back artifact file and distills it
// into an Artifact ready for Opener.Contribute — the code-lane analogue of
// LoadArtifact (which handles the DATA lane). It maps each customer-repo detector
// file to its OSS destination under core/detect/authored/<name>/, records the
// provenance (gap fingerprint + gate reference), and composes a PR body that
// states the promotion must pass the OSS repo's OWN exam.yml + CODEOWNERS review
// and is NEVER auto-merged.
//
// Because such an artifact is emitted ONLY on tenant consent for a universally
// promotable authored detector, the returned Artifact has Consented=true and
// Universal=true (a promoted authored detector in core/detect/authored is a
// general capability by construction — tenant-specificity does not apply to
// net-new detector CODE the way it does to a tuning widen). Contribute re-checks
// both as defense in depth.
func LoadCodeArtifact(path string) (Artifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Artifact{}, fmt.Errorf("contribback: read code artifact %s: %w", path, err)
	}
	var f codeArtifactFile
	if err := json.Unmarshal(data, &f); err != nil {
		return Artifact{}, fmt.Errorf("contribback: decode code artifact %s: %w", path, err)
	}
	if f.Kind != "authored_detector" {
		return Artifact{}, fmt.Errorf("contribback: code artifact %s has kind %q, want \"authored_detector\"", path, f.Kind)
	}
	name := strings.TrimSpace(f.Detector.Name)
	if name == "" {
		return Artifact{}, fmt.Errorf("contribback: code artifact %s has no detector name", path)
	}
	if strings.TrimSpace(f.Provenance.Fingerprint) == "" {
		return Artifact{}, fmt.Errorf("contribback: code artifact %s has no provenance fingerprint", path)
	}
	if len(f.Detector.Files) == 0 {
		return Artifact{}, fmt.Errorf("contribback: code artifact %s promotes no files", path)
	}

	files := make([]PromotedFile, 0, len(f.Detector.Files))
	for _, src := range f.Detector.Files {
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		files = append(files, PromotedFile{Src: src, Dest: ossDestFor(src)})
	}
	if len(files) == 0 {
		return Artifact{}, fmt.Errorf("contribback: code artifact %s promotes no non-empty files", path)
	}

	art := Artifact{
		Lane:         LaneCode,
		Fingerprint:  f.Provenance.Fingerprint,
		Consented:    true, // emitted only on tenant consent
		Universal:    true, // an authored detector promoted into OSS core is general by construction
		DetectorName: name,
		Files:        files,
		GateRef:      strings.TrimSpace(f.Provenance.GateRef),
	}
	art.Title = codePRTitle(name)
	art.Body = codePRBody(art)
	return art, nil
}

func codePRTitle(name string) string {
	return fmt.Sprintf("selfext(contribute-back): promote authored detector %s into OSS core", name)
}

func codePRBody(a Artifact) string {
	var b strings.Builder
	b.WriteString("Automated contribute-back proposal from a mallcop self-extension run — CODE lane.\n\n")
	fmt.Fprintf(&b, "Promotes the customer-authored detector `%s` (merged into the customer's own thin-embed repo behind their exam gate + human review) into the shared OSS corpus at `%s/%s/`.\n\n", a.DetectorName, ossAuthoredDest, a.DetectorName)
	fmt.Fprintf(&b, "- Originating gap fingerprint: `%s`\n", a.Fingerprint)
	if a.GateRef != "" {
		fmt.Fprintf(&b, "- Certifying gate reference: `%s`\n", a.GateRef)
	}
	b.WriteString("\nPromoted files:\n\n")
	for _, f := range a.Files {
		fmt.Fprintf(&b, "- `%s` → `%s`\n", f.Src, f.Dest)
	}
	b.WriteString("\n**This PR is NOT auto-merged.** It must pass the OSS project's OWN `exam.yml` CI and CODEOWNERS review, at every autonomy dial setting including the most-autonomous one. Merging a shared-OSS detector is a maintainer decision (design rulings R3/R8).\n")
	return b.String()
}

// ossDestFor returns the OSS destination path for a customer-repo detector file.
// Exposed for callers (and the workflow's mirror script) that need the same
// deterministic mapping. base is the detectors/ subtree prefix stripped.
func ossDestFor(src string) string {
	return filepath.ToSlash(ossAuthoredDest + "/" + strings.TrimPrefix(src, "detectors/"))
}
