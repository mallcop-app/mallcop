package contribback

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ossArtifactFile mirrors the on-disk JSON the router emits for an OSS
// contribute-back proposal (router.emitOSSArtifact → "oss-pr-*.json"). We decode
// only the fields this package needs; unknown fields are ignored. The router
// ONLY emits this file when the customer consented AND the widen is universal, so
// loading one implies both facts — recorded explicitly on the returned Artifact.
type ossArtifactFile struct {
	Proposal struct {
		Kind      string `json:"kind"`
		Universal bool   `json:"universal"`
		Mapping   *struct {
			Source    string `json:"source"`
			RawAction string `json:"raw_action"`
			EventType string `json:"event_type"`
		} `json:"mapping"`
		Tuning *struct {
			Detector    string   `json:"detector"`
			Key         string   `json:"key"`
			AddedValues []string `json:"added_values"`
		} `json:"tuning"`
		Fingerprint string `json:"fingerprint"`
		Model       string `json:"model"`
	} `json:"proposal"`
}

// LoadArtifact reads a router-emitted OSS-PR artifact file (oss-pr-*.json) and
// distills it into an Artifact ready for Opener.Contribute. Because the router
// emits that file ONLY on customer consent AND a universal widen, the returned
// Artifact has Consented=true and Universal mirrored from the proposal; the
// Opener re-checks both as defense in depth.
func LoadArtifact(path string) (Artifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Artifact{}, fmt.Errorf("contribback: read OSS artifact %s: %w", path, err)
	}
	var f ossArtifactFile
	if err := json.Unmarshal(data, &f); err != nil {
		return Artifact{}, fmt.Errorf("contribback: decode OSS artifact %s: %w", path, err)
	}
	if strings.TrimSpace(f.Proposal.Fingerprint) == "" {
		return Artifact{}, fmt.Errorf("contribback: OSS artifact %s has no proposal fingerprint", path)
	}
	art := Artifact{
		Fingerprint: f.Proposal.Fingerprint,
		Consented:   true, // the router only emits this file on consent
		Universal:   f.Proposal.Universal,
		Title:       prTitle(f),
		Body:        prBody(f),
	}
	return art, nil
}

func prTitle(f ossArtifactFile) string {
	switch f.Proposal.Kind {
	case "mapping":
		if f.Proposal.Mapping != nil {
			return fmt.Sprintf("selfext(contribute-back): map %s/%s -> %s",
				f.Proposal.Mapping.Source, f.Proposal.Mapping.RawAction, f.Proposal.Mapping.EventType)
		}
	case "tuning":
		if f.Proposal.Tuning != nil {
			return fmt.Sprintf("selfext(contribute-back): widen %s.%s",
				f.Proposal.Tuning.Detector, f.Proposal.Tuning.Key)
		}
	}
	return "selfext(contribute-back): universal detection widen"
}

func prBody(f ossArtifactFile) string {
	var b strings.Builder
	b.WriteString("Automated contribute-back proposal from a mallcop self-extension run.\n\n")
	b.WriteString("A universally-applicable, widen-only detection improvement the customer consented to share back to the shared OSS corpus.\n\n")
	fmt.Fprintf(&b, "- Originating gap fingerprint: `%s`\n", f.Proposal.Fingerprint)
	if f.Proposal.Model != "" {
		fmt.Fprintf(&b, "- Proposer model: `%s`\n", f.Proposal.Model)
	}
	b.WriteString("\n**This PR is NOT auto-merged.** It is gated by the OSS project's CI (`exam.yml`) and CODEOWNERS review, at every autonomy dial setting including the most-autonomous one. Merging is a maintainer decision.\n")
	return b.String()
}
