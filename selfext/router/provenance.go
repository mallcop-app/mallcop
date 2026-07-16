package router

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mallcop-app/mallcop/selfext/engine"
	"github.com/mallcop-app/mallcop/selfext/proposer"
)

// RoutedRecord is the auditable provenance written per routed proposal AND per
// rejection. It extends engine.Provenance's spirit (engine.go:149) with the
// routing Destination + Decision, and carries the gate run's base/head shas so a
// routed overlay can be traced back to the exact gate that certified it.
type RoutedRecord struct {
	Fingerprint    string   `json:"fingerprint"`
	SampleEventIDs []string `json:"sample_event_ids,omitempty"`
	ProposerModel  string   `json:"proposer_model"`
	// Endpoint is the inference base URL the proposal was billed to (the Forge
	// URL on the donut rail, the user's URL on BYOI). Mirrors
	// engine.Provenance.Endpoint (engine.go) — provenance only, NEVER the key.
	Endpoint    string    `json:"endpoint,omitempty"`
	BaseSHA     string    `json:"base_sha"`
	HeadSHA     string    `json:"head_sha"`
	GitSHA      string    `json:"git_sha,omitempty"`
	Destination string    `json:"destination"`
	Decision    string    `json:"decision"`
	Timestamp   time.Time `json:"timestamp"`
}

// ossArtifact is the reviewable OSS contribute-back proposal. It is DATA the
// operator reviews and opens a PR from by hand — the router NEVER pushes or
// merges. It carries the widen and its provenance, no credentials.
type ossArtifact struct {
	Proposal   proposer.Proposal `json:"proposal"`
	Gate       engine.GateResult `json:"gate"`
	Provenance RoutedRecord      `json:"provenance"`
	Note       string            `json:"note"`
}

// shortFP is the first 12 hex chars of a fingerprint, for filenames.
func shortFP(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	if fp == "" {
		return "nofp"
	}
	return fp
}

// writeProvenance persists a RoutedRecord under ProvenanceDir. An empty
// ProvenanceDir is a no-op (the record is still returned in the Decision).
func (r *Router) writeProvenance(rec RoutedRecord) error {
	if r.ProvenanceDir == "" {
		return nil
	}
	if err := os.MkdirAll(r.ProvenanceDir, 0o755); err != nil {
		return fmt.Errorf("router: create provenance dir: %w", err)
	}
	name := fmt.Sprintf("routed-%s-%s-%s.json", shortFP(rec.Fingerprint), rec.Destination, rec.Timestamp.Format("20060102-150405.000000"))
	return writeJSONFile(filepath.Join(r.ProvenanceDir, name), rec)
}

// emitOSSArtifact writes a reviewable OSS-PR artifact under ArtifactDir and
// returns its path. This is the router's ONLY OSS output — a human reviews it and
// opens the PR; nothing is pushed or merged.
func (r *Router) emitOSSArtifact(p proposer.Proposal, gate engine.GateResult) (string, error) {
	if r.ArtifactDir == "" {
		return "", fmt.Errorf("router: OSS contribute-back requested but ArtifactDir is empty")
	}
	if err := os.MkdirAll(r.ArtifactDir, 0o755); err != nil {
		return "", fmt.Errorf("router: create OSS artifact dir: %w", err)
	}
	art := ossArtifact{
		Proposal: p,
		Gate:     gate,
		Provenance: RoutedRecord{
			Fingerprint:   p.Fingerprint,
			ProposerModel: p.Model,
			Endpoint:      p.Endpoint,
			BaseSHA:       gate.BaseSHA,
			HeadSHA:       gate.HeadSHA,
			GitSHA:        r.GitSHA,
			Destination:   string(DestOSSContribBack),
			Timestamp:     r.now().UTC(),
		},
		Note: "OSS contribute-back proposal. Tenant consented to this build. REVIEW MANUALLY and open the PR by hand — the router never pushes or merges.",
	}
	path := filepath.Join(r.ArtifactDir, fmt.Sprintf("oss-pr-%s-%s.json", shortFP(p.Fingerprint), r.now().UTC().Format("20060102-150405.000000")))
	if err := writeJSONFile(path, art); err != nil {
		return "", err
	}
	return path, nil
}

// writeJSONFile marshals v (indented) and writes it to path.
func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("router: marshal %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("router: write %s: %w", filepath.Base(path), err)
	}
	return nil
}
