package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanDeclRequiresSpec proves the --connector decl wiring: without a
// --connector-spec, runScan fails loud.
func TestScanDeclRequiresSpec(t *testing.T) {
	store := filepath.Join(t.TempDir(), "store")
	err := runScan([]string{"--store", store, "--connector", "decl"})
	if err == nil || !strings.Contains(err.Error(), "connector-spec is required") {
		t.Fatalf("want 'connector-spec is required' error, got: %v", err)
	}
}

// TestScanDeclSSRFRejectionWired proves the PRODUCTION SSRF guard is wired into
// the scan path: a spec whose base_url is a loopback address is rejected at
// construction, so a decl spec can never make mallcop dial a private address.
func TestScanDeclSSRFRejectionWired(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.yaml")
	spec := `
source_id: acme
base_url: https://127.0.0.1:8443
auth_scheme: none
endpoints:
  - path: /events
    pagination: none
    response_path: events
    field_map:
      id: id
      actor: who
      action: act
`
	if err := os.WriteFile(specPath, []byte(spec), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	err := runScan([]string{"--store", filepath.Join(dir, "store"), "--connector", "decl", "--connector-spec", specPath})
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("want SSRF 'non-public' rejection, got: %v", err)
	}
}

// TestScanRejectsBadLearnedMappings proves an invalid --learned-mappings file is
// fatal — an unknown target event_type is rejected fail-loud before any
// connector is built.
func TestScanRejectsBadLearnedMappings(t *testing.T) {
	dir := t.TempDir()
	ovPath := filepath.Join(dir, "lm.yaml")
	if err := os.WriteFile(ovPath, []byte("github:\n  repo.rename: not_a_real_event_type\n"), 0o644); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	err := runScan([]string{
		"--store", filepath.Join(dir, "store"),
		"--connector", "github", "--github-org", "acme",
		"--learned-mappings", ovPath,
	})
	if err == nil || !strings.Contains(err.Error(), "unknown event_type") {
		t.Fatalf("want overlay validation error, got: %v", err)
	}
}
