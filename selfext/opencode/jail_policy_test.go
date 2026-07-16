package opencode

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/selfext/sandbox"
)

func TestInferencePort(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		want    uint16
		wantErr bool
	}{
		{"https default", "https://api.mallcop.app", 443, false},
		{"https with path", "https://api.mallcop.app/v1", 443, false},
		{"http default", "http://byoi.invalid", 80, false},
		{"explicit loopback shim port", "http://127.0.0.1:53817", 53817, false},
		{"explicit https port", "https://host.example:8443/v1", 8443, false},
		{"empty", "", 0, true},
		{"unknown scheme", "ftp://host.example", 0, true},
		{"port zero", "http://host.example:0", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inferencePort(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("inferencePort(%q) = %d, want error", tc.url, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("inferencePort(%q): %v", tc.url, err)
			}
			if got != tc.want {
				t.Errorf("inferencePort(%q) = %d, want %d", tc.url, got, tc.want)
			}
		})
	}
}

// TestJailPolicyDerivation proves the policy the adapter hands the OS jail binds
// the opencode child to exactly the worktree scratch tree (+ git metadata + /dev)
// for writes, a read-only rootfs, and ONLY the inference endpoint's TCP port.
func TestJailPolicyDerivation(t *testing.T) {
	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	pol, err := jailPolicy(wt, "http://127.0.0.1:44100")
	if err != nil {
		t.Fatalf("jailPolicy: %v", err)
	}

	// Egress: exactly the endpoint port, nothing else.
	if len(pol.AllowTCPPorts) != 1 || pol.AllowTCPPorts[0] != 44100 {
		t.Errorf("AllowTCPPorts = %v, want [44100]", pol.AllowTCPPorts)
	}
	// Read-only rootfs.
	if len(pol.ReadPaths) != 1 || pol.ReadPaths[0] != "/" {
		t.Errorf("ReadPaths = %v, want [/]", pol.ReadPaths)
	}
	// Writes: the worktree tree must be covered, and the repo's tracked working
	// tree must NOT be a write path (only its .git metadata dir may be).
	if !containsPathUnder(pol.WritePaths, wt.Dir) {
		t.Errorf("WritePaths %v does not cover the worktree dir %q", pol.WritePaths, wt.Dir)
	}
	gitDir := filepath.Join(repo, ".git")
	if !contains(pol.WritePaths, gitDir) {
		t.Errorf("WritePaths %v missing git metadata dir %q", pol.WritePaths, gitDir)
	}
	if contains(pol.WritePaths, repo) {
		t.Errorf("WritePaths %v must NOT grant write to the repo working tree %q", pol.WritePaths, repo)
	}
	if !contains(pol.WritePaths, "/dev") {
		t.Errorf("WritePaths %v missing /dev (needed for opencode device I/O)", pol.WritePaths)
	}
}

func TestJailPolicyRejectsBadEndpoint(t *testing.T) {
	repo := initFixtureRepo(t)
	j := &sandbox.Jail{TargetRepo: repo, BaseRef: "main"}
	wt, err := j.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer wt.Close()

	if _, err := jailPolicy(wt, ""); err == nil {
		t.Fatal("jailPolicy should fail-closed on an empty inference endpoint")
	}
}

func contains(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

// containsPathUnder reports whether target equals or is nested under any path in
// paths (the worktree Dir lives under the tmpRoot write path).
func containsPathUnder(paths []string, target string) bool {
	for _, p := range paths {
		if p == target {
			return true
		}
		if rel, err := filepath.Rel(p, target); err == nil && rel != ".." && !filepath.IsAbs(rel) && !startsWithDotDot(rel) {
			return true
		}
	}
	return false
}

func startsWithDotDot(rel string) bool {
	return len(rel) >= 2 && rel[0] == '.' && rel[1] == '.'
}
