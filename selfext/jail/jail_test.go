package jail

import (
	"context"
	"strings"
	"testing"
)

func TestPolicyEnvRoundTrip(t *testing.T) {
	in := Policy{
		WritePaths:    []string{"/tmp/wt", "/repo/.git"},
		ReadPaths:     []string{"/"},
		AllowTCPPorts: []uint16{443, 8080},
	}
	entry, err := PolicyEnv(in)
	if err != nil {
		t.Fatalf("PolicyEnv: %v", err)
	}
	if !strings.HasPrefix(entry, policyEnvKey+"=") {
		t.Fatalf("env entry %q missing %q prefix", entry, policyEnvKey)
	}
	// Reconstruct via the same env the child would read.
	t.Setenv(policyEnvKey, strings.TrimPrefix(entry, policyEnvKey+"="))
	got, err := policyFromEnv()
	if err != nil {
		t.Fatalf("policyFromEnv: %v", err)
	}
	if len(got.WritePaths) != 2 || got.WritePaths[0] != "/tmp/wt" || got.WritePaths[1] != "/repo/.git" {
		t.Errorf("WritePaths round-trip mismatch: %v", got.WritePaths)
	}
	if len(got.ReadPaths) != 1 || got.ReadPaths[0] != "/" {
		t.Errorf("ReadPaths round-trip mismatch: %v", got.ReadPaths)
	}
	if len(got.AllowTCPPorts) != 2 || got.AllowTCPPorts[0] != 443 || got.AllowTCPPorts[1] != 8080 {
		t.Errorf("AllowTCPPorts round-trip mismatch: %v", got.AllowTCPPorts)
	}
}

func TestPolicyValidateFailClosed(t *testing.T) {
	cases := []struct {
		name string
		p    Policy
	}{
		{"no write tree", Policy{ReadPaths: []string{"/"}, AllowTCPPorts: []uint16{443}}},
		{"no allowed port", Policy{WritePaths: []string{"/tmp/wt"}, ReadPaths: []string{"/"}}},
		{"port zero", Policy{WritePaths: []string{"/tmp/wt"}, AllowTCPPorts: []uint16{0}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.p.validate(); err == nil {
				t.Fatalf("expected validate() to reject %+v", tc.p)
			}
		})
	}
}

func TestPolicyValidateAcceptsMinimal(t *testing.T) {
	p := Policy{WritePaths: []string{"/tmp/wt"}, ReadPaths: []string{"/"}, AllowTCPPorts: []uint16{443}}
	if err := p.validate(); err != nil {
		t.Fatalf("validate() rejected a valid policy: %v", err)
	}
}

func TestPolicyFromEnvEmpty(t *testing.T) {
	t.Setenv(policyEnvKey, "")
	if _, err := policyFromEnv(); err == nil {
		t.Fatal("policyFromEnv should error on empty env")
	}
}

func TestWrapCommandArgv(t *testing.T) {
	cmd := WrapCommand(context.Background(), "/proc/self/exe", "opencode", "run", "task", "-m", "forge/heal")
	want := []string{"/proc/self/exe", ReexecMarker, "opencode", "run", "task", "-m", "forge/heal"}
	if len(cmd.Args) != len(want) {
		t.Fatalf("argv length: got %v want %v", cmd.Args, want)
	}
	for i := range want {
		if cmd.Args[i] != want[i] {
			t.Errorf("argv[%d]: got %q want %q", i, cmd.Args[i], want[i])
		}
	}
	if cmd.Path != "/proc/self/exe" {
		t.Errorf("cmd.Path: got %q want /proc/self/exe", cmd.Path)
	}
}
