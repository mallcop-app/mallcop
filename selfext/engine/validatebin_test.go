package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeMallcop writes an executable named "mallcop" (or, if goodMarker is
// false, an executable that behaves like an unrelated/stale binary sharing
// the name) into a fresh directory and returns that directory — suitable for
// prepending to PATH so exec.LookPath("mallcop") resolves to it.
func writeFakeMallcop(t *testing.T, goodMarker bool) string {
	t.Helper()
	dir := t.TempDir()
	var script string
	if goodMarker {
		// Mimics cli/main.go's default case for an unrecognized subcommand:
		// fmt.Fprintf(os.Stderr, "mallcop: unknown command %q\n\n", cmd); exit 1.
		script = "#!/bin/sh\necho 'mallcop: unknown command \"'\"$1\"'\"' >&2\nexit 1\n"
	} else {
		// Simulates a stale/wrong binary sharing the "mallcop" name on PATH
		// (e.g. the deprecated python-legacy shim) — it does not know the
		// probe subcommand and does not emit the Go CLI's marker text.
		script = "#!/bin/sh\necho 'Traceback: ModuleNotFoundError: no module named mallcop' >&2\nexit 1\n"
	}
	path := filepath.Join(dir, "mallcop")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestResolveValidateBinExplicitTrustedVerbatim proves an explicitly
// configured Engine.ValidateBin is returned as-is, with NO PATH lookup and NO
// version probe — operator/test-injected configuration is trusted directly
// (the probe only guards the unverified default-PATH-lookup path).
func TestResolveValidateBinExplicitTrustedVerbatim(t *testing.T) {
	e := &Engine{ValidateBin: "/does/not/exist/on/this/machine/mallcop"}
	bin, err := e.resolveValidateBin(context.Background())
	if err != nil {
		t.Fatalf("resolveValidateBin: unexpected error for explicit config: %v", err)
	}
	if bin != "/does/not/exist/on/this/machine/mallcop" {
		t.Fatalf("resolveValidateBin: got %q, want explicit path returned verbatim", bin)
	}
}

// TestResolveValidateBinDefaultAcceptsGoMallcop proves the default (empty
// ValidateBin) resolution accepts a PATH-resolved "mallcop" that answers the
// version probe like the real Go CLI does.
func TestResolveValidateBinDefaultAcceptsGoMallcop(t *testing.T) {
	dir := writeFakeMallcop(t, true)
	t.Setenv("PATH", dir)

	e := &Engine{}
	bin, err := e.resolveValidateBin(context.Background())
	if err != nil {
		t.Fatalf("resolveValidateBin: unexpected error for a probe-passing binary: %v", err)
	}
	want := filepath.Join(dir, "mallcop")
	if bin != want {
		t.Fatalf("resolveValidateBin: got %q, want %q", bin, want)
	}
}

// TestResolveValidateBinDefaultRejectsStaleShim is the regression test for
// a bare, unverified `mallcop` resolved from PATH must be
// rejected — loudly, with an actionable error — when it does not behave like
// the mallcop Go CLI (e.g. a stale python-legacy shim, or any other unrelated
// binary sharing the name). Before this fix, the engine would silently exec
// whatever "mallcop" PATH resolved to.
func TestResolveValidateBinDefaultRejectsStaleShim(t *testing.T) {
	dir := writeFakeMallcop(t, false)
	t.Setenv("PATH", dir)

	e := &Engine{}
	bin, err := e.resolveValidateBin(context.Background())
	if err == nil {
		t.Fatalf("resolveValidateBin: expected an error rejecting the non-Go-mallcop binary, got bin=%q", bin)
	}
	if bin != "" {
		t.Fatalf("resolveValidateBin: expected an empty bin on error, got %q", bin)
	}
	if !strings.Contains(err.Error(), "does not look like the mallcop Go CLI") {
		t.Fatalf("resolveValidateBin: error does not explain the rejection: %v", err)
	}
}

// TestResolveValidateBinDefaultMissingFromPATH proves a missing "mallcop" on
// PATH fails loudly with an actionable message instead of a bare exec error
// surfacing deep inside the gate step.
func TestResolveValidateBinDefaultMissingFromPATH(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty dir: LookPath("mallcop") fails

	e := &Engine{}
	bin, err := e.resolveValidateBin(context.Background())
	if err == nil {
		t.Fatalf("resolveValidateBin: expected an error when mallcop is absent from PATH, got bin=%q", bin)
	}
	if !strings.Contains(err.Error(), "not found on PATH") {
		t.Fatalf("resolveValidateBin: error does not explain the missing binary: %v", err)
	}
	if !strings.Contains(err.Error(), "-validate-bin") {
		t.Fatalf("resolveValidateBin: error does not point at the escape hatch: %v", err)
	}
}

// TestProbeGoMallcopBinaryDirect exercises probeGoMallcopBinary standalone
// (the same function resolveValidateBin delegates to) against both a
// passing and a failing fake binary.
func TestProbeGoMallcopBinaryDirect(t *testing.T) {
	good := filepath.Join(writeFakeMallcop(t, true), "mallcop")
	if err := probeGoMallcopBinary(context.Background(), good); err != nil {
		t.Fatalf("probeGoMallcopBinary: unexpected error for a Go-CLI-shaped binary: %v", err)
	}

	bad := filepath.Join(writeFakeMallcop(t, false), "mallcop")
	if err := probeGoMallcopBinary(context.Background(), bad); err == nil {
		t.Fatalf("probeGoMallcopBinary: expected an error for a non-Go-mallcop binary")
	}
}
