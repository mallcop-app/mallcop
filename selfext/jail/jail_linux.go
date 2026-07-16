//go:build linux

package jail

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// minABI is the lowest Landlock ABI version that supports everything the jail
// needs: v4 adds TCP connect restriction on top of v1 filesystem restriction.
// Below it, the egress half of the jail cannot be enforced, so confinement is
// treated as unavailable (fail-closed).
const minABI = 4

// Supported reports nil when the running kernel exposes a Landlock ABI high
// enough to enforce both halves of the jail (filesystem + TCP egress). It
// returns ErrUnsupported otherwise so the adapter can refuse to author BEFORE
// spawning anything.
func Supported() error {
	v, err := llsyscall.LandlockGetABIVersion()
	if err != nil {
		return fmt.Errorf("%w: probe Landlock ABI: %v", ErrUnsupported, err)
	}
	if v < minABI {
		return fmt.Errorf("%w: kernel Landlock ABI v%d < required v%d", ErrUnsupported, v, minABI)
	}
	return nil
}

// Apply enforces p on the current process via Landlock and never widens rights.
// It is STRICT (not best-effort): if the kernel cannot enforce every requested
// filesystem and network right, Restrict returns an error and Apply propagates
// it — the caller must then abort. Once Apply returns nil the process (and every
// descendant it execs) can only read/execute under ReadPaths, read+write under
// WritePaths, and connect(2) to AllowTCPPorts; all other filesystem writes and
// all other TCP egress are denied by the kernel.
func Apply(p Policy) error {
	if err := p.validate(); err != nil {
		return err
	}
	if err := Supported(); err != nil {
		return err
	}

	rules := make([]landlock.Rule, 0, len(p.WritePaths)+len(p.ReadPaths)+len(p.AllowTCPPorts))
	for _, dir := range p.ReadPaths {
		rules = append(rules, landlock.RODirs(dir))
	}
	for _, dir := range p.WritePaths {
		rules = append(rules, landlock.RWDirs(dir))
	}
	for _, port := range p.AllowTCPPorts {
		rules = append(rules, landlock.ConnectTCP(port))
	}

	// landlock.V4 handles the v1..v4 filesystem access rights PLUS TCP connect.
	// Using the exact version (not BestEffort) makes this fail-closed: on a
	// kernel that cannot honor a requested right, Restrict errors instead of
	// silently downgrading to a weaker (or empty) sandbox.
	if err := landlock.V4.Restrict(rules...); err != nil {
		return fmt.Errorf("jail: apply Landlock confinement: %w", err)
	}
	return nil
}

// MaybeReexec turns the current process into the jailed opencode child when it
// was launched with ReexecMarker as argv[1] (see WrapCommand). It reads the
// Policy from the environment, applies the jail, and then execs the real
// command carried in argv[2:]. It NEVER returns on that path: on success it
// hands the (now confined) process over to opencode via execve; on ANY failure
// to establish the jail it prints the reason and exits non-zero WITHOUT execing
// opencode — so a confinement failure can never degrade into an unconfined run.
//
// When argv[1] is not the marker (the normal operator-binary invocation) it
// returns immediately and main() proceeds as usual. Call it at the very top of main().
func MaybeReexec() {
	if len(os.Args) < 2 || os.Args[1] != ReexecMarker {
		return
	}
	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "selfext jail: "+format+"\n", args...)
		os.Exit(127)
	}

	p, err := policyFromEnv()
	if err != nil {
		fail("%v", err)
	}
	if len(os.Args) < 3 {
		fail("no command to exec after marker")
	}
	if err := Apply(p); err != nil {
		fail("refusing to author unconfined: %v", err)
	}

	argv := os.Args[2:]
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		fail("resolve %q: %v", argv[0], err)
	}
	// Scrub the policy from the child's environment so opencode never sees it.
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if len(kv) > len(policyEnvKey) && kv[:len(policyEnvKey)+1] == policyEnvKey+"=" {
			continue
		}
		env = append(env, kv)
	}
	if err := syscall.Exec(bin, argv, env); err != nil {
		fail("exec %q: %v", bin, err)
	}
}

// WrapCommand builds an *exec.Cmd that launches (name, args...) inside the jail
// described by p. It re-execs self (normally "/proc/self/exe", the operator
// binary) with ReexecMarker as argv[1] so MaybeReexec in that process applies p
// and then execs the real command. The caller MUST set cmd.Env to include the
// PolicyEnv(p) entry (Apply reads the policy from the environment) and may set
// cmd.Dir; every other field is the caller's to fill exactly as for a direct
// exec.CommandContext of (name, args...). Cancelling ctx kills the jailed child.
func WrapCommand(ctx context.Context, self, name string, args ...string) *exec.Cmd {
	full := append([]string{ReexecMarker, name}, args...)
	return exec.CommandContext(ctx, self, full...)
}
