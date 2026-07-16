// Package jail applies OS-enforced, fail-closed confinement to the headless
// opencode code-authoring child of mallcop's self-extension loop.
//
// # Threat model
//
// The authoring subprocess (opencode, run with --dangerously-skip-permissions)
// executes model-influenced shell inside the runner. Even though the prompt is
// built only from TRUSTED structural signals (see internal/selfext/opencode),
// defense-in-depth demands that the *process itself* cannot:
//
//   - reach the network for anything other than its one inference endpoint, and
//   - write anywhere on the filesystem outside its own authoring scratch tree.
//
// # Mechanism (Linux Landlock LSM)
//
// Confinement is enforced by the kernel's Landlock LSM (ABI v4+, which adds TCP
// connect restriction on top of the v1 filesystem restriction). It is:
//
//   - unprivileged — needs no root, no CAP_NET_ADMIN, no privileged container,
//     so it works inside a stock GitHub Actions ubuntu runner container;
//   - inherited across exec — restrictions applied to the launcher stick to the
//     opencode process it execs and every descendant; and
//   - irreversible — a confined process cannot widen its own rights.
//
// This is the OS layer BELOW the runner-level controls (step-security/
// harden-runner egress-policy:block host allowlist, ephemeral runner, worthless
// short-lived subkey, agent-unreachable exam gate, human PR review). Landlock
// binds the child to exactly the TCP port of its configured inference endpoint
// and a read-only rootfs with a single writable scratch tree; harden-runner
// binds which hosts are reachable on that port. Together they are a real jail,
// not just risk-reduction.
//
// # Fail-closed
//
// If confinement cannot be established — non-Linux host, kernel without the
// required Landlock ABI, or a rule that fails to load — Apply returns an error
// and MaybeReexec exits non-zero WITHOUT execing opencode. Authoring therefore
// refuses to start rather than running unconfined.
//
// # Launcher pattern
//
// Landlock restricts the WHOLE calling process, so the unjailed parent
// (mallcop-ops, which still needs full filesystem/network to run the gate, git,
// and the stream shim) cannot apply it to itself. Instead the adapter builds a
// command that re-execs the mallcop-ops binary itself (/proc/self/exe) with the
// reexec marker as argv[1] and the policy in the environment. MaybeReexec, called
// at the very top of main(), intercepts that marker, applies the jail, then execs
// the real opencode argv — so only the child is confined.
package jail

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// ReexecMarker is the argv[1] sentinel that tells MaybeReexec this process was
// spawned to become the jailed opencode child. It is deliberately unlikely to
// collide with any real mallcop-ops subcommand.
const ReexecMarker = "__selfext_jail_exec__"

// policyEnvKey is the environment variable carrying the JSON-encoded Policy from
// the launcher to the re-exec'd child. Passing it in the environment (not argv)
// keeps the child's argv equal to the real opencode command line.
const policyEnvKey = "MALLCOP_SELFEXT_JAIL_POLICY"

// ErrUnsupported is returned when OS-enforced confinement is unavailable on this
// host (non-Linux, or a kernel lacking the required Landlock ABI). Callers MUST
// treat it as fatal — authoring refuses to start.
var ErrUnsupported = errors.New("jail: OS-enforced confinement unavailable")

// Policy is the confinement to enforce on the authoring child. Zero values are
// rejected by Apply (fail-closed): an empty WritePaths or AllowTCPPorts would be
// a confinement with no scratch tree or no reachable endpoint, which is never a
// legitimate authoring configuration.
type Policy struct {
	// WritePaths are the directories the child may read AND write. It must
	// contain exactly the authoring scratch tree (worktree + throwaway
	// HOME/TMPDIR) and the git metadata dir the worktree writes through.
	WritePaths []string `json:"write_paths"`
	// ReadPaths are directories the child may read and execute from but never
	// write. Normally just "/" — the child needs to read the toolchain, libs,
	// and CA bundle, but must not modify anything outside WritePaths.
	ReadPaths []string `json:"read_paths"`
	// AllowTCPPorts are the only TCP ports the child may connect(2) to. It must
	// be exactly the port of the configured inference endpoint (the loopback
	// stream-shim port on the donut rail, or 443 for a direct BYOI endpoint).
	AllowTCPPorts []uint16 `json:"allow_tcp_ports"`
}

// PolicyEnv encodes p as the environment entry ("KEY=<json>") the launcher must
// add to the re-exec'd child's environment so MaybeReexec can reconstruct it.
func PolicyEnv(p Policy) (string, error) {
	blob, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("jail: marshal policy: %w", err)
	}
	return policyEnvKey + "=" + string(blob), nil
}

// policyFromEnv reconstructs the Policy the launcher stored in the environment.
func policyFromEnv() (Policy, error) {
	raw := os.Getenv(policyEnvKey)
	if raw == "" {
		return Policy{}, errors.New("jail: " + policyEnvKey + " is empty")
	}
	var p Policy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return Policy{}, fmt.Errorf("jail: decode policy: %w", err)
	}
	return p, nil
}

// validate enforces the fail-closed invariants shared by Apply on every OS.
func (p Policy) validate() error {
	if len(p.WritePaths) == 0 {
		return errors.New("jail: policy has no writable authoring tree")
	}
	if len(p.AllowTCPPorts) == 0 {
		return errors.New("jail: policy allows no inference endpoint port")
	}
	for _, port := range p.AllowTCPPorts {
		if port == 0 {
			return errors.New("jail: policy allows TCP port 0")
		}
	}
	return nil
}
