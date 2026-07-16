//go:build !linux

package jail

import (
	"context"
	"os/exec"
)

// Supported always reports ErrUnsupported off Linux: Landlock is a Linux LSM, so
// no OS-enforced confinement exists here. Authoring must refuse to start.
func Supported() error { return ErrUnsupported }

// Apply cannot confine anything off Linux and fails closed.
func Apply(Policy) error { return ErrUnsupported }

// MaybeReexec is a no-op off Linux — the jail launcher is never used because
// Supported() gates the adapter before any wrapped command is built.
func MaybeReexec() {}

// WrapCommand exists for symmetry so callers compile on every OS; it is never
// reached off Linux because the adapter checks Supported() first.
func WrapCommand(ctx context.Context, self, name string, args ...string) *exec.Cmd {
	full := append([]string{ReexecMarker, name}, args...)
	return exec.CommandContext(ctx, self, full...)
}
