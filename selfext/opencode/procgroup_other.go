//go:build !unix

package opencode

import "os/exec"

// setProcessGroup is a no-op on non-unix platforms; CommandContext's default
// single-process kill applies. The product runtime targets linux.
func setProcessGroup(cmd *exec.Cmd) {}
