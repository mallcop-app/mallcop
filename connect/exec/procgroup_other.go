//go:build !unix

package exec

import osexec "os/exec"

// setProcessGroup is a no-op on non-unix platforms; CommandContext's default
// single-process kill applies. The product runtime targets linux.
func setProcessGroup(cmd *osexec.Cmd) {}
