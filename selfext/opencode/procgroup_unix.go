//go:build unix

package opencode

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the opencode subprocess in its OWN process group and
// makes context expiry (Adapter.Timeout) kill the WHOLE
// group. Mirrors mallcop connect/exec's procgroup_unix.go byte-for-byte in
// intent: headless opencode may itself fork tool subprocesses (a shell tool
// call, a paginating sub-process) that inherit the stdout/stderr pipes;
// killing only the direct child could leave a grandchild holding a pipe open,
// so runOnce's read of stdout/stderr would never observe EOF and Wait could
// still hang past the timeout. Killing the group closes the pipes promptly.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative PID targets the process group led by the child.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
