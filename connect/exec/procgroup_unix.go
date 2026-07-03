//go:build unix

package exec

import (
	osexec "os/exec"
	"syscall"
)

// setProcessGroup puts the sibling in its own process group and makes context
// cancellation kill the WHOLE group. A sibling implemented as a shell wrapper
// may fork grandchildren (e.g. `sleep`, a paginating sub-tool) that inherit the
// stdout pipe; killing only the direct child would leave a grandchild holding
// the pipe open, so the parser's read would block past the deadline. Killing the
// group closes the pipe promptly and honors budgets.scan_timeout.
func setProcessGroup(cmd *osexec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative PID targets the process group led by the child.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
