//go:build linux

package jail

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// TestApplyEnforced is the ground-truth proof that the jail is a REAL,
// kernel-enforced sandbox — not a configured-but-unproven one. It runs a child
// process that applies a Policy and then exercises the boundaries the jail must
// hold:
//
//	filesystem: a write inside the authoring tree SUCCEEDS; a write outside it
//	            is DENIED; a read of the (read-only) rootfs still SUCCEEDS.
//	egress:     a TCP connect to the allowed inference port SUCCEEDS; a connect
//	            to any other port is DENIED with EACCES.
//
// The parent sets up the two live listeners and the two directories BEFORE the
// jail exists, so absent confinement every operation would succeed — meaning a
// failure of the "blocked" assertions can only be the kernel enforcing Landlock.
//
// It runs for real on any Linux host with Landlock ABI >= 4 (every current
// GitHub Actions ubuntu runner; the CI `go test ./...` step exercises it). It is
// skipped ONLY on a kernel that genuinely lacks the required ABI — never
// mocked, never skipped everywhere.
func TestApplyEnforced(t *testing.T) {
	if os.Getenv(childEnv) == "1" {
		runJailChild()
		return
	}
	if err := Supported(); err != nil {
		t.Skipf("kernel lacks required Landlock ABI: %v", err)
	}

	// Two directories: one the child may write, a sibling it must not.
	writeDir := t.TempDir()
	outsideDir := t.TempDir()

	// Two live loopback listeners: one whose port the policy allows, one it does
	// not. Both accept before the jail is applied, so only Landlock can make the
	// blocked connect fail.
	allowLn := mustListen(t)
	defer allowLn.Close()
	blockLn := mustListen(t)
	defer blockLn.Close()
	go acceptLoop(allowLn)
	go acceptLoop(blockLn)

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(self, "-test.run=TestApplyEnforced")
	cmd.Env = append(os.Environ(),
		childEnv+"=1",
		"JAIL_WRITE_DIR="+writeDir,
		"JAIL_OUTSIDE_DIR="+outsideDir,
		"JAIL_ALLOW_PORT="+strconv.Itoa(portOf(allowLn)),
		"JAIL_BLOCK_PORT="+strconv.Itoa(portOf(blockLn)),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("jailed child failed (jail did not behave as required):\n%s\nerr: %v", out, err)
	}
	t.Logf("jailed child assertions passed:\n%s", out)
}

const childEnv = "JAIL_TEST_CHILD"

// runJailChild executes inside the forked test binary: it applies the jail, then
// asserts every boundary. Any violation prints to stderr and exits non-zero so
// the parent's CombinedOutput/err surfaces it as a test failure.
func runJailChild() {
	writeDir := os.Getenv("JAIL_WRITE_DIR")
	outsideDir := os.Getenv("JAIL_OUTSIDE_DIR")
	allowPort, _ := strconv.Atoi(os.Getenv("JAIL_ALLOW_PORT"))
	blockPort, _ := strconv.Atoi(os.Getenv("JAIL_BLOCK_PORT"))

	die := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", a...)
		os.Exit(1)
	}

	p := Policy{
		WritePaths:    []string{writeDir},
		ReadPaths:     []string{"/"},
		AllowTCPPorts: []uint16{uint16(allowPort)},
	}
	if err := Apply(p); err != nil {
		die("Apply: %v", err)
	}

	// 1) write inside the authoring tree — must succeed.
	if err := os.WriteFile(filepath.Join(writeDir, "inside.txt"), []byte("ok"), 0o600); err != nil {
		die("write inside authoring tree denied: %v", err)
	}
	// 2) write outside the authoring tree — must be denied by the kernel.
	if err := os.WriteFile(filepath.Join(outsideDir, "escape.txt"), []byte("nope"), 0o600); err == nil {
		die("write OUTSIDE authoring tree was ALLOWED — filesystem jail not enforced")
	} else if !errors.Is(err, syscall.EACCES) {
		die("write outside failed with %v, expected EACCES", err)
	}
	// 3) read of the read-only rootfs must still work (child needs the toolchain).
	if _, err := os.ReadFile("/proc/self/status"); err != nil {
		die("read of read-only rootfs denied: %v", err)
	}

	// 4) connect to the allowed inference port — must succeed.
	if err := rawConnect(allowPort); err != nil {
		die("connect to ALLOWED port %d denied: %v", allowPort, err)
	}
	// 5) connect to any other port — must be denied with EACCES.
	if err := rawConnect(blockPort); err == nil {
		die("connect to DISALLOWED port %d was ALLOWED — egress jail not enforced", blockPort)
	} else if !errors.Is(err, syscall.EACCES) {
		die("connect to disallowed port failed with %v, expected EACCES", err)
	}

	os.Stdout.WriteString("PASS fs-inside fs-outside-blocked ro-read egress-allowed egress-blocked\n")
	os.Exit(0)
}

// rawConnect performs a plain AF_INET TCP connect(2) to 127.0.0.1:port. A raw
// socket (never a Go net.Dialer) is used so the syscall is unambiguously the one
// Landlock restricts — no Multipath-TCP fallback that the kernel would not gate.
func rawConnect(port int) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	sa := &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
	return syscall.Connect(fd, sa)
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

func acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
	}
}

func portOf(ln net.Listener) int { return ln.Addr().(*net.TCPAddr).Port }
