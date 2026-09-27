//go:build !windows

package osp

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcAttr puts the child in its own process group so a signal aimed at
// applianced (PID 1 in the container) is not delivered to redis/ospd twice.
func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminate asks the child to exit; loop() escalates to Kill after 30 s.
func terminate(p *os.Process) error { return p.Signal(syscall.SIGTERM) }
