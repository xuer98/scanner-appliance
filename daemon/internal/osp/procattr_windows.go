//go:build windows

package osp

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcAttr detaches the child from the console so Ctrl-C aimed at
// applianced is not delivered to it as well. The supervisor is only ever
// useful on Linux (redis-openvas / ospd-openvas are not built for Windows);
// this keeps the package compiling and behaving sanely there.
func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

// terminate: Windows has no SIGTERM; os.Process.Signal only supports Kill.
func terminate(p *os.Process) error { return p.Kill() }
