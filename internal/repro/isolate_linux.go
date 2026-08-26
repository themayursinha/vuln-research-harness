//go:build linux

package repro

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

// isolateCommand is the process-local sandbox for one reproduction:
// a new user+network namespace (no host network), a dedicated process
// group so the deadline can kill descendants, Pdeathsig so orphans die
// with vrh, and WaitDelay so a leaked pipe cannot hang Run forever.
func isolateCommand(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Setpgid:                    true,
		Pdeathsig:                  syscall.SIGKILL,
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return err
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
	return nil
}
