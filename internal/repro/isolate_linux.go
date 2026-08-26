//go:build linux

package repro

import (
	"os"
	"os/exec"
	"syscall"
)

// denyNetwork places the child in a new user+network namespace with no
// interfaces besides the empty netns. That is the process-local enforcement
// boundary: probes can lie about two destinations, but this child cannot
// use the host's network.
func denyNetwork(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	return nil
}
