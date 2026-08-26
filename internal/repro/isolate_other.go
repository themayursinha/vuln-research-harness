//go:build !linux

package repro

import (
	"fmt"
	"os/exec"
)

func isolateCommand(cmd *exec.Cmd) error {
	return fmt.Errorf("network-denied reproduction requires Linux")
}
