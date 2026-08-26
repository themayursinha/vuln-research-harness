//go:build !linux

package repro

import (
	"fmt"
	"os/exec"
)

func denyNetwork(cmd *exec.Cmd) error {
	return fmt.Errorf("network-denied reproduction requires Linux")
}
