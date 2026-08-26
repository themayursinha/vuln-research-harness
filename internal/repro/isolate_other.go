//go:build !linux

package repro

import (
	"context"
	"fmt"
	"os/exec"
)

func startIsolatedCommand(ctx context.Context, interpreter, script string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("network-denied reproduction requires Linux")
}
