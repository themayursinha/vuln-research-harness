// detect-runtime prints the container runtime binary VRH would select.
// Used by make fixture-image so the build targets the same local engine as
// container.Detect, not merely the first binary on PATH.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/themayursinha/vuln-research-harness/internal/container"
)

func main() {
	prefer := ""
	switch len(os.Args) {
	case 1:
	case 2:
		prefer = strings.TrimSpace(os.Args[1])
	default:
		fmt.Fprintln(os.Stderr, "usage: detect-runtime [docker|podman]")
		os.Exit(2)
	}

	var rt container.Runtime
	var err error
	if prefer == "" {
		rt, err = container.Detect()
	} else {
		rt, err = container.DetectKind(prefer)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(rt.Bin)
}
