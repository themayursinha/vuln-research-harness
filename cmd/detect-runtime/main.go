// detect-runtime prints the container runtime kind VRH would select (podman or
// docker). Used by make fixture-image so the build targets the same runtime as
// container.Detect, not merely the first binary on PATH.
package main

import (
	"fmt"
	"os"

	"github.com/themayursinha/vuln-research-harness/internal/container"
)

func main() {
	rt, err := container.Detect()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(rt.Kind)
}
