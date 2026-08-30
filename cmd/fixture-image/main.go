// fixture-image builds the reference campaign image with the same local
// runtime and sanitized client environment VRH uses for repro, then prints
// a digest pin for campaign.yaml.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/themayursinha/vuln-research-harness/internal/container"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("fixture-image", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	image := fs.String("image", container.DefaultFixtureImage, "local image tag to build")
	runtime := fs.String("runtime", "", "docker or podman (default: same as container.Detect)")
	contextDir := fs.String("context", "campaigns/fixture-lab", "build context directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: fixture-image [-runtime docker|podman] [-image tag] [-context dir]")
	}
	prefer := strings.TrimSpace(*runtime)
	if prefer == "" {
		prefer = strings.TrimSpace(os.Getenv("CONTAINER_RUNTIME"))
	}

	var rt container.Runtime
	var err error
	if prefer == "" {
		rt, err = container.Detect()
	} else {
		rt, err = container.DetectKind(prefer)
	}
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "building with %s (%s)\n", rt.Kind, rt.Bin)
	if err := rt.BuildImage(context.Background(), *contextDir, *image); err != nil {
		return err
	}
	pin, err := rt.PinLocalImage(*image)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "container_image for campaign.yaml:\n")
	fmt.Println(pin)
	return nil
}
