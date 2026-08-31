package container

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultFixtureImage is the local tag make fixture-image builds.
	DefaultFixtureImage = "localhost/vrh-fixture-lab:latest"
	fixtureBuildTimeout = 10 * time.Minute
)

// BuildImage builds contextDir into tag using the same sanitized local
// client environment as Detect/repro (no DOCKER_CONTEXT, local unix socket
// only). Build logs go to stderr; a failed build does not inspect a tag.
func (rt Runtime) BuildImage(ctx context.Context, contextDir, tag string) error {
	if rt.Bin == "" {
		return fmt.Errorf("container runtime is required")
	}
	if strings.TrimSpace(tag) == "" || strings.ContainsAny(tag, " \t\n\r") {
		return fmt.Errorf("image tag is required and must not contain whitespace")
	}
	env, err := rt.clientEnv()
	if err != nil {
		return err
	}
	dir, err := filepath.Abs(contextDir)
	if err != nil {
		return fmt.Errorf("fixture context: %w", err)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("fixture context %s is not a directory", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "Dockerfile")); err != nil {
		return fmt.Errorf("fixture context missing Dockerfile: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, fixtureBuildTimeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, rt.Bin, "build", "-t", tag, dir)
	cmd.Env = withBuildProxyEnv(env)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build %s: %w", tag, err)
	}
	return nil
}

// PinLocalImage returns a digest pin for a local tag that RequireImage will
// accept. Local docker build often has an image ID but no RepoDigests entry
// until a registry push; Id (sha256:...) is a valid pin in that case.
func (rt Runtime) PinLocalImage(tag string) (string, error) {
	out, err := rt.preflightStdout("image", "inspect", "--format", "{{json .}}", tag)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %s", tag, strings.TrimSpace(string(out)))
	}
	pin, err := pinFromInspect(out)
	if err != nil {
		return "", fmt.Errorf("image %s: %w", tag, err)
	}
	if err := rt.RequireImage(pin); err != nil {
		return "", err
	}
	return pin, nil
}

type imageInspect struct {
	ID          string   `json:"Id"`
	Digest      string   `json:"Digest"`
	RepoDigests []string `json:"RepoDigests"`
}

func pinFromInspect(raw []byte) (string, error) {
	var img imageInspect
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &img); err != nil {
		return "", fmt.Errorf("parse image inspect: %w", err)
	}
	for _, d := range img.RepoDigests {
		if p := strings.TrimSpace(d); PinnedImage(p) {
			return p, nil
		}
	}
	if p := strings.TrimSpace(img.Digest); PinnedImage(p) {
		return p, nil
	}
	if p := strings.TrimSpace(img.ID); PinnedImage(p) {
		return p, nil
	}
	return "", fmt.Errorf("no digest pin (RepoDigests, Digest, or Id)")
}

func withBuildProxyEnv(env []string) []string {
	out := copyEnv(env)
	keys := []string{
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "no_proxy",
	}
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			out = append(out, key+"="+v)
		}
	}
	return out
}

func (rt Runtime) preflightStdout(args ...string) ([]byte, error) {
	env, err := rt.clientEnv()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), preflightTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, rt.Bin, args...)
	cmd.Env = env
	return runBoundedStdout(cmd)
}
