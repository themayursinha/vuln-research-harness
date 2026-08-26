// Package container is the disposable OCI adapter for reproduction:
// podman or docker, never a pull, never a published port, never a
// writable snapshot. Process-local namespaces remain available for unit
// tests; vrh repro uses this adapter as the execution boundary.
package container

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const (
	SnapshotMount = "/vrh/snapshot"
	CaseMount     = "/vrh/case"
	ScratchMount  = "/vrh/scratch"
)

// Runtime is a local podman or docker binary that can run a locked spec.
type Runtime struct {
	Bin  string
	Kind string
}

// Spec is one locked container invocation. Callers cannot request network,
// a pull, a writable snapshot, or extra privileges; those flags are
// hardcoded in RunArgs.
type Spec struct {
	Image    string
	Snapshot string // host dir, mounted read-only at SnapshotMount; optional for probes
	Script   string // host file, mounted read-only at CaseMount; optional for probes
	Command  []string
}

// Detect finds a working podman or docker binary. It does not pull images
// and does not create containers.
func Detect() (Runtime, error) {
	for _, kind := range []string{"podman", "docker"} {
		bin, err := exec.LookPath(kind)
		if err != nil {
			continue
		}
		cmd := exec.Command(bin, "version")
		cmd.Env = clientEnv()
		if err := cmd.Run(); err != nil {
			continue
		}
		return Runtime{Bin: bin, Kind: kind}, nil
	}
	return Runtime{}, fmt.Errorf("no container runtime (podman or docker) is available")
}

// PinnedImage reports whether ref is a digest-pinned image (name@sha256:hex
// or sha256:hex). Mutable tags are refused so a local name cannot silently
// start resolving to a different image.
func PinnedImage(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.ContainsAny(ref, " \t\n\r") {
		return false
	}
	digest := ""
	switch {
	case strings.HasPrefix(ref, "sha256:"):
		digest = strings.TrimPrefix(ref, "sha256:")
	default:
		_, d, ok := strings.Cut(ref, "@sha256:")
		if !ok {
			return false
		}
		digest = d
	}
	if len(digest) != 64 {
		return false
	}
	for _, r := range digest {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) {
			return false
		}
	}
	return true
}

func (s Spec) validate() error {
	if !PinnedImage(s.Image) {
		return fmt.Errorf("container image must be digest-pinned (@sha256:... or sha256:...); got %q", s.Image)
	}
	if len(s.Command) == 0 || strings.TrimSpace(s.Command[0]) == "" {
		return fmt.Errorf("container command is required")
	}
	if strings.HasPrefix(s.Command[0], "-") {
		return fmt.Errorf("container command must not start with a flag")
	}
	if strings.ContainsRune(s.Command[0], os.PathSeparator) {
		if _, err := os.Stat(s.Command[0]); err == nil {
			return fmt.Errorf("host interpreter %s cannot run inside the container; use an interpreter from the pinned image", s.Command[0])
		}
	}
	if s.Snapshot != "" {
		if err := absCleanPath(s.Snapshot, "snapshot"); err != nil {
			return err
		}
	}
	if s.Script != "" {
		if err := absCleanPath(s.Script, "script"); err != nil {
			return err
		}
	}
	return nil
}

func absCleanPath(p, what string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s path must be absolute", what)
	}
	if strings.Contains(p, ",") {
		return fmt.Errorf("%s path must not contain a comma", what)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("%s path must not contain ..", what)
	}
	return nil
}

// RunArgs is the argv after the runtime binary. Tests lock this list so a
// future caller cannot add -p, --privileged, or a pull.
func RunArgs(spec Spec, cidFile string) ([]string, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	if cidFile == "" || !filepath.IsAbs(cidFile) {
		return nil, fmt.Errorf("cidfile must be an absolute path")
	}
	args := []string{
		"run", "--rm",
		"--network=none",
		"--pull=never",
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--memory=512m",
		"--cidfile=" + cidFile,
		fmt.Sprintf("--user=%d:%d", os.Getuid(), os.Getgid()),
		"--tmpfs=/tmp:rw,noexec,nosuid,nodev",
		"--tmpfs=" + ScratchMount + ":rw,exec,nosuid,nodev",
		"-e", "VRH_SNAPSHOT=" + SnapshotMount,
		"-e", "VRH_SCRATCH=" + ScratchMount,
		"-e", "HOME=" + ScratchMount,
		"-e", "TMPDIR=" + ScratchMount,
		"-e", "PYTHONDONTWRITEBYTECODE=1",
		"-e", "LANG=C",
		"-e", "LC_ALL=C",
		"--entrypoint=" + spec.Command[0],
	}
	if spec.Snapshot != "" {
		args = append(args, "--mount=type=bind,src="+spec.Snapshot+",dst="+SnapshotMount+",ro=true")
	}
	if spec.Script != "" {
		args = append(args, "--mount=type=bind,src="+spec.Script+",dst="+CaseMount+",ro=true")
	}
	args = append(args, spec.Image)
	args = append(args, spec.Command[1:]...)
	if err := forbidUnsafeArgs(args); err != nil {
		return nil, err
	}
	return args, nil
}

func forbidUnsafeArgs(args []string) error {
	joined := strings.Join(args, "\x00")
	for _, bad := range []string{
		"--privileged",
		"--network=host",
		"--net=host",
		"--pid=host",
		"--pull=always",
		"--pull=missing",
		"--publish-all",
		"-p\x00",
		"--publish\x00",
	} {
		if strings.Contains(joined, bad) {
			return fmt.Errorf("refusing unsafe container flag")
		}
	}
	hasNone, hasNever, hasRO := false, false, false
	for i, a := range args {
		if a == "--network=none" {
			hasNone = true
		}
		if a == "--pull=never" {
			hasNever = true
		}
		if a == "--read-only" {
			hasRO = true
		}
		if a == "-p" || a == "--publish" || strings.HasPrefix(a, "-p=") || strings.HasPrefix(a, "--publish=") {
			return fmt.Errorf("refusing published ports")
		}
		if a == "--privileged" {
			return fmt.Errorf("refusing privileged container")
		}
		if i+1 < len(args) && (a == "--network" || a == "--net") && args[i+1] != "none" {
			return fmt.Errorf("container network must be none")
		}
	}
	if !hasNone || !hasNever || !hasRO {
		return fmt.Errorf("locked isolation flags missing from container argv")
	}
	return nil
}

// RequireImage fails closed unless the digest-pinned image is already local.
func (rt Runtime) RequireImage(image string) error {
	if rt.Bin == "" {
		return fmt.Errorf("container runtime is required")
	}
	if !PinnedImage(image) {
		return fmt.Errorf("container image must be digest-pinned (@sha256:...); got %q", image)
	}
	cmd := exec.Command(rt.Bin, "image", "inspect", "--format", "{{.Id}}", image)
	cmd.Env = clientEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("image %s is not present locally; refusing to pull: %s", image, strings.TrimSpace(string(out)))
	}
	if strings.TrimSpace(string(out)) == "" {
		return fmt.Errorf("image %s inspect returned no id; isolation unproven", image)
	}
	return nil
}

// Command builds a runtime invocation for spec. Cancel removes the
// container by cidfile so a deadline cannot leave a running research box.
func (rt Runtime) Command(ctx context.Context, spec Spec, cidFile string) (*exec.Cmd, error) {
	args, err := RunArgs(spec, cidFile)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, rt.Bin, args...)
	cmd.Env = clientEnv()
	cmd.Dir = filepath.Dir(cidFile)
	cmd.WaitDelay = 2 * time.Second
	cmd.Cancel = func() error {
		rt.removeCID(cidFile)
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return cmd.Process.Kill()
	}
	return cmd, nil
}

func (rt Runtime) removeCID(cidFile string) {
	cid, err := os.ReadFile(cidFile)
	if err != nil {
		return
	}
	id := string(bytes.TrimSpace(cid))
	if id == "" {
		return
	}
	rm := exec.Command(rt.Bin, "rm", "-f", id)
	rm.Env = clientEnv()
	_ = rm.Run()
}

func clientEnv() []string {
	keys := []string{"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "CONTAINER_HOST", "XDG_RUNTIME_DIR"}
	var env []string
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			env = append(env, key+"="+v)
		}
	}
	if len(env) == 0 {
		return []string{"PATH=/usr/bin:/bin"}
	}
	return env
}

// UniqueCIDFile returns a path under dir that docker/podman can create.
func UniqueCIDFile(dir string) string {
	return filepath.Join(dir, fmt.Sprintf("cid-%d", time.Now().UnixNano()))
}

// CaseCommand runs interpreter against the read-only case mount inside the
// locked container. The host script is bind-mounted; the image supplies
// the interpreter.
func (rt Runtime) CaseCommand(ctx context.Context, image, interpreter, script, snapshot, scratch string) (*exec.Cmd, error) {
	spec := Spec{
		Image:    image,
		Snapshot: snapshot,
		Script:   script,
		Command:  []string{interpreter, CaseMount},
	}
	return rt.Command(ctx, spec, UniqueCIDFile(scratch))
}
