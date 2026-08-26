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

	preflightTimeout = 15 * time.Second
	cleanupTimeout   = 5 * time.Second
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

// Detect finds a working local podman or docker binary. It does not pull
// images, does not create containers, and refuses a remote daemon.
func Detect() (Runtime, error) {
	var remoteErr error
	for _, kind := range []string{"podman", "docker"} {
		bin, err := exec.LookPath(kind)
		if err != nil {
			continue
		}
		env, err := clientEnv(kind)
		if err != nil {
			remoteErr = err
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), preflightTimeout)
		cmd := exec.CommandContext(ctx, bin, "version")
		cmd.Env = env
		err = cmd.Run()
		cancel()
		if err != nil {
			continue
		}
		return Runtime{Bin: bin, Kind: kind}, nil
	}
	if remoteErr != nil {
		return Runtime{}, remoteErr
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
func RunArgs(kind string, spec Spec, cidFile string) ([]string, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	if cidFile == "" || !filepath.IsAbs(cidFile) {
		return nil, fmt.Errorf("cidfile must be an absolute path")
	}
	iso, err := isolationFlags(kind)
	if err != nil {
		return nil, err
	}
	args := []string{"run", "--rm"}
	args = append(args, iso...)
	args = append(args,
		"--cidfile="+cidFile,
		"--tmpfs=/tmp:rw,noexec,nosuid,nodev",
		"--tmpfs="+ScratchMount+":rw,exec,nosuid,nodev",
		"-e", "VRH_SNAPSHOT="+SnapshotMount,
		"-e", "VRH_SCRATCH="+ScratchMount,
		"-e", "HOME="+ScratchMount,
		"-e", "TMPDIR="+ScratchMount,
		"-e", "PYTHONDONTWRITEBYTECODE=1",
		"-e", "LANG=C",
		"-e", "LC_ALL=C",
		"--entrypoint="+spec.Command[0],
	)
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

func isolationFlags(kind string) ([]string, error) {
	switch kind {
	case "docker", "podman":
	default:
		return nil, fmt.Errorf("unknown container runtime %q", kind)
	}
	flags := []string{
		"--network=none",
		"--pull=never",
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--memory=512m",
	}
	return append(flags, identityFlags(kind)...), nil
}

func identityFlags(kind string) []string {
	switch kind {
	case "podman":
		// Rootless Podman maps the caller to container uid 0 by default.
		// keep-id keeps the caller's UID so 0700 bind mounts stay readable.
		return []string{"--userns=keep-id"}
	case "docker":
		return []string{fmt.Sprintf("--user=%d:%d", os.Getuid(), os.Getgid())}
	default:
		return nil
	}
}

func forbidUnsafeArgs(args []string) error {
	joined := strings.Join(args, "\x00")
	for _, bad := range []string{
		"--privileged",
		"--network=host",
		"--net=host",
		"--pid=host",
		"--userns=host",
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
	out, err := rt.preflight("image", "inspect", "--format", "{{.Id}}", image)
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
	args, err := RunArgs(rt.Kind, spec, cidFile)
	if err != nil {
		return nil, err
	}
	env, err := clientEnv(rt.Kind)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, rt.Bin, args...)
	cmd.Env = env
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
	env, err := clientEnv(rt.Kind)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	rm := exec.CommandContext(ctx, rt.Bin, "rm", "-f", id)
	rm.Env = env
	_ = rm.Run()
}

func (rt Runtime) preflight(args ...string) ([]byte, error) {
	env, err := clientEnv(rt.Kind)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), preflightTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, rt.Bin, args...)
	cmd.Env = env
	return cmd.CombinedOutput()
}

// clientEnv is the subprocess environment for podman/docker. It never
// forwards DOCKER_CONTEXT or CONTAINER_CONNECTION, and it only sets
// DOCKER_HOST/CONTAINER_HOST to a local unix socket. Remote tcp/ssh
// endpoints are refused so vrh repro cannot leave this machine.
func clientEnv(kind string) ([]string, error) {
	host, err := localRuntimeHost(kind)
	if err != nil {
		return nil, err
	}
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/bin:/bin"
	}
	env := []string{"PATH=" + path}
	if v := os.Getenv("HOME"); v != "" {
		env = append(env, "HOME="+v)
	}
	if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" {
		env = append(env, "XDG_RUNTIME_DIR="+v)
	}
	if host != "" {
		env = append(env, "DOCKER_HOST="+host, "CONTAINER_HOST="+host)
	}
	return env, nil
}

func localRuntimeHost(kind string) (string, error) {
	if err := rejectRemoteEnv(kind); err != nil {
		return "", err
	}
	if h := explicitUnixHost(kind); h != "" {
		return normalizeUnixHost(h), nil
	}
	if kind == "docker" {
		h, err := dockerContextHost()
		if err == nil {
			h = strings.TrimSpace(h)
			if h != "" && !isLocalUnixEndpoint(h) {
				return "", fmt.Errorf("refusing remote Docker endpoint %s; VRH only uses a local unix socket", h)
			}
			if isLocalUnixEndpoint(h) {
				return normalizeUnixHost(h), nil
			}
		}
	}
	if sock := probeLocalSocket(kind); sock != "" {
		return sock, nil
	}
	if kind == "docker" {
		return "", fmt.Errorf("no local unix socket for docker; VRH refuses remote or unproven runtimes")
	}
	// Rootless podman can start its own local service without an existing socket.
	return "", nil
}

func rejectRemoteEnv(kind string) error {
	keys := []string{"DOCKER_HOST"}
	if kind == "podman" {
		keys = []string{"CONTAINER_HOST", "DOCKER_HOST"}
	}
	for _, key := range keys {
		v := strings.TrimSpace(os.Getenv(key))
		if v == "" {
			continue
		}
		if !isLocalUnixEndpoint(v) {
			return fmt.Errorf("refusing remote container runtime (%s=%s); VRH only uses a local unix socket", key, v)
		}
	}
	if kind == "podman" {
		if v := os.Getenv("CONTAINER_CONNECTION"); v != "" {
			return fmt.Errorf("refusing Podman connection %q; VRH only uses a local unix socket", v)
		}
	}
	return nil
}

func explicitUnixHost(kind string) string {
	keys := []string{"DOCKER_HOST"}
	if kind == "podman" {
		keys = []string{"CONTAINER_HOST", "DOCKER_HOST"}
	}
	for _, key := range keys {
		v := strings.TrimSpace(os.Getenv(key))
		if v != "" {
			return v
		}
	}
	return ""
}

func isLocalUnixEndpoint(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "unix://") {
		return true
	}
	if strings.HasPrefix(v, "/") && !strings.Contains(v, "://") {
		return true
	}
	return false
}

func normalizeUnixHost(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "unix://") {
		return "unix://" + v
	}
	return v
}

func probeLocalSocket(kind string) string {
	xdg := os.Getenv("XDG_RUNTIME_DIR")
	if xdg == "" {
		xdg = fmt.Sprintf("/run/user/%d", os.Getuid())
	}
	var candidates []string
	switch kind {
	case "docker":
		candidates = []string{
			filepath.Join(xdg, "docker.sock"),
			"/var/run/docker.sock",
			"/run/docker.sock",
		}
	case "podman":
		candidates = []string{
			filepath.Join(xdg, "podman", "podman.sock"),
			"/run/podman/podman.sock",
			"/var/run/podman/podman.sock",
		}
	}
	for _, p := range candidates {
		st, err := os.Stat(p)
		if err != nil || st.Mode()&os.ModeSocket == 0 {
			continue
		}
		return "unix://" + p
	}
	return ""
}

func dockerContextHost() (string, error) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return "", err
	}
	env := inspectEnv()
	ctx, cancel := context.WithTimeout(context.Background(), preflightTimeout)
	defer cancel()
	show := exec.CommandContext(ctx, bin, "context", "show")
	show.Env = env
	nameOut, err := show.Output()
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(nameOut))
	if name == "" {
		name = "default"
	}
	inspect := exec.CommandContext(ctx, bin, "context", "inspect", name, "--format", "{{.Endpoints.docker.Host}}")
	inspect.Env = env
	hostOut, err := inspect.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(hostOut)), nil
}

func inspectEnv() []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/bin:/bin"
	}
	env := []string{"PATH=" + path}
	if v := os.Getenv("HOME"); v != "" {
		env = append(env, "HOME="+v)
	}
	if v := os.Getenv("DOCKER_CONTEXT"); v != "" {
		env = append(env, "DOCKER_CONTEXT="+v)
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
