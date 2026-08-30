// Package container is the disposable OCI adapter for reproduction:
// podman or docker, never a pull, never a published port, never a
// writable snapshot. Process-local namespaces remain available for unit
// tests; vrh repro uses this adapter as the execution boundary.
package container

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
)

var errNoPreflightEnv = errors.New("container runtime has no preflighted client environment")

const (
	SnapshotMount = "/vrh/snapshot"
	CaseMount     = "/vrh/case"
	ScratchMount  = "/vrh/scratch"

	memoryLimit      = "512m"
	swapLimit        = "512m"
	pidsLimit        = "256"
	preflightTimeout = 15 * time.Second
	cleanupTimeout   = 5 * time.Second
	maxPreflightOut  = 1 << 20
)

// Runtime is a local podman or docker binary that can run a locked spec.
type Runtime struct {
	Bin      string
	Kind     string
	Rootless bool
	// env is the sanitized client environment captured during Detect.
	// Later calls reuse it so a socket disappearing mid-run cannot switch
	// the build/inspect to a different daemon.
	env []string
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
	return detectKinds("podman", "docker")
}

// DetectKind probes one runtime the same way Detect does, without falling
// back to the other engine. Callers that requested docker or podman explicitly
// must not silently switch runtimes.
func DetectKind(kind string) (Runtime, error) {
	switch kind {
	case "podman", "docker":
		return detectKinds(kind)
	default:
		return Runtime{}, fmt.Errorf("container runtime must be podman or docker, got %q", kind)
	}
}

func detectKinds(kinds ...string) (Runtime, error) {
	var remoteErr error
	for _, kind := range kinds {
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
		_, err = runBounded(cmd)
		cancel()
		if err != nil {
			continue
		}
		rootless, err := inspectRootless(kind, bin, env)
		if err != nil {
			remoteErr = err
			continue
		}
		return Runtime{Bin: bin, Kind: kind, Rootless: rootless, env: copyEnv(env)}, nil
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

func (s Spec) validateBinds() error {
	if !PinnedImage(s.Image) {
		return fmt.Errorf("container image must be digest-pinned (@sha256:... or sha256:...); got %q", s.Image)
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

func (s Spec) validate() error {
	if err := s.validateBinds(); err != nil {
		return err
	}
	if len(s.Command) == 0 || strings.TrimSpace(s.Command[0]) == "" {
		return fmt.Errorf("container command is required")
	}
	if strings.HasPrefix(s.Command[0], "-") {
		return fmt.Errorf("container command must not start with a flag")
	}
	return nil
}

func absCleanPath(p, what string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s path must be absolute", what)
	}
	if strings.ContainsAny(p, ",=\n\r\x00") {
		return fmt.Errorf("%s path must not contain mount-spec metacharacters", what)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("%s path must not contain ..", what)
	}
	return nil
}

func validContainerName(name string) bool {
	if !strings.HasPrefix(name, "vrh-") || len(name) < 5 {
		return false
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
			continue
		}
		return false
	}
	return true
}

// RunArgs is the argv after the runtime binary. Tests lock this list so a
// future caller cannot add -p, --privileged, or a pull.
func RunArgs(kind string, spec Spec, cidFile, name string, rootless bool) ([]string, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	if cidFile == "" || !filepath.IsAbs(cidFile) {
		return nil, fmt.Errorf("cidfile must be an absolute path")
	}
	if !validContainerName(name) {
		return nil, fmt.Errorf("container name must be a vrh-* token")
	}
	iso, err := isolationFlags(kind, rootless)
	if err != nil {
		return nil, err
	}
	args := []string{"run", "--rm"}
	args = append(args, iso...)
	args = append(args,
		"--name="+name,
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
	args = append(args, bindMounts(spec)...)
	args = append(args, spec.Image)
	args = append(args, spec.Command[1:]...)
	if err := forbidUnsafeArgs(args); err != nil {
		return nil, err
	}
	return args, nil
}

func bindMounts(spec Spec) []string {
	var args []string
	if spec.Snapshot != "" {
		args = append(args, "--mount=type=bind,src="+spec.Snapshot+",dst="+SnapshotMount+",ro=true")
	}
	if spec.Script != "" {
		args = append(args, "--mount=type=bind,src="+spec.Script+",dst="+CaseMount+",ro=true")
	}
	return args
}

func isolationFlags(kind string, rootless bool) ([]string, error) {
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
		"--memory=" + memoryLimit,
		"--memory-swap=" + swapLimit,
		"--pids-limit=" + pidsLimit,
	}
	return append(flags, identityFlags(kind, rootless)...), nil
}

func identityFlags(kind string, rootless bool) []string {
	switch kind {
	case "podman":
		// Rootless Podman maps the caller to container uid 0 by default.
		// keep-id keeps the caller's UID so 0700 bind mounts stay readable.
		return []string{"--userns=keep-id"}
	case "docker":
		if rootless {
			// Rootless Docker maps container uid 0 to the caller. --user=0:0
			// overrides a Dockerfile USER so 0700 bind mounts stay readable.
			return []string{"--user=0:0"}
		}
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
		"--uts=host",
		"--ipc=host",
		"--cgroupns=host",
		"--userns=host",
		"--pull=always",
		"--pull=missing",
		"--publish-all",
		"--cap-add",
		"--device",
		"--add-host",
		"-p\x00",
		"--publish\x00",
		"-v\x00",
		"--volume\x00",
	} {
		if strings.Contains(joined, bad) {
			return fmt.Errorf("refusing unsafe container flag")
		}
	}
	hasNone, hasNever, hasRO, hasCapDrop, hasNNP, hasMem, hasSwap, hasPids := false, false, false, false, false, false, false, false
	for i, a := range args {
		switch {
		case a == "--network=none":
			hasNone = true
		case a == "--pull=never":
			hasNever = true
		case a == "--read-only":
			hasRO = true
		case a == "--cap-drop=ALL":
			hasCapDrop = true
		case a == "--security-opt=no-new-privileges":
			hasNNP = true
		case a == "--memory="+memoryLimit:
			hasMem = true
		case a == "--memory-swap="+swapLimit:
			hasSwap = true
		case a == "--pids-limit="+pidsLimit:
			hasPids = true
		}
		if a == "-p" || a == "--publish" || strings.HasPrefix(a, "-p=") || strings.HasPrefix(a, "--publish=") {
			return fmt.Errorf("refusing published ports")
		}
		if a == "--privileged" {
			return fmt.Errorf("refusing privileged container")
		}
		if a == "--cap-add" || strings.HasPrefix(a, "--cap-add=") {
			return fmt.Errorf("refusing added capabilities")
		}
		if a == "--device" || strings.HasPrefix(a, "--device=") {
			return fmt.Errorf("refusing host devices")
		}
		if i+1 < len(args) && (a == "--network" || a == "--net") && args[i+1] != "none" {
			return fmt.Errorf("container network must be none")
		}
		if strings.HasPrefix(a, "--userns=") && a != "--userns=keep-id" {
			return fmt.Errorf("refusing host user namespace")
		}
	}
	if !hasNone || !hasNever || !hasRO || !hasCapDrop || !hasNNP || !hasMem || !hasSwap || !hasPids {
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

// Command builds a runtime invocation for spec. Cancel interrupts the
// CLI; the returned AfterStop proves the named container is gone so a
// deadline cannot be recorded while a research box is still running.
func (rt Runtime) Command(ctx context.Context, spec Spec, cidFile string) (*exec.Cmd, func() error, error) {
	name := UniqueName()
	args, err := RunArgs(rt.Kind, spec, cidFile, name, rt.Rootless)
	if err != nil {
		return nil, nil, err
	}
	env, err := rt.clientEnv()
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.CommandContext(ctx, rt.Bin, args...)
	cmd.Env = env
	cmd.Dir = filepath.Dir(cidFile)
	cmd.WaitDelay = 2 * time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		_ = rt.removeContainer(name, cidFile)
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Process.Kill()
		}
		return nil
	}
	return cmd, func() error { return rt.removeContainer(name, cidFile) }, nil
}

func (rt Runtime) removeContainer(name, cidFile string) error {
	var errs []error
	provenGone := false
	if validContainerName(name) {
		if err := rt.forceRemove(name); err != nil {
			errs = append(errs, err)
		} else {
			provenGone = true
		}
	}
	if cidFile != "" {
		cid, err := os.ReadFile(cidFile)
		if err == nil {
			id := string(bytes.TrimSpace(cid))
			if id != "" && !strings.HasPrefix(id, "-") {
				if err := rt.forceRemove(id); err != nil {
					errs = append(errs, err)
				} else {
					provenGone = true
				}
			}
		}
	}
	if provenGone {
		return nil
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

func (rt Runtime) forceRemove(id string) error {
	out, err := rt.cleanup("rm", "-f", id)
	if err != nil && !containerAbsent(out) {
		return fmt.Errorf("rm %s: %s", id, strings.TrimSpace(string(out)))
	}
	inspectOut, inspectErr := rt.cleanup("inspect", id)
	if inspectErr == nil {
		return fmt.Errorf("container %s still present after rm", id)
	}
	if containerAbsent(inspectOut) {
		return nil
	}
	return fmt.Errorf("container %s cleanup unproven: %s", id, strings.TrimSpace(string(inspectOut)))
}

func containerAbsent(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "no such container") ||
		strings.Contains(s, "no such object") ||
		strings.Contains(s, "no container with name")
}

func (rt Runtime) cleanup(args ...string) ([]byte, error) {
	env, err := rt.clientEnv()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, rt.Bin, args...)
	cmd.Env = env
	return runBounded(cmd)
}

func inspectRootless(kind, bin string, env []string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), preflightTimeout)
	defer cancel()
	var cmd *exec.Cmd
	switch kind {
	case "docker":
		cmd = exec.CommandContext(ctx, bin, "info", "--format", "{{json .SecurityOptions}}")
	case "podman":
		cmd = exec.CommandContext(ctx, bin, "info", "--format", "{{.Host.Security.Rootless}}")
	default:
		return false, fmt.Errorf("unknown container runtime %q", kind)
	}
	cmd.Env = env
	out, err := runBounded(cmd)
	if err != nil {
		return false, fmt.Errorf("inspect %s rootless mode: %s", kind, strings.TrimSpace(string(out)))
	}
	return rootlessFromInfo(kind, string(out)), nil
}

func rootlessFromInfo(kind, out string) bool {
	s := strings.ToLower(strings.TrimSpace(out))
	switch kind {
	case "docker":
		return strings.Contains(s, "rootless")
	case "podman":
		return s == "true" || strings.Contains(s, "rootless")
	default:
		return false
	}
}

func (rt Runtime) preflight(args ...string) ([]byte, error) {
	env, err := rt.clientEnv()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), preflightTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, rt.Bin, args...)
	cmd.Env = env
	return runBounded(cmd)
}

func runBounded(cmd *exec.Cmd) ([]byte, error) {
	w := &boundedWriter{max: maxPreflightOut}
	cmd.Stdout = w
	cmd.Stderr = w
	err := cmd.Run()
	return w.buf.Bytes(), err
}

func runBoundedStdout(cmd *exec.Cmd) ([]byte, error) {
	out := &boundedWriter{max: maxPreflightOut}
	errw := &boundedWriter{max: maxPreflightOut}
	cmd.Stdout = out
	cmd.Stderr = errw
	err := cmd.Run()
	return out.buf.Bytes(), err
}

type boundedWriter struct {
	buf bytes.Buffer
	max int
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if w.buf.Len() < w.max {
		n := w.max - w.buf.Len()
		if len(p) < n {
			n = len(p)
		}
		_, _ = w.buf.Write(p[:n])
	}
	return len(p), nil
}

// clientEnv returns the sanitized environment captured at Detect time.
func (rt Runtime) clientEnv() ([]string, error) {
	if len(rt.env) == 0 {
		return nil, errNoPreflightEnv
	}
	return copyEnv(rt.env), nil
}

func copyEnv(env []string) []string {
	out := make([]string, len(env))
	copy(out, env)
	return out
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
	env = append(env, "DOCKER_HOST="+host, "CONTAINER_HOST="+host)
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
		if ctx := os.Getenv("DOCKER_CONTEXT"); ctx != "" {
			return "", fmt.Errorf("refusing Docker context %q: cannot prove a local unix socket", ctx)
		}
	}
	if sock := probeLocalSocket(kind); sock != "" {
		return sock, nil
	}
	return "", fmt.Errorf("no local unix socket for %s; VRH refuses remote or unproven runtimes", kind)
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
	if strings.HasPrefix(v, "/") && !strings.Contains(v, "://") {
		return filepath.IsAbs(v)
	}
	u, err := url.Parse(v)
	if err != nil || !strings.EqualFold(u.Scheme, "unix") {
		return false
	}
	if u.Host != "" || u.User != nil {
		return false
	}
	return filepath.IsAbs(u.Path)
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
	nameOut, err := runBoundedStdout(show)
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(nameOut))
	if i := strings.IndexAny(name, "\n\r"); i >= 0 {
		name = strings.TrimSpace(name[:i])
	}
	if name == "" {
		name = "default"
	}
	if strings.ContainsAny(name, " \t\n\r") {
		return "", fmt.Errorf("refusing Docker context name %q", name)
	}
	inspect := exec.CommandContext(ctx, bin, "context", "inspect", name, "--format", "{{.Endpoints.docker.Host}}")
	inspect.Env = env
	hostOut, err := runBoundedStdout(inspect)
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

// UniqueName is a docker/podman container name used for fail-closed cleanup.
func UniqueName() string {
	return fmt.Sprintf("vrh-%d-%d", os.Getpid(), time.Now().UnixNano())
}

// CaseCommand runs interpreter against the read-only case mount inside the
// locked container. The host script is bind-mounted; the image supplies
// the interpreter.
func (rt Runtime) CaseCommand(ctx context.Context, image, interpreter, script, snapshot, scratch string) (*exec.Cmd, func() error, error) {
	spec := Spec{
		Image:    image,
		Snapshot: snapshot,
		Script:   script,
		Command:  []string{interpreter, CaseMount},
	}
	return rt.Command(ctx, spec, UniqueCIDFile(scratch))
}
