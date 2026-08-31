package container

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPinnedImage(t *testing.T) {
	ok := "python@sha256:" + strings.Repeat("ab", 32)
	id := "sha256:" + strings.Repeat("cd", 32)
	cases := []struct {
		ref  string
		want bool
	}{
		{ok, true},
		{id, true},
		{"python:3.12", false},
		{"python@sha256:deadbeef", false},
		{"python@sha256:" + strings.Repeat("g", 64), false},
		{"", false},
		{"python@sha256:" + strings.Repeat("ab", 32) + " extra", false},
	}
	for _, tc := range cases {
		if got := PinnedImage(tc.ref); got != tc.want {
			t.Errorf("PinnedImage(%q)=%v want %v", tc.ref, got, tc.want)
		}
	}
}

func TestRunArgsLocksIsolation(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "snap")
	script := filepath.Join(dir, "case.py")
	if err := os.Mkdir(snap, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("print(1)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cid := filepath.Join(dir, "cid")
	image := "localhost/vrh@sha256:" + strings.Repeat("11", 32)
	args, err := RunArgs("docker", Spec{
		Image:    image,
		Snapshot: snap,
		Script:   script,
		Command:  []string{"python3", CaseMount},
	}, cid, "vrh-test", false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, need := range []string{"--network=none", "--pull=never", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=512m", "--memory-swap=512m", "--pids-limit=256", "--name=vrh-test", "ro=true"} {
		if !strings.Contains(joined, need) {
			t.Errorf("missing %q in %s", need, joined)
		}
	}
	for _, bad := range []string{"--privileged", "--network=host", "--pull=always", "-p ", "--publish"} {
		if strings.Contains(joined, bad) {
			t.Errorf("unsafe flag %q in %s", bad, joined)
		}
	}
	if !strings.Contains(joined, "src="+snap) || !strings.Contains(joined, "dst="+SnapshotMount) {
		t.Errorf("snapshot mount missing: %s", joined)
	}
	if strings.Count(joined, "ro=true") < 2 {
		t.Errorf("script and snapshot must both be read-only: %s", joined)
	}
	if strings.Contains(joined, "--userns=keep-id") {
		t.Errorf("docker must not use podman keep-id: %s", joined)
	}
	if !strings.Contains(joined, "--user=") {
		t.Errorf("docker missing --user: %s", joined)
	}
}

func TestRunArgsRejectsTag(t *testing.T) {
	_, err := RunArgs("docker", Spec{
		Image:   "python:3.12",
		Command: []string{"python3"},
	}, filepath.Join(t.TempDir(), "cid"), "vrh-test", false)
	if err == nil {
		t.Fatal("mutable tag accepted")
	}
}

func TestRunArgsAcceptsInImageAbsolutePath(t *testing.T) {
	_, err := RunArgs("docker", Spec{
		Image:   "sha256:" + strings.Repeat("11", 32),
		Command: []string{"/usr/bin/python3", CaseMount},
	}, filepath.Join(t.TempDir(), "cid"), "vrh-test", false)
	if err != nil {
		t.Fatalf("in-image absolute interpreter rejected: %v", err)
	}
}

func TestRunArgsPodmanKeepID(t *testing.T) {
	args, err := RunArgs("podman", Spec{
		Image:   "sha256:" + strings.Repeat("11", 32),
		Command: []string{"python3", CaseMount},
	}, filepath.Join(t.TempDir(), "cid"), "vrh-test", false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--userns=keep-id") {
		t.Fatalf("podman missing keep-id: %s", joined)
	}
	if strings.Contains(joined, "--user=") {
		t.Fatalf("podman must not pass --user with keep-id: %s", joined)
	}
}

func TestCreateArgsHasNoInterpreter(t *testing.T) {
	image := "sha256:" + strings.Repeat("11", 32)
	args, err := CreateArgs("docker", Spec{Image: image}, "vrh-iso", false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "python") {
		t.Fatalf("isolation create must not require python: %s", joined)
	}
	for _, need := range []string{"create", "--network=none", "--pull=never", "--read-only", "--entrypoint=/vrh/isolation-probe-never-exec"} {
		if !strings.Contains(joined, need) {
			t.Errorf("missing %q in %s", need, joined)
		}
	}
}

func TestCertifyHostConfig(t *testing.T) {
	good := []byte(`{"HostConfig":{"NetworkMode":"none","Privileged":false,"ReadonlyRootfs":true,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Memory":536870912,"MemorySwap":536870912,"PidsLimit":256}}`)
	if err := certifyHostConfig(good, Spec{}); err != nil {
		t.Fatal(err)
	}
	if err := certifyHostConfig([]byte(`{"HostConfig":{"NetworkMode":"bridge","Privileged":false,"ReadonlyRootfs":true,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Memory":536870912,"MemorySwap":536870912,"PidsLimit":256}}`), Spec{}); err == nil {
		t.Fatal("bridge network accepted")
	}
	if err := certifyHostConfig([]byte(`{"HostConfig":{"NetworkMode":"none","Privileged":true,"ReadonlyRootfs":true,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Memory":536870912,"MemorySwap":536870912,"PidsLimit":256}}`), Spec{}); err == nil {
		t.Fatal("privileged accepted")
	}
	if err := certifyHostConfig([]byte(`{"HostConfig":{"NetworkMode":"none","PidMode":"host","Privileged":false,"ReadonlyRootfs":true,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Memory":536870912,"MemorySwap":536870912,"PidsLimit":256}}`), Spec{}); err == nil {
		t.Fatal("pid=host accepted")
	}
	if err := certifyHostConfig([]byte(`{"HostConfig":{"NetworkMode":"none","Privileged":false,"ReadonlyRootfs":true,"CapDrop":["ALL"],"CapAdd":["NET_ADMIN"],"SecurityOpt":["no-new-privileges"],"Memory":536870912,"MemorySwap":536870912,"PidsLimit":256}}`), Spec{}); err == nil {
		t.Fatal("cap-add accepted")
	}
	if err := certifyHostConfig([]byte(`{"HostConfig":{"NetworkMode":"none","Privileged":false,"ReadonlyRootfs":true,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Memory":536870912,"MemorySwap":-1,"PidsLimit":256}}`), Spec{}); err == nil {
		t.Fatal("unlimited swap accepted")
	}
	if err := certifyHostConfig([]byte(`{"HostConfig":{"NetworkMode":"none","Privileged":false,"ReadonlyRootfs":true,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Memory":536870912,"MemorySwap":0,"PidsLimit":256}}`), Spec{}); err == nil {
		t.Fatal("omitted swap limit accepted")
	}
	if err := certifyHostConfig([]byte(`{"HostConfig":{"NetworkMode":"none","Privileged":false,"ReadonlyRootfs":true,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Memory":536870912,"MemorySwap":536870912,"PidsLimit":256},"Mounts":[{"Destination":"/vrh/snapshot","RW":true,"Type":"bind"}]}`), Spec{Snapshot: "/tmp/snap"}); err == nil {
		t.Fatal("writable snapshot mount accepted")
	}
}

func TestRunArgsRejectsRelativeBind(t *testing.T) {
	_, err := RunArgs("docker", Spec{
		Image:    "sha256:" + strings.Repeat("11", 32),
		Snapshot: "snap",
		Command:  []string{"python3"},
	}, filepath.Join(t.TempDir(), "cid"), "vrh-test", false)
	if err == nil {
		t.Fatal("relative snapshot accepted")
	}
}

func TestDetectKindRejectsUnknown(t *testing.T) {
	if _, err := DetectKind("nerdctl"); err == nil {
		t.Fatal("unknown runtime accepted")
	}
	if _, err := DetectKind(""); err == nil {
		t.Fatal("empty runtime accepted")
	}
}

func TestDetectKindProbesNamedRuntime(t *testing.T) {
	rt, err := Detect()
	if err != nil {
		t.Skip(err)
	}
	got, err := DetectKind(rt.Kind)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != rt.Kind || got.Bin != rt.Bin {
		t.Fatalf("DetectKind(%s)=%+v, Detect=%+v", rt.Kind, got, rt)
	}
}

func TestRequireImageMissing(t *testing.T) {
	rt, err := Detect()
	if err != nil {
		t.Skip(err)
	}
	fake := "localhost/vrh-repro-missing@sha256:" + strings.Repeat("00", 32)
	if err := rt.RequireImage(fake); err == nil {
		t.Fatal("missing image accepted")
	}
}

func TestLiveVerifyIsolation(t *testing.T) {
	image := os.Getenv("VRH_TEST_IMAGE")
	if image == "" {
		t.Skip("set VRH_TEST_IMAGE to a local digest-pinned image")
	}
	rt, err := Detect()
	if err != nil {
		t.Skip(err)
	}
	if err := rt.VerifyIsolation(image); err != nil {
		t.Fatal(err)
	}
}

func TestIsLocalUnixEndpoint(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"unix:///var/run/docker.sock", true},
		{"/var/run/docker.sock", true},
		{"unix://localhost/var/run/docker.sock", false},
		{"unix://192.0.2.1/var/run/docker.sock", false},
		{"tcp://192.0.2.1:2375", false},
		{"ssh://user@host", false},
		{"npipe:////./pipe/docker_engine", false},
		{"fd://3", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isLocalUnixEndpoint(tc.in); got != tc.want {
			t.Errorf("isLocalUnixEndpoint(%q)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestClientEnvRefusesRemoteHost(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://192.0.2.1:2375")
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("CONTAINER_HOST", "")
	if _, err := clientEnv("docker"); err == nil {
		t.Fatal("remote DOCKER_HOST accepted")
	}
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("CONTAINER_HOST", "ssh://lab")
	if _, err := clientEnv("podman"); err == nil {
		t.Fatal("remote CONTAINER_HOST accepted")
	}
}

func TestClientEnvRefusesPodmanConnection(t *testing.T) {
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("CONTAINER_HOST", "")
	t.Setenv("CONTAINER_CONNECTION", "remote-lab")
	if _, err := clientEnv("podman"); err == nil {
		t.Fatal("named Podman connection accepted")
	}
}

func TestClientEnvPinsUnixAndDropsContext(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("DOCKER_CONTEXT", "remote-lab")
	t.Setenv("CONTAINER_HOST", "")
	env, err := clientEnv("docker")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "DOCKER_HOST=unix:///var/run/docker.sock") {
		t.Fatalf("local unix host not pinned: %s", joined)
	}
	if strings.Contains(joined, "DOCKER_CONTEXT=") {
		t.Fatalf("DOCKER_CONTEXT must not be forwarded: %s", joined)
	}
	if !strings.Contains(joined, "CONTAINER_HOST=unix:///var/run/docker.sock") {
		t.Fatalf("CONTAINER_HOST must be pinned to the local socket: %s", joined)
	}
}

func TestRuntimeRetainsPreflightEnv(t *testing.T) {
	rt, err := Detect()
	if err != nil {
		t.Skip(err)
	}
	first, err := rt.clientEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HOST", "unix:///tmp/vrh-other-docker.sock")
	t.Setenv("CONTAINER_HOST", "unix:///tmp/vrh-other-podman.sock")
	t.Setenv("DOCKER_CONTEXT", "desktop-linux")
	second, err := rt.clientEnv()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(first, "\n") != strings.Join(second, "\n") {
		t.Fatalf("preflight env recomputed after host change:\n%s\nvs\n%s", first, second)
	}
}

func TestPreflightRefusesUnpreflightedRuntime(t *testing.T) {
	rt := Runtime{Bin: "/usr/bin/docker", Kind: "docker"}
	_, err := rt.preflight("version")
	if err == nil {
		t.Fatal("preflight without Detect env accepted")
	}
	if !errors.Is(err, errNoPreflightEnv) {
		t.Fatalf("got %v, want %v", err, errNoPreflightEnv)
	}
}

func TestPreflightTimeoutsAreBounded(t *testing.T) {
	if preflightTimeout <= 0 || preflightTimeout > 30*time.Second {
		t.Fatalf("preflightTimeout=%s; want a short fail-closed bound", preflightTimeout)
	}
	if cleanupTimeout <= 0 || cleanupTimeout > preflightTimeout {
		t.Fatalf("cleanupTimeout=%s", cleanupTimeout)
	}
	if maxPreflightOut < 4096 || maxPreflightOut > 4<<20 {
		t.Fatalf("maxPreflightOut=%d", maxPreflightOut)
	}
}

func TestRunArgsRejectsBadName(t *testing.T) {
	_, err := RunArgs("docker", Spec{
		Image:   "sha256:" + strings.Repeat("11", 32),
		Command: []string{"python3"},
	}, filepath.Join(t.TempDir(), "cid"), "--privileged", false)
	if err == nil {
		t.Fatal("flag-like container name accepted")
	}
}

func TestRunArgsRejectsMountMetacharacters(t *testing.T) {
	_, err := RunArgs("docker", Spec{
		Image:    "sha256:" + strings.Repeat("11", 32),
		Snapshot: "/tmp/snap,dst=/evil",
		Command:  []string{"python3"},
	}, filepath.Join(t.TempDir(), "cid"), "vrh-test", false)
	if err == nil {
		t.Fatal("comma in snapshot path accepted")
	}
}

func TestRunArgsDockerRootlessUsesContainerRoot(t *testing.T) {
	args, err := RunArgs("docker", Spec{
		Image:   "sha256:" + strings.Repeat("11", 32),
		Command: []string{"python3", CaseMount},
	}, filepath.Join(t.TempDir(), "cid"), "vrh-test", true)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--user=0:0") {
		t.Fatalf("rootless docker missing --user=0:0: %s", joined)
	}
	if strings.Contains(joined, "--userns=keep-id") {
		t.Fatalf("docker must not use podman keep-id: %s", joined)
	}
}

func TestRootlessFromInfo(t *testing.T) {
	if !rootlessFromInfo("docker", `["name=seccomp,profile=builtin","name=rootless"]`) {
		t.Fatal("docker rootless SecurityOptions not detected")
	}
	if rootlessFromInfo("docker", `["name=seccomp,profile=builtin"]`) {
		t.Fatal("rootful docker treated as rootless")
	}
	if !rootlessFromInfo("podman", "true") {
		t.Fatal("podman rootless not detected")
	}
	if rootlessFromInfo("podman", "false") {
		t.Fatal("rootful podman treated as rootless")
	}
}

func TestContainerAbsent(t *testing.T) {
	if !containerAbsent([]byte("Error: No such container: vrh-1")) {
		t.Fatal("docker missing-container message not recognized")
	}
	if containerAbsent([]byte("permission denied")) {
		t.Fatal("daemon error treated as absent")
	}
}
