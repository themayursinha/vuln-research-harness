package container

import (
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
	}, cid)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, need := range []string{"--network=none", "--pull=never", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "ro=true"} {
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
	}, filepath.Join(t.TempDir(), "cid"))
	if err == nil {
		t.Fatal("mutable tag accepted")
	}
}

func TestRunArgsAcceptsInImageAbsolutePath(t *testing.T) {
	_, err := RunArgs("docker", Spec{
		Image:   "sha256:" + strings.Repeat("11", 32),
		Command: []string{"/usr/bin/python3", CaseMount},
	}, filepath.Join(t.TempDir(), "cid"))
	if err != nil {
		t.Fatalf("in-image absolute interpreter rejected: %v", err)
	}
}

func TestRunArgsPodmanKeepID(t *testing.T) {
	args, err := RunArgs("podman", Spec{
		Image:   "sha256:" + strings.Repeat("11", 32),
		Command: []string{"python3", CaseMount},
	}, filepath.Join(t.TempDir(), "cid"))
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
	args, err := CreateArgs("docker", image)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "python") {
		t.Fatalf("isolation create must not require python: %s", joined)
	}
	for _, need := range []string{"create", "--network=none", "--pull=never", "--read-only"} {
		if !strings.Contains(joined, need) {
			t.Errorf("missing %q in %s", need, joined)
		}
	}
}

func TestCertifyHostConfig(t *testing.T) {
	good := []byte(`{"HostConfig":{"NetworkMode":"none","Privileged":false,"ReadonlyRootfs":true,"CapDrop":["ALL"]}}`)
	if err := certifyHostConfig(good); err != nil {
		t.Fatal(err)
	}
	if err := certifyHostConfig([]byte(`{"HostConfig":{"NetworkMode":"bridge","Privileged":false,"ReadonlyRootfs":true,"CapDrop":["ALL"]}}`)); err == nil {
		t.Fatal("bridge network accepted")
	}
	if err := certifyHostConfig([]byte(`{"HostConfig":{"NetworkMode":"none","Privileged":true,"ReadonlyRootfs":true,"CapDrop":["ALL"]}}`)); err == nil {
		t.Fatal("privileged accepted")
	}
}

func TestRunArgsRejectsRelativeBind(t *testing.T) {
	_, err := RunArgs("docker", Spec{
		Image:    "sha256:" + strings.Repeat("11", 32),
		Snapshot: "snap",
		Command:  []string{"python3"},
	}, filepath.Join(t.TempDir(), "cid"))
	if err == nil {
		t.Fatal("relative snapshot accepted")
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
		{"unix:///run/user/1000/podman/podman.sock", true},
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
}

func TestPreflightTimeoutsAreBounded(t *testing.T) {
	if preflightTimeout <= 0 || preflightTimeout > 30*time.Second {
		t.Fatalf("preflightTimeout=%s; want a short fail-closed bound", preflightTimeout)
	}
	if cleanupTimeout <= 0 || cleanupTimeout > preflightTimeout {
		t.Fatalf("cleanupTimeout=%s", cleanupTimeout)
	}
}
