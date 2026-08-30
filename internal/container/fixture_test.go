package container

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinFromInspectPrefersRepoDigest(t *testing.T) {
	digest := "localhost/vrh-fixture-lab@sha256:" + strings.Repeat("aa", 32)
	id := "sha256:" + strings.Repeat("bb", 32)
	raw := []byte(`{"Id":"` + id + `","RepoDigests":["` + digest + `"]}`)
	got, err := pinFromInspect(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != digest {
		t.Fatalf("got %q want repo digest", got)
	}
}

func TestPinFromInspectUsesImageIDWhenNoRepoDigest(t *testing.T) {
	id := "sha256:" + strings.Repeat("cc", 32)
	raw := []byte(`{"Id":"` + id + `","RepoDigests":[]}`)
	got, err := pinFromInspect(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("got %q want image id pin", got)
	}
}

func TestPinFromInspectUsesPodmanDigest(t *testing.T) {
	d := "sha256:" + strings.Repeat("dd", 32)
	raw := []byte(`{"Id":"not-a-pin","Digest":"` + d + `","RepoDigests":[]}`)
	got, err := pinFromInspect(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != d {
		t.Fatalf("got %q want Digest field", got)
	}
}

func TestPinFromInspectFailsClosed(t *testing.T) {
	if _, err := pinFromInspect([]byte(`{"Id":"image:latest","RepoDigests":[]}`)); err == nil {
		t.Fatal("mutable id accepted as pin")
	}
	if _, err := pinFromInspect([]byte(`not-json`)); err == nil {
		t.Fatal("malformed inspect accepted")
	}
}

func TestBuildImageRefusesMissingDockerfile(t *testing.T) {
	rt, err := Detect()
	if err != nil {
		t.Skip(err)
	}
	err = rt.BuildImage(t.Context(), t.TempDir(), DefaultFixtureImage)
	if err == nil {
		t.Fatal("build without Dockerfile succeeded")
	}
	if !strings.Contains(err.Error(), "Dockerfile") {
		t.Fatalf("got %v, want Dockerfile error", err)
	}
}

func TestBuildImageRefusesUnpreflightedRuntime(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rt := Runtime{Bin: "/usr/bin/docker", Kind: "docker"}
	err := rt.BuildImage(t.Context(), dir, DefaultFixtureImage)
	if err == nil {
		t.Fatal("runtime without Detect env accepted")
	}
	if !errors.Is(err, errNoPreflightEnv) {
		t.Fatalf("got %v, want %v", err, errNoPreflightEnv)
	}
}
