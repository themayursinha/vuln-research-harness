package main

import (
	"strings"
	"testing"
)

func TestRunRejectsUnknownRuntime(t *testing.T) {
	err := run([]string{"-runtime", "nerdctl", "-context", t.TempDir()})
	if err == nil {
		t.Fatal("unknown runtime accepted")
	}
	if !strings.Contains(err.Error(), "podman or docker") {
		t.Fatalf("got %v, want runtime rejection", err)
	}
}

func TestRunRejectsExtraArgs(t *testing.T) {
	err := run([]string{"extra"})
	if err == nil {
		t.Fatal("extra args accepted")
	}
	if !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("got %v, want usage error", err)
	}
}

func TestRunRefusesContextWithoutDockerfile(t *testing.T) {
	dir := t.TempDir()
	err := run([]string{"-context", dir, "-image", "localhost/vrh-fixture-lab:test"})
	if err == nil {
		t.Fatal("missing Dockerfile accepted")
	}
	if !strings.Contains(err.Error(), "Dockerfile") && !strings.Contains(err.Error(), "no container runtime") {
		t.Fatalf("got %v", err)
	}
}
