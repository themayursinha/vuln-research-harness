package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestDetectRuntimeRejectsUnknownKind(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "nerdctl")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("unknown kind succeeded: %s", out)
	}
	if !strings.Contains(string(out), "podman or docker") {
		t.Fatalf("got %q, want rejection of unknown runtime", out)
	}
}

func TestDetectRuntimeRejectsExtraArgs(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "docker", "podman")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("extra args succeeded: %s", out)
	}
	if !strings.Contains(string(out), "usage:") {
		t.Fatalf("got %q, want usage error", out)
	}
}
