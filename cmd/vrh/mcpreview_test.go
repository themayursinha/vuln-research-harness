package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/vuln-research-harness/internal/mcpreview"
)

func TestReviewMCPSchemaWritesStdoutJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tools.json")
	input := `{"tools":[{"name":"exec_query","description":"Runs a command","inputSchema":{"properties":{"url":{"type":"string"}}}}]}`
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	cmdErr := reviewMCPSchemaCmd([]string{path})
	w.Close()
	os.Stdout = old
	if cmdErr != nil {
		t.Fatal(cmdErr)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 || out[len(out)-1] != '\n' {
		t.Fatalf("expected trailing-newline JSON, got %q", out)
	}
	var report mcpreview.Report
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	if report.Kind != mcpreview.ReportKind || len(report.Hypotheses) == 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "tools.json" {
		t.Fatalf("CLI wrote extra files: %v", entries)
	}
}

func TestReviewMCPSchemaRejectsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"tools":[{"name":"alpha","inputSchema":[]}]}`), 0600); err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	cmdErr := reviewMCPSchemaCmd([]string{path})
	w.Close()
	os.Stdout = old
	out, readErr := io.ReadAll(r)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if cmdErr == nil {
		t.Fatal("invalid input accepted")
	}
	if len(out) != 0 {
		t.Fatalf("stdout not empty on failure: %s", out)
	}
}

func TestReviewMCPSchemaRequiresPath(t *testing.T) {
	if err := reviewMCPSchemaCmd(nil); err == nil {
		t.Fatal("missing path accepted")
	}
	if err := reviewMCPSchemaCmd([]string{"a.json", "b.json"}); err == nil {
		t.Fatal("extra args accepted")
	}
}

func TestReviewMCPSchemaMissingFile(t *testing.T) {
	err := reviewMCPSchemaCmd([]string{filepath.Join(t.TempDir(), "missing.json")})
	if err == nil {
		t.Fatal("missing file accepted")
	}
	if !strings.Contains(err.Error(), "read tools") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReviewMCPSchemaCompiledBinarySmoke(t *testing.T) {
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "vrh")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	t.Run("valid", func(t *testing.T) {
		work := t.TempDir()
		path := filepath.Join(work, "tools.json")
		input := `{"tools":[{"name":"exec_query","description":"Runs a command","inputSchema":{"properties":{"url":{"type":"string"}}}}]}`
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, err := runVRH(t, bin, work, "review-mcp-schema", path)
		if err != nil {
			t.Fatalf("exit error: %v\nstderr=%s\nstdout=%s", err, stderr, stdout)
		}
		if len(stderr) != 0 {
			t.Fatalf("stderr not empty: %s", stderr)
		}
		if len(stdout) == 0 || stdout[len(stdout)-1] != '\n' {
			t.Fatalf("expected trailing-newline JSON, got %q", stdout)
		}
		var report mcpreview.Report
		if err := json.Unmarshal(stdout, &report); err != nil {
			t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
		}
		if report.Kind != mcpreview.ReportKind || report.Disclaimer != mcpreview.Disclaimer {
			t.Fatalf("unexpected report header: %+v", report)
		}
		if len(report.Hypotheses) == 0 {
			t.Fatalf("expected hypotheses, got %+v", report)
		}
		assertWorkDirUnchanged(t, work, "tools.json")
	})

	t.Run("invalid", func(t *testing.T) {
		work := t.TempDir()
		path := filepath.Join(work, "bad.json")
		if err := os.WriteFile(path, []byte(`{"tools":[{"name":"alpha","inputSchema":[]}]}`), 0600); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, err := runVRH(t, bin, work, "review-mcp-schema", path)
		if err == nil {
			t.Fatalf("invalid input accepted\nstdout=%s", stdout)
		}
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			t.Fatalf("want exit 1, got err=%v stderr=%s", err, stderr)
		}
		if len(stdout) != 0 {
			t.Fatalf("stdout not empty on failure: %s", stdout)
		}
		if !bytes.Contains(stderr, []byte("vrh:")) {
			t.Fatalf("stderr missing vrh prefix: %s", stderr)
		}
		assertWorkDirUnchanged(t, work, "bad.json")
	})
}

func runVRH(t *testing.T, bin, dir string, args ...string) (stdout, stderr []byte, err error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.Bytes(), errBuf.Bytes(), err
}

func assertWorkDirUnchanged(t *testing.T, dir, wantName string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != wantName {
		t.Fatalf("CLI wrote extra files: %v", entries)
	}
}
