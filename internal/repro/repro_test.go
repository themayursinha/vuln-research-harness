package repro

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeScript(t *testing.T, dir, name, interpreterLine, body string) string {
	t.Helper()
	ext := ".sh"
	if interpreterLine == "python3" {
		ext = ".py"
	}
	full := filepath.Join(dir, name+ext)
	content := "#!" + interpreterLine + "\n" + body
	if err := os.WriteFile(full, []byte(content), 0700); err != nil {
		t.Fatal(err)
	}
	return full
}

func TestRunDetectsVulnerableCase(t *testing.T) {
	dir := t.TempDir()
	snapshot := t.TempDir()
	script := writeScript(t, dir, "vuln_check", "python3",
		"import os\nprint(\"LEAKMARKER present:\", bool(os.environ.get(\"VRH_SNAPSHOT\")))\n")

	outcome, err := Run(Case{
		ID: "f1", Finding: "test", ScriptPath: script,
		Interpreter: "python3", Marker: "LEAKMARKER", SnapshotDir: snapshot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Vulnerable {
		t.Fatalf("expected vulnerable outcome, got %+v", outcome)
	}
	if outcome.OutputDigest == "" {
		t.Fatal("output digest not recorded")
	}
}

func TestRunDetectsPatchedCase(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "patched_check", "python3", "print(\"all clean\")\n")

	outcome, err := Run(Case{
		ID: "f2", ScriptPath: script,
		Interpreter: "python3", Marker: "LEAKMARKER", SnapshotDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Vulnerable {
		t.Fatalf("clean script reported vulnerable: %+v", outcome)
	}
	if outcome.Error == "" {
		t.Fatal("non-reproduction should carry an explanatory error")
	}
}

func TestRunRejectsEmptyMarker(t *testing.T) {
	_, err := Run(Case{
		ID: "f-empty", ScriptPath: "/nonexistent", Interpreter: "python3",
		Marker: "  ", SnapshotDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("empty marker accepted")
	}
}

func TestRunTimesOutHungScript(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "hang", "python3", "import time\ntime.sleep(30)\nprint(\"LEAKMARKER\")\n")
	outcome, err := Run(Case{
		ID: "f-hang", ScriptPath: script, Interpreter: "python3",
		Marker: "LEAKMARKER", SnapshotDir: t.TempDir(), Timeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Vulnerable {
		t.Fatalf("timed-out script reported vulnerable: %+v", outcome)
	}
	if outcome.Error == "" {
		t.Fatal("timeout should record an error")
	}
}

func TestRunDeniesOutboundNetwork(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "net", "python3", `
import socket
try:
    socket.create_connection(("1.1.1.1", 80), timeout=2)
    print("NETWORK_OK")
except OSError:
    print("BLOCKED")
`)
	outcome, err := Run(Case{
		ID: "f-net", ScriptPath: script, Interpreter: "python3",
		Marker: "NETWORK_OK", SnapshotDir: t.TempDir(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Vulnerable {
		t.Fatalf("reproduction child reached the network: %+v", outcome)
	}
}

func TestExportWritesJSONAtomically(t *testing.T) {
	dir := t.TempDir()
	outcomes := []Outcome{{CaseID: "c1", Vulnerable: true}}
	if err := Export(outcomes, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "repro_outcomes.json")); err != nil {
		t.Fatalf("export file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "repro_outcomes.json.tmp")); !os.IsNotExist(err) {
		t.Fatal("temp file left behind after rename")
	}
}
