package repro

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	if outcome.Finding != "test" {
		t.Fatalf("finding not preserved: %+v", outcome)
	}
}

func TestRunDetectsPatchedCase(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "patched_check", "python3", "print(\"all clean\")\n")

	outcome, err := Run(Case{
		ID: "f2", Finding: "test", ScriptPath: script,
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
		ID: "f-empty", Finding: "test", ScriptPath: "/nonexistent", Interpreter: "python3",
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
		ID: "f-hang", Finding: "test", ScriptPath: script, Interpreter: "python3",
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

func TestRunWithReportsCleanupFailureOnTimeout(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "hang-clean", "python3", "import time\ntime.sleep(30)\nprint(\"LEAKMARKER\")\n")
	_, err := RunWith(Case{
		ID: "f-hang-clean", Finding: "test", ScriptPath: script, Interpreter: "python3",
		Marker: "LEAKMARKER", SnapshotDir: t.TempDir(), Timeout: 200 * time.Millisecond,
	}, func(ctx context.Context, req StartRequest) (*Invocation, error) {
		cmd := exec.CommandContext(ctx, "sleep", "30")
		return &Invocation{
			Cmd: cmd,
			AfterStop: func() error {
				return errors.New("container still present after rm")
			},
		}, nil
	})
	if err == nil {
		t.Fatal("cleanup failure after timeout treated as a non-reproduction")
	}
	if !strings.Contains(err.Error(), "cleanup unproven") {
		t.Fatalf("got %v, want cleanup unproven", err)
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
		ID: "f-net", Finding: "test", ScriptPath: script, Interpreter: "python3",
		Marker: "NETWORK_OK", SnapshotDir: t.TempDir(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Vulnerable {
		t.Fatalf("reproduction child reached the network: %+v", outcome)
	}
}

func TestRunRejectsNonzeroExitEvenWithMarker(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "crash", "python3", "print(\"LEAKMARKER\")\nraise SystemExit(1)\n")
	outcome, err := Run(Case{
		ID: "f-crash", Finding: "test", ScriptPath: script, Interpreter: "python3",
		Marker: "LEAKMARKER", SnapshotDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Vulnerable {
		t.Fatalf("nonzero exit reported vulnerable: %+v", outcome)
	}
}

func TestRunResolvesRelativeScriptPath(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "rel", "python3", "print(\"LEAKMARKER\")\n")
	t.Chdir(dir)
	outcome, err := Run(Case{
		ID: "f-rel", Finding: "test", ScriptPath: "rel.py", Interpreter: "python3",
		Marker: "LEAKMARKER", SnapshotDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Vulnerable {
		t.Fatalf("relative script path failed after workdir change: %+v", outcome)
	}
}

func TestRunKillsDescendantsAtDeadline(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "fork", "python3", `
import os, time
if os.fork() == 0:
    time.sleep(30)
time.sleep(30)
print("LEAKMARKER")
`)
	start := time.Now()
	outcome, err := Run(Case{
		ID: "f-fork", Finding: "test", ScriptPath: script, Interpreter: "python3",
		Marker: "LEAKMARKER", SnapshotDir: t.TempDir(), Timeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("deadline did not kill descendants, ran %s", time.Since(start))
	}
	if outcome.Vulnerable {
		t.Fatalf("forked hang reported vulnerable: %+v", outcome)
	}
}

func TestRunRequiresFinding(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "ok", "python3", "print(\"LEAKMARKER\")\n")
	if _, err := Run(Case{
		ID: "f-nofind", ScriptPath: script, Interpreter: "python3",
		Marker: "LEAKMARKER", SnapshotDir: t.TempDir(),
	}); err == nil {
		t.Fatal("empty finding accepted")
	}
}

func TestRunRejectsChmodRewriteOfSnapshot(t *testing.T) {
	dir := t.TempDir()
	snapshot := t.TempDir()
	if err := os.WriteFile(filepath.Join(snapshot, "app.py"), []byte("print('ok')\n"), 0444); err != nil {
		t.Fatal(err)
	}
	script := writeScript(t, dir, "rewrite", "python3", `
import os
p = os.path.join(os.environ["VRH_SNAPSHOT"], "app.py")
try:
    os.chmod(p, 0o644)
    open(p, "w").write("LEAKMARKER")
except OSError:
    pass
print(open(p).read())
`)
	outcome, err := Run(Case{
		ID: "f-ro", Finding: "test", ScriptPath: script, Interpreter: "python3",
		Marker: "LEAKMARKER", SnapshotDir: snapshot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Vulnerable {
		t.Fatalf("child rewrote the snapshot extract: %+v", outcome)
	}
	got, err := os.ReadFile(filepath.Join(snapshot, "app.py"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "print('ok')\n" {
		t.Fatalf("host snapshot mutated: %q", got)
	}
}

func TestRunAllowsScratchWrites(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "scratch", "python3", `
import os
open(os.path.join(os.environ["VRH_SCRATCH"], "out.txt"), "w").write("ok")
print("LEAKMARKER")
`)
	outcome, err := Run(Case{
		ID: "f-scratch", Finding: "test", ScriptPath: script, Interpreter: "python3",
		Marker: "LEAKMARKER", SnapshotDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Vulnerable {
		t.Fatalf("scratch was not writable: %+v", outcome)
	}
}

func TestRunAllowsLoopback(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "lo", "python3", `
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print("LEAKMARKER", s.getsockname())
s.close()
`)
	outcome, err := Run(Case{
		ID: "f-lo", Finding: "test", ScriptPath: script, Interpreter: "python3",
		Marker: "LEAKMARKER", SnapshotDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Vulnerable {
		t.Fatalf("loopback was not available: %+v", outcome)
	}
}

func TestRunFindsMarkerBeyondKeptPrefix(t *testing.T) {
	dir := t.TempDir()
	script := writeScript(t, dir, "big", "python3", `
print("A" * 2_000_000)
print("LEAKMARKER")
`)
	outcome, err := Run(Case{
		ID: "f-big", Finding: "test", ScriptPath: script, Interpreter: "python3",
		Marker: "LEAKMARKER", SnapshotDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Vulnerable {
		t.Fatalf("marker after 2MiB prefix missed: %+v", outcome)
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
