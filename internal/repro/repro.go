// Package repro runs minimal reproductions for confirmed findings: a finding
// ships with a reproduction script plus the expected marker it must surface;
// the runner executes it in a fresh temp workspace from the pinned snapshot
// and records whether the marker appeared.
package repro

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultTimeout bounds one reproduction script so a deadlock cannot stall
// the rest of the campaign.
const DefaultTimeout = 60 * time.Second

// Case is one reproduction: a script run against the snapshot source with a
// synthetic marker that must appear in its output if the vulnerability holds.
type Case struct {
	ID          string        `json:"id"`
	Finding     string        `json:"finding"`
	ScriptPath  string        `json:"script_path"`
	Interpreter string        `json:"interpreter"` // e.g. "python3", "bash"
	Marker      string        `json:"marker"`      // synthetic; must appear when vulnerable
	SnapshotDir string        `json:"snapshot_dir"`
	Timeout     time.Duration `json:"timeout,omitempty"`
}

// Outcome records one executed case.
type Outcome struct {
	CaseID       string `json:"case_id"`
	Vulnerable   bool   `json:"vulnerable"`
	ExitCode     int    `json:"exit_code"`
	DurationMs   int64  `json:"duration_ms"`
	OutputDigest string `json:"output_digest"`
	Error        string `json:"error,omitempty"`
}

// Run executes the case in a clean temp working directory. The script sees
// the snapshot path via VRH_SNAPSHOT, inherits a stripped environment, and
// is placed in a new network namespace. A case is vulnerable only when the
// interpreter exits 0 and the marker appears on stdout — a crash or syntax
// error that echoes the marker is not evidence.
func Run(c Case) (Outcome, error) {
	outcome := Outcome{CaseID: c.ID}
	if c.ID == "" || c.ScriptPath == "" || c.Interpreter == "" {
		return outcome, fmt.Errorf("case needs id, script_path and interpreter")
	}
	if strings.TrimSpace(c.Marker) == "" {
		return outcome, fmt.Errorf("case %s has an empty marker; refusing to fabricate a reproduction", c.ID)
	}

	scriptPath, err := regularFile(c.ScriptPath)
	if err != nil {
		return outcome, fmt.Errorf("script: %w", err)
	}
	snapshotDir, err := existingDir(c.SnapshotDir)
	if err != nil {
		return outcome, fmt.Errorf("snapshot dir: %w", err)
	}
	interpreter := c.Interpreter
	if strings.ContainsRune(interpreter, os.PathSeparator) {
		abs, err := filepath.Abs(interpreter)
		if err != nil {
			return outcome, fmt.Errorf("interpreter: %w", err)
		}
		interpreter = abs
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	workdir, err := os.MkdirTemp("", "vrh-repro-")
	if err != nil {
		return outcome, fmt.Errorf("create workdir: %w", err)
	}
	defer os.RemoveAll(workdir)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, interpreter, scriptPath)
	cmd.Dir = workdir
	cmd.Env = reproEnv(workdir, snapshotDir)
	if err := isolateCommand(cmd); err != nil {
		return outcome, fmt.Errorf("sandbox: %w", err)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	outcome.DurationMs = time.Since(start).Milliseconds()
	output := stdout.String() + stderr.String()
	sum := sha256.Sum256([]byte(output))
	outcome.OutputDigest = hex.EncodeToString(sum[:])

	if ctx.Err() == context.DeadlineExceeded {
		outcome.Vulnerable = false
		outcome.Error = fmt.Sprintf("timed out after %s; finding did not reproduce", timeout)
		return outcome, nil
	}

	var exitCode int
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if runErr != nil {
		return outcome, fmt.Errorf("run script: %w", runErr)
	}
	outcome.ExitCode = exitCode

	if exitCode != 0 {
		outcome.Vulnerable = false
		outcome.Error = fmt.Sprintf("script exited %d; refusing to treat marker as evidence", exitCode)
		return outcome, nil
	}
	if !bytes.Contains(stdout.Bytes(), []byte(c.Marker)) {
		outcome.Vulnerable = false
		outcome.Error = "marker not observed on stdout; finding did not reproduce"
		return outcome, nil
	}
	outcome.Vulnerable = true
	return outcome, nil
}

func regularFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	return filepath.Abs(path)
}

func existingDir(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", path)
	}
	return filepath.Abs(path)
}

func reproEnv(workdir, snapshotDir string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + workdir,
		"TMPDIR=" + workdir,
		"VRH_SNAPSHOT=" + snapshotDir,
		"LANG=C",
		"LC_ALL=C",
	}
}

// Export writes outcomes as JSON for the evidence ledger.
func Export(outcomes []Outcome, dir string) error {
	data, err := json.MarshalIndent(outcomes, "", "  ")
	if err != nil {
		return fmt.Errorf("encode outcomes: %w", err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create export dir: %w", err)
	}
	path := filepath.Join(dir, "repro_outcomes.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write outcomes: %w", err)
	}
	return os.Rename(tmp, path)
}
