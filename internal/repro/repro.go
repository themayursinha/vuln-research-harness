// Package repro runs minimal reproductions for confirmed findings: a finding
// ships with a reproduction script plus the expected marker it must surface;
// the runner executes it in a fresh temp workspace from the pinned snapshot
// and records whether the marker appeared.
package repro

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Case is one reproduction: a script run against the snapshot source with a
// synthetic marker that must appear in its output if the vulnerability holds.
type Case struct {
	ID          string `json:"id"`
	Finding     string `json:"finding"`
	ScriptPath  string `json:"script_path"`
	Interpreter string `json:"interpreter"` // e.g. "python3", "bash"
	Marker      string `json:"marker"`      // synthetic; must appear when vulnerable
	SnapshotDir string `json:"snapshot_dir"`
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
// the snapshot path via the VRH_SNAPSHOT environment variable. Network
// isolation is enforced upstream by the sandbox adapter, not here — this
// runner is process-local only.
func Run(c Case) (Outcome, error) {
	outcome := Outcome{CaseID: c.ID}
	if c.ID == "" || c.ScriptPath == "" || c.Interpreter == "" {
		return outcome, fmt.Errorf("case needs id, script_path and interpreter")
	}
	if _, err := os.Stat(c.ScriptPath); err != nil {
		return outcome, fmt.Errorf("script not found: %w", err)
	}
	if _, err := os.Stat(c.SnapshotDir); err != nil {
		return outcome, fmt.Errorf("snapshot dir not found: %w", err)
	}

	workdir, err := os.MkdirTemp("", "vrh-repro-")
	if err != nil {
		return outcome, fmt.Errorf("create workdir: %w", err)
	}
	defer os.RemoveAll(workdir)

	cmd := exec.Command(c.Interpreter, c.ScriptPath)
	cmd.Dir = workdir
	cmd.Env = append(os.Environ(), "VRH_SNAPSHOT="+c.SnapshotDir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	outcome.DurationMs = time.Since(start).Milliseconds()
	output := stdout.String() + stderr.String()

	var exitCode int
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if runErr != nil {
		return outcome, fmt.Errorf("run script: %w", runErr)
	}

	sum := sha256.Sum256([]byte(output))
	outcome.ExitCode = exitCode
	outcome.OutputDigest = hex.EncodeToString(sum[:])
	outcome.Vulnerable = bytes.Contains([]byte(output), []byte(c.Marker))
	if !outcome.Vulnerable {
		outcome.Error = "marker not observed in output; finding did not reproduce"
	}
	return outcome, nil
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
