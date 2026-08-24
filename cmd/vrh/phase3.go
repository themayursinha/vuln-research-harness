package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/themayursinha/vuln-research-harness/internal/repro"
	"github.com/themayursinha/vuln-research-harness/internal/sandbox"
	"github.com/themayursinha/vuln-research-harness/internal/validate"
	"gopkg.in/yaml.v3"
)

// reproCaseFile is the on-disk form of one reproduction case.
type reproCaseFile struct {
	ID          string `yaml:"id"`
	Finding     string `yaml:"finding"`
	ScriptPath  string `yaml:"script_path"`
	Interpreter string `yaml:"interpreter"`
	VenvPython  string `yaml:"venv_python,omitempty"` // optional: use this interpreter instead
	Marker      string `yaml:"marker"`
}

func reproCmd(args []string) error {
	if len(args) != 2 {
		return errors.New("repro requires <cases.yaml> <snapshot-dir>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read cases: %w", err)
	}
	var cases []reproCaseFile
	if err := yaml.Unmarshal(data, &cases); err != nil {
		return fmt.Errorf("parse cases: %w", err)
	}
	if len(cases) == 0 {
		return errors.New("no reproduction cases defined")
	}

	var outcomes []repro.Outcome
	for _, c := range cases {
		outcome, err := repro.Run(repro.Case{
			ID:          c.ID,
			Finding:     c.Finding,
			ScriptPath:  c.ScriptPath,
			Interpreter: resolveInterpreter(c),
			Marker:      c.Marker,
			SnapshotDir: args[1],
		})
		if err != nil {
			return err
		}
		status := "did not reproduce"
		if outcome.Vulnerable {
			status = "REPRODUCED"
		}
		fmt.Printf("%-12s %s\n", outcome.CaseID, status)
		outcomes = append(outcomes, outcome)
	}

	exportDir := filepath.Dir(args[0])
	if err := repro.Export(outcomes, exportDir); err != nil {
		return err
	}
	fmt.Println("outcomes exported:", filepath.Join(exportDir, "repro_outcomes.json"))
	return nil
}

func verifySandboxCmd(args []string) error {
	if len(args) != 0 {
		return errors.New("verify-sandbox takes no arguments; probes run in the current environment")
	}
	v, err := sandbox.VerifyNetwork(sandbox.DefaultNetworkProbes())
	if err != nil {
		return err
	}
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
	if !v.Passed {
		return errors.New("network boundary NOT verified: live access detected")
	}
	fmt.Println("network boundary verified: DNS and TCP both blocked")
	return nil
}

func validateCmd(args []string) error {
	if len(args) < 3 {
		return errors.New("validate requires <finding-id> <attempts.json> <summary>")
	}
	findingID, attemptsPath, summary := args[0], args[1], strings.Join(args[2:], " ")
	data, err := os.ReadFile(attemptsPath)
	if err != nil {
		return fmt.Errorf("read attempts: %w", err)
	}
	var attempts []struct {
		Name       string `json:"name"`
		Hypothesis string `json:"hypothesis"`
		Result     string `json:"result"`
		BrokeIt    bool   `json:"broke_it"`
	}
	if err := json.Unmarshal(data, &attempts); err != nil {
		return fmt.Errorf("parse attempts: %w", err)
	}

	builder := validate.NewBuilder(findingID)
	for _, a := range attempts {
		builder.Attempt(a.Name, a.Hypothesis, a.Result, a.BrokeIt)
	}
	report, err := builder.Finalize(summary)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(attemptsPath)
	outPath := filepath.Join(dir, "validation_"+findingID+".json")
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, outPath); err != nil {
		return err
	}
	fmt.Printf("finding %s verdict: %s (%d attempts)\nwritten to %s\n", findingID, report.Verdict, len(report.Attempts), outPath)
	return nil
}

// resolveInterpreter prefers a case-specific interpreter (e.g. the target
// project's venv python) when one is configured, falling back to the generic
// interpreter name.
func resolveInterpreter(c reproCaseFile) string {
	if c.VenvPython != "" {
		return c.VenvPython
	}
	return c.Interpreter
}
