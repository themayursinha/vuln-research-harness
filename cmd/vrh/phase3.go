package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/themayursinha/vuln-research-harness/internal/container"
	"github.com/themayursinha/vuln-research-harness/internal/contract"
	"github.com/themayursinha/vuln-research-harness/internal/manifest"
	"github.com/themayursinha/vuln-research-harness/internal/repro"
	"github.com/themayursinha/vuln-research-harness/internal/validate"
	"gopkg.in/yaml.v3"
)

// reproCaseFile is the on-disk form of one reproduction case.
type reproCaseFile struct {
	ID             string `yaml:"id"`
	Finding        string `yaml:"finding"`
	ScriptPath     string `yaml:"script_path"`
	Interpreter    string `yaml:"interpreter"`
	VenvPython     string `yaml:"venv_python,omitempty"` // optional: use this interpreter instead
	Marker         string `yaml:"marker"`
	TimeoutSeconds int    `yaml:"timeout_seconds,omitempty"`
}

func reproCmd(args []string) error {
	return runRepro(args, nil)
}

func runRepro(args []string, isolate func() error) error {
	if len(args) != 2 {
		return errors.New("repro requires <cases.yaml> <campaign-dir>")
	}
	casesPath, campaignDir := args[0], args[1]
	data, err := os.ReadFile(casesPath)
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

	if err := requireAdmission(campaignDir); err != nil {
		return err
	}
	campaign, err := contract.Load(campaignFiles(campaignDir)["contract"])
	if err != nil {
		return fmt.Errorf("load campaign: %w", err)
	}
	mani, err := manifest.Load(campaignFiles(campaignDir)["manifest"])
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	runCase := repro.Run
	if isolate != nil {
		if err := isolate(); err != nil {
			return err
		}
	} else {
		for _, c := range cases {
			if c.VenvPython != "" {
				return fmt.Errorf("case %s: venv_python is a host path and cannot run inside the pinned container image", c.ID)
			}
			if strings.ContainsRune(c.Interpreter, os.PathSeparator) && !filepath.IsAbs(c.Interpreter) {
				return fmt.Errorf("case %s: interpreter must be an in-image name or absolute in-image path", c.ID)
			}
		}
		rt, err := requireContainerRuntime(campaign.Environment.ContainerImage)
		if err != nil {
			return err
		}
		runCase = func(c repro.Case) (repro.Outcome, error) {
			image := campaign.Environment.ContainerImage
			return repro.RunWith(c, func(ctx context.Context, req repro.StartRequest) (*exec.Cmd, error) {
				return rt.CaseCommand(ctx, image, req.Interpreter, req.Script, req.Snapshot, req.Scratch)
			})
		}
	}

	archivePath := filepath.Join(campaignDir, "source.tar.gz")
	casesDir := filepath.Dir(casesPath)

	var outcomes []repro.Outcome
	for _, c := range cases {
		snapDir, err := os.MkdirTemp("", "vrh-repro-snap-")
		if err != nil {
			return fmt.Errorf("create snapshot extract: %w", err)
		}
		if err := mani.Extract(archivePath, snapDir); err != nil {
			_ = manifest.RemoveReadOnly(snapDir)
			return err
		}
		timeout, err := caseTimeout(c)
		if err != nil {
			_ = manifest.RemoveReadOnly(snapDir)
			return err
		}
		outcome, err := runCase(repro.Case{
			ID:          c.ID,
			Finding:     c.Finding,
			ScriptPath:  resolvePath(casesDir, c.ScriptPath),
			Interpreter: resolveInterpreter(casesDir, c),
			Marker:      c.Marker,
			SnapshotDir: snapDir,
			Timeout:     timeout,
		})
		_ = manifest.RemoveReadOnly(snapDir)
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
	if err := mani.Verify(campaign.Target.SourcePath); err != nil {
		return fmt.Errorf("pinned source mutated during reproduction; refusing to export: %w", err)
	}

	exportDir := filepath.Dir(casesPath)
	if err := repro.Export(outcomes, exportDir); err != nil {
		return err
	}
	fmt.Println("outcomes exported:", filepath.Join(exportDir, "repro_outcomes.json"))
	return nil
}

func requireContainerRuntime(image string) (container.Runtime, error) {
	rt, err := container.Detect()
	if err != nil {
		return container.Runtime{}, fmt.Errorf("refusing to run reproductions: %w", err)
	}
	if err := rt.VerifyIsolation(image); err != nil {
		return container.Runtime{}, fmt.Errorf("refusing to run reproductions: %w", err)
	}
	return rt, nil
}

func verifySandboxCmd(args []string) error {
	if len(args) != 1 {
		return errors.New("verify-sandbox requires <campaign-dir>")
	}
	campaign, err := contract.Load(campaignFiles(args[0])["contract"])
	if err != nil {
		return fmt.Errorf("load campaign: %w", err)
	}
	if err := campaign.Validate(); err != nil {
		return err
	}
	rt, err := container.Detect()
	if err != nil {
		return err
	}
	if err := rt.VerifyIsolation(campaign.Environment.ContainerImage); err != nil {
		return err
	}
	fmt.Printf("container runtime: %s\n", rt.Kind)
	fmt.Printf("image: %s\n", campaign.Environment.ContainerImage)
	fmt.Println("container isolation verified: network=none, read-only rootfs, capabilities dropped, no published ports")
	return nil
}

func validateCmd(args []string) error {
	if len(args) < 3 {
		return errors.New("adversarial requires <finding-id> <attempts.json> <summary>")
	}
	findingID := strings.TrimSpace(args[0])
	attemptsPath, summary := args[1], strings.Join(args[2:], " ")
	data, err := os.ReadFile(attemptsPath)
	if err != nil {
		return fmt.Errorf("read attempts: %w", err)
	}
	attempts, err := validate.ParseAttempts(data)
	if err != nil {
		return err
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
	outPath := filepath.Join(dir, "validation_"+report.FindingID+".json")
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, outPath); err != nil {
		return err
	}
	fmt.Printf("finding %s verdict: %s (%d attempts)\nwritten to %s\n", report.FindingID, report.Verdict, len(report.Attempts), outPath)
	return nil
}

// resolveInterpreter prefers a case-specific interpreter (e.g. the target
// project's venv python) when one is configured, falling back to the generic
// interpreter name.
func resolveInterpreter(casesDir string, c reproCaseFile) string {
	if c.VenvPython != "" {
		return resolvePath(casesDir, c.VenvPython)
	}
	return c.Interpreter
}

func resolvePath(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

func caseTimeout(c reproCaseFile) (time.Duration, error) {
	if c.TimeoutSeconds < 0 {
		return 0, fmt.Errorf("case %s: timeout_seconds must be >= 0", c.ID)
	}
	if c.TimeoutSeconds == 0 {
		return 0, nil
	}
	d := time.Duration(c.TimeoutSeconds) * time.Second
	if d > repro.MaxTimeout {
		return 0, fmt.Errorf("case %s: timeout_seconds exceeds %s", c.ID, repro.MaxTimeout)
	}
	return d, nil
}
