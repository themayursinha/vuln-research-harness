package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/themayursinha/vuln-research-harness/internal/contract"
	"github.com/themayursinha/vuln-research-harness/internal/manifest"
	"gopkg.in/yaml.v3"
)

func setupCampaign(t *testing.T) (campaignDir, sourceDir string) {
	t.Helper()
	sourceDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceDir, "app.py"), []byte("print('ok')\n"), 0600); err != nil {
		t.Fatal(err)
	}
	campaignDir = t.TempDir()
	m, err := manifest.Snapshot(sourceDir, campaignDir)
	if err != nil {
		t.Fatal(err)
	}
	camp := contract.Template("repro-test")
	camp.Target.Name = "fixture"
	camp.Target.SourcePath = sourceDir
	camp.Target.SourceSnapshot = "sha256:" + m.ArchiveSHA
	data, err := yaml.Marshal(camp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(campaignDir, "campaign.yaml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return campaignDir, sourceDir
}

func writeReproInputs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "check.py")
	if err := os.WriteFile(script, []byte("print('LEAKMARKER')\n"), 0700); err != nil {
		t.Fatal(err)
	}
	casesPath := filepath.Join(dir, "cases.yaml")
	content := "- id: f1\n  finding: test\n  script_path: " + script + "\n  interpreter: python3\n  marker: LEAKMARKER\n"
	if err := os.WriteFile(casesPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return casesPath
}

func TestRunReproRefusesWithoutIsolation(t *testing.T) {
	campaignDir, _ := setupCampaign(t)
	casesPath := writeReproInputs(t)
	err := runRepro([]string{casesPath, campaignDir}, func() error {
		return errors.New("network isolation not verified")
	})
	if err == nil {
		t.Fatal("repro ran without isolation")
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(casesPath), "repro_outcomes.json")); !os.IsNotExist(statErr) {
		t.Fatal("outcomes exported despite isolation failure")
	}
}

func TestRunReproRefusesUnverifiedSnapshot(t *testing.T) {
	campaignDir, sourceDir := setupCampaign(t)
	if err := os.WriteFile(filepath.Join(sourceDir, "app.py"), []byte("tampered\n"), 0600); err != nil {
		t.Fatal(err)
	}
	casesPath := writeReproInputs(t)
	ran := false
	err := runRepro([]string{casesPath, campaignDir}, func() error {
		ran = true
		return nil
	})
	if err == nil {
		t.Fatal("repro ran against a mutated snapshot")
	}
	if ran {
		t.Fatal("isolation check ran before snapshot admission failed")
	}
}

func TestRunReproUsesPinnedSourcePath(t *testing.T) {
	campaignDir, _ := setupCampaign(t)
	casesPath := writeReproInputs(t)
	if err := runRepro([]string{casesPath, campaignDir}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(casesPath), "repro_outcomes.json")); err != nil {
		t.Fatalf("expected exported outcomes: %v", err)
	}
}

func TestRunReproIsolatesSnapshotMutations(t *testing.T) {
	campaignDir, sourceDir := setupCampaign(t)
	dir := t.TempDir()
	mutate := filepath.Join(dir, "mutate.py")
	if err := os.WriteFile(mutate, []byte("import os\ntry:\n    open(os.path.join(os.environ['VRH_SNAPSHOT'], 'mutated.txt'), 'w').write('x')\nexcept OSError:\n    pass\nprint('LEAKMARKER')\n"), 0700); err != nil {
		t.Fatal(err)
	}
	check := filepath.Join(dir, "check.py")
	if err := os.WriteFile(check, []byte("import os\nprint('MUTATED' if os.path.exists(os.path.join(os.environ['VRH_SNAPSHOT'], 'mutated.txt')) else 'LEAKMARKER')\n"), 0700); err != nil {
		t.Fatal(err)
	}
	casesPath := filepath.Join(dir, "cases.yaml")
	content := "- id: f1\n  finding: test\n  script_path: " + mutate + "\n  interpreter: python3\n  marker: LEAKMARKER\n" +
		"- id: f2\n  finding: test\n  script_path: " + check + "\n  interpreter: python3\n  marker: LEAKMARKER\n"
	if err := os.WriteFile(casesPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runRepro([]string{casesPath, campaignDir}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sourceDir, "mutated.txt")); !os.IsNotExist(err) {
		t.Fatal("reproduction mutated the pinned source tree")
	}
}

func TestRunReproResolvesScriptRelativeToCasesFile(t *testing.T) {
	campaignDir, _ := setupCampaign(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "check.py"), []byte("print('LEAKMARKER')\n"), 0700); err != nil {
		t.Fatal(err)
	}
	casesPath := filepath.Join(dir, "cases.yaml")
	content := "- id: f1\n  finding: test\n  script_path: check.py\n  interpreter: python3\n  marker: LEAKMARKER\n"
	if err := os.WriteFile(casesPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runRepro([]string{casesPath, campaignDir}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}
