package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/vuln-research-harness/internal/codemap"
	"github.com/themayursinha/vuln-research-harness/internal/contract"
	"github.com/themayursinha/vuln-research-harness/internal/manifest"
	"github.com/themayursinha/vuln-research-harness/internal/worker"
	"gopkg.in/yaml.v3"
)

func TestCodemapIndexReachSliceAndRound(t *testing.T) {
	dir, _ := setupCodemapCampaign(t)
	out := captureStdout(t, func() error {
		return codemapIndexCmd([]string{dir})
	})
	if !strings.Contains(out, "codemap indexed:") || !strings.Contains(out, "wrote ") {
		t.Fatalf("index output: %s", out)
	}

	out = captureStdout(t, func() error {
		return codemapReachCmd([]string{dir, "cmd/main.go#main"})
	})
	if out != "auth/auth.go\ncmd/main.go\n" {
		t.Fatalf("reach output: %q", out)
	}

	out = captureStdout(t, func() error {
		return codemapSliceCmd([]string{dir, "cmd/main.go#main", "8"})
	})
	var slice codemap.Slice
	if err := json.Unmarshal([]byte(out), &slice); err != nil {
		t.Fatalf("slice stdout: %v\n%s", err, out)
	}
	if slice.Entry != "cmd/main.go#main" || len(slice.Files) != 2 || slice.MaxFiles != 8 {
		t.Fatalf("slice = %+v", slice)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "codemap-slices"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("slice files: %v", entries)
	}
	slicePath := filepath.Join(dir, "codemap-slices", entries[0].Name())

	if err := familiesCmd([]string{"add", dir, "parser", "synthetic call path"}); err != nil {
		t.Fatal(err)
	}
	if err := roundPlanCmd([]string{dir, "1", slicePath}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "inbox", "requests", "parser--r1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var req worker.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(req.Context) != 4 || req.Context[0] != "synthetic call path" {
		t.Fatalf("context = %v", req.Context)
	}
	if req.Context[1] != "codemap-entry:cmd/main.go#main" {
		t.Fatalf("context = %v", req.Context)
	}
	if req.Context[2] != "codemap-file:auth/auth.go" || req.Context[3] != "codemap-file:cmd/main.go" {
		t.Fatalf("context = %v", req.Context)
	}
}

func TestCodemapRefusesTamperStaleGraphAndBadContract(t *testing.T) {
	dir, source := setupCodemapCampaign(t)
	if err := codemapIndexCmd([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "cmd", "main.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := codemapReachCmd([]string{dir, "cmd/main.go#main"}); err == nil || !strings.Contains(err.Error(), "admission") {
		t.Fatalf("tampered source: %v", err)
	}

	dir, _ = setupCodemapCampaign(t)
	if err := codemapIndexCmd([]string{dir}); err != nil {
		t.Fatal(err)
	}
	graphPath := filepath.Join(dir, "codemap.json")
	raw, err := os.ReadFile(graphPath)
	if err != nil {
		t.Fatal(err)
	}
	var graph codemap.Graph
	if err := json.Unmarshal(raw, &graph); err != nil {
		t.Fatal(err)
	}
	graph.Functions = nil
	graph.Edges = nil
	encoded, err := json.MarshalIndent(graph, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(graphPath, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := codemapReachCmd([]string{dir, "cmd/main.go#main"}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("stale graph: %v", err)
	}

	dir, _ = setupCodemapCampaign(t)
	campPath := filepath.Join(dir, "campaign.yaml")
	camp, err := contract.Load(campPath)
	if err != nil {
		t.Fatal(err)
	}
	camp.Authorization.WrittenPermission = false
	data, err := yaml.Marshal(camp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(campPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := codemapIndexCmd([]string{dir}); err == nil || !strings.Contains(err.Error(), "admission") {
		t.Fatalf("unsafe contract: %v", err)
	}
}

func TestCodemapSliceBoundAndMissingIndex(t *testing.T) {
	dir, _ := setupCodemapCampaign(t)
	if err := codemapReachCmd([]string{dir, "cmd/main.go#main"}); err == nil {
		t.Fatal("expected reach without an index to fail")
	}
	if err := codemapIndexCmd([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if err := codemapSliceCmd([]string{dir, "cmd/main.go#main", "1"}); err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("bound: %v", err)
	}
	if err := codemapIndexCmd(nil); err == nil {
		t.Fatal("expected usage error")
	}
}

func TestRoundPlanRejectsForeignSlice(t *testing.T) {
	dir, _ := setupCodemapCampaign(t)
	if err := codemapIndexCmd([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdoutErr(func() error {
		return codemapSliceCmd([]string{dir, "other/other.go#Unused", "4"})
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "codemap-slices"))
	if err != nil {
		t.Fatal(err)
	}
	slicePath := filepath.Join(dir, "codemap-slices", entries[0].Name())
	raw, err := os.ReadFile(slicePath)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte("other/other.go#Unused"), []byte("cmd/main.go#main"), 1)
	if err := os.WriteFile(slicePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := familiesCmd([]string{"add", dir, "parser", "synthetic call path"}); err != nil {
		t.Fatal(err)
	}
	if err := roundPlanCmd([]string{dir, "1", slicePath}); err == nil {
		t.Fatal("expected mismatched slice to fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "inbox", "requests", "parser--r1.json")); !os.IsNotExist(err) {
		t.Fatal("round plan wrote a request after rejecting the slice")
	}
}

func TestRefuseInsideSource(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := refuseInsideSource(filepath.Join(source, "codemap.json"), source); err == nil {
		t.Fatal("expected refusal")
	}
	if err := refuseInsideSource(filepath.Join(root, "codemap.json"), source); err != nil {
		t.Fatal(err)
	}
}

func setupCodemapCampaign(t *testing.T) (campaignDir, sourceDir string) {
	t.Helper()
	sourceDir = t.TempDir()
	copyTree(t, synthGoFixture(t), sourceDir)
	campaignDir = t.TempDir()
	snap, err := manifest.Snapshot(sourceDir, campaignDir)
	if err != nil {
		t.Fatal(err)
	}
	camp := contract.Template("codemap-test")
	camp.Target.Name = "synthetic-codemap"
	camp.Target.SourcePath = sourceDir
	camp.Target.SourceSnapshot = "sha256:" + snap.ArchiveSHA
	data, err := yaml.Marshal(camp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(campaignDir, "campaign.yaml"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return campaignDir, sourceDir
}

func synthGoFixture(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "internal", "codemap", "testdata", "synth", "go"),
		filepath.Join("internal", "codemap", "testdata", "synth", "go"),
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	t.Fatal("missing synthetic go fixture")
	return ""
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()
	out, err := captureStdoutErr(fn)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func captureStdoutErr(fn func() error) (string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	cmdErr := fn()
	w.Close()
	out, readErr := io.ReadAll(r)
	if readErr != nil {
		return "", readErr
	}
	return string(out), cmdErr
}
