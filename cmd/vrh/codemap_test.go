package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/themayursinha/vuln-research-harness/internal/codemap"
	"github.com/themayursinha/vuln-research-harness/internal/contract"
	"github.com/themayursinha/vuln-research-harness/internal/executor"
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

	link := filepath.Join(root, "linked-slices")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if err := refuseInsideSource(filepath.Join(link, "slice.json"), source); err == nil || !strings.Contains(err.Error(), "inside the pinned source") {
		t.Fatalf("directory symlink: %v", err)
	}
	dangling := filepath.Join(root, "codemap.json")
	if err := os.Symlink(filepath.Join(source, "sneak.json"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := refuseInsideSource(dangling, source); err == nil {
		t.Fatal("expected dangling symlink to fail")
	}
	if _, err := os.Lstat(filepath.Join(source, "sneak.json")); !os.IsNotExist(err) {
		t.Fatal("dangling symlink was created")
	}
}

func TestRoundPlanSliceSurvivesRetry(t *testing.T) {
	dir, _ := setupCodemapCampaign(t)
	if err := codemapIndexCmd([]string{dir}); err != nil {
		t.Fatal(err)
	}
	mainSlice := mustSlice(t, dir, "cmd/main.go#main")
	otherSlice := mustSlice(t, dir, "other/other.go#Unused")
	if err := familiesCmd([]string{"add", dir, "alpha", "alpha mechanism"}); err != nil {
		t.Fatal(err)
	}
	if err := familiesCmd([]string{"add", dir, "beta", "beta mechanism"}); err != nil {
		t.Fatal(err)
	}
	blockInbox(t, dir)
	if err := roundPlanCmd([]string{dir, "2", mainSlice}); err == nil {
		t.Fatal("expected plan to stop before publish")
	}
	state := readRoundState(t, dir)
	lines, err := sliceContext(dir, mainSlice)
	if err != nil {
		t.Fatal(err)
	}
	if !sameContext(state.PendingSlice, lines) || len(state.PendingPlan) != 2 {
		t.Fatalf("pending state = %+v, lines = %v", state, lines)
	}
	if err := os.Remove(mainSlice); err != nil {
		t.Fatal(err)
	}
	unblockInbox(t, dir)
	alphaPath := filepath.Join(dir, "inbox", "requests", "alpha--r1.json")
	publishRequest(t, dir, worker.Request{
		ID:      "alpha--r1",
		Round:   1,
		Family:  "alpha",
		Goal:    requestGoal("alpha", "alpha mechanism"),
		Context: append([]string{"alpha mechanism"}, lines...),
	})
	alphaBefore := mustRead(t, alphaPath)

	if err := roundPlanCmd([]string{dir, "2", otherSlice}); err == nil || !strings.Contains(err.Error(), "different slice") {
		t.Fatalf("changed slice: %v", err)
	}
	if !bytes.Equal(alphaBefore, mustRead(t, alphaPath)) {
		t.Fatal("rejected retry rewrote the published envelope")
	}
	if _, err := os.Stat(filepath.Join(dir, "inbox", "requests", "beta--r1.json")); !os.IsNotExist(err) {
		t.Fatal("rejected retry published the remaining worker")
	}

	if err := roundPlanCmd([]string{dir, "2"}); err != nil {
		t.Fatalf("omit slice on retry: %v", err)
	}
	if !bytes.Equal(alphaBefore, mustRead(t, alphaPath)) {
		t.Fatal("omit retry rewrote the published envelope")
	}
	beta := readRequest(t, filepath.Join(dir, "inbox", "requests", "beta--r1.json"))
	if !sameContext(beta.Context, append([]string{"beta mechanism"}, lines...)) {
		t.Fatalf("beta context = %v", beta.Context)
	}
}

func TestRoundPlanRejectsSliceAddedWhileResuming(t *testing.T) {
	dir, _ := setupCodemapCampaign(t)
	if err := codemapIndexCmd([]string{dir}); err != nil {
		t.Fatal(err)
	}
	otherSlice := mustSlice(t, dir, "other/other.go#Unused")
	if err := familiesCmd([]string{"add", dir, "alpha", "alpha mechanism"}); err != nil {
		t.Fatal(err)
	}
	if err := familiesCmd([]string{"add", dir, "beta", "beta mechanism"}); err != nil {
		t.Fatal(err)
	}
	blockInbox(t, dir)
	if err := roundPlanCmd([]string{dir, "2"}); err == nil {
		t.Fatal("expected plan to stop before publish")
	}
	state := readRoundState(t, dir)
	if state.PendingSlice != nil || len(state.PendingPlan) != 2 {
		t.Fatalf("pending state = %+v", state)
	}
	unblockInbox(t, dir)
	alphaPath := filepath.Join(dir, "inbox", "requests", "alpha--r1.json")
	publishRequest(t, dir, worker.Request{
		ID:      "alpha--r1",
		Round:   1,
		Family:  "alpha",
		Goal:    requestGoal("alpha", "alpha mechanism"),
		Context: []string{"alpha mechanism"},
	})
	alphaBefore := mustRead(t, alphaPath)
	if err := roundPlanCmd([]string{dir, "2", otherSlice}); err == nil || !strings.Contains(err.Error(), "different slice") {
		t.Fatalf("added slice: %v", err)
	}
	if !bytes.Equal(alphaBefore, mustRead(t, alphaPath)) {
		t.Fatal("rejected retry rewrote the published envelope")
	}
	if _, err := os.Stat(filepath.Join(dir, "inbox", "requests", "beta--r1.json")); !os.IsNotExist(err) {
		t.Fatal("rejected retry published the remaining worker")
	}
}

func TestCodemapWriteRefusesSymlinkIntoSource(t *testing.T) {
	dir, source := setupCodemapCampaign(t)
	before := dirSnapshot(t, source)
	link := filepath.Join(dir, "codemap-slices")
	rel, err := filepath.Rel(dir, source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rel, link); err != nil {
		t.Fatal(err)
	}
	if err := codemapIndexCmd([]string{dir}); err != nil {
		t.Fatal(err)
	}
	err = codemapSliceCmd([]string{dir, "cmd/main.go#main", "8"})
	if err == nil || !strings.Contains(err.Error(), "inside the pinned source") {
		t.Fatalf("slice through directory symlink: %v", err)
	}
	if got := dirSnapshot(t, source); !sameContext(got, before) {
		t.Fatalf("source changed through symlink\nbefore %v\nafter %v", before, got)
	}

	dir, source = setupCodemapCampaign(t)
	dangling := filepath.Join(dir, "codemap.json")
	if err := os.Symlink(filepath.Join(source, "sneak.json"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := codemapIndexCmd([]string{dir}); err == nil {
		t.Fatal("expected dangling symlink to fail")
	}
	if _, err := os.Lstat(filepath.Join(source, "sneak.json")); !os.IsNotExist(err) {
		t.Fatal("index wrote through a dangling symlink")
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

func mustSlice(t *testing.T, dir, entry string) string {
	t.Helper()
	if _, err := captureStdoutErr(func() error {
		return codemapSliceCmd([]string{dir, entry, "8"})
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "codemap-slices"))
	if err != nil {
		t.Fatal(err)
	}
	var match string
	for _, entryInfo := range entries {
		path := filepath.Join(dir, "codemap-slices", entryInfo.Name())
		slice, err := codemap.LoadSlice(path)
		if err != nil {
			t.Fatal(err)
		}
		if slice.Entry == entry {
			if match != "" {
				t.Fatalf("duplicate slice for %s", entry)
			}
			match = path
		}
	}
	if match == "" {
		t.Fatalf("no slice for %s", entry)
	}
	return match
}

func blockInbox(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "inbox")
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
}

func unblockInbox(t *testing.T, dir string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, "inbox")); err != nil {
		t.Fatal(err)
	}
}

func readRoundState(t *testing.T, dir string) roundState {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state roundState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func publishRequest(t *testing.T, dir string, request worker.Request) {
	t.Helper()
	inbox, err := executor.NewInbox(filepath.Join(dir, "inbox"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Publish(request); err != nil {
		t.Fatal(err)
	}
}

func readRequest(t *testing.T, path string) worker.Request {
	t.Helper()
	var request worker.Request
	if err := json.Unmarshal(mustRead(t, path), &request); err != nil {
		t.Fatal(err)
	}
	return request
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func dirSnapshot(t *testing.T, root string) []string {
	t.Helper()
	var rels []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rels = append(rels, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(rels)
	return rels
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
