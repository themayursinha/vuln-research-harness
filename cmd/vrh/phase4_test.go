package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/themayursinha/vuln-research-harness/internal/mcpreview"
	"github.com/themayursinha/vuln-research-harness/internal/worker"
)

func campaignFixture(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "campaigns", "mcp-filesystem", name)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	path = filepath.Join("campaigns", "mcp-filesystem", name)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	t.Fatalf("missing campaigns/mcp-filesystem/%s (cwd=%s)", name, mustWD(t))
	return ""
}

func mustWD(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

func TestFamiliesSeedThenFourWorkerPlan(t *testing.T) {
	campaignDir, _ := setupCampaign(t)
	seedPath := campaignFixture(t, "approaches.yaml")
	if err := familiesCmd([]string{"seed", campaignDir, seedPath}); err != nil {
		t.Fatal(err)
	}
	if err := familiesCmd([]string{"seed", campaignDir, seedPath}); err != nil {
		t.Fatalf("identical re-seed must be recoverable, got %v", err)
	}
	if err := roundPlanCmd([]string{campaignDir, "4"}); err != nil {
		t.Fatal(err)
	}
	reqDir := filepath.Join(campaignDir, "inbox", "requests")
	entries, err := os.ReadDir(reqDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("want 4 request envelopes, got %d", len(entries))
	}
	want := map[string]string{
		"dotdot--r1.json":  "parent-directory segments through validatePath",
		"symlink--r1.json": "symlink inside the allowed root that resolves outside it",
		"prefix--r1.json":  "allowed-directory string-prefix matching",
		"roots--r1.json":   "MCP roots protocol changing allowed directories after start",
	}
	for _, e := range entries {
		mech, ok := want[e.Name()]
		if !ok {
			t.Fatalf("unexpected envelope %s", e.Name())
		}
		raw, err := os.ReadFile(filepath.Join(reqDir, e.Name()))
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
		if req.Round != 1 {
			t.Fatalf("%s round=%d", e.Name(), req.Round)
		}
		if req.Goal != requestGoal(req.Family, mech) {
			t.Fatalf("%s goal=%q missing mechanism %q", e.Name(), req.Goal, mech)
		}
		if len(req.Context) != 1 || req.Context[0] != mech {
			t.Fatalf("%s context=%v want [%q]", e.Name(), req.Context, mech)
		}
	}
}

func TestFamiliesSeedResumesAfterPartialAppend(t *testing.T) {
	campaignDir, _ := setupCampaign(t)
	seedPath := campaignFixture(t, "approaches.yaml")
	if err := familiesCmd([]string{"add", campaignDir, "dotdot", "parent-directory segments through validatePath"}); err != nil {
		t.Fatal(err)
	}
	if err := familiesCmd([]string{"seed", campaignDir, seedPath}); err != nil {
		t.Fatal(err)
	}
	if err := roundPlanCmd([]string{campaignDir, "4"}); err != nil {
		t.Fatal(err)
	}
	reqDir := filepath.Join(campaignDir, "inbox", "requests")
	entries, err := os.ReadDir(reqDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("want 4 request envelopes after partial seed recovery, got %d", len(entries))
	}
}

func TestFamiliesSeedRejectsMechanismConflict(t *testing.T) {
	campaignDir, _ := setupCampaign(t)
	if err := familiesCmd([]string{"add", campaignDir, "dotdot", "some other mechanism"}); err != nil {
		t.Fatal(err)
	}
	err := familiesCmd([]string{"seed", campaignDir, campaignFixture(t, "approaches.yaml")})
	if err == nil {
		t.Fatal("seed must refuse a family that already exists with a different mechanism")
	}
}

func TestMCPFilesystemToolsJSONCoversEveryRegisteredTool(t *testing.T) {
	want := []string{
		"read_file", "read_text_file", "read_media_file", "read_multiple_files",
		"write_file", "edit_file", "create_directory", "list_directory",
		"list_directory_with_sizes", "directory_tree", "move_file", "search_files",
		"get_file_info", "list_allowed_directories",
	}
	data, err := os.ReadFile(campaignFixture(t, "tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range doc.Tools {
		got[tool.Name] = true
	}
	if len(doc.Tools) != len(want) {
		t.Fatalf("tools.json has %d tools, pin registers %d", len(doc.Tools), len(want))
	}
	for _, name := range want {
		if !got[name] {
			t.Fatalf("tools.json missing registered tool %q", name)
		}
	}
}

func TestMCPFilesystemToolsReviewEmitsUnconstrainedPaths(t *testing.T) {
	data, err := os.ReadFile(campaignFixture(t, "tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := mcpreview.Review(data)
	if err != nil {
		t.Fatal(err)
	}
	var pathHits int
	for _, h := range rep.Hypotheses {
		if h.Category == mcpreview.CategoryUnconstrainedPath {
			pathHits++
		}
	}
	if pathHits < 4 {
		t.Fatalf("want unconstrained_path hypotheses from the filesystem schema, got %d in %+v", pathHits, rep.Hypotheses)
	}
}
