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
	if err := familiesCmd([]string{"seed", campaignDir, seedPath}); err == nil {
		t.Fatal("second seed must refuse existing families")
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
	want := map[string]bool{
		"dotdot--r1.json":  true,
		"symlink--r1.json": true,
		"prefix--r1.json":  true,
		"roots--r1.json":   true,
	}
	for _, e := range entries {
		if !want[e.Name()] {
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
