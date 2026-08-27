package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/vuln-research-harness/internal/ledger"
)

func TestReproAppendsLedgerEvent(t *testing.T) {
	campaignDir, _ := setupCampaign(t)
	casesPath := writeReproInputs(t)
	if err := runRepro([]string{casesPath, campaignDir}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	events, err := ledgerEventsFor(campaignDir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, event := range events {
		if event.Type == "reproduction_run" {
			found = true
			if event.Data["outcomes_digest"] == "" || event.Data["case_ids"] == "" {
				t.Fatalf("incomplete reproduction_run event: %#v", event.Data)
			}
		}
	}
	if !found {
		t.Fatal("repro did not append reproduction_run to ledger")
	}
}

func TestAdversarialAppendsLedgerEvent(t *testing.T) {
	campaignDir, _ := setupCampaign(t)
	dir := t.TempDir()
	attemptsPath := filepath.Join(dir, "attempts.json")
	attempts := `[{"name":"control-check","hypothesis":"auth blocks it","result":"blocked","broke_it":false}]`
	if err := os.WriteFile(attemptsPath, []byte(attempts), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateCmd([]string{campaignDir, "F1", attemptsPath, "finding stands"}); err != nil {
		t.Fatal(err)
	}
	events, err := ledgerEventsFor(campaignDir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, event := range events {
		if event.Type == "validation_verdict" && event.Data["finding_id"] == "F1" {
			found = true
			if event.Data["verdict"] != "upheld" || event.Data["report_digest"] == "" {
				t.Fatalf("unexpected validation_verdict: %#v", event.Data)
			}
		}
	}
	if !found {
		t.Fatal("adversarial did not append validation_verdict to ledger")
	}
}

func TestCampaignStatusShowsLedgerEvents(t *testing.T) {
	campaignDir, _ := setupCampaign(t)
	casesPath := writeReproInputs(t)
	if err := runRepro([]string{casesPath, campaignDir}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	attemptsPath := filepath.Join(dir, "attempts.json")
	attempts := `[{"name":"control-check","hypothesis":"auth blocks it","result":"blocked","broke_it":false}]`
	if err := os.WriteFile(attemptsPath, []byte(attempts), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateCmd([]string{campaignDir, "F1", attemptsPath, "finding stands"}); err != nil {
		t.Fatal(err)
	}

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	err = campaignStatusCmd([]string{campaignDir})
	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatal(err)
	}
	outBytes, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	out := string(outBytes)
	if !strings.Contains(out, "reproduction_run") || !strings.Contains(out, "validation_verdict") {
		t.Fatalf("status output missing ledger summary:\n%s", out)
	}
	if !strings.Contains(out, "finding=F1") {
		t.Fatalf("status output missing validation finding:\n%s", out)
	}
}

func TestLedgerAppendPreservesChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")
	ldg, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ldg.Append("a", "reproduction_run", map[string]string{"case_ids": "f1"}); err != nil {
		t.Fatal(err)
	}
	if err := ldg.Close(); err != nil {
		t.Fatal(err)
	}
	ldg2, err := ledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ldg2.Close()
	events, err := ldg2.Events()
	if err != nil || len(events) != 1 || events[0].Hash == "" {
		t.Fatalf("ledger chain broken: events=%v err=%v", events, err)
	}
}
