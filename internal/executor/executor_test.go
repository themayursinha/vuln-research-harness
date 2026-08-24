package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/themayursinha/vuln-research-harness/internal/capability"
	"github.com/themayursinha/vuln-research-harness/internal/worker"
)

func satisfiedClaims() []capability.Claim {
	return []capability.Claim{
		{Name: "no_external_network", Satisfied: true, Evidence: "unshare -n"},
		{Name: "no_real_credentials", Satisfied: true, Evidence: "synthetic fixtures"},
		{Name: "disposable_environment", Satisfied: true, Evidence: "tmpfs container"},
		{Name: "read_only_source_mount", Satisfied: true, Evidence: "mount -o ro"},
	}
}

func TestPublishAndCollectRoundTrip(t *testing.T) {
	inbox, err := NewInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := worker.Request{ID: "parser--r1", Round: 1, Family: "parser", Goal: "map request validation order"}
	if err := inbox.Publish(request); err != nil {
		t.Fatal(err)
	}
	if err := inbox.Publish(request); err == nil {
		t.Fatal("duplicate publish unexpectedly succeeded")
	}

	envelope := struct {
		Capabilities []capability.Claim `json:"capabilities"`
		Result       worker.Result      `json:"result"`
	}{
		Capabilities: satisfiedClaims(),
		Result: worker.Result{
			RequestID:   "parser--r1",
			Status:      worker.ResultBlocked,
			Summary:     "validation ordering pinned down",
			BlockReason: "no mismatch reachable pre-auth",
		},
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inbox.dir, "results", "parser--r1.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	results, err := inbox.CollectResults(DefaultGate())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].RequestID != "parser--r1" {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestCollectRejectsFailingCapabilityGate(t *testing.T) {
	inbox, err := NewInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	claims := satisfiedClaims()
	claims[0] = capability.Claim{Name: "no_external_network", Satisfied: false, Evidence: "none"}
	envelope := struct {
		Capabilities []capability.Claim `json:"capabilities"`
		Result       worker.Result      `json:"result"`
	}{
		Capabilities: claims,
		Result: worker.Result{
			RequestID: "cache--r1",
			Status:    worker.ResultProgress,
			Summary:   "work done",
		},
	}
	data, _ := json.Marshal(envelope)
	if err := os.WriteFile(filepath.Join(inbox.dir, "results", "cache--r1.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.CollectResults(DefaultGate()); err == nil {
		t.Fatal("results from a failing capability gate were accepted")
	}
}
