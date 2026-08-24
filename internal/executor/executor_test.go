package executor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/themayursinha/vuln-research-harness/internal/capability"
	"github.com/themayursinha/vuln-research-harness/internal/ledger"
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

func writeResultEnvelope(t *testing.T, inbox *Inbox, filename string, result worker.Result, claims []capability.Claim) string {
	t.Helper()
	envelope := struct {
		Capabilities []capability.Claim `json:"capabilities"`
		Result       worker.Result      `json:"result"`
	}{Capabilities: claims, Result: result}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(inbox.dir, "results", filename)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPublishIsIdempotentForIdenticalRequests(t *testing.T) {
	inbox, err := NewInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := worker.Request{ID: "parser--r1", Round: 1, Family: "parser", Goal: "map request validation order"}
	if _, err := inbox.Publish(request); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Publish(request); err != nil {
		t.Fatalf("identical re-publish must succeed (retry-safe): %v", err)
	}
	conflicting := request
	conflicting.Goal = "different goal"
	if _, err := inbox.Publish(conflicting); err == nil {
		t.Fatal("conflicting re-publish unexpectedly succeeded")
	}
}

func TestCollectRejectsFailingCapabilityGate(t *testing.T) {
	inbox, err := NewInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Publish(worker.Request{ID: "cache--r1", Round: 1, Family: "cache", Goal: "g"}); err != nil {
		t.Fatal(err)
	}
	claims := satisfiedClaims()
	claims[0] = capability.Claim{Name: "no_external_network", Satisfied: false, Evidence: "none"}
	writeResultEnvelope(t, inbox, "cache--r1.json", worker.Result{
		RequestID: "cache--r1",
		Status:    worker.ResultProgress,
		Summary:   "work done",
	}, claims)
	outstanding := map[string]string{"cache--r1": "cache"}
	if _, err := inbox.CollectResults(DefaultGate(), outstanding); err == nil {
		t.Fatal("results from a failing capability gate were accepted")
	}
}

func TestCollectRejectsResultsWithoutOutstandingRequest(t *testing.T) {
	inbox, err := NewInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// No request published for auth--r1 — an invented envelope must not collect.
	writeResultEnvelope(t, inbox, "auth--r1.json", worker.Result{
		RequestID: "auth--r1",
		Status:    worker.ResultProgress,
		Summary:   "invented",
	}, satisfiedClaims())
	outstanding := map[string]string{"cache--r1": "cache"}
	if _, err := inbox.CollectResults(DefaultGate(), outstanding); err == nil {
		t.Fatal("result for a never-dispatched request was accepted")
	}
}

func TestConsumeUsesCollectedFilename(t *testing.T) {
	inbox, err := NewInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Publish(worker.Request{ID: "auth--r1", Round: 1, Family: "auth", Goal: "g"}); err != nil {
		t.Fatal(err)
	}
	// Worker follows the flow but names the envelope result.json instead of
	// <request_id>.json. Consume must archive the exact file that was read,
	// otherwise the envelope lingers and the request stays outstanding.
	writeResultEnvelope(t, inbox, "result.json", worker.Result{
		RequestID: "auth--r1",
		Status:    worker.ResultProgress,
		Summary:   "work done",
	}, satisfiedClaims())

	outstanding, err := inbox.OutstandingRequests()
	if err != nil {
		t.Fatal(err)
	}
	collected, err := inbox.CollectResults(DefaultGate(), outstanding)
	if err != nil {
		t.Fatal(err)
	}
	if len(collected) != 1 || collected[0].Filename != "result.json" {
		t.Fatalf("unexpected collected set: %+v", collected)
	}
	if err := inbox.Consume(collected); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(inbox.dir, "results", "result.json")); !os.IsNotExist(err) {
		t.Fatal("misnamed envelope was not consumed")
	}
	if _, err := os.Stat(filepath.Join(inbox.dir, "results", "consumed", "result.json")); err != nil {
		t.Fatal("misnamed envelope not archived under consumed/")
	}
	outstanding, err = inbox.OutstandingRequests()
	if err != nil {
		t.Fatal(err)
	}
	if len(outstanding) != 0 {
		t.Fatalf("request still outstanding after consume: %v", outstanding)
	}
}

func TestConsumePreventsReingestAfterReopen(t *testing.T) {
	inbox, err := NewInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Publish(worker.Request{ID: "auth--r1", Round: 1, Family: "auth", Goal: "g"}); err != nil {
		t.Fatal(err)
	}
	writeResultEnvelope(t, inbox, "auth--r1.json", worker.Result{
		RequestID:   "auth--r1",
		Status:      worker.ResultBlocked,
		Summary:     "blocked",
		BlockReason: "exhausted in round 1",
	}, satisfiedClaims())

	outstanding, err := inbox.OutstandingRequests()
	if err != nil {
		t.Fatal(err)
	}
	if len(outstanding) != 1 {
		t.Fatalf("expected 1 outstanding request, got %v", outstanding)
	}
	collected, err := inbox.CollectResults(DefaultGate(), outstanding)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.Consume(collected); err != nil {
		t.Fatal(err)
	}

	// After consumption the old blocked result must not be collectable again,
	// so a reopened family cannot be re-blocked by stale evidence.
	outstanding, err = inbox.OutstandingRequests()
	if err != nil {
		t.Fatal(err)
	}
	if len(outstanding) != 0 {
		t.Fatalf("consumed request still outstanding: %v", outstanding)
	}
	if _, err := inbox.CollectResults(DefaultGate(), outstanding); err == nil {
		t.Fatal("collect after consume unexpectedly succeeded")
	}
}

func TestOutstandingFromLedgerRejectsUnpublishedRequestFile(t *testing.T) {
	inbox, err := NewInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A hand-placed request file with no request_published event must never
	// be treated as dispatched, even though it sits in requests/.
	data := []byte(`{"id":"injected--r1","round":1,"family":"injected","goal":"g"}`)
	if err := os.WriteFile(filepath.Join(inbox.dir, "requests", "injected--r1.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OutstandingFromLedger(inbox, nil); err == nil {
		t.Fatal("unpublished request file accepted as dispatched")
	}
}

func TestOutstandingFromLedgerRejectsTamperedFamily(t *testing.T) {
	inbox, err := NewInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Publish(worker.Request{ID: "auth--r1", Round: 1, Family: "auth", Goal: "g"}); err != nil {
		t.Fatal(err)
	}
	events := []ledger.Event{{
		ID:   "auth--r1",
		Type: "request_published",
		Data: map[string]string{"round": "1", "family": "auth"},
	}}
	// Tamper with the envelope's family after publication.
	path := filepath.Join(inbox.dir, "requests", "auth--r1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(data), `"family": "auth"`, `"family": "other"`, 1))
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OutstandingFromLedger(inbox, events); err == nil {
		t.Fatal("envelope family diverging from ledger was accepted")
	}
}

func TestConsumeRejectsDuplicateRequestIDs(t *testing.T) {
	inbox, err := NewInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Publish(worker.Request{ID: "auth--r1", Round: 1, Family: "auth", Goal: "g"}); err != nil {
		t.Fatal(err)
	}
	writeResultEnvelope(t, inbox, "auth--r1.json", worker.Result{
		RequestID: "auth--r1",
		Status:    worker.ResultProgress,
		Summary:   "first",
	}, satisfiedClaims())
	writeResultEnvelope(t, inbox, "duplicate.json", worker.Result{
		RequestID:   "auth--r1",
		Status:      worker.ResultBlocked,
		Summary:     "second",
		BlockReason: "contradicting verdict",
	}, satisfiedClaims())
	outstanding, err := OutstandingFromLedger(inbox, []ledger.Event{{
		ID:   "auth--r1",
		Type: "request_published",
		Data: map[string]string{"round": "1", "family": "auth"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.CollectResults(DefaultGate(), outstanding); err == nil {
		t.Fatal("two envelopes answering the same request were accepted together")
	}
}

func TestOutstandingFromLedgerExcludesIngestedRequests(t *testing.T) {
	inbox, err := NewInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Publish(worker.Request{ID: "auth--r1", Round: 1, Family: "auth", Goal: "g"}); err != nil {
		t.Fatal(err)
	}
	events := []ledger.Event{
		{ID: "auth--r1", Type: "request_published", Data: map[string]string{"round": "1", "family": "auth"}},
		{ID: "auth--r1", Type: "result_ingested", Data: map[string]string{"status": "progress"}},
	}
	outstanding, err := OutstandingFromLedger(inbox, events)
	if err != nil {
		t.Fatal(err)
	}
	if len(outstanding) != 0 {
		t.Fatalf("ingested request still outstanding: %v", outstanding)
	}
}

func TestOutstandingFromLedgerAllowsRedroppedConsumedEnvelopeFile(t *testing.T) {
	inbox, err := NewInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Publish(worker.Request{ID: "auth--r1", Round: 1, Family: "auth", Goal: "g"}); err != nil {
		t.Fatal(err)
	}
	events := []ledger.Event{
		{ID: "auth--r1", Type: "request_published", Data: map[string]string{"round": "1", "family": "auth"}},
		{ID: "auth--r1", Type: "result_ingested", Data: map[string]string{}},
	}
	// The envelope file lingers (worker re-dropped it after consume); the
	// ledger already recorded ingestion, so this is not an unpublished file.
	if _, err := OutstandingFromLedger(inbox, events); err != nil {
		t.Fatalf("consumed-but-present envelope treated as unpublished: %v", err)
	}
}
