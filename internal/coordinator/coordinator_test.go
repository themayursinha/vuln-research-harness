package coordinator

import (
	"testing"

	"github.com/themayursinha/vuln-research-harness/internal/ledger"
	"github.com/themayursinha/vuln-research-harness/internal/registry"
	"github.com/themayursinha/vuln-research-harness/internal/worker"
)

func setupRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	reg := registry.New()
	for _, family := range []string{"parser", "auth", "cache"} {
		if err := reg.Add(family, "initial mechanism for "+family); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

func TestPlanFavorsNeglectedFamilies(t *testing.T) {
	reg := setupRegistry(t)
	if err := reg.RecordDispatch("parser"); err != nil {
		t.Fatal(err)
	}
	state, err := NewState(2)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := state.Plan(reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Dispatched) != 2 {
		t.Fatalf("expected 2 dispatches, got %v", plan.Dispatched)
	}
	for _, family := range plan.Dispatched {
		if family == "parser" {
			t.Fatalf("converged family parser was dispatched first: %v", plan.Dispatched)
		}
	}
}

func TestIngestRequiresExactOutstandingRequestID(t *testing.T) {
	reg := setupRegistry(t)
	state, err := NewState(3)
	if err != nil {
		t.Fatal(err)
	}
	outstanding := map[string]string{
		"auth--r1":  "auth",
		"cache--r1": "cache",
	}

	// Invented IDs are rejected even when they share a family prefix.
	if err := state.Ingest(reg, outstanding, []worker.Result{{
		RequestID: "auth--never-dispatched",
		Status:    worker.ResultProgress,
		Summary:   "invented",
	}}); err == nil {
		t.Fatal("invented request id unexpectedly ingested")
	}

	// Overlapping prefixes: auth--oauth--r1 must NOT match family "auth".
	if err := state.Ingest(reg, outstanding, []worker.Result{{
		RequestID: "auth--oauth--r1",
		Status:    worker.ResultProgress,
		Summary:   "wrong family",
	}}); err == nil {
		t.Fatal("overlapping prefix id unexpectedly ingested")
	}
}

func TestIngestBlocksFamilyAndAdvancesRound(t *testing.T) {
	reg := setupRegistry(t)
	state, err := NewState(3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Plan(reg); err != nil {
		t.Fatal(err)
	}
	outstanding := map[string]string{
		"parser--r1": "parser",
		"auth--r1":   "auth",
		"cache--r1":  "cache",
	}
	results := []worker.Result{{
		RequestID:   "auth--r1",
		Status:      worker.ResultBlocked,
		Summary:     "no reachable primitive",
		BlockReason: "permission callback runs before sink",
	}}
	if err := state.Ingest(reg, outstanding, results); err != nil {
		t.Fatal(err)
	}
	if state.Round != 2 {
		t.Fatalf("round did not advance: %d", state.Round)
	}
	approach, _ := reg.Get("auth")
	if approach.Status != registry.Blocked {
		t.Fatalf("family not blocked: %+v", approach)
	}
	plan, err := state.Plan(reg)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range plan.Dispatched {
		if family == "auth" {
			t.Fatal("blocked family received work")
		}
	}
}

func TestIngestRejectsEmptyOutstanding(t *testing.T) {
	reg := setupRegistry(t)
	state, err := NewState(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Ingest(reg, nil, nil); err == nil {
		t.Fatal("ingest with no outstanding requests unexpectedly accepted")
	}
}

func TestReconcileFromLedgerRestoresBlockedState(t *testing.T) {
	reg := setupRegistry(t)
	events := []ledger.Event{{
		ID:   "auth--r1",
		Type: "result_ingested",
		Data: map[string]string{"status": "blocked", "family": "auth", "block_reason": "no primitive"},
	}}
	if err := ReconcileFromLedger(reg, events); err != nil {
		t.Fatal(err)
	}
	approach, _ := reg.Get("auth")
	if approach.Status != registry.Blocked {
		t.Fatalf("reconcile did not restore blocked state: %+v", approach)
	}
}

func TestReconcileDoesNotDowngradeExhausted(t *testing.T) {
	reg := setupRegistry(t)
	if err := reg.Exhaust("auth"); err != nil {
		t.Fatal(err)
	}
	events := []ledger.Event{{
		ID:   "auth--r1",
		Type: "result_ingested",
		Data: map[string]string{"status": "blocked", "family": "auth", "block_reason": "no primitive"},
	}}
	if err := ReconcileFromLedger(reg, events); err != nil {
		t.Fatal(err)
	}
	approach, _ := reg.Get("auth")
	if approach.Status != registry.Exhausted {
		t.Fatalf("reconcile downgraded exhausted family: %+v", approach)
	}
}

func TestReconcileHonorsReopenAfterBlock(t *testing.T) {
	reg := setupRegistry(t)
	events := []ledger.Event{
		{
			ID:   "auth--r1",
			Type: "result_ingested",
			Data: map[string]string{"status": "blocked", "family": "auth", "block_reason": "no primitive"},
		},
		{
			ID:   "family:auth",
			Type: "family_reopened",
			Data: map[string]string{"family": "auth", "mechanism": "new mechanism"},
		},
	}
	if err := ReconcileFromLedger(reg, events); err != nil {
		t.Fatal(err)
	}
	approach, _ := reg.Get("auth")
	if approach.Status != registry.Active {
		t.Fatalf("reopen after block was not honored: %+v", approach)
	}
}

func TestReconcileHonorsLaterBlockAfterReopen(t *testing.T) {
	reg := setupRegistry(t)
	events := []ledger.Event{
		{
			ID:   "auth--r1",
			Type: "result_ingested",
			Data: map[string]string{"status": "blocked", "family": "auth", "block_reason": "first"},
		},
		{
			ID:   "family:auth",
			Type: "family_reopened",
			Data: map[string]string{"family": "auth", "mechanism": "new mechanism"},
		},
		{
			ID:   "auth--r2",
			Type: "result_ingested",
			Data: map[string]string{"status": "blocked", "family": "auth", "block_reason": "blocked again"},
		},
	}
	if err := ReconcileFromLedger(reg, events); err != nil {
		t.Fatal(err)
	}
	approach, _ := reg.Get("auth")
	if approach.Status != registry.Blocked || approach.BlockReason != "blocked again" {
		t.Fatalf("later block after reopen was not honored: %+v", approach)
	}
}
