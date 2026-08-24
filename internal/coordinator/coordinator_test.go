package coordinator

import (
	"testing"

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

func TestIngestBlocksFamilyAndAdvancesRound(t *testing.T) {
	reg := setupRegistry(t)
	state, err := NewState(3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Plan(reg); err != nil {
		t.Fatal(err)
	}
	results := []worker.Result{{
		RequestID:   "auth--r1",
		Status:      worker.ResultBlocked,
		Summary:     "no reachable primitive",
		BlockReason: "permission callback runs before sink",
	}}
	if err := state.Ingest(reg, results); err != nil {
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

func TestIngestRejectsUnknownRequest(t *testing.T) {
	reg := setupRegistry(t)
	state, err := NewState(3)
	if err != nil {
		t.Fatal(err)
	}
	err = state.Ingest(reg, []worker.Result{{
		RequestID: "ghost--r1",
		Status:    worker.ResultProgress,
		Summary:   "working",
	}})
	if err == nil {
		t.Fatal("unknown request id unexpectedly ingested")
	}
}
