// Package coordinator implements the round state machine that drives a
// campaign: plan work per round while preventing approach convergence, then
// ingest structured results and update registry state.
package coordinator

import (
	"fmt"
	"sort"

	"github.com/themayursinha/vuln-research-harness/internal/registry"
	"github.com/themayursinha/vuln-research-harness/internal/worker"
)

// State is one coordinator round.
type State struct {
	Round      int
	MaxWorkers int
}

// PlanResult records which families received work in a round.
type PlanResult struct {
	Round      int
	Dispatched []string
	Blocked    []string
}

// NewState starts round 1 with the given parallel-worker cap.
func NewState(maxWorkers int) (State, error) {
	if maxWorkers < 1 {
		return State{}, fmt.Errorf("maxWorkers must be >= 1")
	}
	return State{Round: 1, MaxWorkers: maxWorkers}, nil
}

// Plan assigns the next round's work. Active families are sorted by attempt
// count (fewest first) so neglected approaches receive work before converged
// ones. Blocked and exhausted families never receive work; reopening a
// blocked family is only possible through registry.Reopen with a new
// mechanism.
func (s *State) Plan(reg *registry.Registry) (PlanResult, error) {
	if reg == nil {
		return PlanResult{}, fmt.Errorf("registry is required")
	}
	result := PlanResult{Round: s.Round}
	type candidate struct {
		family   string
		attempts int
	}
	var active []candidate
	for _, approach := range reg.All() {
		switch approach.Status {
		case registry.Active:
			active = append(active, candidate{family: approach.Family, attempts: approach.Attempts})
		case registry.Blocked, registry.Exhausted:
			result.Blocked = append(result.Blocked, approach.Family)
		}
	}
	sort.Slice(active, func(i, j int) bool {
		if active[i].attempts != active[j].attempts {
			return active[i].attempts < active[j].attempts
		}
		return active[i].family < active[j].family
	})
	limit := s.MaxWorkers
	if len(active) < limit {
		limit = len(active)
	}
	for _, c := range active[:limit] {
		if err := reg.RecordDispatch(c.family); err != nil {
			return PlanResult{}, err
		}
		result.Dispatched = append(result.Dispatched, c.family)
	}
	return result, nil
}

// Ingest applies a batch of worker results to the registry. Every result must
// name the exact ID of an outstanding request in outstanding; invented IDs
// and prefix-based family guesses are rejected. Blocked results block their
// family; progress/refuted/finding results leave the family active (a finding
// is a validated claim, not a reason to stop searching the family).
func (s *State) Ingest(reg *registry.Registry, outstanding map[string]string, results []worker.Result) error {
	if len(outstanding) == 0 {
		return fmt.Errorf("no outstanding requests; ingest nothing")
	}
	for _, result := range results {
		if err := result.Validate(); err != nil {
			return err
		}
		if _, ok := outstanding[result.RequestID]; !ok {
			return fmt.Errorf("result %q does not match any outstanding request", result.RequestID)
		}
	}
	for _, result := range results {
		family := outstanding[result.RequestID]
		if result.Status == worker.ResultBlocked {
			if err := reg.Block(family, result.BlockReason); err != nil {
				return err
			}
		}
	}
	s.Round++
	return nil
}
