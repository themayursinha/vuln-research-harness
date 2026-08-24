package registry

import (
	"fmt"
	"sort"
)

type Status string

const (
	Active    Status = "active"
	Blocked   Status = "blocked"
	Exhausted Status = "exhausted"
)

type Approach struct {
	Family           string `json:"family" yaml:"family"`
	Mechanism        string `json:"mechanism" yaml:"mechanism"`
	Status           Status `json:"status" yaml:"status"`
	Attempts         int    `json:"attempts" yaml:"attempts"`
	BlockReason      string `json:"block_reason,omitempty" yaml:"block_reason,omitempty"`
	LastNewMechanism string `json:"last_new_mechanism,omitempty" yaml:"last_new_mechanism,omitempty"`
}

type Registry struct {
	approaches map[string]Approach
}

func New() *Registry { return &Registry{approaches: make(map[string]Approach)} }

func (r *Registry) Add(family, mechanism string) error {
	if family == "" || mechanism == "" {
		return fmt.Errorf("family and mechanism are required")
	}
	if _, exists := r.approaches[family]; exists {
		return fmt.Errorf("approach family %q already exists", family)
	}
	r.approaches[family] = Approach{Family: family, Mechanism: mechanism, Status: Active, Attempts: 1}
	return nil
}

func (r *Registry) Block(family, reason string) error {
	approach, ok := r.approaches[family]
	if !ok {
		return fmt.Errorf("unknown approach family %q", family)
	}
	if reason == "" {
		return fmt.Errorf("block reason is required")
	}
	approach.Status = Blocked
	approach.BlockReason = reason
	r.approaches[family] = approach
	return nil
}

func (r *Registry) Reopen(family, newMechanism string) error {
	approach, ok := r.approaches[family]
	if !ok {
		return fmt.Errorf("unknown approach family %q", family)
	}
	if approach.Status != Blocked {
		return fmt.Errorf("approach family %q is not blocked", family)
	}
	if newMechanism == "" || newMechanism == approach.Mechanism || newMechanism == approach.LastNewMechanism {
		return fmt.Errorf("reopening %q requires a materially new mechanism", family)
	}
	approach.Status = Active
	approach.Attempts++
	approach.LastNewMechanism = newMechanism
	approach.BlockReason = ""
	r.approaches[family] = approach
	return nil
}

func (r *Registry) Exhaust(family string) error {
	approach, ok := r.approaches[family]
	if !ok {
		return fmt.Errorf("unknown approach family %q", family)
	}
	approach.Status = Exhausted
	r.approaches[family] = approach
	return nil
}

func (r *Registry) Get(family string) (Approach, bool) {
	approach, ok := r.approaches[family]
	return approach, ok
}

func (r *Registry) All() []Approach {
	families := make([]string, 0, len(r.approaches))
	for family := range r.approaches {
		families = append(families, family)
	}
	sort.Strings(families)
	result := make([]Approach, 0, len(families))
	for _, family := range families {
		result = append(result, r.approaches[family])
	}
	return result
}
