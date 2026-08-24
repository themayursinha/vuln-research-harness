// Package worker defines the structured request and result schema exchanged
// between the coordinator and research workers. Workers never execute target
// code directly; requests are executed through an executor.
package worker

import (
	"fmt"
	"path/filepath"
	"strings"
)

type RequestStatus string

const (
	ResultProgress RequestStatus = "progress"
	ResultBlocked  RequestStatus = "blocked"
	ResultFinding  RequestStatus = "finding"
	ResultRefuted  RequestStatus = "refuted"
)

// Request is one research assignment to a worker or worker lane.
type Request struct {
	ID          string   `json:"id"`
	Round       int      `json:"round"`
	Family      string   `json:"family"`
	Goal        string   `json:"goal"`
	Context     []string `json:"context,omitempty"`
	MaxSteps    int      `json:"max_steps,omitempty"`
	CreatedFrom string   `json:"created_from,omitempty"`
}

// Finding is a candidate security property the worker wants validated.
type Finding struct {
	Title         string   `json:"title"`
	Hypothesis    string   `json:"hypothesis"`
	CodePaths     []string `json:"code_paths"`
	EvidencePaths []string `json:"evidence_paths"`
}

// Result is the worker's structured answer for one request.
type Result struct {
	RequestID   string        `json:"request_id"`
	Status      RequestStatus `json:"status"`
	Summary     string        `json:"summary"`
	BlockReason string        `json:"block_reason,omitempty"`
	Findings    []Finding     `json:"findings,omitempty"`
}

func (r Request) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("request id is required")
	}
	if r.Round < 1 {
		return fmt.Errorf("request round must be >= 1")
	}
	if strings.TrimSpace(r.Family) == "" {
		return fmt.Errorf("request family is required")
	}
	if strings.TrimSpace(r.Goal) == "" {
		return fmt.Errorf("request goal is required")
	}
	// The ID becomes an envelope filename under inbox/requests/ and the family
	// feeds that ID, so both must be safe path components.
	if err := validateSafeID(r.ID); err != nil {
		return fmt.Errorf("request id: %w", err)
	}
	if err := validateSafeID(r.Family); err != nil {
		return fmt.Errorf("request family: %w", err)
	}
	return nil
}

// validateSafeID ensures an identifier can be used as a single filename
// component. Request IDs become envelope filenames under inbox/requests/, so
// a family like "../auth" must never be allowed to escape that directory.
func validateSafeID(id string) error {
	if id == "." || id == ".." {
		return fmt.Errorf("%q is not a safe identifier", id)
	}
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, string(filepath.Separator)) {
		return fmt.Errorf("%q must not contain path separators", id)
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return fmt.Errorf("%q contains character %q; use letters, digits, '-', '_' or '.'", id, r)
		}
	}
	return nil
}

func (r Result) Validate() error {
	if strings.TrimSpace(r.RequestID) == "" {
		return fmt.Errorf("result request_id is required")
	}
	switch r.Status {
	case ResultProgress, ResultBlocked, ResultFinding, ResultRefuted:
	default:
		return fmt.Errorf("unknown result status %q", r.Status)
	}
	if strings.TrimSpace(r.Summary) == "" {
		return fmt.Errorf("result summary is required")
	}
	if r.Status == ResultBlocked && strings.TrimSpace(r.BlockReason) == "" {
		return fmt.Errorf("blocked result requires block_reason")
	}
	for i, finding := range r.Findings {
		if strings.TrimSpace(finding.Title) == "" || strings.TrimSpace(finding.Hypothesis) == "" {
			return fmt.Errorf("finding %d needs title and hypothesis", i+1)
		}
		if len(finding.EvidencePaths) == 0 {
			return fmt.Errorf("finding %q needs evidence paths", finding.Title)
		}
	}
	if r.Status == ResultFinding && len(r.Findings) == 0 {
		return fmt.Errorf("finding result needs at least one finding")
	}
	return nil
}
