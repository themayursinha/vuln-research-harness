// Package capability implements the executor admission gate. An executor
// must present explicit capability claims, and the gate fails closed unless
// every required capability is satisfied with stated evidence.
package capability

import (
	"fmt"
	"strings"
)

// Claim is a single capability assertion made by an executor.
type Claim struct {
	Name      string `json:"name"`
	Satisfied bool   `json:"satisfied"`
	Evidence  string `json:"evidence"`
}

// Gate defines the capabilities a campaign requires of any executor.
type Gate struct {
	required []string
}

// NewGate builds a gate with the given required capability names.
func NewGate(required ...string) *Gate {
	return &Gate{required: required}
}

// Report is the outcome of one gate verification.
type Report struct {
	Passed   bool     `json:"passed"`
	Verified []string `json:"verified"`
	Problems []string `json:"problems"`
}

// Verify checks the executor's claims against the required capabilities. It
// fails closed: a missing claim, an unsatisfied claim, or a claim without
// evidence is a problem. Unknown extra claims are allowed but recorded.
func (g *Gate) Verify(claims []Claim) Report {
	report := Report{Passed: true}
	index := make(map[string]Claim, len(claims))
	for _, claim := range claims {
		index[strings.TrimSpace(claim.Name)] = claim
	}
	for _, required := range g.required {
		claim, ok := index[required]
		switch {
		case !ok:
			report.Passed = false
			report.Problems = append(report.Problems, fmt.Sprintf("missing capability claim: %s", required))
		case !claim.Satisfied:
			report.Passed = false
			report.Problems = append(report.Problems, fmt.Sprintf("unsatisfied capability: %s", required))
		case strings.TrimSpace(claim.Evidence) == "":
			report.Passed = false
			report.Problems = append(report.Problems, fmt.Sprintf("capability %s has no evidence", required))
		default:
			report.Verified = append(report.Verified, required)
		}
	}
	return report
}
