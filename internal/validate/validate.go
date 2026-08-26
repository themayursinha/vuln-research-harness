// Package validate implements the independent adversarial validator lane:
// given a confirmed finding, it records structured attempts to DISPROVE it
// and computes a verdict from whether the finding survived.
package validate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Verdict is the adversarial lane's conclusion about one finding.
type Verdict string

const (
	Upheld  Verdict = "upheld"  // disproof attempts failed; finding stands
	Refuted Verdict = "refuted" // a disproof attempt succeeded
)

// DisproofAttempt records one attempt to break the finding.
type DisproofAttempt struct {
	Name       string `json:"name"`
	Hypothesis string `json:"hypothesis"` // what would refute the finding
	Result     string `json:"result"`     // what actually happened
	BrokeIt    bool   `json:"broke_it"`
}

// Report is the full validation record for one finding.
type Report struct {
	FindingID    string            `json:"finding_id"`
	Verdict      Verdict           `json:"verdict"`
	Attempts     []DisproofAttempt `json:"attempts"`
	Summary      string            `json:"summary"`
	SeverityNote string            `json:"severity_note,omitempty"`
}

// Builder accumulates disproof attempts for one finding.
type Builder struct {
	report Report
}

// NewBuilder starts a validation report for a finding.
func NewBuilder(findingID string) *Builder {
	return &Builder{report: Report{FindingID: strings.TrimSpace(findingID)}}
}

// Attempt records one disproof attempt. brokeIt=true means the finding did
// NOT survive this attempt (e.g. a compensating control exists).
func (b *Builder) Attempt(name, hypothesis, result string, brokeIt bool) *Builder {
	b.report.Attempts = append(b.report.Attempts, DisproofAttempt{
		Name: name, Hypothesis: hypothesis, Result: result, BrokeIt: brokeIt,
	})
	return b
}

// SeverityNote records an explicit severity framing requirement (e.g.
// "not RCE — sensitive-data exposure only").
func (b *Builder) SeverityNote(note string) *Builder {
	b.report.SeverityNote = strings.TrimSpace(note)
	return b
}

// ParseAttempts decodes a JSON array of disproof attempts. broke_it must be
// present on every object; a missing field must not silently become false.
func ParseAttempts(data []byte) ([]DisproofAttempt, error) {
	var raw []struct {
		Name       string `json:"name"`
		Hypothesis string `json:"hypothesis"`
		Result     string `json:"result"`
		BrokeIt    *bool  `json:"broke_it"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse attempts: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("parse attempts: trailing JSON after attempts array")
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("no disproof attempts")
	}
	attempts := make([]DisproofAttempt, 0, len(raw))
	for i, item := range raw {
		if item.BrokeIt == nil {
			return nil, fmt.Errorf("attempt %d omitted broke_it", i+1)
		}
		attempts = append(attempts, DisproofAttempt{
			Name: item.Name, Hypothesis: item.Hypothesis, Result: item.Result, BrokeIt: *item.BrokeIt,
		})
	}
	return attempts, nil
}

// Finalize computes the verdict: upheld only when every attempt failed to
// break the finding AND at least one attempt was made.
func (b *Builder) Finalize(summary string) (Report, error) {
	if strings.TrimSpace(b.report.FindingID) == "" {
		return Report{}, fmt.Errorf("finding id is required; refusing to export an unattributed validation report")
	}
	if len(b.report.Attempts) == 0 {
		return Report{}, fmt.Errorf("finding %s has no disproof attempts; cannot validate", b.report.FindingID)
	}
	for i, attempt := range b.report.Attempts {
		if strings.TrimSpace(attempt.Name) == "" || strings.TrimSpace(attempt.Hypothesis) == "" || strings.TrimSpace(attempt.Result) == "" {
			return Report{}, fmt.Errorf("finding %s attempt %d is incomplete: name, hypothesis, and result are required", b.report.FindingID, i+1)
		}
	}
	for _, attempt := range b.report.Attempts {
		if attempt.BrokeIt {
			b.report.Verdict = Refuted
			b.report.Summary = summary
			return b.report, nil
		}
	}
	b.report.Verdict = Upheld
	b.report.Summary = summary
	return b.report, nil
}
