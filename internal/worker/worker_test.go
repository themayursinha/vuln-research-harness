package worker

import "testing"

func TestResultValidation(t *testing.T) {
	if err := (Result{RequestID: "r1", Status: ResultFinding, Summary: "candidate found"}).Validate(); err == nil {
		t.Fatal("finding without findings unexpectedly valid")
	}
	if err := (Result{RequestID: "r1", Status: ResultBlocked, Summary: "stuck"}).Validate(); err == nil {
		t.Fatal("blocked result without reason unexpectedly valid")
	}
	if err := (Result{RequestID: "r1", Status: "invented", Summary: "x"}).Validate(); err == nil {
		t.Fatal("unknown status unexpectedly valid")
	}
	valid := Result{
		RequestID: "r1",
		Status:    ResultFinding,
		Summary:   "candidate desync",
		Findings: []Finding{{
			Title:         "validation mismatch",
			Hypothesis:    "arrays desynchronize on early continue",
			EvidencePaths: []string{"evidence/desync.md"},
		}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
}
