package capability

import "testing"

func TestGateFailsClosedOnMissingOrWeakClaims(t *testing.T) {
	gate := NewGate("no_network", "no_real_credentials", "disposable_environment")

	report := gate.Verify([]Claim{
		{Name: "no_network", Satisfied: true, Evidence: "network namespace without routes"},
	})
	if report.Passed {
		t.Fatal("gate passed with missing claims")
	}
	if len(report.Problems) != 2 {
		t.Fatalf("expected 2 problems, got %v", report.Problems)
	}

	report = gate.Verify([]Claim{
		{Name: "no_network", Satisfied: true, Evidence: ""},
		{Name: "no_real_credentials", Satisfied: false, Evidence: "none"},
		{Name: "disposable_environment", Satisfied: true, Evidence: "tmpfs"},
	})
	if report.Passed {
		t.Fatal("gate passed with evidenceless and unsatisfied claims")
	}
}

func TestGatePassesWithCompleteClaims(t *testing.T) {
	gate := NewGate("no_network", "synthetic_data")
	report := gate.Verify([]Claim{
		{Name: "no_network", Satisfied: true, Evidence: "unshare net"},
		{Name: "synthetic_data", Satisfied: true, Evidence: "fixture db"},
		{Name: "extra_capability", Satisfied: true, Evidence: "not required"},
	})
	if !report.Passed || len(report.Verified) != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
}
