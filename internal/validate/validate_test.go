package validate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpheldWhenNoAttemptBreaksIt(t *testing.T) {
	b := NewBuilder("F1")
	b.Attempt("compensating control", "a second layer catches it", "none found", false)
	report, err := b.Finalize("stands")
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != Upheld {
		t.Fatalf("expected upheld, got %s", report.Verdict)
	}
}

func TestRefutedWhenAnyAttemptBreaksIt(t *testing.T) {
	b := NewBuilder("F2")
	b.Attempt("first try", "x", "failed", false)
	b.Attempt("second try", "y", "compensating control exists", true)
	report, err := b.Finalize("refuted by control")
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != Refuted {
		t.Fatalf("expected refuted, got %s", report.Verdict)
	}
}

func TestFinalizeRejectsAttemptlessReport(t *testing.T) {
	if _, err := NewBuilder("F3").Finalize("nothing"); err == nil {
		t.Fatal("attemptless report accepted")
	}
}

func TestFinalizeRejectsEmptyAttempt(t *testing.T) {
	b := NewBuilder("F-empty")
	b.Attempt("", "", "", false)
	if _, err := b.Finalize("rubber stamp"); err == nil {
		t.Fatal("empty disproof attempt accepted as upheld")
	}
}

func TestSeverityNoteSurvivesExport(t *testing.T) {
	b := NewBuilder("F4")
	b.Attempt("check", "h", "r", false).SeverityNote("not RCE; exposure only")
	report, err := b.Finalize("ok")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "not RCE") {
		t.Fatal("severity note lost in export")
	}
	tmp := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		t.Fatal(err)
	}
}
