package registry

import (
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	registry := New()
	if err := registry.Add("auth", "identity confusion"); err != nil {
		t.Fatal(err)
	}
	if err := registry.Block("auth", "no reachable path"); err != nil {
		t.Fatal(err)
	}
	if err := registry.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	approach, ok := loaded.Get("auth")
	if !ok || approach.Status != Blocked || approach.BlockReason != "no reachable path" {
		t.Fatalf("round trip lost state: %+v", approach)
	}
}

func TestRecordDispatchRequiresActiveFamily(t *testing.T) {
	registry := New()
	if err := registry.Add("cache", "poisoning"); err != nil {
		t.Fatal(err)
	}
	if err := registry.Block("cache", "exhausted"); err != nil {
		t.Fatal(err)
	}
	if err := registry.RecordDispatch("cache"); err == nil {
		t.Fatal("dispatch to blocked family unexpectedly accepted")
	}
	if err := registry.Reopen("cache", "new timing mechanism"); err != nil {
		t.Fatal(err)
	}
	if err := registry.RecordDispatch("cache"); err != nil {
		t.Fatal(err)
	}
	approach, _ := registry.Get("cache")
	if approach.Attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", approach.Attempts)
	}
}

func TestSaveIsAtomicAndNeverTruncates(t *testing.T) {
	dir := t.TempDir()
	registry := New()
	if err := registry.Add("auth", "identity confusion"); err != nil {
		t.Fatal(err)
	}
	if err := registry.Save(dir); err != nil {
		t.Fatal(err)
	}
	// A crash mid-write must never leave a truncated registry.json behind:
	// Save writes a temp file and renames it over the target.
	if _, err := Load(dir); err != nil {
		t.Fatalf("registry unreadable after save: %v", err)
	}
	if entries, err := filepath.Glob(filepath.Join(dir, ".registry.json.tmp")); err != nil || len(entries) != 0 {
		t.Fatalf("temp file left behind: %v %v", entries, err)
	}
}

func TestValidateFamilyNameRejectsTraversal(t *testing.T) {
	for _, bad := range []string{"../auth", "a/b", `a\b`, "..", ".", "auth--", "--auth", " auth"} {
		if err := ValidateFamilyName(bad); err == nil {
			t.Errorf("family %q unexpectedly accepted", bad)
		}
	}
	for _, good := range []string{"auth", "auth--oauth", "request-parsing", "parser.deep"} {
		if err := ValidateFamilyName(good); err != nil {
			t.Errorf("family %q unexpectedly rejected: %v", good, err)
		}
	}
}
