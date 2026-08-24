package registry

import (
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
