package registry

import "testing"

func TestBlockedApproachRequiresNewMechanism(t *testing.T) {
	registry := New()
	if err := registry.Add("parser", "alternate framing"); err != nil {
		t.Fatal(err)
	}
	if err := registry.Block("parser", "no reachable mismatch"); err != nil {
		t.Fatal(err)
	}
	if err := registry.Reopen("parser", "alternate framing"); err == nil {
		t.Fatal("blocked approach reopened without a new mechanism")
	}
	if err := registry.Reopen("parser", "nested parser state transition"); err != nil {
		t.Fatal(err)
	}
	approach, ok := registry.Get("parser")
	if !ok || approach.Status != Active || approach.Attempts != 2 {
		t.Fatalf("unexpected approach after reopen: %+v", approach)
	}
}

func TestRegistryRejectsDuplicateFamily(t *testing.T) {
	registry := New()
	if err := registry.Add("auth", "identity confusion"); err != nil {
		t.Fatal(err)
	}
	if err := registry.Add("auth", "another idea"); err == nil {
		t.Fatal("duplicate family accepted")
	}
}
