package ledger

import (
	"os"
	"testing"
)

func TestAppendAndReopen(t *testing.T) {
	path := t.TempDir() + "/evidence.jsonl"
	ledger, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ledger.Append("h1", "hypothesis", map[string]string{"family": "parser"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Hash == "" || first.PrevHash != "" {
		t.Fatalf("unexpected first event: %+v", first)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	ledger, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	second, err := ledger.Append("h2", "reproduction", map[string]string{"result": "pass"})
	if err != nil {
		t.Fatal(err)
	}
	if second.PrevHash != first.Hash {
		t.Fatalf("chain did not continue: got %q want %q", second.PrevHash, first.Hash)
	}
}

func TestOpenRejectsTamperedLedger(t *testing.T) {
	path := t.TempDir() + "/evidence.jsonl"
	ledger, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Append("h1", "hypothesis", nil); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-3] = 'x'
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("tampered ledger unexpectedly opened")
	}
}
