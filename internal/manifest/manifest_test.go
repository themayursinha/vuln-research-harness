package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(filepath.Join(path, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, name), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "sub", "file.txt"), []byte("nested"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSnapshotIsDeterministicAndVerifies(t *testing.T) {
	src := writeFixture(t, "main.go", "package main")
	out := t.TempDir()

	first, err := Snapshot(src, out)
	if err != nil {
		t.Fatal(err)
	}
	if first.ArchiveSHA == "" || first.FileCount != 2 {
		t.Fatalf("unexpected manifest: %+v", first)
	}

	second, err := Snapshot(src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if first.ArchiveSHA != second.ArchiveSHA {
		t.Fatalf("snapshot digest not deterministic: %s vs %s", first.ArchiveSHA, second.ArchiveSHA)
	}

	if err := first.Verify(src); err != nil {
		t.Fatalf("clean source failed verification: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := first.Verify(src); err == nil {
		t.Fatal("modified source unexpectedly verified")
	}
}

func TestSnapshotSkipsGitAndIgnores(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".git", "HEAD"), []byte("ref"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte("package main"), 0600); err != nil {
		t.Fatal(err)
	}

	manifest, err := Snapshot(src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if manifest.FileCount != 1 || manifest.Files[0].Path != "main.go" {
		t.Fatalf(".git was not excluded: %+v", manifest.Files)
	}
}

func TestLoadRejectsIncompleteManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{"target":"x"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("incomplete manifest unexpectedly loaded")
	}
}

func TestSnapshotRejectsSymlinks(t *testing.T) {
	src := t.TempDir()
	secret := filepath.Join(t.TempDir(), "outside-secret.txt")
	if err := os.WriteFile(secret, []byte("sensitive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte("package main"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(src, ".env")); err != nil {
		t.Fatal(err)
	}
	if _, err := Snapshot(src, t.TempDir()); err == nil {
		t.Fatal("snapshot followed a symlink instead of rejecting it")
	}
}

func TestVerifyDetectsAddedFiles(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte("package main"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := Snapshot(src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "extra.go"), []byte("package main"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(src); err == nil {
		t.Fatal("verify accepted a file added after the snapshot")
	}
}

func TestVerifyRejectsNonRegularFiles(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte("package main"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := Snapshot(src, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(src, "main.go")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(src, "main.go")); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(src); err == nil {
		t.Fatal("verify accepted a symlink replacement")
	}
}

func TestExtractRoundTrip(t *testing.T) {
	src := writeFixture(t, "main.go", "package main")
	out := t.TempDir()
	m, err := Snapshot(src, out)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "snap")
	if err := os.MkdirAll(dest, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.Extract(filepath.Join(out, "source.tar.gz"), dest); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(dest); err != nil {
		t.Fatalf("extracted tree failed verify: %v", err)
	}
	t.Cleanup(func() { _ = RemoveReadOnly(dest) })
}
