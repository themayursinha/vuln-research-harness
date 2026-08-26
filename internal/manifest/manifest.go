// Package manifest pins a campaign's source snapshot to a content digest so
// findings can be reproduced from the exact same tree.
package manifest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Manifest records the target snapshot a campaign runs against.
type Manifest struct {
	Target     string       `json:"target"`
	CreatedAt  time.Time    `json:"created_at"`
	ArchiveSHA string       `json:"archive_sha256"`
	FileCount  int          `json:"file_count"`
	Files      []FileDigest `json:"files"`
}

type FileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

const maxSnapshotFileBytes int64 = 256 << 20

// Snapshot walks sourceDir deterministically and writes a manifest plus a
// normalized tar.gz archive into outDir. The archive digest is the
// source_snapshot value for the campaign contract.
func Snapshot(sourceDir, outDir string) (Manifest, error) {
	info, err := os.Stat(sourceDir)
	if err != nil || !info.IsDir() {
		return Manifest{}, fmt.Errorf("source directory not found: %s", sourceDir)
	}
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return Manifest{}, fmt.Errorf("create campaign dir: %w", err)
	}

	rels, err := walkRegularFiles(sourceDir)
	if err != nil {
		return Manifest{}, err
	}
	files := make([]FileDigest, 0, len(rels))
	for _, rel := range rels {
		data, err := os.ReadFile(filepath.Join(sourceDir, filepath.FromSlash(rel)))
		if err != nil {
			return Manifest{}, fmt.Errorf("read %s: %w", rel, err)
		}
		files = append(files, FileDigest{
			Path:   rel,
			SHA256: digest(data),
			Size:   int64(len(data)),
		})
	}

	archive, err := normalizedArchive(sourceDir, files)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{
		Target:     filepath.Base(sourceDir),
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
		ArchiveSHA: digest(archive),
		FileCount:  len(files),
		Files:      files,
	}
	manifestPath := filepath.Join(outDir, "manifest.json")
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(manifestPath, data, 0600); err != nil {
		return Manifest{}, fmt.Errorf("write manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "source.tar.gz"), archive, 0600); err != nil {
		return Manifest{}, fmt.Errorf("write archive: %w", err)
	}
	return manifest, nil
}

// walkRegularFiles returns the slash-separated relative paths of every plain
// regular file under sourceDir, applying the snapshot exclusions. It refuses
// non-regular entries (symlinks, devices, FIFOs, sockets) so a link such as
// ".env -> /home/user/.ssh/id_rsa" can never be read into a snapshot, and so
// entries added later are detected by Verify.
func walkRegularFiles(sourceDir string) ([]string, error) {
	var rels []string
	err := filepath.WalkDir(sourceDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || name == ".worktrees" || name == "node_modules" || name == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&fs.ModeType != 0 {
			rel, relErr := filepath.Rel(sourceDir, path)
			if relErr != nil {
				rel = path
			}
			return fmt.Errorf("refusing to snapshot non-regular file: %s", rel)
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", rel, err)
		}
		if info.Size() > maxSnapshotFileBytes {
			return fmt.Errorf("refusing to snapshot %s: size %d exceeds %d-byte limit", rel, info.Size(), maxSnapshotFileBytes)
		}
		rels = append(rels, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk source: %w", err)
	}
	sort.Strings(rels)
	return rels, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func normalizedArchive(sourceDir string, files []FileDigest) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.ModTime = time.Unix(0, 0)
	tw := tar.NewWriter(gz)
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(sourceDir, filepath.FromSlash(file.Path)))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", file.Path, err)
		}
		header := &tar.Header{
			Name:     file.Path,
			Size:     int64(len(data)),
			Mode:     0644,
			ModTime:  time.Unix(0, 0),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Load reads and validates a manifest file.
func Load(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if strings.TrimSpace(manifest.Target) == "" || strings.TrimSpace(manifest.ArchiveSHA) == "" || manifest.FileCount == 0 {
		return Manifest{}, fmt.Errorf("manifest is incomplete")
	}
	if manifest.FileCount != len(manifest.Files) {
		return Manifest{}, fmt.Errorf("manifest file count mismatch: header says %d, entries list %d", manifest.FileCount, len(manifest.Files))
	}
	return manifest, nil
}

// Verify checks that sourceDir still matches the recorded snapshot exactly:
// every recorded file must still be a regular file with the recorded digest,
// no file may have been added or removed, and the normalized archive rebuilt
// from the tree must hash to the recorded archive digest. The archive check
// closes the gap where manifest.json and the source are modified together:
// per-file digests alone would then pass while the pinned snapshot digest in
// the campaign contract no longer describes what workers actually see.
func (m Manifest) Verify(sourceDir string) error {
	current, err := walkRegularFiles(sourceDir)
	if err != nil {
		return fmt.Errorf("source changed: %w", err)
	}
	recorded := make(map[string]FileDigest, len(m.Files))
	for _, file := range m.Files {
		recorded[file.Path] = file
	}
	currentSet := make(map[string]bool, len(current))
	for _, rel := range current {
		currentSet[rel] = true
		file, ok := recorded[rel]
		if !ok {
			return fmt.Errorf("source changed: %s added after snapshot", rel)
		}
		full := filepath.Join(sourceDir, filepath.FromSlash(rel))
		data, err := os.ReadFile(full)
		if err != nil {
			return fmt.Errorf("source changed: %s: %w", rel, err)
		}
		if sum := digest(data); sum != file.SHA256 {
			return fmt.Errorf("source changed: %s digest mismatch", rel)
		}
	}
	for rel := range recorded {
		if !currentSet[rel] {
			return fmt.Errorf("source changed: %s removed after snapshot", rel)
		}
	}
	files := make([]FileDigest, 0, len(current))
	for _, rel := range current {
		data, err := os.ReadFile(filepath.Join(sourceDir, filepath.FromSlash(rel)))
		if err != nil {
			return fmt.Errorf("source changed: %s: %w", rel, err)
		}
		files = append(files, FileDigest{Path: rel, SHA256: digest(data), Size: int64(len(data))})
	}
	archive, err := normalizedArchive(sourceDir, files)
	if err != nil {
		return fmt.Errorf("source changed: rebuild archive: %w", err)
	}
	if rebuilt := digest(archive); rebuilt != m.ArchiveSHA {
		return fmt.Errorf("source changed: rebuilt archive digest %s does not match pinned %s", rebuilt, m.ArchiveSHA)
	}
	return nil
}

// Extract unpacks the pinned archive into dest after checking its digest,
// refusing non-regular entries and path traversal. dest is then verified
// against the manifest so a reproduction never sees a different tree than
// the one the campaign contract pinned.
func (m Manifest) Extract(archivePath, dest string) error {
	data, err := os.ReadFile(archivePath)
	if err != nil {
		return fmt.Errorf("read archive: %w", err)
	}
	if got := digest(data); got != m.ArchiveSHA {
		return fmt.Errorf("archive digest %s does not match pinned %s", got, m.ArchiveSHA)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read archive entry: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("refusing non-regular archive entry: %s", hdr.Name)
		}
		rel, err := safeArchivePath(hdr.Name)
		if err != nil {
			return err
		}
		full := filepath.Join(dest, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			return fmt.Errorf("extract %s: %w", rel, err)
		}
		file, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0444)
		if err != nil {
			return fmt.Errorf("extract %s: %w", rel, err)
		}
		if hdr.Size < 0 || hdr.Size > maxSnapshotFileBytes {
			return fmt.Errorf("extract %s: size %d exceeds %d-byte limit", rel, hdr.Size, maxSnapshotFileBytes)
		}
		if _, err := io.CopyN(file, tr, hdr.Size); err != nil {
			file.Close()
			return fmt.Errorf("extract %s: %w", rel, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("extract %s: %w", rel, err)
		}
	}
	if err := m.Verify(dest); err != nil {
		return fmt.Errorf("extracted snapshot does not match manifest: %w", err)
	}
	if err := makeReadOnly(dest); err != nil {
		return fmt.Errorf("lock extracted snapshot: %w", err)
	}
	return nil
}

// RemoveReadOnly restores write bits then deletes a tree produced by Extract.
func RemoveReadOnly(dir string) error {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		mode := os.FileMode(0700)
		if !d.IsDir() {
			mode = 0600
		}
		_ = os.Chmod(p, mode)
		return nil
	})
	return os.RemoveAll(dir)
}

func makeReadOnly(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p, 0555)
		}
		return os.Chmod(p, 0444)
	})
}

func safeArchivePath(name string) (string, error) {
	cleaned := path.Clean("/" + strings.TrimPrefix(filepath.ToSlash(name), "/"))
	rel := strings.TrimPrefix(cleaned, "/")
	if rel == "" || rel == "." || strings.HasPrefix(rel, "../") || strings.Contains(rel, ":") {
		return "", fmt.Errorf("refusing unsafe archive path: %s", name)
	}
	return rel, nil
}
