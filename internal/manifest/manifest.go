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
	"io/fs"
	"os"
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

	var files []FileDigest
	err = filepath.WalkDir(sourceDir, func(path string, entry fs.DirEntry, walkErr error) error {
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
		// Reject anything that is not a plain regular file. Symlinks are the
		// dangerous case: os.ReadFile would follow a link such as
		// ".env -> /home/user/.ssh/id_rsa" and bake data from outside the
		// source root into the manifest and archive. Devices, FIFOs and
		// sockets would hang or misbehave on read, so they are refused too.
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
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		files = append(files, FileDigest{
			Path:   filepath.ToSlash(rel),
			SHA256: digest(data),
			Size:   int64(len(data)),
		})
		return nil
	})
	if err != nil {
		return Manifest{}, fmt.Errorf("walk source: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

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

// Verify checks that sourceDir still hashes to the recorded per-file digests.
func (m Manifest) Verify(sourceDir string) error {
	for _, file := range m.Files {
		full := filepath.Join(sourceDir, filepath.FromSlash(file.Path))
		info, err := os.Lstat(full)
		if err != nil {
			return fmt.Errorf("source changed: %s: %w", file.Path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("source changed: %s is no longer a regular file", file.Path)
		}
		data, err := os.ReadFile(full)
		if err != nil {
			return fmt.Errorf("source changed: %s: %w", file.Path, err)
		}
		sum := digest(data)
		if sum != file.SHA256 {
			return fmt.Errorf("source changed: %s digest mismatch", file.Path)
		}
	}
	return nil
}
