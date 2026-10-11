package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/themayursinha/vuln-research-harness/internal/codemap"
	"github.com/themayursinha/vuln-research-harness/internal/contract"
	"github.com/themayursinha/vuln-research-harness/internal/manifest"
)

func codemapIndexCmd(args []string) error {
	if len(args) != 1 {
		return errors.New("codemap index requires <campaign-dir>")
	}
	graph, source, err := freshGraph(args[0])
	if err != nil {
		return err
	}
	dest := filepath.Join(args[0], "codemap.json")
	if err := refuseInsideSource(dest, source); err != nil {
		return err
	}
	if err := graph.Save(dest); err != nil {
		return err
	}
	fmt.Printf("codemap indexed: %d functions, %d edges, %d non-source skipped, digest sha256:%s\n", len(graph.Functions), len(graph.Edges), graph.Skipped, graph.SnapshotSHA)
	fmt.Printf("wrote %s\n", dest)
	return nil
}

func codemapReachCmd(args []string) error {
	if len(args) != 2 {
		return errors.New("codemap reach requires <campaign-dir> <file#symbol>")
	}
	graph, _, _, err := loadMatchingGraph(args[0])
	if err != nil {
		return err
	}
	files, _, err := graph.Reachable(args[1])
	if err != nil {
		return err
	}
	for _, file := range files {
		fmt.Println(file)
	}
	return nil
}

func codemapSliceCmd(args []string) error {
	if len(args) != 2 && len(args) != 3 {
		return errors.New("codemap slice requires <campaign-dir> <file#symbol> [max-files]")
	}
	maxFiles := codemap.DefaultMaxFiles
	if len(args) == 3 {
		n, err := strconv.Atoi(args[2])
		if err != nil || n < 1 {
			return errors.New("max-files must be a positive integer")
		}
		maxFiles = n
	}
	dir := args[0]
	graph, source, mani, err := loadMatchingGraph(dir)
	if err != nil {
		return err
	}
	slice, err := graph.Slice(args[1], maxFiles)
	if err != nil {
		return err
	}
	if err := slice.Validate(mani.ArchiveSHA, manifestFiles(mani)); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(slice.Entry))
	dest := filepath.Join(dir, "codemap-slices", hex.EncodeToString(sum[:8])+".json")
	if err := refuseInsideSource(dest, source); err != nil {
		return err
	}
	if err := slice.Save(dest); err != nil {
		return err
	}
	data, err := json.MarshalIndent(slice, "", "  ")
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "codemap slice written: %s\n", dest)
	return nil
}

// sliceContext loads a slice and checks it is exactly the reachable set of the
// pinned snapshot. The returned lines are appended to each worker request.
func sliceContext(dir, path string) ([]string, error) {
	slice, err := codemap.LoadSlice(path)
	if err != nil {
		return nil, err
	}
	graph, _, mani, err := loadMatchingGraph(dir)
	if err != nil {
		return nil, err
	}
	if err := slice.Validate(mani.ArchiveSHA, manifestFiles(mani)); err != nil {
		return nil, fmt.Errorf("round plan slice: %w", err)
	}
	fresh, err := graph.Slice(slice.Entry, slice.MaxFiles)
	if err != nil {
		return nil, fmt.Errorf("round plan slice: %w", err)
	}
	if !codemap.SameSlice(fresh, slice) {
		return nil, errors.New("round plan slice: does not match reachability from the pinned snapshot")
	}
	return slice.ContextLines(), nil
}

func freshGraph(dir string) (codemap.Graph, string, error) {
	if err := requireAdmission(dir); err != nil {
		return codemap.Graph{}, "", err
	}
	camp, mani, err := loadAdmitted(dir)
	if err != nil {
		return codemap.Graph{}, "", err
	}
	rels := make([]string, len(mani.Files))
	for i, file := range mani.Files {
		rels[i] = file.Path
	}
	graph, err := codemap.Index(camp.Target.SourcePath, mani.ArchiveSHA, rels)
	if err != nil {
		return codemap.Graph{}, "", err
	}
	return graph, camp.Target.SourcePath, nil
}

func loadMatchingGraph(dir string) (codemap.Graph, string, manifest.Manifest, error) {
	graph, source, err := freshGraph(dir)
	if err != nil {
		return codemap.Graph{}, "", manifest.Manifest{}, err
	}
	saved, err := codemap.Load(filepath.Join(dir, "codemap.json"))
	if err != nil {
		return codemap.Graph{}, "", manifest.Manifest{}, fmt.Errorf("%w (run: vrh codemap index)", err)
	}
	want, err := graph.Canonical()
	if err != nil {
		return codemap.Graph{}, "", manifest.Manifest{}, err
	}
	got, err := saved.Canonical()
	if err != nil {
		return codemap.Graph{}, "", manifest.Manifest{}, err
	}
	if !bytes.Equal(want, got) {
		return codemap.Graph{}, "", manifest.Manifest{}, errors.New("codemap.json does not match the pinned source snapshot; run: vrh codemap index")
	}
	_, mani, err := loadAdmitted(dir)
	if err != nil {
		return codemap.Graph{}, "", manifest.Manifest{}, err
	}
	return graph, source, mani, nil
}

func loadAdmitted(dir string) (contract.Campaign, manifest.Manifest, error) {
	files := campaignFiles(dir)
	camp, err := contract.Load(files["contract"])
	if err != nil {
		return contract.Campaign{}, manifest.Manifest{}, err
	}
	mani, err := manifest.Load(files["manifest"])
	if err != nil {
		return contract.Campaign{}, manifest.Manifest{}, err
	}
	return camp, mani, nil
}

func manifestFiles(mani manifest.Manifest) map[string]struct{} {
	allowed := make(map[string]struct{}, len(mani.Files))
	for _, file := range mani.Files {
		allowed[file.Path] = struct{}{}
	}
	return allowed
}

func refuseInsideSource(dest, source string) error {
	destResolved, err := resolveExisting(dest)
	if err != nil {
		return err
	}
	sourceResolved, err := resolveExisting(source)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(sourceResolved, destResolved)
	if err != nil {
		return err
	}
	if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("refusing to write %s inside the pinned source tree", dest)
	}
	return nil
}

// resolveExisting resolves the longest prefix of path that exists. Symlinks
// on that prefix are expanded, so a campaign path that points into the pinned
// source tree is compared as the real destination. A dangling symlink is an
// error: writing through it would create the target.
func resolveExisting(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var missing []string
	cur := abs
	for {
		if _, err := os.Lstat(cur); err == nil {
			resolved, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return "", fmt.Errorf("resolve %s: %w", path, err)
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		missing = append(missing, filepath.Base(cur))
		cur = parent
	}
}
