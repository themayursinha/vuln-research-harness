// Package codemap indexes a pinned source snapshot into a queryable graph of
// functions and direct call edges. From an entry point it returns the
// reachable files, and from that a bounded slice a campaign round can hand
// to a worker.
//
// The graph is syntactic. Go functions and methods come from the parser.
// Python def statements and JavaScript or TypeScript function declarations
// are scanned directly. Ambiguous and unresolved calls are kept on the graph
// and are not treated as reachable. There is no type resolution and no taint.
package codemap

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	// LimitsNote is stored on every graph and slice. An altered note is rejected
	// so a file cannot claim a stronger analysis than this package performs.
	LimitsNote = "syntactic direct calls only (Go functions and methods, Python def, JavaScript/TypeScript function declarations); ambiguous or unresolved calls are not reachable; no types and no taint"

	// DefaultMaxFiles is the slice bound used when the caller does not set one.
	DefaultMaxFiles = 32

	// HardMaxFiles is the largest file set a slice may hand to a worker.
	HardMaxFiles = 128

	// ContextEntryPrefix marks the entry point in a worker request context.
	ContextEntryPrefix = "codemap-entry:"

	// ContextFilePrefix marks one file in a worker request context.
	ContextFilePrefix = "codemap-file:"

	maxIndexFileBytes = 1 << 20
)

// Function is one named function or method in the snapshot.
type Function struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Language string `json:"language"`
}

// Edge is a direct call. Resolved is false when the callee is missing or
// ambiguous; those edges do not extend reachability.
type Edge struct {
	From     string `json:"from"`
	To       string `json:"to,omitempty"`
	Call     string `json:"call"`
	Line     int    `json:"line"`
	Resolved bool   `json:"resolved"`
}

// Graph is the queryable index for one snapshot digest.
type Graph struct {
	SnapshotSHA string     `json:"snapshot_sha256"`
	Limits      string     `json:"limits"`
	Skipped     int        `json:"skipped_non_source"`
	Functions   []Function `json:"functions"`
	Edges       []Edge     `json:"edges"`
}

// Slice is the bounded file set a round can attach to a worker request.
type Slice struct {
	SnapshotSHA string   `json:"snapshot_sha256"`
	Entry       string   `json:"entry"`
	Files       []string `json:"files"`
	Functions   []string `json:"functions"`
	MaxFiles    int      `json:"max_files"`
	Limits      string   `json:"limits"`
}

// Index reads only rels under root. Paths outside root, symlinks, and files
// over the size cap are refused. snapshotSHA is the pinned archive digest.
func Index(root, snapshotSHA string, rels []string) (Graph, error) {
	if err := validSHA(snapshotSHA); err != nil {
		return Graph{}, err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return Graph{}, fmt.Errorf("source directory not found: %s", root)
	}
	rels, err = cleanRels(rels)
	if err != nil {
		return Graph{}, err
	}
	allowed := make(map[string]struct{}, len(rels))
	for _, rel := range rels {
		allowed[rel] = struct{}{}
	}

	b := newBuilder()
	skipped := 0
	for _, rel := range rels {
		full, err := absInside(root, rel)
		if err != nil {
			return Graph{}, err
		}
		if err := rejectSymlinkComponents(root, rel); err != nil {
			return Graph{}, err
		}
		fileInfo, err := os.Lstat(full)
		if err != nil {
			return Graph{}, fmt.Errorf("stat %s: %w", rel, err)
		}
		if !fileInfo.Mode().IsRegular() {
			return Graph{}, fmt.Errorf("refusing to index non-regular file: %s", rel)
		}
		if fileInfo.Size() > maxIndexFileBytes {
			return Graph{}, fmt.Errorf("refusing to index %s: size %d exceeds %d-byte limit", rel, fileInfo.Size(), maxIndexFileBytes)
		}
		lang := languageOf(rel)
		if lang == "" {
			skipped++
			continue
		}
		src, err := os.ReadFile(full)
		if err != nil {
			return Graph{}, fmt.Errorf("read %s: %w", rel, err)
		}
		if int64(len(src)) > maxIndexFileBytes {
			return Graph{}, fmt.Errorf("refusing to index %s: size %d exceeds %d-byte limit", rel, len(src), maxIndexFileBytes)
		}
		switch lang {
		case "go":
			err = indexGo(rel, src, b)
		default:
			err = indexText(rel, lang, src, allowed, b)
		}
		if err != nil {
			return Graph{}, err
		}
	}
	if err := b.linkImports(); err != nil {
		return Graph{}, err
	}
	b.resolve()
	graph := Graph{
		SnapshotSHA: snapshotSHA,
		Limits:      LimitsNote,
		Skipped:     skipped,
		Functions:   b.functions(),
		Edges:       b.edges,
	}
	graph = graph.normalized()
	if err := graph.validate(); err != nil {
		return Graph{}, err
	}
	return graph, nil
}

// Reachable returns the files and functions reachable from entry by resolved
// direct calls, including entry itself. The lists are sorted.
func (g Graph) Reachable(entry string) (files, functions []string, err error) {
	g = g.normalized()
	if err := g.validate(); err != nil {
		return nil, nil, err
	}
	byID := make(map[string]Function, len(g.Functions))
	for _, fn := range g.Functions {
		byID[fn.ID] = fn
	}
	if _, ok := byID[entry]; !ok {
		return nil, nil, fmt.Errorf("unknown entry %q", entry)
	}
	out := make(map[string][]string)
	for _, edge := range g.Edges {
		if edge.Resolved {
			out[edge.From] = append(out[edge.From], edge.To)
		}
	}
	seen := map[string]bool{entry: true}
	queue := []string{entry}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range out[cur] {
			if seen[next] {
				continue
			}
			seen[next] = true
			queue = append(queue, next)
		}
	}
	fileSet := make(map[string]struct{})
	for id := range seen {
		functions = append(functions, id)
		fileSet[byID[id].File] = struct{}{}
	}
	for file := range fileSet {
		files = append(files, file)
	}
	sort.Strings(files)
	sort.Strings(functions)
	return files, functions, nil
}

// Slice builds the worker handoff for entry. It fails closed when the
// reachable file set is larger than maxFiles instead of returning a partial set.
func (g Graph) Slice(entry string, maxFiles int) (Slice, error) {
	if maxFiles < 1 || maxFiles > HardMaxFiles {
		return Slice{}, fmt.Errorf("max-files must be between 1 and %d", HardMaxFiles)
	}
	files, fns, err := g.Reachable(entry)
	if err != nil {
		return Slice{}, err
	}
	if len(files) > maxFiles {
		return Slice{}, fmt.Errorf("reachable file set has %d files, bound is %d; narrow the entry point", len(files), maxFiles)
	}
	slice := Slice{
		SnapshotSHA: g.SnapshotSHA,
		Entry:       entry,
		Files:       files,
		Functions:   fns,
		MaxFiles:    maxFiles,
		Limits:      LimitsNote,
	}
	if err := slice.Validate(g.SnapshotSHA, fileSet(files)); err != nil {
		return Slice{}, err
	}
	return slice, nil
}

// ContextLines is the stable context block appended to a worker request.
func (s Slice) ContextLines() []string {
	lines := make([]string, 0, 1+len(s.Files))
	lines = append(lines, ContextEntryPrefix+s.Entry)
	for _, file := range s.Files {
		lines = append(lines, ContextFilePrefix+file)
	}
	return lines
}

// Validate checks the slice against the pinned digest and the snapshot file set.
func (s Slice) Validate(snapshotSHA string, allowed map[string]struct{}) error {
	if snapshotSHA != "" && s.SnapshotSHA != snapshotSHA {
		return fmt.Errorf("slice snapshot %s does not match pinned %s", s.SnapshotSHA, snapshotSHA)
	}
	if err := validSHA(s.SnapshotSHA); err != nil {
		return err
	}
	if s.Limits != LimitsNote {
		return errors.New("slice limits note is missing or was altered")
	}
	if strings.TrimSpace(s.Entry) == "" {
		return errors.New("slice entry is required")
	}
	if s.MaxFiles < 1 || s.MaxFiles > HardMaxFiles {
		return fmt.Errorf("slice max_files must be between 1 and %d", HardMaxFiles)
	}
	if len(s.Files) == 0 || len(s.Files) > s.MaxFiles {
		return errors.New("slice file set is empty or exceeds max_files")
	}
	if len(s.Functions) == 0 {
		return errors.New("slice functions are required")
	}
	entryFile, _, ok := strings.Cut(s.Entry, "#")
	if !ok || entryFile == "" {
		return fmt.Errorf("entry %q is not file#symbol", s.Entry)
	}
	files := map[string]struct{}{}
	for _, file := range s.Files {
		if !safeRel(file) {
			return fmt.Errorf("slice file %q is not a snapshot path", file)
		}
		if _, ok := allowed[file]; !ok {
			return fmt.Errorf("slice file %s is not in the pinned snapshot", file)
		}
		if _, dup := files[file]; dup {
			return fmt.Errorf("duplicate slice file %s", file)
		}
		files[file] = struct{}{}
	}
	if _, ok := files[entryFile]; !ok {
		return fmt.Errorf("slice entry file %s is not in the file set", entryFile)
	}
	seenFn := map[string]struct{}{}
	for _, id := range s.Functions {
		file, _, ok := strings.Cut(id, "#")
		if !ok || !safeRel(file) {
			return fmt.Errorf("slice function %q is not file#symbol", id)
		}
		if _, ok := files[file]; !ok {
			return fmt.Errorf("slice function %s is outside the file set", id)
		}
		if _, dup := seenFn[id]; dup {
			return fmt.Errorf("duplicate slice function %s", id)
		}
		seenFn[id] = struct{}{}
	}
	if _, ok := seenFn[s.Entry]; !ok {
		return fmt.Errorf("slice entry %s is not in the function set", s.Entry)
	}
	return nil
}

// Canonical is the deterministic encoding used to detect a stale codemap.json.
func (g Graph) Canonical() ([]byte, error) {
	g = g.normalized()
	if err := g.validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Save writes the graph atomically.
func (g Graph) Save(path string) error {
	data, err := g.Canonical()
	if err != nil {
		return err
	}
	return writeAtomic(path, data)
}

// Save writes the slice atomically.
func (s Slice) Save(path string) error {
	if err := s.Validate(s.SnapshotSHA, fileSet(s.Files)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeAtomic(path, data)
}

// Load reads a graph written by Save.
func Load(path string) (Graph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Graph{}, fmt.Errorf("read codemap: %w", err)
	}
	var graph Graph
	if err := json.Unmarshal(data, &graph); err != nil {
		return Graph{}, fmt.Errorf("parse codemap: %w", err)
	}
	graph = graph.normalized()
	if err := graph.validate(); err != nil {
		return Graph{}, err
	}
	return graph, nil
}

// LoadSlice reads a slice written by Save.
func LoadSlice(path string) (Slice, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Slice{}, fmt.Errorf("read slice: %w", err)
	}
	var slice Slice
	if err := json.Unmarshal(data, &slice); err != nil {
		return Slice{}, fmt.Errorf("parse slice: %w", err)
	}
	sort.Strings(slice.Files)
	sort.Strings(slice.Functions)
	if slice.Files == nil {
		slice.Files = []string{}
	}
	if slice.Functions == nil {
		slice.Functions = []string{}
	}
	if err := slice.Validate(slice.SnapshotSHA, fileSet(slice.Files)); err != nil {
		return Slice{}, err
	}
	return slice, nil
}

// SameSlice reports whether both slices describe the same handoff.
func SameSlice(a, b Slice) bool {
	if a.SnapshotSHA != b.SnapshotSHA || a.Entry != b.Entry || a.MaxFiles != b.MaxFiles || a.Limits != b.Limits {
		return false
	}
	return stringListEqual(a.Files, b.Files) && stringListEqual(a.Functions, b.Functions)
}

func (g Graph) normalized() Graph {
	if g.Functions == nil {
		g.Functions = []Function{}
	}
	if g.Edges == nil {
		g.Edges = []Edge{}
	}
	sort.Slice(g.Functions, func(i, j int) bool {
		return g.Functions[i].ID < g.Functions[j].ID
	})
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		if g.Edges[i].Line != g.Edges[j].Line {
			return g.Edges[i].Line < g.Edges[j].Line
		}
		if g.Edges[i].Call != g.Edges[j].Call {
			return g.Edges[i].Call < g.Edges[j].Call
		}
		if g.Edges[i].To != g.Edges[j].To {
			return g.Edges[i].To < g.Edges[j].To
		}
		return !g.Edges[i].Resolved && g.Edges[j].Resolved
	})
	return g
}

func (g Graph) validate() error {
	if err := validSHA(g.SnapshotSHA); err != nil {
		return err
	}
	if g.Limits != LimitsNote {
		return errors.New("codemap limits note is missing or was altered")
	}
	if g.Skipped < 0 {
		return errors.New("codemap skipped count is invalid")
	}
	seen := make(map[string]Function, len(g.Functions))
	for _, fn := range g.Functions {
		if fn.ID == "" || fn.Name == "" || fn.Line < 1 {
			return fmt.Errorf("codemap function %q is incomplete", fn.ID)
		}
		if !safeRel(fn.File) {
			return fmt.Errorf("codemap function file %q is not a snapshot path", fn.File)
		}
		file, symbol, ok := strings.Cut(fn.ID, "#")
		if !ok || file != fn.File || symbol == "" {
			return fmt.Errorf("codemap function id %q does not match its file", fn.ID)
		}
		switch fn.Language {
		case "go", "python", "typescript", "javascript":
		default:
			return fmt.Errorf("codemap function %s has unknown language %q", fn.ID, fn.Language)
		}
		if _, dup := seen[fn.ID]; dup {
			return fmt.Errorf("duplicate function %s", fn.ID)
		}
		seen[fn.ID] = fn
	}
	for _, edge := range g.Edges {
		if _, ok := seen[edge.From]; !ok {
			return fmt.Errorf("edge from unknown function %s", edge.From)
		}
		if strings.TrimSpace(edge.Call) == "" || edge.Line < 1 {
			return fmt.Errorf("edge from %s is incomplete", edge.From)
		}
		if edge.Resolved {
			if _, ok := seen[edge.To]; !ok {
				return fmt.Errorf("resolved edge %s -> %s has no function", edge.From, edge.To)
			}
		} else if edge.To != "" {
			return fmt.Errorf("unresolved edge %s must not name a target", edge.From)
		}
	}
	return nil
}

func fileSet(files []string) map[string]struct{} {
	set := make(map[string]struct{}, len(files))
	for _, file := range files {
		set[file] = struct{}{}
	}
	return set
}

func stringListEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validSHA(sum string) error {
	if len(sum) != 64 {
		return fmt.Errorf("snapshot digest must be 64 hex characters")
	}
	for _, c := range sum {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("snapshot digest must be lowercase hex")
		}
	}
	return nil
}

func languageOf(rel string) string {
	switch strings.ToLower(path.Ext(rel)) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".ts", ".tsx":
		return "typescript"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	default:
		return ""
	}
}

func cleanRels(rels []string) ([]string, error) {
	seen := make(map[string]struct{}, len(rels))
	out := make([]string, 0, len(rels))
	for _, rel := range rels {
		if path.Clean(rel) != rel || !safeRel(rel) {
			return nil, fmt.Errorf("refusing unsafe path %q", rel)
		}
		if _, ok := seen[rel]; ok {
			continue
		}
		seen[rel] = struct{}{}
		out = append(out, rel)
	}
	sort.Strings(out)
	return out, nil
}

func safeRel(rel string) bool {
	if rel == "" || rel == "." || rel == ".." || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "../") {
		return false
	}
	if strings.Contains(rel, "\\") || strings.Contains(rel, ":") || strings.Contains(rel, "#") || strings.ContainsRune(rel, 0) {
		return false
	}
	if path.Clean(rel) != rel {
		return false
	}
	return utf8.ValidString(rel)
}

func absInside(root, rel string) (string, error) {
	if !safeRel(rel) {
		return "", fmt.Errorf("refusing unsafe path %q", rel)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	full := filepath.Join(rootAbs, filepath.FromSlash(rel))
	back, err := filepath.Rel(rootAbs, full)
	if err != nil {
		return "", err
	}
	if back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing path outside snapshot: %s", rel)
	}
	return full, nil
}

func rejectSymlinkComponents(root, rel string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	cur := rootAbs
	for _, part := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("stat %s: %w", rel, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to index symlink: %s", rel)
		}
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}
