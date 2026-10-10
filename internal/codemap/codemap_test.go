package codemap

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const testSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestSynthFixtureReachability(t *testing.T) {
	cases := []struct {
		root  string
		entry string
		files []string
		funcs []string
		edges []string
		names []string
	}{
		{
			root:  "testdata/synth/go",
			entry: "cmd/main.go#main",
			files: []string{"auth/auth.go", "cmd/main.go"},
			funcs: []string{
				"auth/auth.go#Check",
				"auth/auth.go#Gate.Allow",
				"auth/auth.go#normalize",
				"cmd/main.go#input",
				"cmd/main.go#main",
			},
			edges: []string{
				"auth/auth.go#Check -> auth/auth.go#Gate.Allow [g.Allow]",
				"auth/auth.go#Gate.Allow -> auth/auth.go#normalize [normalize]",
				"cmd/main.go#main -> auth/auth.go#Check [auth.Check]",
				"cmd/main.go#main -> cmd/main.go#input [input]",
				"other/other.go#Unused -> other/other.go#helper [helper]",
			},
			names: []string{
				"cmd/main.go#main",
				"cmd/main.go#input",
				"auth/auth.go#Check",
				"auth/auth.go#Gate.Allow",
				"auth/auth.go#normalize",
				"other/other.go#Unused",
				"other/other.go#helper",
			},
		},
		{
			root:  "testdata/synth/py",
			entry: "app.py#read_public",
			files: []string{"app.py", "path_utils.py"},
			funcs: []string{"app.py#read_public", "path_utils.py#join_public"},
			edges: []string{
				"app.py#local_only -> app.py#read_public [read_public]",
				"app.py#read_public -> path_utils.py#join_public [join_public]",
			},
			names: []string{
				"app.py#read_public",
				"app.py#local_only",
				"path_utils.py#join_public",
				"unused.py#join_public",
				"unused.py#other",
			},
		},
		{
			root:  "testdata/synth/ts",
			entry: "lib.ts#setAllowed",
			files: []string{"lib.ts", "path-utils.ts"},
			funcs: []string{"lib.ts#setAllowed", "path-utils.ts#normalizePath"},
			edges: []string{
				"lib.ts#setAllowed -> path-utils.ts#normalizePath [normalizePath]",
			},
			names: []string{
				"lib.ts#setAllowed",
				"path-utils.ts#normalizePath",
				"unused.ts#normalizePath",
				"unused.ts#unused",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.root, func(t *testing.T) {
			graph := indexTree(t, tc.root)
			if graph.Limits != LimitsNote {
				t.Fatalf("limits = %q", graph.Limits)
			}
			files, fns, err := graph.Reachable(tc.entry)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(files, tc.files) {
				t.Fatalf("files = %v, want %v", files, tc.files)
			}
			if !reflect.DeepEqual(fns, tc.funcs) {
				t.Fatalf("functions = %v, want %v", fns, tc.funcs)
			}
			if got := functionIDs(graph); !reflect.DeepEqual(got, sortedCopy(tc.names)) {
				t.Fatalf("indexed = %v, want %v", got, sortedCopy(tc.names))
			}
			if got := resolvedEdges(graph); !reflect.DeepEqual(got, tc.edges) {
				t.Fatalf("edges = %v, want %v", got, tc.edges)
			}
		})
	}
}

func TestGoUnresolvedCallDoesNotAddFiles(t *testing.T) {
	graph := indexTree(t, "testdata/synth/go")
	var unresolved []string
	for _, edge := range graph.Edges {
		if !edge.Resolved && edge.From == "cmd/main.go#main" {
			unresolved = append(unresolved, edge.Call)
		}
	}
	if !reflect.DeepEqual(unresolved, []string{"missing"}) {
		t.Fatalf("unresolved = %v", unresolved)
	}
	for _, edge := range graph.Edges {
		if edge.Call == "len" {
			t.Fatalf("builtin len was recorded: %+v", edge)
		}
	}
}

func TestPythonLocalCallReachesImportedFile(t *testing.T) {
	graph := indexTree(t, "testdata/synth/py")
	files, _, err := graph.Reachable("app.py#local_only")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"app.py", "path_utils.py"}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("files = %v, want %v", files, want)
	}
}

func TestSliceBoundsFailClosed(t *testing.T) {
	graph := indexTree(t, "testdata/synth/go")
	if _, err := graph.Slice("cmd/main.go#main", 1); err == nil {
		t.Fatal("expected bound to reject two reachable files")
	}
	slice, err := graph.Slice("cmd/main.go#main", DefaultMaxFiles)
	if err != nil {
		t.Fatal(err)
	}
	if slice.Entry != "cmd/main.go#main" || slice.MaxFiles != DefaultMaxFiles {
		t.Fatalf("slice = %+v", slice)
	}
	want := []string{
		"codemap-entry:cmd/main.go#main",
		"codemap-file:auth/auth.go",
		"codemap-file:cmd/main.go",
	}
	if !reflect.DeepEqual(slice.ContextLines(), want) {
		t.Fatalf("context = %v", slice.ContextLines())
	}
	if _, err := graph.Slice("cmd/main.go#main", HardMaxFiles+1); err == nil {
		t.Fatal("expected hard max to reject")
	}
	if _, _, err := graph.Reachable("missing.go#Nope"); err == nil {
		t.Fatal("expected unknown entry to fail")
	}
}

func TestGraphRoundTrip(t *testing.T) {
	graph := indexTree(t, "testdata/synth/go")
	dir := t.TempDir()
	path := filepath.Join(dir, "codemap.json")
	if err := graph.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := graph.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	b, err := loaded.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("canonical mismatch\n%s\n%s", a, b)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, a) {
		t.Fatal("saved bytes are not canonical")
	}
}

func TestIndexRejectsEscapeSymlinkAndUnlisted(t *testing.T) {
	if _, err := Index(t.TempDir(), testSHA, []string{"../outside.go"}); err == nil {
		t.Fatal("expected escape path to fail")
	}
	root := t.TempDir()
	target := filepath.Join(root, "main.go")
	if err := os.WriteFile(target, []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "extra.go"), []byte("package main\nfunc Extra() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := Index(root, testSHA, []string{"link.go"}); err == nil {
		t.Fatal("expected symlink to fail")
	}
	graph, err := Index(root, testSHA, []string{"main.go"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := graph.Reachable("extra.go#Extra"); err == nil {
		t.Fatal("unlisted file was indexed")
	}
	if ids := functionIDs(graph); !reflect.DeepEqual(ids, []string{"main.go#main"}) {
		t.Fatalf("ids = %v", ids)
	}
}

func TestIndexRejectsOversizedAndInvalidGo(t *testing.T) {
	root := t.TempDir()
	big := filepath.Join(root, "big.go")
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), maxIndexFileBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Index(root, testSHA, []string{"big.go"}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "bad.go"), []byte("package main\nfunc (\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Index(root, testSHA, []string{"bad.go"}); err == nil || !strings.Contains(err.Error(), "parse go") {
		t.Fatalf("invalid go: %v", err)
	}
}

func TestIndexSkipsNonSource(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	graph, err := Index(root, testSHA, []string{"notes.txt", "main.go"})
	if err != nil {
		t.Fatal(err)
	}
	if graph.Skipped != 1 || len(graph.Functions) != 1 {
		t.Fatalf("graph = %+v", graph)
	}
}

func TestAmbiguousGoMethodStaysUnreachable(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"a.go": "package p\nfunc Run() { var x *A; x.Close() }\nfunc (a *A) Close() {}\ntype A struct{}\n",
		"b.go": "package p\nfunc (b *B) Close() { side() }\nfunc side() {}\ntype B struct{}\n",
	})
	graph := indexTree(t, root)
	files, _, err := graph.Reachable("a.go#Run")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, []string{"a.go"}) {
		t.Fatalf("files = %v", files)
	}
	for _, edge := range graph.Edges {
		if edge.From == "a.go#Run" && edge.Resolved {
			t.Fatalf("ambiguous Close was resolved: %+v", edge)
		}
	}
}

func TestMutualRecursionTerminates(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"rec.go": "package p\nfunc A() { B() }\nfunc B() { A() }\n",
	})
	graph := indexTree(t, root)
	files, fns, err := graph.Reachable("rec.go#A")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, []string{"rec.go"}) || len(fns) != 2 {
		t.Fatalf("files=%v functions=%v", files, fns)
	}
}

func TestPythonSelfAndNested(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"box.py":  "class Box:\n    def read(self, name):\n        return self.keep(name)\n\n    def keep(self, name):\n        return name\n",
		"nest.py": "def outer():\n    def inner():\n        return helper()\n    return inner()\n\ndef helper():\n    return 1\n",
	})
	graph := indexTree(t, root)
	files, _, err := graph.Reachable("box.py#Box.read")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, []string{"box.py"}) {
		t.Fatalf("box files = %v", files)
	}
	if !hasEdge(graph, "box.py#Box.read", "box.py#Box.keep") {
		t.Fatalf("missing self.keep edge: %v", resolvedEdges(graph))
	}
	files, _, err = graph.Reachable("nest.py#outer")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, []string{"nest.py"}) {
		t.Fatalf("nest files = %v", files)
	}
	if !hasEdge(graph, "nest.py#outer", "nest.py#inner") || !hasEdge(graph, "nest.py#inner", "nest.py#helper") {
		t.Fatalf("nested edges = %v", resolvedEdges(graph))
	}
	if hasEdge(graph, "nest.py#outer", "nest.py#helper") {
		t.Fatal("outer should not call helper directly")
	}
}

func TestUniqueAndAmbiguousBareNames(t *testing.T) {
	unique := t.TempDir()
	writeFiles(t, unique, map[string]string{
		"a.py": "def run():\n    return only_once()\n",
		"b.py": "def only_once():\n    return 1\n",
	})
	graph := indexTree(t, unique)
	files, _, err := graph.Reachable("a.py#run")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, []string{"a.py", "b.py"}) {
		t.Fatalf("unique files = %v", files)
	}

	ambiguous := t.TempDir()
	writeFiles(t, ambiguous, map[string]string{
		"a.py": "def run():\n    return dup()\n",
		"b.py": "def dup():\n    return 1\n",
		"c.py": "def dup():\n    return 2\n",
	})
	graph = indexTree(t, ambiguous)
	files, _, err = graph.Reachable("a.py#run")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, []string{"a.py"}) {
		t.Fatalf("ambiguous files = %v", files)
	}
}

func TestQualifiedImportDoesNotMatchBareName(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"a.ts": "import fs from \"fs\";\nexport function run() { return fs.readFile(\"synthetic\"); }\n",
		"b.ts": "export function readFile(p) { return p; }\n",
	})
	graph := indexTree(t, root)
	files, _, err := graph.Reachable("a.ts#run")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, []string{"a.ts"}) {
		t.Fatalf("files = %v edges=%v", files, resolvedEdges(graph))
	}
}

func TestGoPackageLevelCall(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"p.go": "package p\n\nvar x = helper()\n\nfunc helper() int { return 1 }\n",
	})
	graph := indexTree(t, root)
	if !hasEdge(graph, "p.go#package-level", "p.go#helper") {
		t.Fatalf("edges = %v", resolvedEdges(graph))
	}
	files, _, err := graph.Reachable("p.go#helper")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, []string{"p.go"}) {
		t.Fatalf("helper files = %v", files)
	}
	fns, ok := reachableSet(graph, "p.go#package-level")
	if !ok || !fns["p.go#helper"] {
		t.Fatalf("package-level reach = %v", fns)
	}
	fns, ok = reachableSet(graph, "p.go#helper")
	if !ok || fns["p.go#package-level"] {
		t.Fatalf("helper should not reach package-level: %v", fns)
	}
}

func TestAlteredLimitsRejected(t *testing.T) {
	graph := indexTree(t, "testdata/synth/go")
	graph.Limits = "taint engine"
	if _, err := graph.Canonical(); err == nil {
		t.Fatal("expected altered limits to fail")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "slice.json")
	slice, err := indexTree(t, "testdata/synth/go").Slice("other/other.go#Unused", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := slice.Save(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(LimitsNote), []byte("taint engine"), 1)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSlice(path); err == nil {
		t.Fatal("expected altered slice limits to fail")
	}
}

func indexTree(t *testing.T, root string) Graph {
	t.Helper()
	graph, err := Index(root, testSHA, listRel(t, root))
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

func listRel(t *testing.T, root string) []string {
	t.Helper()
	var rels []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rels = append(rels, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(rels)
	return rels
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func functionIDs(graph Graph) []string {
	ids := make([]string, 0, len(graph.Functions))
	for _, fn := range graph.Functions {
		ids = append(ids, fn.ID)
	}
	sort.Strings(ids)
	return ids
}

func resolvedEdges(graph Graph) []string {
	var edges []string
	for _, edge := range graph.Edges {
		if !edge.Resolved {
			continue
		}
		edges = append(edges, edge.From+" -> "+edge.To+" ["+edge.Call+"]")
	}
	sort.Strings(edges)
	return edges
}

func reachableSet(graph Graph, entry string) (map[string]bool, bool) {
	_, fns, err := graph.Reachable(entry)
	if err != nil {
		return nil, false
	}
	set := make(map[string]bool, len(fns))
	for _, id := range fns {
		set[id] = true
	}
	return set, true
}

func hasEdge(graph Graph, from, to string) bool {
	for _, edge := range graph.Edges {
		if edge.Resolved && edge.From == from && edge.To == to {
			return true
		}
	}
	return false
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
