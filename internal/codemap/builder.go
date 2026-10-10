package codemap

import (
	"fmt"
	"strings"
)

type rawFunc struct {
	id     string
	name   string
	symbol string
	file   string
	lang   string
	pkg    string
	dir    string
	recv   string
	line   int
}

type rawCall struct {
	from string
	name string
	qual string
	file string
	lang string
	pkg  string
	dir  string
	kind string
	line int
}

type rawImport struct {
	file         string
	local        string
	targetFile   string
	targetSymbol string
}

type builder struct {
	funcs    []rawFunc
	calls    []rawCall
	imports  []rawImport
	aliases  map[string]struct{}
	bound    map[string]string
	edges    []Edge
	seenEdge map[string]struct{}
}

func newBuilder() *builder {
	return &builder{
		aliases:  map[string]struct{}{},
		bound:    map[string]string{},
		seenEdge: map[string]struct{}{},
	}
}

func (b *builder) addFunc(fn rawFunc) {
	b.funcs = append(b.funcs, fn)
}

func (b *builder) addCall(call rawCall) {
	b.calls = append(b.calls, call)
}

func (b *builder) addImport(imp rawImport) {
	b.imports = append(b.imports, imp)
}

func (b *builder) addAlias(file, name string) {
	b.aliases[file+"\x00"+name] = struct{}{}
}

func (b *builder) linkImports() error {
	for _, imp := range b.imports {
		id, ok := b.lookup(imp.targetFile, imp.targetSymbol)
		if !ok {
			continue
		}
		key := imp.file + "\x00" + imp.local
		if _, alias := b.aliases[key]; alias {
			return fmt.Errorf("import %s in %s is both a module alias and a function", imp.local, imp.file)
		}
		if prev, exists := b.bound[key]; exists && prev != id {
			return fmt.Errorf("import %s in %s binds to both %s and %s", imp.local, imp.file, prev, id)
		}
		b.bound[key] = id
	}
	return nil
}

func (b *builder) lookup(file, symbol string) (string, bool) {
	id := ""
	n := 0
	for _, fn := range b.funcs {
		if fn.file == file && fn.symbol == symbol {
			id = fn.id
			n++
		}
	}
	if n == 1 {
		return id, true
	}
	return "", false
}

func (b *builder) resolve() {
	byID := make(map[string]rawFunc, len(b.funcs))
	byPkg := map[string][]rawFunc{}
	pkgKeys := map[string]map[string]struct{}{}
	for _, fn := range b.funcs {
		byID[fn.id] = fn
		if fn.lang != "go" {
			continue
		}
		key := pkgKey(fn.dir, fn.pkg)
		byPkg[key] = append(byPkg[key], fn)
		if pkgKeys[fn.pkg] == nil {
			pkgKeys[fn.pkg] = map[string]struct{}{}
		}
		pkgKeys[fn.pkg][key] = struct{}{}
	}
	for _, call := range b.calls {
		if call.lang == "go" {
			b.resolveGo(call, byPkg, pkgKeys)
			continue
		}
		b.resolveText(call, byID)
	}
}

func (b *builder) resolveGo(call rawCall, byPkg map[string][]rawFunc, pkgKeys map[string]map[string]struct{}) {
	display := call.name
	if call.qual != "" {
		display = call.qual + "." + call.name
	}
	if call.kind == "chain" {
		b.addEdge(call.from, "", display, call.line, false)
		return
	}
	var (
		target rawFunc
		ok     bool
	)
	switch {
	case call.qual == "":
		target, ok = uniqueFunc(byPkg[pkgKey(call.dir, call.pkg)], call.name, false)
		if !ok && isGoBuiltin(call.name) {
			return
		}
	case len(pkgKeys[call.qual]) == 1:
		var key string
		for k := range pkgKeys[call.qual] {
			key = k
		}
		target, ok = uniqueFunc(byPkg[key], call.name, false)
	case len(pkgKeys[call.qual]) > 1:
		ok = false
	default:
		target, ok = uniqueFunc(byPkg[pkgKey(call.dir, call.pkg)], call.name, true)
	}
	if ok {
		b.addEdge(call.from, target.id, display, call.line, true)
		return
	}
	b.addEdge(call.from, "", display, call.line, false)
}

func (b *builder) resolveText(call rawCall, byID map[string]rawFunc) {
	display := call.name
	if call.qual != "" {
		display = call.qual + "." + call.name
	}
	if call.qual == "" {
		if id, ok := b.bound[call.file+"\x00"+call.name]; ok {
			b.addEdge(call.from, id, display, call.line, true)
			return
		}
		if id, ok := b.lookup(call.file, call.name); ok {
			b.addEdge(call.from, id, display, call.line, true)
			return
		}
		if id, ok := b.uniqueTopLevel(call.lang, call.name); ok {
			b.addEdge(call.from, id, display, call.line, true)
			return
		}
		if isTextBuiltin(call.lang, call.name) {
			return
		}
		b.addEdge(call.from, "", display, call.line, false)
		return
	}
	if call.qual == "self" || call.qual == "cls" {
		if owner, ok := byID[call.from]; ok {
			if class, _, cut := strings.Cut(owner.symbol, "."); cut {
				if id, ok := b.lookup(owner.file, class+"."+call.name); ok {
					b.addEdge(call.from, id, display, call.line, true)
					return
				}
			}
		}
	}
	if id, ok := b.lookup(call.file, call.qual+"."+call.name); ok {
		b.addEdge(call.from, id, display, call.line, true)
		return
	}
	b.addEdge(call.from, "", display, call.line, false)
}

func (b *builder) uniqueTopLevel(lang, name string) (string, bool) {
	id := ""
	n := 0
	for _, fn := range b.funcs {
		if fn.lang == lang && fn.symbol == name {
			id = fn.id
			n++
		}
	}
	if n == 1 {
		return id, true
	}
	return "", false
}

func uniqueFunc(list []rawFunc, name string, methods bool) (rawFunc, bool) {
	var hit rawFunc
	n := 0
	for _, fn := range list {
		if fn.name != name {
			continue
		}
		if !methods && fn.recv != "" {
			continue
		}
		hit = fn
		n++
	}
	if n == 1 {
		return hit, true
	}
	return rawFunc{}, false
}

func (b *builder) addEdge(from, to, call string, line int, resolved bool) {
	if !resolved {
		to = ""
	}
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%t", from, to, call, line, resolved)
	if _, ok := b.seenEdge[key]; ok {
		return
	}
	b.seenEdge[key] = struct{}{}
	b.edges = append(b.edges, Edge{
		From:     from,
		To:       to,
		Call:     call,
		Line:     line,
		Resolved: resolved,
	})
}

func (b *builder) functions() []Function {
	out := make([]Function, 0, len(b.funcs))
	for _, fn := range b.funcs {
		out = append(out, Function{
			ID:       fn.id,
			Name:     fn.name,
			File:     fn.file,
			Line:     fn.line,
			Language: fn.lang,
		})
	}
	return out
}

func pkgKey(dir, pkg string) string {
	if dir == "." {
		dir = ""
	}
	return dir + "\x00" + pkg
}

func assignIDs(file string, symbols []string, lines []int) []string {
	count := map[string]int{}
	for _, symbol := range symbols {
		count[file+"#"+symbol]++
	}
	ids := make([]string, len(symbols))
	for i, symbol := range symbols {
		base := file + "#" + symbol
		if count[base] > 1 {
			ids[i] = fmt.Sprintf("%s@%d", base, lines[i])
		} else {
			ids[i] = base
		}
	}
	return ids
}

func isGoBuiltin(name string) bool {
	_, ok := goBuiltins[name]
	return ok
}

func isTextBuiltin(lang, name string) bool {
	switch lang {
	case "python":
		_, ok := pythonBuiltins[name]
		return ok
	case "typescript", "javascript":
		_, ok := jsBuiltins[name]
		return ok
	default:
		return false
	}
}

var goBuiltins = map[string]struct{}{
	"append": {}, "cap": {}, "clear": {}, "close": {}, "complex": {}, "copy": {},
	"delete": {}, "imag": {}, "len": {}, "make": {}, "max": {}, "min": {},
	"new": {}, "panic": {}, "print": {}, "println": {}, "real": {}, "recover": {},
}

var pythonBuiltins = map[string]struct{}{
	"abs": {}, "all": {}, "any": {}, "ascii": {}, "bin": {}, "bool": {},
	"breakpoint": {}, "bytearray": {}, "bytes": {}, "callable": {}, "chr": {},
	"classmethod": {}, "compile": {}, "complex": {}, "delattr": {}, "dict": {},
	"dir": {}, "divmod": {}, "enumerate": {}, "eval": {}, "exec": {}, "filter": {},
	"float": {}, "format": {}, "frozenset": {}, "getattr": {}, "globals": {},
	"hasattr": {}, "hash": {}, "help": {}, "hex": {}, "id": {}, "input": {},
	"int": {}, "isinstance": {}, "issubclass": {}, "iter": {}, "len": {},
	"list": {}, "locals": {}, "map": {}, "max": {}, "memoryview": {}, "min": {},
	"next": {}, "object": {}, "oct": {}, "open": {}, "ord": {}, "pow": {},
	"print": {}, "property": {}, "range": {}, "repr": {}, "reversed": {},
	"round": {}, "set": {}, "setattr": {}, "slice": {}, "sorted": {},
	"staticmethod": {}, "str": {}, "sum": {}, "super": {}, "tuple": {},
	"type": {}, "vars": {}, "zip": {},
}

var jsBuiltins = map[string]struct{}{
	"Array": {}, "Boolean": {}, "Date": {}, "Error": {}, "JSON": {}, "Map": {},
	"Math": {}, "Number": {}, "Object": {}, "Promise": {}, "Proxy": {},
	"RangeError": {}, "Reflect": {}, "Set": {}, "String": {}, "Symbol": {},
	"TypeError": {}, "WeakMap": {}, "WeakSet": {}, "atob": {}, "btoa": {},
	"clearInterval": {}, "clearTimeout": {}, "decodeURI": {},
	"decodeURIComponent": {}, "encodeURI": {}, "encodeURIComponent": {},
	"fetch": {}, "isFinite": {}, "isNaN": {}, "parseFloat": {}, "parseInt": {},
	"queueMicrotask": {}, "require": {}, "setInterval": {}, "setTimeout": {},
	"structuredClone": {},
}
