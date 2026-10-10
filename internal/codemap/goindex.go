package codemap

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
)

func indexGo(rel string, src []byte, b *builder) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return fmt.Errorf("parse go %s: %w", rel, err)
	}
	if file.Name == nil || file.Name.Name == "" {
		return fmt.Errorf("parse go %s: missing package name", rel)
	}
	pkg := file.Name.Name
	dir := path.Dir(rel)
	if dir == "." {
		dir = ""
	}

	type item struct {
		symbol string
		name   string
		recv   string
		line   int
		body   *ast.BlockStmt
		extra  []rawCall
	}
	var items []item
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name == "" {
			continue
		}
		recv := receiverType(fn)
		symbol := fn.Name.Name
		if recv != "" {
			symbol = recv + "." + fn.Name.Name
		}
		items = append(items, item{
			symbol: symbol,
			name:   fn.Name.Name,
			recv:   recv,
			line:   fset.Position(fn.Name.Pos()).Line,
			body:   fn.Body,
		})
	}

	var pkgCalls []rawCall
	for _, decl := range file.Decls {
		if _, ok := decl.(*ast.FuncDecl); ok {
			continue
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, qual, kind, ok := describeCall(call)
			if !ok {
				return true
			}
			pkgCalls = append(pkgCalls, rawCall{
				name: name,
				qual: qual,
				kind: kind,
				file: rel,
				lang: "go",
				pkg:  pkg,
				dir:  dir,
				line: fset.Position(call.Pos()).Line,
			})
			return true
		})
	}
	if len(pkgCalls) > 0 {
		items = append(items, item{
			symbol: "package-level",
			name:   "package-level",
			line:   1,
			extra:  pkgCalls,
		})
	}

	symbols := make([]string, len(items))
	lines := make([]int, len(items))
	for i, item := range items {
		symbols[i] = item.symbol
		lines[i] = item.line
	}
	ids := assignIDs(rel, symbols, lines)
	for i, item := range items {
		b.addFunc(rawFunc{
			id:     ids[i],
			name:   item.name,
			symbol: item.symbol,
			file:   rel,
			lang:   "go",
			pkg:    pkg,
			dir:    dir,
			recv:   item.recv,
			line:   item.line,
		})
		for _, call := range item.extra {
			call.from = ids[i]
			b.addCall(call)
		}
		if item.body == nil {
			continue
		}
		ast.Inspect(item.body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, qual, kind, ok := describeCall(call)
			if !ok {
				return true
			}
			b.addCall(rawCall{
				from: ids[i],
				name: name,
				qual: qual,
				kind: kind,
				file: rel,
				lang: "go",
				pkg:  pkg,
				dir:  dir,
				line: fset.Position(call.Pos()).Line,
			})
			return true
		})
	}
	return nil
}

func receiverType(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	name := typeIdent(fn.Recv.List[0].Type)
	if name == "" {
		// Keep it a method so a bare call cannot bind to an unnamed receiver.
		return "_"
	}
	return name
}

func typeIdent(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeIdent(t.X)
	case *ast.ParenExpr:
		return typeIdent(t.X)
	case *ast.IndexExpr:
		return typeIdent(t.X)
	case *ast.IndexListExpr:
		return typeIdent(t.X)
	default:
		return ""
	}
}

func describeCall(call *ast.CallExpr) (name, qual, kind string, ok bool) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if fn.Name == "" {
			return "", "", "", false
		}
		return fn.Name, "", "bare", true
	case *ast.SelectorExpr:
		if fn.Sel == nil || fn.Sel.Name == "" {
			return "", "", "", false
		}
		if id, ok := fn.X.(*ast.Ident); ok && id.Name != "" {
			return fn.Sel.Name, id.Name, "sel", true
		}
		return fn.Sel.Name, "", "chain", true
	default:
		return "", "", "", false
	}
}
