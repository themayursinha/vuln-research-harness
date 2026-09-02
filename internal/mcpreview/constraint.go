package mcpreview

import (
	"fmt"
	"strings"
)

type constraintKind int

const (
	constraintURL constraintKind = iota
	constraintPath
	constraintCommand
)

type constraintEval struct {
	root       map[string]any
	memo       map[string]struct{}
	active     map[string]struct{}
	activeRefs map[string]struct{}
	visited    int
}

func newConstraintEval(root map[string]any) *constraintEval {
	return &constraintEval{
		root:       root,
		memo:       map[string]struct{}{},
		active:     map[string]struct{}{},
		activeRefs: map[string]struct{}{},
	}
}

func (e *constraintEval) has(node schemaNode, kind constraintKind) bool {
	e.visited = 0
	clear(e.active)
	clear(e.activeRefs)
	return e.search(node, kind, 0)
}

func (e *constraintEval) search(node schemaNode, kind constraintKind, depth int) bool {
	if node.kind == schemaInvalid {
		return false
	}
	if depth >= maxConstraintDepth || e.visited >= maxVisitedNodes {
		return false
	}
	if node.kind == schemaFalse {
		e.visited++
		return true
	}
	if node.kind == schemaTrue {
		e.visited++
		return false
	}
	obj := node.obj
	id := fmt.Sprintf("%p:%d", obj, kind)
	if _, ok := e.memo[id]; ok {
		return true
	}
	if _, looping := e.active[id]; looping {
		return false
	}
	e.visited++
	e.active[id] = struct{}{}
	found := e.direct(obj, kind)
	if !found {
		if ref, ok := obj["$ref"].(string); ok {
			found = e.searchRef(ref, kind, depth)
		}
	}
	if !found {
		found = e.searchComposition(obj, kind, depth)
	}
	delete(e.active, id)
	if found {
		e.memo[id] = struct{}{}
	}
	return found
}

func (e *constraintEval) searchRef(ref string, kind constraintKind, depth int) bool {
	if _, looping := e.activeRefs[ref]; looping {
		return false
	}
	target, ok := resolveLocalRef(e.root, ref)
	if !ok {
		return false
	}
	e.activeRefs[ref] = struct{}{}
	found := e.search(target, kind, depth+1)
	delete(e.activeRefs, ref)
	return found
}

func (e *constraintEval) searchComposition(node map[string]any, kind constraintKind, depth int) bool {
	for _, key := range []string{"allOf", "anyOf", "oneOf"} {
		arr, ok := node[key].([]any)
		if !ok {
			continue
		}
		for _, item := range arr {
			child, ok := asSchema(item)
			if !ok {
				continue
			}
			if e.search(child, kind, depth+1) {
				return true
			}
		}
	}
	return false
}

func (e *constraintEval) direct(node map[string]any, kind constraintKind) bool {
	switch kind {
	case constraintURL:
		return directURLConstraint(node)
	case constraintPath:
		return directPathConstraint(node)
	case constraintCommand:
		return directCommandConstraint(node)
	default:
		return false
	}
}

func directURLConstraint(schema map[string]any) bool {
	if hasEnumOrConst(schema) {
		return true
	}
	for _, key := range []string{
		"scheme", "schemes", "host", "hostname", "hosts",
		"allowedHosts", "allowed_hosts", "allowedSchemes", "allowed_schemes",
		"x-allowed-hosts", "x-allowed-schemes", "x-scheme", "x-host",
	} {
		if _, ok := schema[key]; ok {
			return true
		}
	}
	if pat, ok := schemaString(schema, "pattern"); ok && patternConstrainsURL(pat) {
		return true
	}
	return false
}

func directPathConstraint(schema map[string]any) bool {
	if hasEnumOrConst(schema) {
		return true
	}
	if pat, ok := schemaString(schema, "pattern"); ok && !isVacuousPattern(pat) {
		return true
	}
	for _, key := range []string{
		"root", "roots", "basePath", "base_path", "allowedRoots", "allowed_roots",
		"x-root", "x-allowed-roots", "sandboxRoot", "sandbox_root",
	} {
		if _, ok := schema[key]; ok {
			return true
		}
	}
	return false
}

func directCommandConstraint(schema map[string]any) bool {
	if hasEnumOrConst(schema) {
		return true
	}
	if pat, ok := schemaString(schema, "pattern"); ok && !isVacuousPattern(pat) {
		return true
	}
	return false
}

func hasEnumOrConst(schema map[string]any) bool {
	if _, ok := schema["const"]; ok {
		return true
	}
	enum, ok := schema["enum"].([]any)
	return ok && len(enum) > 0
}

func schemaString(schema map[string]any, key string) (string, bool) {
	s, ok := schema[key].(string)
	return s, ok
}

func patternConstrainsURL(pat string) bool {
	if isVacuousPattern(pat) {
		return false
	}
	low := strings.ToLower(pat)
	return strings.Contains(low, "http") || strings.Contains(low, "://") || strings.Contains(low, "scheme")
}

func isVacuousPattern(pat string) bool {
	switch strings.TrimSpace(pat) {
	case "", ".*", ".+", "^.*$", "^.+$", "(?s).*", "(?s).+", `^[\s\S]*$`, `^[\s\S]+$`:
		return true
	default:
		return false
	}
}
