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

// unconstrained reports whether node/origin can carry a string-like value of
// kind and lacks a constraint. Incompatible declared types (boolean, number,
// integer, null) suppress emission even when the property name cues kind.
func (e *constraintEval) unconstrained(node, origin schemaNode, kind constraintKind) bool {
	if !e.viableForKind(origin, kind, 0) {
		return false
	}
	if !e.viableForKind(node, kind, 0) {
		return false
	}
	return !e.has(origin, kind)
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
	if !found {
		found = e.searchArrayItems(obj, kind, depth)
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
	if e.searchAnyBranch(node["allOf"], kind, depth) {
		return true
	}
	for _, key := range []string{"anyOf", "oneOf"} {
		if e.searchEveryBranch(node[key], kind, depth) {
			return true
		}
	}
	return false
}

func (e *constraintEval) searchAnyBranch(v any, kind constraintKind, depth int) bool {
	for _, child := range schemaBranches(v) {
		if e.search(child, kind, depth+1) {
			return true
		}
	}
	return false
}

func (e *constraintEval) searchEveryBranch(v any, kind constraintKind, depth int) bool {
	branches := schemaBranches(v)
	if len(branches) == 0 {
		return false
	}
	var viable []schemaNode
	for _, child := range branches {
		if e.viableForKind(child, kind, depth+1) {
			viable = append(viable, child)
		}
	}
	if len(viable) == 0 {
		return true
	}
	for _, child := range viable {
		if !e.search(child, kind, depth+1) {
			return false
		}
	}
	return true
}

func (e *constraintEval) searchArrayItems(node map[string]any, kind constraintKind, depth int) bool {
	if !arrayConstraintApplies(node) {
		return false
	}
	prefix, hasPrefix := node["prefixItems"].([]any)
	if hasPrefix {
		if !e.searchEveryItemList(prefix, kind, depth) {
			return false
		}
		if _, hasItems := node["items"]; !hasItems {
			return false
		}
	}
	switch items := node["items"].(type) {
	case nil:
		return false
	case []any:
		if !e.searchEveryItemList(items, kind, depth) {
			return false
		}
		add, ok := node["additionalItems"]
		if !ok {
			return false
		}
		child, ok := asSchema(add)
		return ok && e.search(child, kind, depth+1)
	default:
		child, ok := asSchema(items)
		if !ok {
			return false
		}
		return e.search(child, kind, depth+1)
	}
}

func (e *constraintEval) searchEveryItemList(items []any, kind constraintKind, depth int) bool {
	if len(items) == 0 {
		return false
	}
	for _, item := range items {
		child, ok := asSchema(item)
		if !ok {
			return false
		}
		if !e.search(child, kind, depth+1) {
			return false
		}
	}
	return true
}

func arrayConstraintApplies(node map[string]any) bool {
	types, ok := declaredTypes(node)
	if !ok {
		// Untyped nodes still accept scalar strings, so items/prefixItems
		// keywords do not constrain the argument.
		return false
	}
	hasArray := false
	for _, t := range types {
		if t == "array" {
			hasArray = true
			continue
		}
		if acceptsStringLikeValue([]string{t}) {
			// A viable non-array scalar (string, object, unknown, or a
			// union containing one) is unaffected by item constraints.
			return false
		}
	}
	if !hasArray {
		return false
	}
	if _, ok := node["items"]; ok {
		return true
	}
	_, ok = node["prefixItems"]
	return ok
}

func (e *constraintEval) viableForKind(node schemaNode, kind constraintKind, depth int) bool {
	if depth >= maxConstraintDepth {
		return true
	}
	switch node.kind {
	case schemaTrue:
		return true
	case schemaFalse, schemaInvalid:
		return false
	}
	obj := node.obj
	if obj == nil {
		return true
	}
	if types, ok := declaredTypes(obj); ok && !acceptsStringLikeValue(types) {
		return false
	}
	// allOf is a conjunction: any non-viable branch makes the whole
	// non-viable (e.g. {"allOf":[{"type":"boolean"}]} accepts only booleans).
	if branches := schemaBranches(obj["allOf"]); len(branches) > 0 {
		for _, b := range branches {
			if !e.viableForKind(b, kind, depth+1) {
				return false
			}
		}
	}
	// anyOf/oneOf are conjunctions with the rest of the schema: an
	// all-non-viable disjunction restricts the whole to non-viable values.
	for _, key := range []string{"anyOf", "oneOf"} {
		if _, present := obj[key]; !present {
			continue
		}
		branches := schemaBranches(obj[key])
		if len(branches) == 0 {
			continue
		}
		viable := false
		for _, b := range branches {
			if e.viableForKind(b, kind, depth+1) {
				viable = true
				break
			}
		}
		if !viable {
			return false
		}
	}
	if ref, ok := obj["$ref"].(string); ok {
		if _, looping := e.activeRefs[ref]; !looping {
			if target, ok := resolveLocalRef(e.root, ref); ok {
				e.activeRefs[ref] = struct{}{}
				viable := e.viableForKind(target, kind, depth+1)
				delete(e.activeRefs, ref)
				if !viable {
					return false
				}
			}
		}
	}
	if !e.arrayElementsViable(obj, kind, depth) {
		return false
	}
	return true
}

// arrayElementsViable reports whether an array-only node can hold a
// string-like element. Nodes that also accept a viable non-array scalar
// stay viable via that scalar; untyped nodes stay viable as well. Only
// array-only nodes (modulo non-viable types like null) are gated on their
// applicable item schemas.
func (e *constraintEval) arrayElementsViable(obj map[string]any, kind constraintKind, depth int) bool {
	types, hasTypes := declaredTypes(obj)
	if !hasTypes {
		return true
	}
	hasArray := false
	for _, t := range types {
		if t == "array" {
			hasArray = true
			continue
		}
		if acceptsStringLikeValue([]string{t}) {
			return true
		}
	}
	if !hasArray {
		return true
	}
	_, hasItems := obj["items"]
	_, hasPrefix := obj["prefixItems"]
	if !hasItems && !hasPrefix {
		return true
	}
	if depth+1 >= maxConstraintDepth {
		return true
	}
	if prefix, ok := obj["prefixItems"].([]any); ok {
		for _, item := range prefix {
			child, ok := asSchema(item)
			if !ok {
				return true
			}
			if e.viableForKind(child, kind, depth+1) {
				return true
			}
		}
		if _, hasItems := obj["items"]; !hasItems {
			// prefixItems alone leaves additional positions open.
			return true
		}
	} else if hasPrefix {
		// Malformed prefixItems is ignored conservatively.
		return true
	}
	switch items := obj["items"].(type) {
	case nil:
		// Null or absent tail schema alongside a fully non-viable prefix
		// list is unreachable via the open-tail returns above; stay
		// conservative and treat it as viable.
		return true
	case []any:
		for _, item := range items {
			child, ok := asSchema(item)
			if !ok {
				return true
			}
			if e.viableForKind(child, kind, depth+1) {
				return true
			}
		}
		add, ok := obj["additionalItems"]
		if !ok {
			// Legacy tuple form without additionalItems allows extras.
			return true
		}
		child, ok := asSchema(add)
		if !ok {
			return true
		}
		return e.viableForKind(child, kind, depth+1)
	default:
		child, ok := asSchema(items)
		if !ok {
			return true
		}
		return e.viableForKind(child, kind, depth+1)
	}
}

func declaredTypes(obj map[string]any) ([]string, bool) {
	switch t := obj["type"].(type) {
	case string:
		if t == "" {
			return nil, false
		}
		return []string{t}, true
	case []any:
		var types []string
		for _, item := range t {
			s, ok := item.(string)
			if !ok || s == "" {
				continue
			}
			types = append(types, s)
		}
		if len(types) == 0 {
			return nil, false
		}
		return types, true
	default:
		return nil, false
	}
}

func acceptsStringLikeValue(types []string) bool {
	for _, t := range types {
		switch t {
		case "string", "array", "object":
			return true
		case "null", "boolean", "number", "integer":
			continue
		default:
			return true
		}
	}
	return false
}

func schemaBranches(v any) []schemaNode {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var branches []schemaNode
	for _, item := range arr {
		child, ok := asSchema(item)
		if !ok {
			continue
		}
		branches = append(branches, child)
	}
	return branches
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
