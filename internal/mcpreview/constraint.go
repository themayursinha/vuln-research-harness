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
	return e.searchCtx(node, kind, depth, false)
}

func (e *constraintEval) searchCtx(node schemaNode, kind constraintKind, depth int, arrayCtx bool) bool {
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
	// The array context changes what counts as a constraint, so it is part
	// of the memo/cycle identity: a node constrained only via inherited
	// array typing must not memoize as constrained for unforced lookups.
	id := fmt.Sprintf("%p:%d:%t", obj, kind, arrayCtx)
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
			found = e.searchRef(ref, kind, depth, arrayCtx)
		}
	}
	if !found {
		found = e.searchComposition(obj, kind, depth, arrayCtx)
	}
	if !found {
		found = e.searchArrayItems(obj, kind, depth, arrayCtx)
	}
	delete(e.active, id)
	if found {
		e.memo[id] = struct{}{}
	}
	return found
}

func (e *constraintEval) searchRef(ref string, kind constraintKind, depth int, arrayCtx bool) bool {
	if _, looping := e.activeRefs[ref]; looping {
		return false
	}
	target, ok := resolveLocalRef(e.root, ref)
	if !ok {
		return false
	}
	e.activeRefs[ref] = struct{}{}
	// A $ref names the same instance, so the enclosing array context carries
	// over to the target.
	found := e.searchCtx(target, kind, depth+1, arrayCtx)
	delete(e.activeRefs, ref)
	return found
}

func (e *constraintEval) searchComposition(node map[string]any, kind constraintKind, depth int, arrayCtx bool) bool {
	if branches := schemaBranches(node["allOf"]); len(branches) > 0 {
		if e.searchAnyBranch(branches, kind, depth, arrayCtx || allOfForcesArray(node, branches)) {
			return true
		}
	}
	for _, key := range []string{"anyOf", "oneOf"} {
		// A disjunction under an array-only node (declared here or inherited
		// from an enclosing conjunction) operates on arrays in every branch.
		if e.searchEveryBranch(node[key], kind, depth, arrayCtx || declaresArrayOnly(node)) {
			return true
		}
	}
	return false
}

func (e *constraintEval) searchAnyBranch(branches []schemaNode, kind constraintKind, depth int, arrayCtx bool) bool {
	for _, child := range branches {
		if e.searchCtx(child, kind, depth+1, arrayCtx) {
			return true
		}
	}
	return false
}

func (e *constraintEval) searchEveryBranch(v any, kind constraintKind, depth int, arrayCtx bool) bool {
	branches := schemaBranches(v)
	if len(branches) == 0 {
		return false
	}
	var viable []schemaNode
	for _, child := range branches {
		if arrayCtx && branchExcludedByArrayParent(child) {
			continue
		}
		if e.viableForKind(child, kind, depth+1) {
			viable = append(viable, child)
		}
	}
	if len(viable) == 0 {
		return true
	}
	for _, child := range viable {
		if !e.searchCtx(child, kind, depth+1, arrayCtx) {
			return false
		}
	}
	return true
}

// branchExcludedByArrayParent reports whether a disjunction branch declares
// only known non-array types. Under an array-forcing parent such a branch
// accepts values the parent rejects, so it contributes no accepted values
// and is skipped like any other non-viable branch.
func branchExcludedByArrayParent(b schemaNode) bool {
	if b.kind != schemaObject {
		return false
	}
	types, ok := declaredTypes(b.obj)
	if !ok {
		return false
	}
	for _, t := range types {
		switch t {
		case "array":
			return false
		case "string", "object", "boolean", "null", "number", "integer":
			continue
		default:
			return false
		}
	}
	return true
}

// allOfForcesArray reports whether an allOf conjunction accepts only arrays
// (modulo non-viable types such as null): the parent declares array-only, or
// any branch does. Every accepted instance then satisfies that conjunct, so
// sibling item keywords constrain all of them.
func allOfForcesArray(parent map[string]any, branches []schemaNode) bool {
	if declaresArrayOnly(parent) {
		return true
	}
	for _, b := range branches {
		if b.kind != schemaObject {
			continue
		}
		if declaresArrayOnly(b.obj) {
			return true
		}
	}
	return false
}

// declaresArrayOnly reports whether a type declaration allows arrays but no
// viable non-array scalar (for example "array" or ["array","null"]).
func declaresArrayOnly(obj map[string]any) bool {
	types, ok := declaredTypes(obj)
	if !ok {
		return false
	}
	hasArray := false
	for _, t := range types {
		if t == "array" {
			hasArray = true
			continue
		}
		if acceptsStringLikeValue([]string{t}) {
			return false
		}
	}
	return hasArray
}

func (e *constraintEval) searchArrayItems(node map[string]any, kind constraintKind, depth int, arrayCtx bool) bool {
	if !arrayConstraintAppliesCtx(node, arrayCtx) {
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
		if !ok {
			return false
		}
		// A tail that cannot carry the value kind constrains it vacuously.
		if !e.viableForKind(child, kind, depth+1) {
			return true
		}
		return e.search(child, kind, depth+1)
	default:
		child, ok := asSchema(items)
		if !ok {
			return false
		}
		if !e.viableForKind(child, kind, depth+1) {
			return true
		}
		return e.search(child, kind, depth+1)
	}
}

func (e *constraintEval) searchEveryItemList(items []any, kind constraintKind, depth int) bool {
	if len(items) == 0 {
		return true
	}
	var viable []schemaNode
	for _, item := range items {
		child, ok := asSchema(item)
		if !ok {
			return false
		}
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

func arrayConstraintAppliesCtx(node map[string]any, arrayCtx bool) bool {
	types, ok := declaredTypes(node)
	if !ok {
		// Untyped nodes still accept scalar strings, so items/prefixItems
		// keywords do not constrain the argument — unless an enclosing
		// allOf conjunction already forces array-only typing, in which
		// case every accepted instance is an array.
		if arrayCtx {
			return hasItemsOrPrefixItems(node)
		}
		return false
	}
	if arrayCtx {
		// Under array forcing the parent rejects every non-array
		// alternative (for example the string half of ["array","string"]),
		// so only whether this branch itself allows arrays matters.
		if !hasDeclaredType(types, "array") {
			return false
		}
		return hasItemsOrPrefixItems(node)
	}
	if !declaresArrayOnly(node) {
		// A viable non-array scalar (string, object, unknown, or a union
		// containing one) is unaffected by item constraints.
		return false
	}
	return hasItemsOrPrefixItems(node)
}

func hasItemsOrPrefixItems(node map[string]any) bool {
	if _, ok := node["items"]; ok {
		return true
	}
	_, ok := node["prefixItems"]
	return ok
}

func hasDeclaredType(types []string, want string) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
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
	if pat, ok := schemaString(schema, "pattern"); ok && patternApplies(schema) && patternConstrainsURL(pat) {
		return true
	}
	return false
}

func directPathConstraint(schema map[string]any) bool {
	if hasEnumOrConst(schema) {
		return true
	}
	if pat, ok := schemaString(schema, "pattern"); ok && patternApplies(schema) && !isVacuousPattern(pat) {
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
	if pat, ok := schemaString(schema, "pattern"); ok && patternApplies(schema) && !isVacuousPattern(pat) {
		return true
	}
	return false
}

// patternApplies reports whether a "pattern" keyword can constrain the value
// kind at this node. Pattern tests string instances only, so on nodes that
// may hold arrays or objects (array/object type, unknown types, or untyped
// nodes that still accept them) the pattern leaves those alternatives
// uncovered; array elements are evaluated separately via item constraints.
func patternApplies(node map[string]any) bool {
	types, ok := declaredTypes(node)
	if !ok {
		return false
	}
	for _, t := range types {
		switch t {
		case "string", "null", "boolean", "number", "integer":
			continue
		default:
			return false
		}
	}
	return true
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
	for _, alt := range splitTopLevelAlternatives(low) {
		if !anchoredMarkerConstrainsURL(alt) {
			return false
		}
	}
	return nestedAlternativesConstrained(low)
}

// nestedAlternativesConstrained reports whether every group-internal
// alternative is free of unbounded skips before its URL marker. An anchored
// early marker on the whole pattern is not enough when a nested branch such
// as .* in ^(https://|.*)$ accepts arbitrary URLs on its own.
func nestedAlternativesConstrained(pat string) bool {
	for _, inner := range groupInnerTexts(pat) {
		alts := splitTopLevelAlternatives(inner)
		if len(alts) < 2 {
			continue
		}
		for _, alt := range alts {
			if hasUnboundedSkipBeforeMarker(alt) {
				return false
			}
		}
	}
	return true
}

// hasUnboundedSkipBeforeMarker reports whether frag can match an arbitrary
// prefix before any URL marker appears (or at all, when the fragment carries
// no marker). Fixed text without markers (such as wss in ^(https|wss)://)
// still pins the value; a skip such as .* does not.
func hasUnboundedSkipBeforeMarker(frag string) bool {
	low := strings.ToLower(frag)
	marker := strings.Index(low, "http")
	if j := strings.Index(low, "://"); j >= 0 && (marker < 0 || j < marker) {
		marker = j
	}
	if j := strings.Index(low, "scheme"); j >= 0 && (marker < 0 || j < marker) {
		marker = j
	}
	prefix := low
	if marker >= 0 {
		prefix = low[:marker]
	}
	return hasUnboundedSkip(prefix)
}

// groupInnerTexts returns the inner text of every parenthesized group in
// pat, innermost included, honoring escapes and character classes.
// Unterminated groups run to the end of the pattern.
func groupInnerTexts(pat string) []string {
	var inners []string
	var stack []int
	inClass := false
	escaped := false
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		if escaped {
			escaped = false
			continue
		}
		switch c {
		case '\\':
			escaped = true
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '(':
			if !inClass {
				stack = append(stack, i)
			}
		case ')':
			if !inClass && len(stack) > 0 {
				open := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				inners = append(inners, pat[open+1:i])
			}
		}
	}
	for _, open := range stack {
		inners = append(inners, pat[open+1:])
	}
	return inners
}

// anchoredMarkerConstrainsURL reports whether one top-level regex alternative
// pins a URL marker (http, ://, scheme) at its anchored start. JSON Schema
// patterns are unanchored substring searches, so a merely contained marker
// (as in "https?" or "^.*https?") also matches values like
// "file:///tmp/http" and constrains nothing.
func anchoredMarkerConstrainsURL(alt string) bool {
	rest := stripLeadingRegexGroups(strings.TrimSpace(alt))
	if !strings.HasPrefix(rest, "^") {
		return false
	}
	marker := strings.Index(rest, "http")
	if i := strings.Index(rest, "://"); i >= 0 && (marker < 0 || i < marker) {
		marker = i
	}
	if i := strings.Index(rest, "scheme"); i >= 0 && (marker < 0 || i < marker) {
		marker = i
	}
	if marker < 0 {
		return false
	}
	return !hasUnboundedSkip(rest[1:marker])
}

// hasUnboundedSkip reports whether a regex fragment can skip an arbitrary
// prefix, letting a later marker float (for example ".*" in "^.*https?").
// Fixed-width prefixes (literals, bounded groups) still pin the marker.
func hasUnboundedSkip(frag string) bool {
	if strings.Contains(frag, "*") || strings.Contains(frag, "+") {
		return true
	}
	for i := 0; i < len(frag); i++ {
		if frag[i] != '{' {
			continue
		}
		end := strings.Index(frag[i:], "}")
		if end < 0 {
			continue
		}
		if strings.Contains(frag[i:i+end], ",") {
			return true
		}
	}
	return false
}

// splitTopLevelAlternatives splits a regex source on "|" operators that sit
// outside groups, character classes, and escapes, so each alternative can be
// checked for its own anchor. A malformed remainder is kept whole, which
// fails the anchor check conservatively.
func splitTopLevelAlternatives(pat string) []string {
	var alts []string
	depth := 0
	inClass := false
	escaped := false
	start := 0
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		if escaped {
			escaped = false
			continue
		}
		switch c {
		case '\\':
			escaped = true
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '(':
			if !inClass {
				depth++
			}
		case ')':
			if !inClass && depth > 0 {
				depth--
			}
		case '|':
			if !inClass && depth == 0 {
				alts = append(alts, pat[start:i])
				start = i + 1
			}
		}
	}
	return append(alts, pat[start:])
}

// stripLeadingRegexGroups removes leading "(?...)" groups such as inline
// flags ("(?i)") so anchoring and marker checks see the effective start.
func stripLeadingRegexGroups(s string) string {
	for strings.HasPrefix(s, "(?") {
		end := strings.Index(s, ")")
		if end < 0 {
			return s
		}
		s = strings.TrimSpace(s[end+1:])
	}
	return s
}

func isVacuousPattern(pat string) bool {
	s := stripLeadingRegexGroups(strings.TrimSpace(pat))
	switch s {
	case "", ".*", ".+", "^", "$",
		"^.*", "^.+", ".*$", ".+$", "^.*$", "^.+$",
		`[\s\S]*`, `[\s\S]+`, `^[\s\S]*`, `^[\s\S]+`,
		`[\s\S]*$`, `[\s\S]+$`, `^[\s\S]*$`, `^[\s\S]+$`,
		`[\w\W]*`, `[\w\W]+`, `^[\w\W]*`, `^[\w\W]+`,
		`[\w\W]*$`, `[\w\W]+$`, `^[\w\W]*$`, `^[\w\W]+$`:
		return true
	default:
		return false
	}
}
