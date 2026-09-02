package mcpreview

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	maxConstraintDepth = 32
	maxVisitedNodes    = 256
)

type schemaKind int

const (
	schemaInvalid schemaKind = iota
	schemaObject
	schemaTrue
	schemaFalse
)

// schemaNode is a JSON Schema node: an object, boolean true, or boolean false.
type schemaNode struct {
	kind schemaKind
	obj  map[string]any
}

func asSchema(v any) (schemaNode, bool) {
	switch t := v.(type) {
	case map[string]any:
		return schemaNode{kind: schemaObject, obj: t}, true
	case bool:
		if t {
			return schemaNode{kind: schemaTrue}, true
		}
		return schemaNode{kind: schemaFalse}, true
	default:
		return schemaNode{}, false
	}
}

func (n schemaNode) keywords() map[string]any {
	if n.kind != schemaObject {
		return nil
	}
	return n.obj
}

type schemaVisitor func(loc, propName string, node, origin schemaNode)

type walkFrame struct {
	node     schemaNode
	origin   schemaNode
	loc      string
	propName string
	depth    int
}

func (f walkFrame) constraint() schemaNode {
	if f.origin.kind != schemaInvalid {
		return f.origin
	}
	return f.node
}

type schemaWalker struct {
	root       map[string]any
	visit      schemaVisitor
	active     map[string]struct{}
	activeRefs map[string]struct{}
	visited    int
}

func walkSchema(schema map[string]any, loc string, visit schemaVisitor) {
	if schema == nil {
		return
	}
	w := &schemaWalker{
		root:       schema,
		visit:      visit,
		active:     map[string]struct{}{},
		activeRefs: map[string]struct{}{},
	}
	w.enter(walkFrame{
		node: schemaNode{kind: schemaObject, obj: schema},
		loc:  loc,
	}, false)
}

func (w *schemaWalker) enter(f walkFrame, callVisit bool) {
	if f.depth >= maxConstraintDepth || w.visited >= maxVisitedNodes {
		return
	}
	switch f.node.kind {
	case schemaFalse, schemaTrue:
		w.visited++
		if callVisit {
			w.visit(f.loc, f.propName, f.node, f.constraint())
		}
		return
	case schemaObject:
	default:
		return
	}
	obj := f.node.obj
	if obj != nil {
		id := fmt.Sprintf("%p", obj)
		if _, looping := w.active[id]; looping {
			return
		}
		w.active[id] = struct{}{}
		defer delete(w.active, id)
	}
	w.visited++
	if callVisit {
		w.visit(f.loc, f.propName, f.node, f.constraint())
	}
	w.followRef(obj, f, callVisit)
	w.walkApplicators(obj, f.loc, f.depth)
}

func (w *schemaWalker) followRef(obj map[string]any, f walkFrame, callVisit bool) {
	ref, ok := obj["$ref"].(string)
	if !ok {
		return
	}
	if _, looping := w.activeRefs[ref]; looping {
		return
	}
	target, ok := resolveLocalRef(w.root, ref)
	if !ok {
		return
	}
	w.activeRefs[ref] = struct{}{}
	w.enter(walkFrame{
		node:     target,
		origin:   f.constraint(),
		loc:      f.loc,
		propName: f.propName,
		depth:    f.depth + 1,
	}, callVisit)
	delete(w.activeRefs, ref)
}

func (w *schemaWalker) walkApplicators(obj map[string]any, loc string, depth int) {
	if props, ok := asObject(obj["properties"]); ok {
		for _, name := range sortedKeys(props) {
			child, ok := asSchema(props[name])
			if !ok {
				continue
			}
			w.enter(walkFrame{
				node:     child,
				loc:      loc + ".properties." + name,
				propName: name,
				depth:    depth + 1,
			}, true)
		}
	}
	if patterns, ok := asObject(obj["patternProperties"]); ok {
		for _, pattern := range sortedKeys(patterns) {
			child, ok := asSchema(patterns[pattern])
			if !ok {
				continue
			}
			w.enter(walkFrame{
				node:     child,
				loc:      loc + ".patternProperties." + pattern,
				propName: pattern,
				depth:    depth + 1,
			}, true)
		}
	}
	if child, ok := asSchema(obj["additionalProperties"]); ok {
		w.enter(walkFrame{
			node:     child,
			loc:      loc + ".additionalProperties",
			propName: "",
			depth:    depth + 1,
		}, true)
	}
	switch items := obj["items"].(type) {
	case []any:
		w.walkSchemaList(items, loc+".items", "items", depth)
	default:
		if child, ok := asSchema(items); ok {
			w.enter(walkFrame{
				node:     child,
				loc:      loc + ".items",
				propName: "items",
				depth:    depth + 1,
			}, true)
		}
	}
	if prefix, ok := obj["prefixItems"].([]any); ok {
		w.walkSchemaList(prefix, loc+".prefixItems", "items", depth)
	}
	for _, key := range []string{"allOf", "anyOf", "oneOf"} {
		arr, ok := obj[key].([]any)
		if !ok {
			continue
		}
		for i, item := range arr {
			child, ok := asSchema(item)
			if !ok {
				continue
			}
			w.enter(walkFrame{
				node:     child,
				loc:      fmt.Sprintf("%s.%s[%d]", loc, key, i),
				propName: "",
				depth:    depth + 1,
			}, false)
		}
	}
	for _, key := range []string{"then", "else", "not", "if"} {
		child, ok := asSchema(obj[key])
		if !ok {
			continue
		}
		w.enter(walkFrame{
			node:     child,
			loc:      loc + "." + key,
			propName: "",
			depth:    depth + 1,
		}, false)
	}
}

func (w *schemaWalker) walkSchemaList(items []any, loc, propName string, depth int) {
	for i, item := range items {
		child, ok := asSchema(item)
		if !ok {
			continue
		}
		w.enter(walkFrame{
			node:     child,
			loc:      fmt.Sprintf("%s[%d]", loc, i),
			propName: propName,
			depth:    depth + 1,
		}, true)
	}
}

func resolveLocalRef(root map[string]any, ref string) (schemaNode, bool) {
	pointer, ok := localJSONPointer(ref)
	if !ok {
		return schemaNode{}, false
	}
	return evalJSONPointer(root, pointer)
}

func localJSONPointer(ref string) (string, bool) {
	if ref == "#" {
		return "", true
	}
	if strings.HasPrefix(ref, "#/") {
		return ref[1:], true
	}
	return "", false
}

func evalJSONPointer(root map[string]any, pointer string) (schemaNode, bool) {
	if pointer == "" {
		return schemaNode{kind: schemaObject, obj: root}, true
	}
	if !strings.HasPrefix(pointer, "/") {
		return schemaNode{}, false
	}
	var cur any = root
	for _, part := range strings.Split(pointer, "/")[1:] {
		token := decodeJSONPointerToken(part)
		next, ok := jsonPointerStep(cur, token)
		if !ok {
			return schemaNode{}, false
		}
		cur = next
	}
	return asSchema(cur)
}

func jsonPointerStep(cur any, token string) (any, bool) {
	switch node := cur.(type) {
	case map[string]any:
		next, ok := node[token]
		return next, ok
	case []any:
		i, ok := jsonPointerIndex(token)
		if !ok || i >= len(node) {
			return nil, false
		}
		return node[i], true
	default:
		return nil, false
	}
}

func jsonPointerIndex(token string) (int, bool) {
	if token == "" || (len(token) > 1 && token[0] == '0') {
		return 0, false
	}
	i, err := strconv.Atoi(token)
	if err != nil || i < 0 {
		return 0, false
	}
	return i, true
}

func decodeJSONPointerToken(token string) string {
	token = strings.ReplaceAll(token, "~1", "/")
	token = strings.ReplaceAll(token, "~0", "~")
	return token
}

func asObject(v any) (map[string]any, bool) {
	obj, ok := v.(map[string]any)
	return obj, ok
}

func sortedKeys(obj map[string]any) []string {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
