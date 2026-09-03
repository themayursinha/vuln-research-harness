package mcpreview

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	maxConstraintDepth = 32
	maxVisitedNodes    = 256

	limitDepth   = "depth"
	limitVisited = "visited_nodes"
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

type schemaVisitor func(loc, propName string, node, origin, instance schemaNode)

type walkFrame struct {
	node     schemaNode
	origin   schemaNode
	instance schemaNode
	loc      string
	propName string
	depth    int
	// inspect asks enter to surface composition-branch cues at cueLoc/cueName
	// (the logical property) instead of at the physical composition path.
	inspect bool
	cueLoc  string
	cueName string
}

func (f walkFrame) constraint() schemaNode {
	if f.origin.kind != schemaInvalid {
		return f.origin
	}
	return f.node
}

func (f walkFrame) cueSite() (loc, name string) {
	if f.inspect && f.cueLoc != "" {
		return f.cueLoc, f.cueName
	}
	return f.loc, f.propName
}

// objectInstance is the enclosing object schema for this frame when instance
// was not set explicitly. Named-property frames still carry the parent object
// in instance so composition inspect can see sibling constraints; nested
// properties of that value are assigned in walkApplicators.
func (f walkFrame) objectInstance() schemaNode {
	if f.instance.kind != schemaInvalid {
		return f.instance
	}
	if f.propName == "" && f.origin.kind != schemaInvalid {
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
	truncated  bool
	limitHit   string
}

func walkSchema(schema map[string]any, loc string, visit schemaVisitor) (truncated bool, limitHit string) {
	if schema == nil {
		return false, ""
	}
	w := &schemaWalker{
		root:       schema,
		visit:      visit,
		active:     map[string]struct{}{},
		activeRefs: map[string]struct{}{},
	}
	root := schemaNode{kind: schemaObject, obj: schema}
	w.enter(walkFrame{
		node:     root,
		instance: root,
		loc:      loc,
	}, false)
	return w.truncated, w.limitHit
}

func (w *schemaWalker) enter(f walkFrame, callVisit bool) {
	if f.depth >= maxConstraintDepth {
		w.noteTruncation(limitDepth)
		return
	}
	if w.visited >= maxVisitedNodes {
		w.noteTruncation(limitVisited)
		return
	}
	switch f.node.kind {
	case schemaFalse, schemaTrue:
		w.visited++
		w.visitFrame(f, callVisit)
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
	w.visitFrame(f, callVisit)
	w.followRef(obj, f, callVisit)
	w.walkApplicators(obj, f, callVisit)
}

func (w *schemaWalker) visitFrame(f walkFrame, callVisit bool) {
	if callVisit {
		w.visit(f.loc, f.propName, f.node, f.constraint(), f.instance)
		return
	}
	if f.inspect {
		cueLoc, cueName := f.cueSite()
		w.visit(cueLoc, cueName, f.node, f.constraint(), f.instance)
	}
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
		instance: f.instance,
		loc:      f.loc,
		propName: f.propName,
		depth:    f.depth + 1,
		inspect:  f.inspect,
		cueLoc:   f.cueLoc,
		cueName:  f.cueName,
	}, callVisit)
	delete(w.activeRefs, ref)
}

func (w *schemaWalker) walkApplicators(obj map[string]any, f walkFrame, inspectBranches bool) {
	loc := f.loc
	depth := f.depth
	// Nested properties belong to this schema when the frame is already a
	// named property's value ($ref target, items object, etc.). Composition
	// inspect of a property value keeps the enclosing object so sibling
	// allOf/anyOf constraints still apply at the cue site.
	nestedObject := f.objectInstance()
	if f.propName != "" {
		nestedObject = f.node
	}
	composeInst := f.instance
	if composeInst.kind == schemaInvalid {
		composeInst = f.objectInstance()
	}
	declared, _ := asObject(obj["properties"])
	if declared != nil {
		for _, name := range sortedKeys(declared) {
			child, ok := asSchema(declared[name])
			if !ok {
				continue
			}
			w.enter(walkFrame{
				node:     child,
				loc:      loc + ".properties." + name,
				propName: name,
				depth:    depth + 1,
				instance: nestedObject,
			}, true)
		}
	}
	for _, name := range requiredOnlyNames(obj, declared) {
		w.enter(walkFrame{
			node:     schemaForUndeclaredProperty(obj, name),
			loc:      loc + ".properties." + name,
			propName: name,
			depth:    depth + 1,
			instance: nestedObject,
		}, true)
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
	parent := f.constraint()
	switch items := obj["items"].(type) {
	case []any:
		w.walkSchemaList(items, loc+".items", "items", depth, parent)
	default:
		if child, ok := asSchema(items); ok {
			w.enter(walkFrame{
				node:     child,
				origin:   parent,
				loc:      loc + ".items",
				propName: "items",
				depth:    depth + 1,
			}, true)
		}
	}
	if prefix, ok := obj["prefixItems"].([]any); ok {
		w.walkSchemaList(prefix, loc+".prefixItems", "items", depth, parent)
	}
	if _, ok := obj["items"].([]any); ok {
		// additionalItems only constrains elements for the legacy tuple
		// form (items as an array); otherwise the keyword is ignored.
		if child, ok := asSchema(obj["additionalItems"]); ok {
			w.enter(walkFrame{
				node:     child,
				origin:   parent,
				loc:      loc + ".additionalItems",
				propName: "items",
				depth:    depth + 1,
			}, true)
		}
	}
	for _, key := range []string{"allOf", "anyOf", "oneOf"} {
		arr, ok := obj[key].([]any)
		if !ok {
			continue
		}
		inspect := inspectBranches || f.inspect
		cueLoc, cueName := f.loc, f.propName
		if f.inspect && f.cueLoc != "" {
			cueLoc, cueName = f.cueLoc, f.cueName
		}
		for i, item := range arr {
			child, ok := asSchema(item)
			if !ok {
				continue
			}
			w.enter(walkFrame{
				node:     child,
				origin:   f.constraint(),
				instance: composeInst,
				loc:      fmt.Sprintf("%s.%s[%d]", loc, key, i),
				propName: "",
				depth:    depth + 1,
				inspect:  inspect,
				cueLoc:   cueLoc,
				cueName:  cueName,
			}, false)
		}
	}
	if deps, ok := asObject(obj["dependentSchemas"]); ok {
		for _, name := range sortedKeys(deps) {
			child, ok := asSchema(deps[name])
			if !ok {
				continue
			}
			w.enter(walkFrame{
				node:     child,
				origin:   composeInst,
				instance: composeInst,
				loc:      loc + ".dependentSchemas." + name,
				propName: "",
				depth:    depth + 1,
			}, false)
		}
	}
	// then/else/if describe conditionally accepted instances, but not
	// describes rejected ones, so its properties are never arguments.
	for _, key := range []string{"then", "else", "if"} {
		child, ok := asSchema(obj[key])
		if !ok {
			continue
		}
		w.enter(walkFrame{
			node:     child,
			origin:   composeInst,
			instance: composeInst,
			loc:      loc + "." + key,
			propName: "",
			depth:    depth + 1,
		}, false)
	}
}

func (w *schemaWalker) walkSchemaList(items []any, loc, propName string, depth int, origin schemaNode) {
	for i, item := range items {
		child, ok := asSchema(item)
		if !ok {
			continue
		}
		w.enter(walkFrame{
			node:     child,
			origin:   origin,
			loc:      fmt.Sprintf("%s[%d]", loc, i),
			propName: propName,
			depth:    depth + 1,
		}, true)
	}
}

// requiredOnlyNames returns required property names that have no properties
// entry, so they are still accepted arguments without a declared schema.
func requiredOnlyNames(obj, declared map[string]any) []string {
	arr, ok := obj["required"].([]any)
	if !ok {
		return nil
	}
	seen := map[string]struct{}{}
	var names []string
	for _, item := range arr {
		name, ok := item.(string)
		if !ok || name == "" {
			continue
		}
		if declared != nil {
			if _, exists := declared[name]; exists {
				continue
			}
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// schemaForUndeclaredProperty is the schema that applies to a required name
// that has no properties entry: matching patternProperties, else
// additionalProperties (including boolean false), else an empty object.
func schemaForUndeclaredProperty(obj map[string]any, name string) schemaNode {
	var matched []schemaNode
	if patterns, ok := asObject(obj["patternProperties"]); ok {
		for _, pat := range sortedKeys(patterns) {
			if !patternMatchesName(pat, name) {
				continue
			}
			child, ok := asSchema(patterns[pat])
			if ok {
				matched = append(matched, child)
			}
		}
	}
	switch len(matched) {
	case 1:
		return matched[0]
	case 0:
	default:
		arr := make([]any, len(matched))
		for i, m := range matched {
			switch m.kind {
			case schemaTrue:
				arr[i] = true
			case schemaFalse:
				arr[i] = false
			default:
				arr[i] = m.obj
			}
		}
		return schemaNode{kind: schemaObject, obj: map[string]any{"allOf": arr}}
	}
	if add, ok := obj["additionalProperties"]; ok {
		if child, ok := asSchema(add); ok {
			return child
		}
	}
	return schemaNode{kind: schemaObject, obj: map[string]any{}}
}

func patternMatchesName(pat, name string) bool {
	re, err := regexp.Compile(pat)
	if err != nil {
		return false
	}
	return re.MatchString(name)
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
		// RFC 6901 section 6: the URI fragment is percent-decoded before
		// JSON Pointer tokenization, so an encoded slash (%2F) is a token
		// separator. A literal slash inside a key is written ~1 instead.
		decoded, err := url.PathUnescape(ref[1:])
		if err != nil {
			return "", false
		}
		return decoded, true
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
		token, ok := decodeJSONPointerToken(part)
		if !ok {
			return schemaNode{}, false
		}
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

func decodeJSONPointerToken(token string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(token); i++ {
		if token[i] != '~' {
			b.WriteByte(token[i])
			continue
		}
		if i+1 >= len(token) {
			return "", false
		}
		switch token[i+1] {
		case '0':
			b.WriteByte('~')
		case '1':
			b.WriteByte('/')
		default:
			return "", false
		}
		i++
	}
	return b.String(), true
}

func (w *schemaWalker) noteTruncation(limit string) {
	w.truncated = true
	if w.limitHit == "" {
		w.limitHit = limit
	}
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
