// Package mcpreview is an offline, deterministic reviewer that turns sanitized
// MCP tool schemas into trust-boundary hypotheses. Output is research triage:
// it is never a vulnerability finding and never evidence.
package mcpreview

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	ReportKind = "trust_boundary_hypotheses"
	Disclaimer = "Research triage only. Hypotheses are not confirmed vulnerabilities or evidence."

	CategoryPrivilegedName       = "privileged_or_side_effecting_name"
	CategoryBoundaryDescription  = "boundary_crossing_description"
	CategoryUnconstrainedURL     = "unconstrained_url_argument"
	CategoryUnconstrainedPath    = "unconstrained_path_argument"
	CategoryUnconstrainedCommand = "unconstrained_command_argument"
)

var categoryOrder = map[string]int{
	CategoryPrivilegedName:       0,
	CategoryBoundaryDescription:  1,
	CategoryUnconstrainedURL:     2,
	CategoryUnconstrainedPath:    3,
	CategoryUnconstrainedCommand: 4,
}

// Report is a byte-stable JSON document of trust-boundary hypotheses.
type Report struct {
	Kind       string       `json:"kind"`
	Disclaimer string       `json:"disclaimer"`
	Hypotheses []Hypothesis `json:"hypotheses"`
	Truncated  bool         `json:"truncated,omitempty"`
	LimitHit   string       `json:"limit_hit,omitempty"`
}

// Hypothesis is one deterministic triage signal. It is not a confirmed finding.
type Hypothesis struct {
	ToolName    string `json:"tool_name"`
	Category    string `json:"category"`
	Location    string `json:"location"`
	MatchedText string `json:"matched_text"`
	Rationale   string `json:"rationale"`
}

type toolJSON struct {
	Name        *string         `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// Review inspects sanitized MCP tool schemas and returns sorted hypotheses.
// Malformed input, missing tool names, or non-object input schemas fail.
func Review(input []byte) (Report, error) {
	tools, err := parseTools(input)
	if err != nil {
		return Report{}, err
	}
	rep := newReporter()
	for i, tool := range tools {
		if tool.Name == nil || strings.TrimSpace(*tool.Name) == "" {
			return Report{}, fmt.Errorf("tool %d: name is required", i)
		}
		name := *tool.Name
		schema, err := requireObject(tool.InputSchema, fmt.Sprintf("tool %q inputSchema", name))
		if err != nil {
			return Report{}, err
		}
		reviewTool(rep, name, tool.Description, schema)
	}
	return rep.finish(), nil
}

// Encode serializes a report as compact JSON plus a trailing newline.
func Encode(report Report) ([]byte, error) {
	if report.Hypotheses == nil {
		report.Hypotheses = []Hypothesis{}
	}
	data, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func parseTools(input []byte) ([]toolJSON, error) {
	trimmed := bytes.TrimSpace(input)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("malformed input: empty document")
	}
	if trimmed[0] != '{' {
		return nil, fmt.Errorf("malformed input: expected a JSON object containing tools")
	}
	dec := json.NewDecoder(bytes.NewReader(input))
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("malformed input: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("malformed input: trailing JSON after tools document")
	}
	toolsRaw, ok := raw["tools"]
	if !ok {
		return nil, fmt.Errorf("malformed input: missing tools")
	}
	toolsTrim := bytes.TrimSpace(toolsRaw)
	if len(toolsTrim) == 0 || toolsTrim[0] != '[' {
		return nil, fmt.Errorf("malformed input: tools must be a JSON array")
	}
	var tools []toolJSON
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return nil, fmt.Errorf("malformed input: %w", err)
	}
	return tools, nil
}

func requireObject(raw json.RawMessage, what string) (map[string]any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, fmt.Errorf("%s must be a JSON object", what)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if obj == nil {
		obj = map[string]any{}
	}
	return obj, nil
}

func reviewTool(rep *reporter, name, description string, schema map[string]any) {
	if token, ok := privilegedNameToken(name); ok {
		rep.add(Hypothesis{
			ToolName:    name,
			Category:    CategoryPrivilegedName,
			Location:    "name",
			MatchedText: token,
			Rationale:   "Tool name suggests a privileged or side-effecting capability (research triage, not a confirmed vulnerability).",
		})
	}
	if matched := boundaryMatches(description); len(matched) > 0 {
		rep.add(Hypothesis{
			ToolName:    name,
			Category:    CategoryBoundaryDescription,
			Location:    "description",
			MatchedText: strings.Join(matched, ", "),
			Rationale:   "Description refers to a filesystem, process, credential, or external-resource boundary (research triage, not a confirmed vulnerability).",
		})
	}
	eval := newConstraintEval(schema)
	truncated, limitHit := walkSchema(schema, "inputSchema", func(loc, propName string, node, origin, instance schemaNode) {
		keywords := node.keywords()
		if desc, _ := keywords["description"].(string); desc != "" {
			if matched := boundaryMatches(desc); len(matched) > 0 {
				rep.add(Hypothesis{
					ToolName:    name,
					Category:    CategoryBoundaryDescription,
					Location:    loc + ".description",
					MatchedText: strings.Join(matched, ", "),
					Rationale:   "Description refers to a filesystem, process, credential, or external-resource boundary (research triage, not a confirmed vulnerability).",
				})
			}
		}
		if cue, ok := urlCue(propName, keywords); ok && eval.unconstrained(node, origin, instance, propName, constraintURL) {
			rep.add(Hypothesis{
				ToolName:    name,
				Category:    CategoryUnconstrainedURL,
				Location:    loc,
				MatchedText: cue,
				Rationale:   "URL-like argument has no scheme, host, or enum constraint (research triage, not a confirmed vulnerability).",
			})
		}
		if cue, ok := pathCue(propName, keywords, description); ok && eval.unconstrained(node, origin, instance, propName, constraintPath) {
			rep.add(Hypothesis{
				ToolName:    name,
				Category:    CategoryUnconstrainedPath,
				Location:    loc,
				MatchedText: cue,
				Rationale:   "Path-like argument has no root or enum constraint (research triage, not a confirmed vulnerability).",
			})
		}
		if cue, ok := commandCue(propName, keywords); ok && eval.unconstrained(node, origin, instance, propName, constraintCommand) {
			rep.add(Hypothesis{
				ToolName:    name,
				Category:    CategoryUnconstrainedCommand,
				Location:    loc,
				MatchedText: cue,
				Rationale:   "Command-like argument has no enum or const constraint (research triage, not a confirmed vulnerability).",
			})
		}
	})
	rep.noteTruncation(truncated, limitHit)
}

type reporter struct {
	seen      map[string]struct{}
	items     []Hypothesis
	truncated bool
	limitHit  string
}

func newReporter() *reporter {
	return &reporter{seen: map[string]struct{}{}}
}

func (r *reporter) add(h Hypothesis) {
	key := h.ToolName + "\n" + h.Category + "\n" + h.Location
	if _, exists := r.seen[key]; exists {
		return
	}
	r.seen[key] = struct{}{}
	r.items = append(r.items, h)
}

func (r *reporter) noteTruncation(truncated bool, limitHit string) {
	if !truncated {
		return
	}
	r.truncated = true
	if r.limitHit == "" {
		r.limitHit = limitHit
	}
}

func (r *reporter) finish() Report {
	items := r.items
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.ToolName != b.ToolName {
			return a.ToolName < b.ToolName
		}
		ao, bo := categoryOrder[a.Category], categoryOrder[b.Category]
		if ao != bo {
			return ao < bo
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		return a.MatchedText < b.MatchedText
	})
	if items == nil {
		items = []Hypothesis{}
	}
	return Report{
		Kind:       ReportKind,
		Disclaimer: Disclaimer,
		Hypotheses: items,
		Truncated:  r.truncated,
		LimitHit:   r.limitHit,
	}
}
