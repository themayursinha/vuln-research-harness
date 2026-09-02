package mcpreview

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestReviewCategories(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantCat  string
		wantTool string
		wantLoc  string
		absent   string
	}{
		{
			name:     "privileged name",
			input:    toolsJSON(`{"name":"exec_query","inputSchema":{}}`),
			wantCat:  CategoryPrivilegedName,
			wantTool: "exec_query",
			wantLoc:  "name",
		},
		{
			name:     "boundary description",
			input:    toolsJSON(`{"name":"alpha","description":"Reads files from disk","inputSchema":{}}`),
			wantCat:  CategoryBoundaryDescription,
			wantTool: "alpha",
			wantLoc:  "description",
		},
		{
			name:     "unconstrained url",
			input:    toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"type":"string"}}}}`),
			wantCat:  CategoryUnconstrainedURL,
			wantTool: "alpha",
			wantLoc:  "inputSchema.properties.url",
		},
		{
			name:     "unconstrained path",
			input:    toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"path":{"type":"string"}}}}`),
			wantCat:  CategoryUnconstrainedPath,
			wantTool: "alpha",
			wantLoc:  "inputSchema.properties.path",
		},
		{
			name:     "unconstrained command",
			input:    toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"command":{"type":"string"}}}}`),
			wantCat:  CategoryUnconstrainedCommand,
			wantTool: "alpha",
			wantLoc:  "inputSchema.properties.command",
		},
		{
			name:    "url format without scheme host or enum",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"target":{"type":"string","format":"uri"}}}}`),
			wantCat: CategoryUnconstrainedURL,
			wantLoc: "inputSchema.properties.target",
		},
		{
			name:    "vacuous url pattern is unconstrained",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"type":"string","pattern":".*"}}}}`),
			wantCat: CategoryUnconstrainedURL,
			wantLoc: "inputSchema.properties.url",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := mustReview(t, tt.input)
			h := findHypothesis(rep, tt.wantCat, tt.wantLoc)
			if h == nil {
				t.Fatalf("missing %s at %s in %+v", tt.wantCat, tt.wantLoc, rep.Hypotheses)
			}
			if tt.wantTool != "" && h.ToolName != tt.wantTool {
				t.Fatalf("tool_name=%q want %q", h.ToolName, tt.wantTool)
			}
			assertHypothesisTriage(t, *h)
		})
	}
}

func TestReviewConstrainedArgumentsProduceNoMatchingHypothesis(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		absent string
	}{
		{
			name:   "url enum",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"type":"string","enum":["https://example.invalid/a"]}}}}`),
			absent: CategoryUnconstrainedURL,
		},
		{
			name:   "url const",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"type":"string","const":"https://example.invalid/a"}}}}`),
			absent: CategoryUnconstrainedURL,
		},
		{
			name:   "url hostname constraint",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"type":"string","hostname":"example.invalid"}}}}`),
			absent: CategoryUnconstrainedURL,
		},
		{
			name:   "url scheme constraint",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"webhook":{"type":"string","scheme":"https"}}}}`),
			absent: CategoryUnconstrainedURL,
		},
		{
			name:   "url restrictive pattern",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"type":"string","pattern":"^https://"}}}}`),
			absent: CategoryUnconstrainedURL,
		},
		{
			name:   "path root",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"path":{"type":"string","root":"/tmp/sandbox"}}}}`),
			absent: CategoryUnconstrainedPath,
		},
		{
			name:   "path pattern",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"file":{"type":"string","pattern":"^/tmp/sandbox/"}}}}`),
			absent: CategoryUnconstrainedPath,
		},
		{
			name:   "path enum",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"path":{"type":"string","enum":["/tmp/a"]}}}}`),
			absent: CategoryUnconstrainedPath,
		},
		{
			name:   "command enum",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"command":{"type":"string","enum":["status"]}}}}`),
			absent: CategoryUnconstrainedCommand,
		},
		{
			name:   "command pattern",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"cmd":{"type":"string","pattern":"^(status|health)$"}}}}`),
			absent: CategoryUnconstrainedCommand,
		},
		{
			name:   "empty enum is not a constraint",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"type":"string","enum":[]}}}}`),
			absent: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := mustReview(t, tt.input)
			if tt.absent == "" {
				if findHypothesis(rep, CategoryUnconstrainedURL, "inputSchema.properties.url") == nil {
					t.Fatalf("empty enum should still be unconstrained: %+v", rep.Hypotheses)
				}
				return
			}
			if hasCategory(rep, tt.absent) {
				t.Fatalf("constrained field produced %s: %+v", tt.absent, rep.Hypotheses)
			}
		})
	}
}

func TestReviewPluralArgumentNames(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantCat string
		wantLoc string
	}{
		{
			name:    "urls array with plain-string items",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"urls":{"type":"array","items":{"type":"string"}}}}}`),
			wantCat: CategoryUnconstrainedURL,
			wantLoc: "inputSchema.properties.urls",
		},
		{
			name:    "webhooks array with plain-string items",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"webhooks":{"type":"array","items":{"type":"string"}}}}}`),
			wantCat: CategoryUnconstrainedURL,
			wantLoc: "inputSchema.properties.webhooks",
		},
		{
			name:    "endpoints array with plain-string items",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"endpoints":{"type":"array","items":{"type":"string"}}}}}`),
			wantCat: CategoryUnconstrainedURL,
			wantLoc: "inputSchema.properties.endpoints",
		},
		{
			name:    "directories array with plain-string items",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"directories":{"type":"array","items":{"type":"string"}}}}}`),
			wantCat: CategoryUnconstrainedPath,
			wantLoc: "inputSchema.properties.directories",
		},
		{
			name:    "binaries array with plain-string items",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"binaries":{"type":"array","items":{"type":"string"}}}}}`),
			wantCat: CategoryUnconstrainedCommand,
			wantLoc: "inputSchema.properties.binaries",
		},
		{
			name:    "files array still matches via regular plural",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"files":{"type":"array","items":{"type":"string"}}}}}`),
			wantCat: CategoryUnconstrainedPath,
			wantLoc: "inputSchema.properties.files",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := mustReview(t, tt.input)
			h := findHypothesis(rep, tt.wantCat, tt.wantLoc)
			if h == nil {
				t.Fatalf("missing %s at %s in %+v", tt.wantCat, tt.wantLoc, rep.Hypotheses)
			}
			assertHypothesisTriage(t, *h)
		})
	}
}

func TestSingularToken(t *testing.T) {
	tests := []struct{ in, want string }{
		{in: "urls", want: "url"},
		{in: "webhooks", want: "webhook"},
		{in: "endpoints", want: "endpoint"},
		{in: "directories", want: "directory"},
		{in: "binaries", want: "binary"},
		{in: "libraries", want: "library"},
		{in: "entries", want: "entry"},
		{in: "files", want: "file"},
		{in: "url", want: "url"},
		{in: "s", want: "s"},
	}
	for _, tt := range tests {
		if got := singularToken(tt.in); got != tt.want {
			t.Fatalf("singularToken(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestReviewNestedProperties(t *testing.T) {
	input := toolsJSON(`{"name":"alpha","inputSchema":{"type":"object","properties":{"outer":{"type":"object","properties":{"callback_url":{"type":"string"},"nested":{"type":"object","properties":{"path":{"type":"string"}}}}}}}}`)
	rep := mustReview(t, input)
	if findHypothesis(rep, CategoryUnconstrainedURL, "inputSchema.properties.outer.properties.callback_url") == nil {
		t.Fatalf("nested url missed: %+v", rep.Hypotheses)
	}
	if findHypothesis(rep, CategoryUnconstrainedPath, "inputSchema.properties.outer.properties.nested.properties.path") == nil {
		t.Fatalf("nested path missed: %+v", rep.Hypotheses)
	}
}

func TestReviewArrayItemsAndDefs(t *testing.T) {
	input := toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"urls":{"type":"array","items":{"type":"string","format":"uri"}}},"$defs":{"Command":{"type":"string","description":"shell to spawn"}}}}`)
	rep := mustReview(t, input)
	if findHypothesis(rep, CategoryUnconstrainedURL, "inputSchema.properties.urls.items") == nil {
		t.Fatalf("items format uri missed: %+v", rep.Hypotheses)
	}
	if findHypothesis(rep, CategoryUnconstrainedCommand, "inputSchema.$defs.Command") != nil {
		t.Fatalf("unreferenced $defs must not be an argument location: %+v", rep.Hypotheses)
	}
}

func TestReviewMalformedInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "array root", input: `[]`},
		{name: "not json", input: `{`},
		{name: "missing tools", input: `{"nope":[]}`},
		{name: "tools object", input: `{"tools":{}}`},
		{name: "trailing json", input: `{"tools":[]}{}`},
		{name: "missing name", input: `{"tools":[{"inputSchema":{}}]}`},
		{name: "empty name", input: `{"tools":[{"name":"","inputSchema":{}}]}`},
		{name: "blank name", input: `{"tools":[{"name":"  ","inputSchema":{}}]}`},
		{name: "null schema", input: `{"tools":[{"name":"alpha","inputSchema":null}]}`},
		{name: "array schema", input: `{"tools":[{"name":"alpha","inputSchema":[]}]}`},
		{name: "missing schema", input: `{"tools":[{"name":"alpha"}]}`},
		{name: "true schema", input: `{"tools":[{"name":"alpha","inputSchema":true}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Review([]byte(tt.input)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestReviewUnknownKeywordsAccepted(t *testing.T) {
	input := toolsJSON(`{"name":"alpha","inputSchema":{"type":"object","xCustom":{"ignored":1},"unevaluatedProperties":false,"dependentSchemas":{"a":{}}}}`)
	rep := mustReview(t, input)
	if len(rep.Hypotheses) != 0 {
		t.Fatalf("unknown keywords should not create hypotheses: %+v", rep.Hypotheses)
	}
}

func TestReviewEmptyTools(t *testing.T) {
	rep := mustReview(t, `{"tools":[]}`)
	if rep.Kind != ReportKind || rep.Disclaimer != Disclaimer {
		t.Fatalf("unexpected report header: %+v", rep)
	}
	if rep.Hypotheses == nil || len(rep.Hypotheses) != 0 {
		t.Fatalf("empty tools should yield empty slice, got %#v", rep.Hypotheses)
	}
	out, err := Encode(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`"hypotheses":[]`)) {
		t.Fatalf("hypotheses not encoded as []: %s", out)
	}
}

func TestReviewDedupAndDeterministicOrder(t *testing.T) {
	input := `{"tools":[
		{"name":"zeta_exec","description":"file file files","inputSchema":{"properties":{"url":{"type":"string"},"path":{"type":"string"}}}},
		{"name":"alpha_write","inputSchema":{"properties":{"command":{"type":"string"}}}}
	]}`
	rep := mustReview(t, input)
	if len(rep.Hypotheses) < 2 {
		t.Fatalf("expected multiple hypotheses, got %+v", rep.Hypotheses)
	}
	if rep.Hypotheses[0].ToolName != "alpha_write" {
		t.Fatalf("tools not sorted: first=%q", rep.Hypotheses[0].ToolName)
	}
	var lastTool, lastCat, lastLoc string
	seen := map[string]struct{}{}
	for _, h := range rep.Hypotheses {
		key := h.ToolName + "\n" + h.Category + "\n" + h.Location
		if _, ok := seen[key]; ok {
			t.Fatalf("duplicate hypothesis key %q", key)
		}
		seen[key] = struct{}{}
		if lastTool != "" {
			if h.ToolName < lastTool {
				t.Fatalf("tool order %q after %q", h.ToolName, lastTool)
			}
			if h.ToolName == lastTool && categoryOrder[h.Category] < categoryOrder[lastCat] {
				t.Fatalf("category order %q after %q", h.Category, lastCat)
			}
			if h.ToolName == lastTool && h.Category == lastCat && h.Location < lastLoc {
				t.Fatalf("location order %q after %q", h.Location, lastLoc)
			}
		}
		lastTool, lastCat, lastLoc = h.ToolName, h.Category, h.Location
		assertHypothesisTriage(t, h)
	}
	desc := findHypothesis(rep, CategoryBoundaryDescription, "description")
	if desc == nil {
		t.Fatal("expected deduped boundary description")
	}
	if desc.MatchedText != "file, files" {
		t.Fatalf("matched text not deduped: %q", desc.MatchedText)
	}

	reordered := `{"tools":[
		{"name":"alpha_write","inputSchema":{"properties":{"command":{"type":"string"}}}},
		{"name":"zeta_exec","description":"file file files","inputSchema":{"properties":{"path":{"type":"string"},"url":{"type":"string"}}}}
	]}`
	rep2 := mustReview(t, reordered)
	a, err := Encode(rep)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(rep2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("output not byte-stable:\n%s\n%s", a, b)
	}
}

func TestReviewSanitizedFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/sanitized-tools.json")
	if err != nil {
		t.Fatal(err)
	}
	rep := mustReview(t, string(data))
	if findHypothesis(rep, CategoryPrivilegedName, "name") == nil {
		t.Fatal("fixture missing privileged name")
	}
	if findHypothesis(rep, CategoryBoundaryDescription, "description") == nil {
		t.Fatal("fixture missing boundary description")
	}
	if findHypothesis(rep, CategoryUnconstrainedURL, "inputSchema.properties.url") == nil {
		t.Fatal("fixture missing unconstrained url")
	}
	if findHypothesis(rep, CategoryUnconstrainedPath, "inputSchema.properties.path") == nil {
		t.Fatal("fixture missing unconstrained path")
	}
	if findHypothesis(rep, CategoryUnconstrainedCommand, "inputSchema.properties.command") == nil {
		t.Fatal("fixture missing unconstrained command")
	}
	for _, h := range rep.Hypotheses {
		if h.ToolName == "safe_echo" {
			t.Fatalf("constrained safe_echo produced hypothesis: %+v", h)
		}
		assertHypothesisTriage(t, h)
	}
}

func TestEncodeStableAndHypothesesOnly(t *testing.T) {
	rep := mustReview(t, toolsJSON(`{"name":"exec_query","inputSchema":{"properties":{"url":{"type":"string"}}}}`))
	a, err := Encode(rep)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("Encode is not byte-stable")
	}
	if !bytes.HasSuffix(a, []byte("\n")) {
		t.Fatal("Encode missing trailing newline")
	}
	var parsed Report
	if err := json.Unmarshal(a, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Kind != ReportKind || parsed.Disclaimer != Disclaimer {
		t.Fatalf("unexpected header: %+v", parsed)
	}
	lower := strings.ToLower(string(a))
	if strings.Contains(string(a), `"findings"`) {
		t.Fatalf("report looks like a finding: %s", a)
	}
	if strings.Contains(lower, "confirmed vulnerability") && !strings.Contains(lower, "not a confirmed") {
		t.Fatalf("report labels a confirmed vulnerability: %s", a)
	}
}

func toolsJSON(tool string) string {
	return `{"tools":[` + tool + `]}`
}

func mustReview(t *testing.T, input string) Report {
	t.Helper()
	rep, err := Review([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func findHypothesis(rep Report, category, location string) *Hypothesis {
	for i := range rep.Hypotheses {
		h := &rep.Hypotheses[i]
		if h.Category == category && h.Location == location {
			return h
		}
	}
	return nil
}

func hasCategory(rep Report, category string) bool {
	for _, h := range rep.Hypotheses {
		if h.Category == category {
			return true
		}
	}
	return false
}

func assertHypothesisTriage(t *testing.T, h Hypothesis) {
	t.Helper()
	if h.ToolName == "" || h.Category == "" || h.Location == "" || h.MatchedText == "" || h.Rationale == "" {
		t.Fatalf("incomplete hypothesis: %+v", h)
	}
	if !strings.Contains(strings.ToLower(h.Rationale), "research triage") {
		t.Fatalf("rationale must stay triage-only: %q", h.Rationale)
	}
	if strings.Contains(strings.ToLower(h.Rationale), "confirmed vulnerability") && !strings.Contains(strings.ToLower(h.Rationale), "not a confirmed") {
		t.Fatalf("rationale labels a confirmed vulnerability: %q", h.Rationale)
	}
}
