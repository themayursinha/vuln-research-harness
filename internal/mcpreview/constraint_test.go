package mcpreview

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestReviewCompositionAndLocalRefs(t *testing.T) {
	type locCat struct {
		cat string
		loc string
	}
	const urlLoc = "inputSchema.properties.url"
	const pathLoc = "inputSchema.properties.path"
	const cmdLoc = "inputSchema.properties.command"
	const webhookLoc = "inputSchema.properties.webhook"

	tests := []struct {
		name    string
		input   string
		present []locCat
		absent  []locCat
	}{
		{
			name:   "url constrained via allOf enum",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"allOf":[{"type":"string"},{"enum":["https://example.invalid"]}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "url unconstrained via allOf type only",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"allOf":[{"type":"string"},{"minLength":1}]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "url unconstrained via mixed anyOf hostname",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"anyOf":[{"type":"string"},{"hostname":"example.invalid"}]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "url unconstrained via anyOf type only",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"anyOf":[{"type":"string"},{"type":"null"}]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "url constrained via oneOf pattern",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"oneOf":[{"type":"string","pattern":"^https://"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "url unconstrained via oneOf vacuous pattern",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"oneOf":[{"type":"string","pattern":".*"}]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "url constrained via nested allOf anyOf",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"allOf":[{"anyOf":[{"oneOf":[{"const":"https://example.invalid"}]}]}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "path constrained via allOf root",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"path":{"allOf":[{"type":"string"},{"root":"/tmp/sandbox"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedPath, pathLoc}},
		},
		{
			name:    "path unconstrained via allOf type only",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"path":{"allOf":[{"type":"string"}]}}}}`),
			present: []locCat{{CategoryUnconstrainedPath, pathLoc}},
		},
		{
			name:   "command constrained via anyOf enum",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"command":{"anyOf":[{"enum":["status"]}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedCommand, cmdLoc}},
		},
		{
			name:    "command unconstrained via oneOf type only",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"command":{"oneOf":[{"type":"string"}]}}}}`),
			present: []locCat{{CategoryUnconstrainedCommand, cmdLoc}},
		},
		{
			name:   "url constrained via local $defs ref",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/HttpsURL"}},"$defs":{"HttpsURL":{"type":"string","enum":["https://example.invalid"]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "path constrained via local definitions ref",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"path":{"$ref":"#/definitions/SandboxPath"}},"definitions":{"SandboxPath":{"type":"string","root":"/tmp/sandbox"}}}}`),
			absent: []locCat{{CategoryUnconstrainedPath, pathLoc}},
		},
		{
			name:   "command constrained via nested $defs refs",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"command":{"$ref":"#/$defs/A"}},"$defs":{"A":{"$ref":"#/$defs/B"},"B":{"type":"string","enum":["status"]}}}}`),
			absent: []locCat{{CategoryUnconstrainedCommand, cmdLoc}},
		},
		{
			name:   "url constrained via escaped slash pointer token",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/foo~1bar"}},"$defs":{"foo/bar":{"type":"string","hostname":"example.invalid"}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "url constrained via escaped tilde pointer token",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/foo~0bar"}},"$defs":{"foo~bar":{"type":"string","scheme":"https"}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "url constrained via combined escaped pointer tokens",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/foo~0~1bar"}},"$defs":{"foo~/bar":{"enum":["https://example.invalid"]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "url constrained via pointer into allOf array",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"allOf":[{"enum":["https://example.invalid"]}],"properties":{"url":{"$ref":"#/allOf/0"}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "unresolved local ref is not a constraint",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/Missing"}},"$defs":{"Other":{"enum":["https://example.invalid"]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "external http ref is not a constraint",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"https://example.invalid/schema.json"}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "external ref with fragment is not a constraint",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"https://example.invalid/schema.json#/$defs/Url"}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "relative file ref is not a constraint",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"path":{"$ref":"other.json#/definitions/Path"}}}}`),
			present: []locCat{{CategoryUnconstrainedPath, pathLoc}},
		},
		{
			name:    "anchor ref is not a json pointer constraint",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#HttpsURL"}},"$defs":{"HttpsURL":{"enum":["https://example.invalid"]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "malformed non-string ref is not a constraint",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":1}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "cyclic refs terminate without counting as a constraint",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/A"}},"$defs":{"A":{"$ref":"#/$defs/B"},"B":{"$ref":"#/$defs/A"}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "cyclic ref still honors a direct enum on the cycle node",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/A"}},"$defs":{"A":{"enum":["https://example.invalid"],"allOf":[{"$ref":"#/$defs/A"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "self ref without other keywords is unconstrained",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"command":{"$ref":"#/$defs/Loop"}},"$defs":{"Loop":{"$ref":"#/$defs/Loop"}}}}`),
			present: []locCat{{CategoryUnconstrainedCommand, cmdLoc}},
		},
		{
			name:   "shallow nested allOf still finds constraint",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":` + wrapAllOf(`{"enum":["https://example.invalid"]}`, 8) + `}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "constraint past depth bound is not treated as evidence",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":` + wrapAllOf(`{"enum":["https://example.invalid"]}`, maxConstraintDepth+8) + `}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "constraint past visited bound is not treated as evidence",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":` + allOfPadding(maxVisitedNodes, `{"enum":["https://example.invalid"]}`) + `}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "sibling unconstrained url remains at property location",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"allOf":[{"enum":["https://example.invalid"]}]},"webhook":{"type":"string"}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, webhookLoc}},
			absent:  []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "constrained $ref preserves original property location",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/HttpsURL"},"webhook":{"type":"string"}},"$defs":{"HttpsURL":{"enum":["https://example.invalid"]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, webhookLoc}},
			absent:  []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "external ref sibling enum is still a constraint",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"https://example.invalid/schema.json","enum":["https://example.invalid"]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "unresolved ref sibling allOf enum is still a constraint",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"path":{"$ref":"#/$defs/Missing","allOf":[{"root":"/tmp/sandbox"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedPath, pathLoc}},
		},
		{
			name:   "url constrained via $ref to false",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/Denied"}},"$defs":{"Denied":false}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "path constrained via $ref to false",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"path":{"$ref":"#/$defs/Denied"}},"$defs":{"Denied":false}}}`),
			absent: []locCat{{CategoryUnconstrainedPath, pathLoc}},
		},
		{
			name:   "command constrained via $ref to false",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"command":{"$ref":"#/$defs/Denied"}},"$defs":{"Denied":false}}}`),
			absent: []locCat{{CategoryUnconstrainedCommand, cmdLoc}},
		},
		{
			name:   "url constrained via inline false",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":false}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "url constrained via allOf false",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"allOf":[false]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "url constrained via multi-hop $ref to false",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/A"}},"$defs":{"A":{"$ref":"#/$defs/Denied"},"Denied":false}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "url unconstrained via $ref to true",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/Any"}},"$defs":{"Any":true}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "url unconstrained via inline true",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":true}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "url unconstrained via allOf true",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"allOf":[true]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "sibling enum still constrains $ref to true",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/Any","enum":["https://example.invalid"]}},"$defs":{"Any":true}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "sibling allOf still constrains unresolved boolean-looking pointer",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#HttpsURL","enum":["https://example.invalid"]}},"$defs":{"HttpsURL":false}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "nested url behind $defs is at referring property path",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"config":{"$ref":"#/$defs/Endpoint"}},"$defs":{"Endpoint":{"type":"object","properties":{"url":{"type":"string"}}}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.config.properties.url"}},
			absent:  []locCat{{CategoryUnconstrainedURL, "inputSchema.$defs.Endpoint.properties.url"}, {CategoryUnconstrainedURL, "inputSchema.$defs.Endpoint"}},
		},
		{
			name:    "nested path behind definitions is at referring property path",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"config":{"$ref":"#/definitions/Sandbox"}},"definitions":{"Sandbox":{"type":"object","properties":{"path":{"type":"string"}}}}}}`),
			present: []locCat{{CategoryUnconstrainedPath, "inputSchema.properties.config.properties.path"}},
			absent:  []locCat{{CategoryUnconstrainedPath, "inputSchema.definitions.Sandbox.properties.path"}},
		},
		{
			name:    "multi-hop nested command is at referring property path",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"job":{"$ref":"#/$defs/A"}},"$defs":{"A":{"$ref":"#/$defs/B"},"B":{"type":"object","properties":{"command":{"type":"string"}}}}}}`),
			present: []locCat{{CategoryUnconstrainedCommand, "inputSchema.properties.job.properties.command"}},
			absent:  []locCat{{CategoryUnconstrainedCommand, "inputSchema.$defs.B.properties.command"}, {CategoryUnconstrainedCommand, "inputSchema.$defs.A.properties.command"}},
		},
		{
			name:    "escaped pointer nested url stays at referring property path",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"config":{"$ref":"#/$defs/foo~1bar"}},"$defs":{"foo/bar":{"properties":{"url":{"type":"string"}}}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.config.properties.url"}},
			absent:  []locCat{{CategoryUnconstrainedURL, "inputSchema.$defs.foo/bar.properties.url"}},
		},
		{
			name:    "format cue on referenced schema is at referring property path",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"target":{"$ref":"#/$defs/URI"}},"$defs":{"URI":{"type":"string","format":"uri"}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.target"}},
			absent:  []locCat{{CategoryUnconstrainedURL, "inputSchema.$defs.URI"}},
		},
		{
			name:    "items $ref nested url is at items path not $defs",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"urls":{"type":"array","items":{"$ref":"#/$defs/Endpoint"}}},"$defs":{"Endpoint":{"properties":{"url":{"type":"string"}}}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.urls.items.properties.url"}},
			absent:  []locCat{{CategoryUnconstrainedURL, "inputSchema.$defs.Endpoint.properties.url"}},
		},
		{
			name:   "unreferenced $defs nested url is not an argument location",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"note":{"type":"string"}},"$defs":{"Endpoint":{"properties":{"url":{"type":"string"}}}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, "inputSchema.$defs.Endpoint.properties.url"}, {CategoryUnconstrainedURL, "inputSchema.properties.note"}},
		},
		{
			name:    "external ref does not traverse $defs substitute locations",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"https://example.invalid/schema.json"}},"$defs":{"HttpsURL":{"properties":{"callback":{"type":"string","format":"uri"}}}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
			absent:  []locCat{{CategoryUnconstrainedURL, "inputSchema.$defs.HttpsURL"}, {CategoryUnconstrainedURL, "inputSchema.$defs.HttpsURL.properties.callback"}},
		},
		{
			name:    "cyclic refs do not emit definition-relative nested arguments",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/A"}},"$defs":{"A":{"$ref":"#/$defs/B"},"B":{"$ref":"#/$defs/A","properties":{"webhook":{"type":"string"}}}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}, {CategoryUnconstrainedURL, "inputSchema.properties.url.properties.webhook"}},
			absent:  []locCat{{CategoryUnconstrainedURL, "inputSchema.$defs.B.properties.webhook"}},
		},
		{
			name:   "referenced nested url with enum is constrained at origin",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"config":{"$ref":"#/$defs/Endpoint"}},"$defs":{"Endpoint":{"properties":{"url":{"enum":["https://example.invalid"]}}}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.config.properties.url"}, {CategoryUnconstrainedURL, "inputSchema.$defs.Endpoint.properties.url"}},
		},
		{
			name:   "referenced nesting past depth bound emits no definition-relative location",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"config":{"$ref":"#/$defs/Deep"}},"$defs":{"Deep":` + wrapNestedProperty(`{"properties":{"url":{"type":"string"}}}`, maxConstraintDepth+8) + `}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, "inputSchema.$defs.Deep.properties.url"}, {CategoryUnconstrainedURL, "inputSchema.$defs.Deep.properties.n.properties.url"}},
		},
		{
			name:    "oneOf mixed constrained and unconstrained string is unconstrained",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"oneOf":[{"type":"string","enum":["https://example.invalid"]},{"type":"string"}]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "oneOf every branch constrains",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"oneOf":[{"enum":["https://example.invalid"]},{"const":"https://other.invalid"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "anyOf mixed constrained and unconstrained string is unconstrained",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"anyOf":[{"type":"string","hostname":"example.invalid"},{"type":"string"}]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "anyOf every branch constrains",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"anyOf":[{"enum":["https://example.invalid"]},{"hostname":"example.invalid"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "allOf with one constraining branch stays constrained",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"allOf":[{"type":"string"},{"enum":["https://example.invalid"]}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "anyOf constrained string plus null is constrained",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"anyOf":[{"type":"string","enum":["https://example.invalid"]},{"type":"null"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "oneOf constrained string plus null is constrained",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"oneOf":[{"type":"string","const":"https://example.invalid"},{"type":"null"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "anyOf constrained string plus boolean is constrained",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"anyOf":[{"enum":["https://example.invalid"]},{"type":"boolean"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "anyOf constrained ref plus null ref is constrained",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"anyOf":[{"$ref":"#/$defs/HttpsURL"},{"$ref":"#/$defs/Null"}]}},"$defs":{"HttpsURL":{"type":"string","enum":["https://example.invalid"]},"Null":{"type":"null"}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "anyOf constrained string plus unconstrained string still emits",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"anyOf":[{"type":"string","enum":["https://example.invalid"]},{"type":"string"}]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "nullable unconstrained urls array remains unconstrained",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"urls":{"anyOf":[{"type":"array","items":{"type":"string"}},{"type":"null"}]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.urls"}},
		},
		{
			name:    "format uri cue on allOf branch is at the property location",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"target":{"allOf":[{"type":"string","format":"uri"}]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.target"}},
			absent:  []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.target.allOf[0]"}},
		},
		{
			name:    "boundary description on oneOf branch is at the property location",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"target":{"oneOf":[{"type":"string","description":"Reads files from disk"}]}}}}`),
			present: []locCat{{CategoryBoundaryDescription, "inputSchema.properties.target.description"}},
		},
		{
			name:    "format uri cue on anyOf branch is at the property location",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"target":{"anyOf":[{"type":"string","format":"uri-reference"}]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.target"}},
		},
		{
			name:    "nested allOf format uri cue is at the property location",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"target":{"allOf":[{"allOf":[{"type":"string","format":"uri"}]}]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.target"}},
			absent:  []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.target.allOf[0]"}, {CategoryUnconstrainedURL, "inputSchema.properties.target.allOf[0].allOf[0]"}},
		},
		{
			name:    "three-level nested anyOf boundary description is at the property location",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"target":{"anyOf":[{"anyOf":[{"anyOf":[{"type":"string","description":"Reads files from disk"}]}]}]}}}}`),
			present: []locCat{{CategoryBoundaryDescription, "inputSchema.properties.target.description"}},
		},
		{
			name:    "untyped urls items enum still emits",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"urls":{"items":{"enum":["https://safe.invalid"]}}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.urls"}},
		},
		{
			name:    "urls array plus string union items enum still emits",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"urls":{"type":["array","string"],"items":{"enum":["https://safe.invalid"]}}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.urls"}},
		},
		{
			name:   "urls array plus null union items enum stays constrained",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"urls":{"type":["array","null"],"items":{"enum":["https://safe.invalid"]}}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.urls"}},
		},
		{
			name:   "url allOf boolean is not a URL argument",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"allOf":[{"type":"boolean"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "url anyOf all non-viable is not a URL argument",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"anyOf":[{"type":"boolean"},{"type":"null"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "url oneOf all non-viable is not a URL argument",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"oneOf":[{"type":"boolean"},{"type":"integer"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "url allOf via local ref to boolean is not a URL argument",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"allOf":[{"$ref":"#/$defs/Flag"}]}},"$defs":{"Flag":{"type":"boolean"}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "url ref to allOf boolean is not a URL argument",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/W"}},"$defs":{"W":{"allOf":[{"type":"boolean"}]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "urls array boolean items is not a URL argument",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"urls":{"type":"array","items":{"type":"boolean"}}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.urls"}},
		},
		{
			name:   "urls array closed boolean prefix is not a URL argument",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"urls":{"type":"array","prefixItems":[{"type":"boolean"}],"items":false}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.urls"}},
		},
		{
			name:    "urls array open boolean prefix still emits",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"urls":{"type":"array","prefixItems":[{"type":"boolean"}]}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, "inputSchema.properties.urls"}},
		},
		{
			name:   "url constrained via percent-encoded local ref",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/with%20space"}},"$defs":{"with space":{"type":"string","enum":["https://example.invalid"]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:   "url constrained via percent plus tilde-escaped local ref",
			input:  toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/with%20space~1slash"}},"$defs":{"with space/slash":{"enum":["https://example.invalid"]}}}}`),
			absent: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
		{
			name:    "invalid percent-encoding is not a constraint",
			input:   toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"$ref":"#/$defs/%ZZ"}}}}`),
			present: []locCat{{CategoryUnconstrainedURL, urlLoc}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := mustReview(t, tt.input)
			for _, want := range tt.present {
				h := findHypothesis(rep, want.cat, want.loc)
				if h == nil {
					t.Fatalf("missing %s at %s in %+v", want.cat, want.loc, rep.Hypotheses)
				}
				assertHypothesisTriage(t, *h)
			}
			for _, skip := range tt.absent {
				if h := findHypothesis(rep, skip.cat, skip.loc); h != nil {
					t.Fatalf("unexpected %s at %s: %+v", skip.cat, skip.loc, h)
				}
			}
		})
	}
}

func TestDecodeJSONPointerTokenRFC6901(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{in: "foo", want: "foo"},
		{in: "foo~1bar", want: "foo/bar"},
		{in: "foo~0bar", want: "foo~bar"},
		{in: "foo~0~1bar", want: "foo~/bar"},
		{in: "~01", want: "~1"},
		{in: "~10", want: "/0"},
	}
	for _, tt := range tests {
		if got := decodeJSONPointerToken(tt.in); got != tt.want {
			t.Fatalf("decodeJSONPointerToken(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestResolveLocalRefBooleanObjectAndNonSchema(t *testing.T) {
	root := map[string]any{
		"$defs": map[string]any{
			"Denied": false,
			"Any":    true,
			"Obj":    map[string]any{"type": "string"},
			"List":   []any{map[string]any{"enum": []any{"https://example.invalid"}}},
			"Num":    1,
		},
	}
	n, ok := resolveLocalRef(root, "#/$defs/Denied")
	if !ok || n.kind != schemaFalse {
		t.Fatalf("Denied: node=%+v ok=%v", n, ok)
	}
	n, ok = resolveLocalRef(root, "#/$defs/Any")
	if !ok || n.kind != schemaTrue {
		t.Fatalf("Any: node=%+v ok=%v", n, ok)
	}
	n, ok = resolveLocalRef(root, "#/$defs/Obj")
	if !ok || n.kind != schemaObject || n.obj["type"] != "string" {
		t.Fatalf("Obj: node=%+v ok=%v", n, ok)
	}
	n, ok = resolveLocalRef(root, "#/$defs/List/0")
	if !ok || n.kind != schemaObject {
		t.Fatalf("List/0: node=%+v ok=%v", n, ok)
	}
	if _, ok := resolveLocalRef(root, "#/$defs/List"); ok {
		t.Fatal("array must not resolve as a schema node")
	}
	if _, ok := resolveLocalRef(root, "#/$defs/Num"); ok {
		t.Fatal("number must not resolve as a schema node")
	}
	if _, ok := resolveLocalRef(root, "#/$defs/Missing"); ok {
		t.Fatal("missing pointer must not resolve")
	}
	if _, ok := resolveLocalRef(root, "https://example.invalid/schema.json#/$defs/Obj"); ok {
		t.Fatal("external ref must not resolve")
	}
	if _, ok := resolveLocalRef(root, "#HttpsURL"); ok {
		t.Fatal("anchor ref must not resolve")
	}
}

func TestResolveLocalRefPercentDecoding(t *testing.T) {
	root := map[string]any{
		"$defs": map[string]any{
			"with space":       map[string]any{"type": "string"},
			"with space/slash": map[string]any{"type": "string"},
			"a%b":              map[string]any{"type": "string"},
		},
	}
	for _, tt := range []struct{ ref, key string }{
		{ref: "#/$defs/with%20space", key: "with space"},
		{ref: "#/$defs/with%20space~1slash", key: "with space/slash"},
		{ref: "#/$defs/a%25b", key: "a%b"},
	} {
		n, ok := resolveLocalRef(root, tt.ref)
		if !ok || n.kind != schemaObject {
			t.Fatalf("%s: node=%+v ok=%v", tt.ref, n, ok)
		}
	}
	if _, ok := resolveLocalRef(root, "#/$defs/%ZZ"); ok {
		t.Fatal("invalid percent-encoding must not resolve")
	}
	if _, ok := resolveLocalRef(root, "#/$defs/with%20space%"); ok {
		t.Fatal("truncated percent-encoding must not resolve")
	}
}

func TestLocalJSONPointerRejectsExternal(t *testing.T) {
	tests := []struct {
		ref string
		ok  bool
	}{
		{ref: "#", ok: true},
		{ref: "#/$defs/A", ok: true},
		{ref: "#/definitions/A", ok: true},
		{ref: "#HttpsURL", ok: false},
		{ref: "https://example.invalid/schema.json", ok: false},
		{ref: "https://example.invalid/schema.json#/$defs/A", ok: false},
		{ref: "other.json#/$defs/A", ok: false},
		{ref: "", ok: false},
		{ref: "/$defs/A", ok: false},
	}
	for _, tt := range tests {
		_, ok := localJSONPointer(tt.ref)
		if ok != tt.ok {
			t.Fatalf("localJSONPointer(%q) ok=%v want %v", tt.ref, ok, tt.ok)
		}
	}
}

func wrapAllOf(inner string, depth int) string {
	s := inner
	for i := 0; i < depth; i++ {
		s = `{"allOf":[` + s + `]}`
	}
	return s
}

func allOfPadding(n int, last string) string {
	var b strings.Builder
	b.WriteString(`{"allOf":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{}`)
	}
	if n > 0 {
		b.WriteByte(',')
	}
	b.WriteString(last)
	b.WriteString(`]}`)
	return b.String()
}

func wrapNestedProperty(inner string, depth int) string {
	s := inner
	for i := 0; i < depth; i++ {
		s = `{"type":"object","properties":{"n":` + s + `}}`
	}
	return s
}

func TestWrapHelpersProduceJSON(t *testing.T) {
	for _, s := range []string{
		wrapAllOf(`{"enum":["https://example.invalid"]}`, 3),
		allOfPadding(4, `{"enum":["https://example.invalid"]}`),
		wrapNestedProperty(`{"properties":{"url":{"type":"string"}}}`, 3),
		paddedNoteProperties(4, `"url":{"type":"string"}`),
	} {
		if !json.Valid([]byte(s)) {
			t.Fatalf("helper produced invalid JSON: %s", s)
		}
	}
}

func TestReviewReportsTraversalTruncation(t *testing.T) {
	t.Run("visited_nodes", func(t *testing.T) {
		input := toolsJSON(`{"name":"alpha","inputSchema":{"properties":` + paddedNoteProperties(maxVisitedNodes+8, `"file":{"type":"string"},"url":{"type":"string"}`) + `}}`)
		rep := mustReview(t, input)
		if !rep.Truncated {
			t.Fatalf("expected truncated report, got %+v", rep)
		}
		if rep.LimitHit != limitVisited {
			t.Fatalf("limit_hit=%q want %q", rep.LimitHit, limitVisited)
		}
		if findHypothesis(rep, CategoryUnconstrainedPath, "inputSchema.properties.file") == nil {
			t.Fatalf("hypothesis before cutoff omitted: %+v", rep.Hypotheses)
		}
		if findHypothesis(rep, CategoryUnconstrainedURL, "inputSchema.properties.url") != nil {
			t.Fatalf("url after cutoff should not be visited: %+v", rep.Hypotheses)
		}
		out, err := Encode(rep)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), `"truncated":true`) {
			t.Fatalf("Encode missing truncated signal: %s", out)
		}
		if !strings.Contains(string(out), `"limit_hit":"`+limitVisited+`"`) {
			t.Fatalf("Encode missing limit_hit: %s", out)
		}
	})
	t.Run("depth", func(t *testing.T) {
		input := toolsJSON(`{"name":"alpha","inputSchema":` + wrapNestedProperty(`{"properties":{"url":{"type":"string"}}}`, maxConstraintDepth+8) + `}`)
		rep := mustReview(t, input)
		if !rep.Truncated {
			t.Fatalf("expected truncated report, got %+v", rep)
		}
		if rep.LimitHit != limitDepth {
			t.Fatalf("limit_hit=%q want %q", rep.LimitHit, limitDepth)
		}
		if findHypothesis(rep, CategoryUnconstrainedURL, "inputSchema.properties.url") != nil {
			t.Fatalf("deep url should not be visited: %+v", rep.Hypotheses)
		}
		if hasCategory(rep, CategoryUnconstrainedURL) {
			t.Fatalf("unexpected url hypothesis without truncation context: %+v", rep.Hypotheses)
		}
	})
	t.Run("complete review omits truncation fields", func(t *testing.T) {
		rep := mustReview(t, toolsJSON(`{"name":"alpha","inputSchema":{"properties":{"url":{"type":"string"}}}}`))
		if rep.Truncated || rep.LimitHit != "" {
			t.Fatalf("complete review must not look truncated: %+v", rep)
		}
		out, err := Encode(rep)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), `"truncated"`) || strings.Contains(string(out), `"limit_hit"`) {
			t.Fatalf("complete Encode leaked truncation fields: %s", out)
		}
	})
}

func paddedNoteProperties(n int, extra string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"note%03d":{"type":"string"}`, i)
	}
	if extra != "" {
		if n > 0 {
			b.WriteByte(',')
		}
		b.WriteString(extra)
	}
	b.WriteByte('}')
	return b.String()
}
