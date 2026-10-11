package codemap

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

type textSpan struct {
	symbol string
	name   string
	line   int
	start  int
	end    int
}

func indexText(rel, lang string, src []byte, allowed map[string]struct{}, b *builder) error {
	if !utf8.Valid(src) {
		return fmt.Errorf("index %s: source is not valid UTF-8", rel)
	}
	text := strings.ReplaceAll(string(src), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	var (
		stripped string
		err      error
	)
	switch lang {
	case "python":
		stripped, err = blankPython(text)
	default:
		stripped, err = blankJS(text)
	}
	if err != nil {
		return fmt.Errorf("index %s: %w", rel, err)
	}
	lines := strings.Split(stripped, "\n")
	var spans []textSpan
	switch lang {
	case "python":
		spans = pythonSpans(lines)
	default:
		spans = jsSpans(stripped)
	}
	symbols := make([]string, len(spans))
	lineNums := make([]int, len(spans))
	for i, span := range spans {
		symbols[i] = span.symbol
		lineNums[i] = span.line
	}
	ids := assignIDs(rel, symbols, lineNums)
	for i, span := range spans {
		b.addFunc(rawFunc{
			id:     ids[i],
			name:   span.name,
			symbol: span.symbol,
			file:   rel,
			lang:   lang,
			line:   span.line,
		})
		for _, call := range callsInSpan(lines, span, spans) {
			b.addCall(rawCall{
				from: ids[i],
				name: call.name,
				qual: call.qual,
				kind: call.kind,
				file: rel,
				lang: lang,
				line: call.line,
			})
		}
	}
	// JavaScript import specifiers are quoted strings. Scan them on the
	// original text so blanking those strings does not erase the module path.
	importLines := lines
	if lang != "python" {
		importLines = strings.Split(text, "\n")
	}
	return collectImports(rel, lang, importLines, allowed, b)
}

type foundCall struct {
	name string
	qual string
	kind string
	line int
}

func callsInSpan(lines []string, self textSpan, all []textSpan) []foundCall {
	buf := append([]string(nil), lines...)
	for _, other := range all {
		if other.start == self.start && other.end == self.end && other.symbol == self.symbol && other.line == self.line {
			continue
		}
		if other.start < self.start || other.end > self.end {
			continue
		}
		for line := other.start; line <= other.end; line++ {
			if line >= 1 && line <= len(buf) {
				buf[line-1] = strings.Repeat(" ", len(lines[line-1]))
			}
		}
	}
	var calls []foundCall
	for i := self.start; i <= self.end; i++ {
		if i < 1 || i > len(buf) {
			continue
		}
		calls = append(calls, findCalls(buf[i-1], i)...)
	}
	return calls
}

var callRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_$])([A-Za-z_$][A-Za-z0-9_$]*)(?:\.([A-Za-z_$][A-Za-z0-9_$]*))?[ \t]*\(`)

func findCalls(line string, lineNo int) []foundCall {
	indexes := callRE.FindAllStringSubmatchIndex(line, -1)
	var calls []foundCall
	for _, idx := range indexes {
		if len(idx) < 6 || idx[2] < 0 {
			continue
		}
		name := line[idx[2]:idx[3]]
		qual := ""
		kind := "bare"
		if idx[4] >= 0 {
			qual = name
			name = line[idx[4]:idx[5]]
			kind = "sel"
		}
		if isCallKeyword(name) || isDeclKeyword(wordBefore(line, idx[2])) {
			continue
		}
		calls = append(calls, foundCall{name: name, qual: qual, kind: kind, line: lineNo})
	}
	return calls
}

func wordBefore(line string, identAt int) string {
	j := identAt
	for j > 0 && (line[j-1] == ' ' || line[j-1] == '\t') {
		j--
	}
	k := j
	for k > 0 && isIdentByte(line[k-1]) {
		k--
	}
	if k == j {
		return ""
	}
	return line[k:j]
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isDeclKeyword(word string) bool {
	switch word {
	case "def", "function", "func", "class":
		return true
	default:
		return false
	}
}

func isCallKeyword(word string) bool {
	switch word {
	case "if", "for", "while", "switch", "catch", "elif", "except", "with",
		"def", "function", "func", "class", "async", "export", "return",
		"import", "from", "new", "typeof", "instanceof", "void", "delete",
		"case", "do", "try", "else", "await":
		return true
	default:
		return false
	}
}

var (
	pyDefRE   = regexp.MustCompile(`^[ \t]*(?:async[ \t]+)?def[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(`)
	pyClassRE = regexp.MustCompile(`^[ \t]*class[ \t]+([A-Za-z_][A-Za-z0-9_]*)\b`)
	jsFnRE    = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?(?:default[ \t]+)?(?:async[ \t]+)?function[ \t]+([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*\(`)
)

func pythonSpans(lines []string) []textSpan {
	type frame struct {
		kind   string
		indent int
		name   string
		symbol string
		line   int
	}
	var frames []frame
	var spans []textSpan
	popTo := func(indent, lineNo int) {
		for len(frames) > 0 && indent <= frames[len(frames)-1].indent {
			fr := frames[len(frames)-1]
			frames = frames[:len(frames)-1]
			if fr.kind == "func" {
				spans = append(spans, textSpan{
					symbol: fr.symbol,
					name:   fr.name,
					line:   fr.line,
					start:  fr.line,
					end:    lineNo - 1,
				})
			}
		}
	}
	for i, line := range lines {
		lineNo := i + 1
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := countIndent(line)
		popTo(indent, lineNo)
		if m := pyClassRE.FindStringSubmatch(line); m != nil {
			frames = append(frames, frame{kind: "class", indent: indent, name: m[1], line: lineNo})
			continue
		}
		if m := pyDefRE.FindStringSubmatch(line); m != nil {
			symbol := m[1]
			for j := len(frames) - 1; j >= 0; j-- {
				if frames[j].kind == "class" {
					symbol = frames[j].name + "." + m[1]
					break
				}
			}
			frames = append(frames, frame{kind: "func", indent: indent, name: m[1], symbol: symbol, line: lineNo})
		}
	}
	popTo(-1, len(lines)+1)
	for i := range spans {
		if spans[i].end < spans[i].start {
			spans[i].end = spans[i].start
		}
	}
	return spans
}

func jsSpans(src string) []textSpan {
	matches := jsFnRE.FindAllStringSubmatchIndex(src, -1)
	var spans []textSpan
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		name := src[match[2]:match[3]]
		_, bodyEnd, ok := jsBody(src, match[1]-1)
		if !ok {
			continue
		}
		startLine := lineAt(src, match[0])
		endLine := lineAt(src, bodyEnd)
		spans = append(spans, textSpan{
			symbol: name,
			name:   name,
			line:   startLine,
			start:  startLine,
			end:    endLine,
		})
	}
	return spans
}

func jsBody(src string, openParen int) (bodyStart, bodyEnd int, ok bool) {
	if openParen < 0 || openParen >= len(src) || src[openParen] != '(' {
		return 0, 0, false
	}
	depth := 0
	for i := openParen; i < len(src); i++ {
		switch src[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				j := i + 1
				for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n') {
					j++
				}
				if j >= len(src) || src[j] != '{' {
					return 0, 0, false
				}
				brace := 0
				for k := j; k < len(src); k++ {
					switch src[k] {
					case '{':
						brace++
					case '}':
						brace--
						if brace == 0 {
							return j, k, true
						}
					}
				}
				return 0, 0, false
			}
		}
	}
	return 0, 0, false
}

func lineAt(src string, off int) int {
	if off < 0 {
		off = 0
	}
	if off > len(src) {
		off = len(src)
	}
	return strings.Count(src[:off], "\n") + 1
}

func countIndent(line string) int {
	n := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case ' ':
			n++
		case '\t':
			n += 4
		default:
			return n
		}
	}
	return n
}

func collectImports(rel, lang string, lines []string, allowed map[string]struct{}, b *builder) error {
	switch lang {
	case "python":
		return pythonImports(rel, lines, allowed, b)
	default:
		return jsImports(rel, lines, allowed, b)
	}
}

var pyFromRE = regexp.MustCompile(`^from[ \t]+(\.*[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)[ \t]+import[ \t]+(.+)$`)

func pythonImports(rel string, lines []string, allowed map[string]struct{}, b *builder) error {
	for _, line := range lines {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		m := pyFromRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if strings.Contains(m[2], "(") || strings.Contains(m[2], "*") {
			continue
		}
		targetFile, ok := pythonModuleFile(rel, m[1], allowed)
		if !ok {
			continue
		}
		for _, part := range strings.Split(m[2], ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			local, symbol := part, part
			if left, right, ok := strings.Cut(part, " as "); ok {
				symbol = strings.TrimSpace(left)
				local = strings.TrimSpace(right)
			}
			if !identOnly(symbol) || !identOnly(local) {
				continue
			}
			b.addImport(rawImport{
				file:         rel,
				local:        local,
				targetFile:   targetFile,
				targetSymbol: symbol,
			})
		}
	}
	return nil
}

func pythonModuleFile(importer, module string, allowed map[string]struct{}) (string, bool) {
	if strings.HasPrefix(module, "..") {
		return "", false
	}
	module = strings.TrimPrefix(module, ".")
	if module == "" || strings.Contains(module, "..") {
		return "", false
	}
	relPath := strings.ReplaceAll(module, ".", "/") + ".py"
	dir := path.Dir(importer)
	cand := relPath
	if dir != "." && dir != "" {
		cand = path.Clean(path.Join(dir, relPath))
	}
	if !safeRel(cand) {
		return "", false
	}
	if _, ok := allowed[cand]; !ok {
		return "", false
	}
	return cand, true
}

var (
	jsNamedRE = regexp.MustCompile(`^import[ \t]+(type[ \t]+)?\{([^}]*)\}[ \t]+from[ \t]+['"]([^'"]+)['"]`)
	jsStarRE  = regexp.MustCompile(`^import[ \t]+\*[ \t]+as[ \t]+([A-Za-z_$][A-Za-z0-9_$]*)[ \t]+from[ \t]+['"]([^'"]+)['"]`)
	jsDefRE   = regexp.MustCompile(`^import[ \t]+([A-Za-z_$][A-Za-z0-9_$]*)[ \t]+from[ \t]+['"]([^'"]+)['"]`)
)

func jsImports(rel string, lines []string, allowed map[string]struct{}, b *builder) error {
	for _, line := range lines {
		if m := jsStarRE.FindStringSubmatch(line); m != nil {
			b.addAlias(rel, m[1])
			continue
		}
		if m := jsNamedRE.FindStringSubmatch(line); m != nil {
			if strings.TrimSpace(m[1]) != "" {
				continue
			}
			target, ok := jsSpecifierFile(rel, m[3], allowed)
			if !ok {
				continue
			}
			for _, part := range strings.Split(m[2], ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				local, symbol := part, part
				if left, right, ok := strings.Cut(part, " as "); ok {
					symbol = strings.TrimSpace(left)
					local = strings.TrimSpace(right)
				}
				if !identOnly(symbol) || !identOnly(local) {
					continue
				}
				b.addImport(rawImport{
					file:         rel,
					local:        local,
					targetFile:   target,
					targetSymbol: symbol,
				})
			}
			continue
		}
		if m := jsDefRE.FindStringSubmatch(line); m != nil {
			b.addAlias(rel, m[1])
		}
	}
	return nil
}

func jsSpecifierFile(importer, spec string, allowed map[string]struct{}) (string, bool) {
	if !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") {
		return "", false
	}
	dir := path.Dir(importer)
	if dir == "." {
		dir = ""
	}
	joined := path.Clean(path.Join(dir, spec))
	if dir == "" && !strings.Contains(spec, "/") {
		joined = path.Clean(spec)
	}
	if !safeRel(joined) {
		return "", false
	}
	ext := path.Ext(joined)
	base := strings.TrimSuffix(joined, ext)
	cands := []string{joined}
	for _, alt := range []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"} {
		if alt != ext {
			cands = append(cands, base+alt)
		}
	}
	var hits []string
	seen := map[string]struct{}{}
	for _, cand := range cands {
		if !safeRel(cand) {
			continue
		}
		if _, ok := seen[cand]; ok {
			continue
		}
		seen[cand] = struct{}{}
		if _, ok := allowed[cand]; ok {
			hits = append(hits, cand)
		}
	}
	if len(hits) != 1 {
		return "", false
	}
	return hits[0], true
}

func identOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentByte(s[i]) {
			return false
		}
	}
	return true
}

func blankPython(src string) (string, error) {
	b := []byte(src)
	for i := 0; i < len(b); {
		if content, quote, triple, ok := pythonQuoteAt(b, i); ok {
			next, err := blankPythonString(b, i, content, quote, triple)
			if err != nil {
				return "", err
			}
			i = next
			continue
		}
		if b[i] == '#' {
			for i < len(b) && b[i] != '\n' {
				b[i] = ' '
				i++
			}
			continue
		}
		i++
	}
	return string(b), nil
}

func validPyPrefix(s string) bool {
	switch strings.ToLower(s) {
	case "r", "u", "f", "b", "rf", "fr", "rb", "br", "fb", "bf":
		return true
	default:
		return false
	}
}

func pythonQuoteAt(b []byte, i int) (content int, quote byte, triple, ok bool) {
	if i > 0 && isPyIdent(b[i-1]) {
		return 0, 0, false, false
	}
	for n := 2; n >= 0; n-- {
		if i+n >= len(b) {
			continue
		}
		if n > 0 && !validPyPrefix(string(b[i:i+n])) {
			continue
		}
		if b[i+n] != '\'' && b[i+n] != '"' {
			continue
		}
		quote = b[i+n]
		triple = i+n+2 < len(b) && b[i+n+1] == quote && b[i+n+2] == quote
		return i + n, quote, triple, true
	}
	return 0, 0, false, false
}

func isPyIdent(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func blankPythonString(b []byte, i, content int, quote byte, triple bool) (int, error) {
	qlen := 1
	if triple {
		qlen = 3
	}
	endQuote := content + qlen
	for k := i; k < endQuote && k < len(b); k++ {
		b[k] = ' '
	}
	k := endQuote
	if k > len(b) {
		return len(b), nil
	}
	if triple {
		for k < len(b) {
			if k+2 < len(b) && b[k] == quote && b[k+1] == quote && b[k+2] == quote {
				b[k], b[k+1], b[k+2] = ' ', ' ', ' '
				return k + 3, nil
			}
			if b[k] == '\\' && k+1 < len(b) {
				if b[k] != '\n' {
					b[k] = ' '
				}
				k++
				if b[k] != '\n' {
					b[k] = ' '
				}
				k++
				continue
			}
			if b[k] != '\n' {
				b[k] = ' '
			}
			k++
		}
		return 0, errors.New("unclosed triple-quoted string")
	}
	for k < len(b) && b[k] != '\n' {
		if b[k] == '\\' && k+1 < len(b) {
			b[k] = ' '
			k++
			if b[k] != '\n' {
				b[k] = ' '
			}
			k++
			continue
		}
		if b[k] == quote {
			b[k] = ' '
			return k + 1, nil
		}
		b[k] = ' '
		k++
	}
	return k, nil
}

func blankJS(src string) (string, error) {
	b := []byte(src)
	for i := 0; i < len(b); {
		if b[i] == '/' && i+1 < len(b) && b[i+1] == '/' {
			for i < len(b) && b[i] != '\n' {
				b[i] = ' '
				i++
			}
			continue
		}
		if b[i] == '/' && i+1 < len(b) && b[i+1] == '*' {
			b[i], b[i+1] = ' ', ' '
			i += 2
			closed := false
			for i < len(b) {
				if b[i] == '*' && i+1 < len(b) && b[i+1] == '/' {
					b[i], b[i+1] = ' ', ' '
					i += 2
					closed = true
					break
				}
				if b[i] != '\n' {
					b[i] = ' '
				}
				i++
			}
			if !closed {
				return "", errors.New("unclosed block comment")
			}
			continue
		}
		if b[i] == '\'' || b[i] == '"' {
			i = blankQuoted(b, i, b[i])
			continue
		}
		if b[i] == '`' {
			next, err := blankTemplate(b, i)
			if err != nil {
				return "", err
			}
			i = next
			continue
		}
		i++
	}
	return string(b), nil
}

func blankQuoted(b []byte, i int, quote byte) int {
	b[i] = ' '
	i++
	for i < len(b) && b[i] != '\n' {
		if b[i] == '\\' && i+1 < len(b) {
			b[i] = ' '
			i++
			if b[i] != '\n' {
				b[i] = ' '
			}
			i++
			continue
		}
		if b[i] == quote {
			b[i] = ' '
			return i + 1
		}
		b[i] = ' '
		i++
	}
	return i
}

func blankTemplate(b []byte, i int) (int, error) {
	if i >= len(b) || b[i] != '`' {
		return 0, errors.New("unclosed template string")
	}
	b[i] = ' '
	i++
	for i < len(b) {
		// Escapes cover the next source character, so \${helper()} stays a
		// literal and does not become a call. A doubled backslash ends the
		// escape and the following ${ is a real interpolation.
		if b[i] == '\\' && i+1 < len(b) {
			b[i] = ' '
			i++
			if b[i] != '\n' {
				b[i] = ' '
			}
			i++
			continue
		}
		if b[i] == '`' {
			b[i] = ' '
			return i + 1, nil
		}
		if b[i] == '$' && i+1 < len(b) && b[i+1] == '{' {
			b[i] = ' '
			b[i+1] = ' '
			next, err := blankTemplateExpr(b, i+2)
			if err != nil {
				return 0, err
			}
			i = next
			continue
		}
		if b[i] != '\n' {
			b[i] = ' '
		}
		i++
	}
	return 0, errors.New("unclosed template string")
}

// blankTemplateExpr scans one ${...} expression. The expression text is left
// in place so calls inside it still produce edges. Strings, comments, and
// nested templates are blanked, and their braces do not end the expression.
// The closing "}" is blanked.
func blankTemplateExpr(b []byte, i int) (int, error) {
	depth := 0
	for i < len(b) {
		if b[i] == '/' && i+1 < len(b) && b[i+1] == '/' {
			for i < len(b) && b[i] != '\n' {
				b[i] = ' '
				i++
			}
			continue
		}
		if b[i] == '/' && i+1 < len(b) && b[i+1] == '*' {
			b[i], b[i+1] = ' ', ' '
			i += 2
			closed := false
			for i < len(b) {
				if b[i] == '*' && i+1 < len(b) && b[i+1] == '/' {
					b[i], b[i+1] = ' ', ' '
					i += 2
					closed = true
					break
				}
				if b[i] != '\n' {
					b[i] = ' '
				}
				i++
			}
			if !closed {
				return 0, errors.New("unclosed block comment")
			}
			continue
		}
		if b[i] == '\'' || b[i] == '"' {
			i = blankQuoted(b, i, b[i])
			continue
		}
		if b[i] == '`' {
			next, err := blankTemplate(b, i)
			if err != nil {
				return 0, err
			}
			i = next
			continue
		}
		if b[i] == '{' {
			depth++
			i++
			continue
		}
		if b[i] == '}' {
			if depth == 0 {
				b[i] = ' '
				return i + 1, nil
			}
			depth--
			i++
			continue
		}
		i++
	}
	return 0, errors.New("unclosed template interpolation")
}
