package mcpreview

import (
	"regexp"
	"sort"
	"strings"
)

var (
	nonAlphaNum = regexp.MustCompile(`[^A-Za-z0-9]+`)
	camelBreak  = regexp.MustCompile(`([a-z0-9])([A-Z])|([A-Z]+)([A-Z][a-z])`)

	privilegedNameTokens = map[string]struct{}{
		"admin": {}, "bash": {}, "bind": {}, "chmod": {}, "chown": {}, "chgrp": {},
		"cmd": {}, "command": {}, "credential": {}, "credentials": {}, "delete": {},
		"destroy": {}, "download": {}, "eval": {}, "exec": {}, "execute": {},
		"fetch": {}, "fork": {}, "inject": {}, "install": {}, "kill": {},
		"listen": {}, "mkdir": {}, "mutate": {}, "password": {}, "privilege": {},
		"privileged": {}, "ptrace": {}, "rm": {}, "rmdir": {}, "root": {},
		"run": {}, "secret": {}, "secrets": {}, "send": {}, "setuid": {},
		"shell": {}, "spawn": {}, "sudo": {}, "truncate": {}, "unlink": {},
		"uninstall": {}, "upload": {}, "write": {},
	}

	urlNameTokens = map[string]struct{}{
		"endpoint": {}, "href": {}, "uri": {}, "url": {}, "webhook": {},
	}
	urlFormats = map[string]struct{}{
		"iri": {}, "iri-reference": {}, "uri": {}, "uri-reference": {}, "url": {},
	}

	pathNameTokens = map[string]struct{}{
		"dir": {}, "directory": {}, "file": {}, "filename": {}, "filepath": {},
		"folder": {}, "path": {}, "pathname": {},
	}
	// source/destination are path endpoints only when the tool already talks
	// about a filesystem; alone they are too generic (URL source, etc.).
	pathEndpointTokens = map[string]struct{}{
		"destination": {}, "source": {},
	}
	pathFormats = map[string]struct{}{
		"directory": {}, "file": {}, "filename": {}, "filepath": {}, "folder": {}, "path": {},
	}

	commandNameTokens = map[string]struct{}{
		"argv": {}, "binary": {}, "cmd": {}, "cmdline": {}, "command": {},
		"commandline": {}, "exec": {}, "executable": {}, "program": {},
		"script": {}, "shell": {},
	}

	reFilesystem = regexp.MustCompile(`(?i)\b(filesystem|file system|directories|directory|folders?|filenames?|filepaths?|file path|pathnames?|on disk|from disk|paths?|files?)\b`)
	reProcess    = regexp.MustCompile(`(?i)\b(subprocesses?|processes?|spawn(?:ed|ing)?|pids?|child process|shells?|exec(?:ute|ution|c)?|commands?|command line|cmdlines?)\b`)
	reCredential = regexp.MustCompile(`(?i)\b(passwords?|secrets?|credentials?|api[_-]?keys?|access tokens?|private keys?|cookies?|auth(?:entication|orization)? tokens?)\b`)
	reExternal   = regexp.MustCompile(`(?i)\b(https?://\S+|https?|urls?|uris?|webhooks?|endpoints?|hostnames?|remote hosts?|the internet|networks?|fetch|download)\b`)
	reURLWord    = regexp.MustCompile(`(?i)\b(https?://\S+|urls?|uris?|webhooks?|endpoints?)\b`)
	rePathWord   = regexp.MustCompile(`(?i)\b(filesystem|file path|filepaths?|filenames?|directories|directory|folders?|pathnames?|paths?|files?)\b`)
	reCmdWord    = regexp.MustCompile(`(?i)\b(commands?|cmdlines?|shells?|executables?|binaries?|scripts?|argv|subprocesses?)\b`)
)

func splitIdent(s string) []string {
	var tokens []string
	for _, part := range nonAlphaNum.Split(s, -1) {
		if part == "" {
			continue
		}
		broken := camelBreak.ReplaceAllString(part, "${1}${3} ${2}${4}")
		for _, tok := range strings.Fields(broken) {
			tokens = append(tokens, strings.ToLower(tok))
		}
	}
	return tokens
}

func privilegedNameToken(name string) (string, bool) {
	for _, tok := range splitIdent(name) {
		if tokenInSet(tok, privilegedNameTokens) {
			return tok, true
		}
	}
	return "", false
}

func firstTokenMatch(name string, set map[string]struct{}) (string, bool) {
	for _, tok := range splitIdent(name) {
		if tokenInSet(tok, set) {
			return name, true
		}
	}
	return "", false
}

func tokenInSet(tok string, set map[string]struct{}) bool {
	if _, ok := set[tok]; ok {
		return true
	}
	if singular := singularToken(tok); singular != tok {
		_, ok := set[singular]
		return ok
	}
	return false
}

func singularToken(tok string) string {
	if len(tok) > 3 && strings.HasSuffix(tok, "ies") {
		return tok[:len(tok)-3] + "y"
	}
	if len(tok) > 1 && strings.HasSuffix(tok, "s") {
		return tok[:len(tok)-1]
	}
	return tok
}

func formatCue(schema map[string]any, set map[string]struct{}) (string, bool) {
	format, _ := schema["format"].(string)
	if format == "" {
		return "", false
	}
	if _, ok := set[strings.ToLower(format)]; ok {
		return "format=" + format, true
	}
	return "", false
}

func descriptionCue(schema map[string]any, re *regexp.Regexp) (string, bool) {
	desc, _ := schema["description"].(string)
	if desc == "" {
		return "", false
	}
	if m := re.FindString(desc); m != "" {
		return m, true
	}
	return "", false
}

func urlCue(name string, schema map[string]any) (string, bool) {
	if cue, ok := firstTokenMatch(name, urlNameTokens); ok {
		return cue, true
	}
	if cue, ok := formatCue(schema, urlFormats); ok {
		return cue, true
	}
	return descriptionCue(schema, reURLWord)
}

func pathCue(name string, schema map[string]any, toolDescription string) (string, bool) {
	if cue, ok := firstTokenMatch(name, pathNameTokens); ok {
		return cue, true
	}
	if cue, ok := firstTokenMatch(name, pathEndpointTokens); ok && reFilesystem.MatchString(toolDescription) {
		return cue, true
	}
	if cue, ok := formatCue(schema, pathFormats); ok {
		return cue, true
	}
	return descriptionCue(schema, rePathWord)
}

func commandCue(name string, schema map[string]any) (string, bool) {
	if cue, ok := firstTokenMatch(name, commandNameTokens); ok {
		return cue, true
	}
	return descriptionCue(schema, reCmdWord)
}

func boundaryMatches(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var matched []string
	add := func(re *regexp.Regexp) {
		for _, m := range re.FindAllString(text, -1) {
			key := strings.ToLower(m)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			matched = append(matched, m)
		}
	}
	add(reFilesystem)
	add(reProcess)
	add(reCredential)
	add(reExternal)
	sort.Slice(matched, func(i, j int) bool {
		return strings.ToLower(matched[i]) < strings.ToLower(matched[j])
	})
	return matched
}
