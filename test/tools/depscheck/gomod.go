// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strconv"
	"strings"
)

// requirement is one require line of go.mod, with the reason written for
// holding it where it is, if any.
type requirement struct {
	Path     string
	Version  string
	Indirect bool
	Line     int
	Reason   string
}

// parseGoMod reads the require and replace directives of a go.mod. A reason
// is a comment on the require or replace line, or comment lines directly
// above it. The `indirect` marker the go command writes is not a reason, so
// an indirect requirement documents its pin as `// indirect; <reason>`.
//
// It is deliberately small rather than golang.org/x/mod/modfile: this
// repository takes no dependency for a CI check (CLAUDE.md, one local
// dependency), and the go command has already validated the file by the time
// this runs, because the build reads it first.
func parseGoMod(name string, data []byte) ([]requirement, error) {
	var (
		reqs     []requirement
		replaced = map[string]string{}
		block    string
		above    []string
	)
	for i, raw := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		code, comment := splitComment(raw)
		code = strings.TrimSpace(code)
		if code == "" {
			if comment != "" && strings.TrimSpace(raw) != "" {
				above = append(above, comment)
			} else {
				above = nil
			}
			continue
		}
		fields := strings.Fields(code)
		if block == "" {
			switch {
			case len(fields) == 2 && fields[1] == "(":
				block = fields[0]
				above = nil
				continue
			case fields[0] == "require" || fields[0] == "replace":
				if err := directive(name, lineNo, fields[0], fields[1:], comment, above, &reqs, replaced); err != nil {
					return nil, err
				}
				above = nil
				continue
			default:
				above = nil
				continue
			}
		}
		if code == ")" {
			block = ""
			above = nil
			continue
		}
		if block == "require" || block == "replace" {
			if err := directive(name, lineNo, block, fields, comment, above, &reqs, replaced); err != nil {
				return nil, err
			}
		}
		above = nil
	}
	if block != "" {
		return nil, &ModfileError{Path: name, Msg: "unterminated " + block + " block"}
	}
	for i := range reqs {
		if reqs[i].Reason == "" {
			reqs[i].Reason = replaced[reqs[i].Path]
		}
	}
	return reqs, nil
}

// directive records one require or replace line.
func directive(name string, lineNo int, kind string, fields []string, comment string,
	above []string, reqs *[]requirement, replaced map[string]string) error {
	reason, indirect := commentReason(comment)
	if reason == "" && len(above) > 0 {
		reason = strings.Join(above, " ")
	}
	switch kind {
	case "require":
		if len(fields) != 2 {
			return &ModfileError{Path: name, Line: lineNo, Msg: "require wants a module path and a version"}
		}
		path, err := unquote(fields[0])
		if err != nil {
			return &ModfileError{Path: name, Line: lineNo, Msg: err.Error()}
		}
		*reqs = append(*reqs, requirement{
			Path: path, Version: fields[1], Indirect: indirect, Line: lineNo, Reason: reason,
		})
	case "replace":
		if len(fields) < 3 {
			return &ModfileError{Path: name, Line: lineNo, Msg: "replace wants old => new"}
		}
		path, err := unquote(fields[0])
		if err != nil {
			return &ModfileError{Path: name, Line: lineNo, Msg: err.Error()}
		}
		if reason != "" {
			replaced[path] = reason
		}
	}
	return nil
}

// splitComment separates the code of a go.mod line from its // comment.
// go.mod has no string that can contain "//" except a quoted path, which
// this does not split inside.
func splitComment(line string) (code, comment string) {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '"':
			inQuote = !inQuote
		case !inQuote && strings.HasPrefix(line[i:], "//"):
			return line[:i], strings.TrimSpace(line[i+2:])
		}
	}
	return line, ""
}

// commentReason returns the reason a trailing comment gives, and whether it
// carries the go command's indirect marker.
func commentReason(comment string) (reason string, indirect bool) {
	if comment == "indirect" || strings.HasPrefix(comment, "indirect;") {
		indirect = true
		comment = strings.TrimSpace(strings.TrimPrefix(comment, "indirect"))
		comment = strings.TrimSpace(strings.TrimPrefix(comment, ";"))
	}
	return comment, indirect
}

// unquote accepts a go.mod path token, which may be a quoted string.
func unquote(tok string) (string, error) {
	if strings.HasPrefix(tok, `"`) {
		return strconv.Unquote(tok)
	}
	return tok, nil
}
