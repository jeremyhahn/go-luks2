// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"bytes"
	"strings"
)

// ExemptFile is the tracked file, at the repository root, that lists the
// binary and oversize files the public release may carry. The gate fails
// closed on both kinds -- binary content is not reviewable as text, and an
// oversize blob is not read at all -- so each one that is meant to ship is
// named there with the reason a person accepted it (owner ruling on #211).
//
// The format is one file per line: its exact repository-relative path, then
// whitespace, then the reason. `#` starts a comment line; blank lines are
// ignored. The list is read from the git index like everything else the gate
// sees, so an exemption edited in the working tree and not staged does not
// count.
const ExemptFile = "releasability-exempt.txt"

// Exemptions maps an exempt path to its reason.
type Exemptions map[string]string

// ParseExemptions reads ExemptFile's content. tracked is every path in the
// index: an exemption for a path that is not tracked is refused, because a
// stale entry is an exemption waiting for whatever file takes that name next.
// A line with no reason, and a path listed twice, are refused too. Any error
// stops the gate (exit 2); a malformed list never narrows to the lines that
// happened to parse.
func ParseExemptions(content []byte, tracked map[string]bool) (Exemptions, error) {
	ex := Exemptions{}
	for n, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		path, reason := line, ""
		if i := strings.IndexAny(line, " \t"); i >= 0 {
			path, reason = line[:i], strings.TrimSpace(line[i:])
		}
		switch {
		case reason == "":
			return nil, &ExemptionError{Line: n + 1, Path: path, Problem: "no reason given"}
		case !tracked[path]:
			return nil, &ExemptionError{Line: n + 1, Path: path, Problem: "the path is not tracked"}
		case ex[path] != "":
			return nil, &ExemptionError{Line: n + 1, Path: path, Problem: "listed twice"}
		}
		ex[path] = reason
	}
	return ex, nil
}

// IsBinary reports whether content is binary: it holds a NUL byte anywhere.
// Text never does, in any encoding this repository uses.
func IsBinary(content []byte) bool {
	return bytes.IndexByte(content, 0) >= 0
}

// binaryFile is the reason given for a binary file ExemptFile does not list.
const binaryFile = "a binary file: the gate cannot review it as text, so the public release " +
	"carries it only if " + ExemptFile + " lists it with the reason it may ship"
