// Copyright (c) 2026 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package labstrings

import (
	"bytes"
	"strings"
)

// ExemptFile is the tracked root file listing binary and oversize files the release may carry, one per line as path, whitespace, reason; read from the git index.
const ExemptFile = "releasability-exempt.txt"

// Exemptions maps an exempt path to its reason.
type Exemptions map[string]string

// ParseExemptions reads ExemptFile's content, refusing untracked paths, missing reasons and duplicates; any error stops the gate.
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
