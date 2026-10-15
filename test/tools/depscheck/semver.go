// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strconv"
	"strings"
)

// version is a parsed semantic version as the go command writes it: a
// leading "v", MAJOR.MINOR.PATCH, an optional prerelease and an optional
// build suffix ("+incompatible"). A pseudo-version is a prerelease of the
// version after the last tag, so it orders correctly with no special case:
// v1.1.2-0.20180830191138-d8f796af33cc is newer than v1.1.1.
type version struct {
	core [3]int
	pre  []string
}

// parseVersion parses v, reporting ok=false for anything that is not
// semantic versioning.
func parseVersion(v string) (version, bool) {
	var out version
	if !strings.HasPrefix(v, "v") {
		return out, false
	}
	v = v[1:]
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	core := v
	if i := strings.IndexByte(v, '-'); i >= 0 {
		core = v[:i]
		pre := v[i+1:]
		if pre == "" {
			return out, false
		}
		out.pre = strings.Split(pre, ".")
		for _, id := range out.pre {
			if id == "" {
				return out, false
			}
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || (len(p) > 1 && p[0] == '0') {
			return out, false
		}
		out.core[i] = n
	}
	return out, true
}

// compare orders a and b: negative when a is older, zero when equal,
// positive when a is newer (semver.org §11).
func (a version) compare(b version) int {
	for i := range a.core {
		if a.core[i] != b.core[i] {
			if a.core[i] < b.core[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		if c := compareIdent(a.pre[i], b.pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	}
	return 0
}

// compareIdent orders two prerelease identifiers: numeric ones numerically
// and below alphanumeric ones, alphanumeric ones in ASCII order.
func compareIdent(a, b string) int {
	an, aNum := numeric(a)
	bn, bNum := numeric(b)
	switch {
	case aNum && bNum:
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		}
		return 0
	case aNum:
		return -1
	case bNum:
		return 1
	}
	return strings.Compare(a, b)
}

// numeric reports whether id is all digits, and its value. An identifier too
// large for a uint64 counts as the largest value.
func numeric(id string) (uint64, bool) {
	for i := 0; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return ^uint64(0), true
	}
	return n, true
}
