// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package workflows

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// vulnerableBelow is the first fixed version of each dependency that carried an
// advisory while this module required it. CI's govulncheck fails only on
// vulnerabilities the code can REACH, so a module-level advisory -- reported to
// every consumer's own govulncheck -- would never fail this repository's
// build. This floor does.
var vulnerableBelow = map[string]struct {
	fixed    string
	advisory string
}{
	// GO-2026-6355, GO-2026-6354: x/crypto/ssh channel deadlocks (#247).
	"golang.org/x/crypto": {"v0.56.0", "GO-2026-6355, GO-2026-6354"},
}

var requireLine = regexp.MustCompile(`(?m)^\s*(?:require\s+)?(\S+)\s+(v\d+\.\d+\.\d+\S*)`)

// TestDependenciesAreAtOrAboveTheirFixedVersions (#247).
func TestDependenciesAreAtOrAboveTheirFixedVersions(t *testing.T) {
	mod := readFile(t, "go.mod")
	found := map[string]string{}
	for _, m := range requireLine.FindAllStringSubmatch(mod, -1) {
		found[m[1]] = m[2]
	}
	for module, floor := range vulnerableBelow {
		got, ok := found[module]
		if !ok {
			t.Errorf("go.mod no longer requires %s; drop its floor here if that is deliberate", module)
			continue
		}
		if semverLess(t, got, floor.fixed) {
			t.Errorf("%s %s is below %s, the fix for %s", module, got, floor.fixed, floor.advisory)
		}
	}
}

// semverLess compares the vMAJOR.MINOR.PATCH cores of a and b.
func semverLess(t *testing.T, a, b string) bool {
	t.Helper()
	pa, pb := semverCore(t, a), semverCore(t, b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func semverCore(t *testing.T, v string) [3]int {
	t.Helper()
	core := strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		t.Fatalf("%q is not a semantic version", v)
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("%q is not a semantic version: %v", v, err)
		}
		out[i] = n
	}
	return out
}

func TestSemverLess(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"v0.55.0", "v0.56.0", true},
		{"v0.57.0", "v0.56.0", false},
		{"v0.56.0", "v0.56.0", false},
		{"v0.9.0", "v0.10.0", true},
		{"v1.0.0-alpha", "v0.99.0", false},
	} {
		if got := semverLess(t, tc.a, tc.b); got != tc.want {
			t.Errorf("semverLess(%s, %s) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
