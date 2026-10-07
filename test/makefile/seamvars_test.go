// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package makefile

import (
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seamAllowlist names pkg/luks2's package-level vars of func or interface
// type that are still real test seams (DESIGN.md §E), not yet folded into
// Volume.sys. H13 folded every pkg/luks2 seam into Volume.sys or a per-call
// sys a free function builds (docs/design/DECISIONS.md's H13 entry), so this
// list is empty; it stays here, with TestSeamAllowlistNamesOnlyRealSeams, so
// a future seam that cannot yet be migrated has somewhere sanctioned to go
// rather than being quietly left unmigrated.
//
// This list is an upper bound, not a target: entries are removed as seams
// are migrated, but nothing here requires the list to be updated when that
// happens. Anything NOT on this list, in ANY package, fails the test.
var seamAllowlist = map[string]bool{}

// seamFinding is one package-level var of func or interface type found
// outside errors.go.
type seamFinding struct {
	name string
	pkg  string
	pos  string
}

// findSeamVars type-checks every non-test, build-tag-applicable .go file in
// dir as a single package and reports every package-level *types.Var whose
// underlying type is a function signature or an interface, skipping
// errors.go (sentinel declarations there are typed *errs.Error, not
// func/interface, but the file is excluded on principle: it is the one file
// §E designates for const-like declarations, never seams).
//
// It uses go/build.Context.MatchFile, not a filename-suffix guess, so
// build-tag pairs like a _linux.go/_other.go split on the same function name
// are not mistaken for a redeclaration.
func findSeamVars(t *testing.T, dir string) []seamFinding {
	t.Helper()

	fset := token.NewFileSet()
	bctx := build.Default
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		if strings.HasSuffix(fi.Name(), "_test.go") {
			return false
		}
		ok, matchErr := bctx.MatchFile(dir, fi.Name())
		return matchErr == nil && ok
	}, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", dir, err)
	}

	var findings []seamFinding
	for name, pkg := range pkgs {
		files := make([]*ast.File, 0, len(pkg.Files))
		for _, f := range pkg.Files {
			files = append(files, f)
		}

		conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
		tpkg, _ := conf.Check(name, fset, files, nil)
		if tpkg == nil {
			continue
		}

		scope := tpkg.Scope()
		for _, n := range scope.Names() {
			v, ok := scope.Lookup(n).(*types.Var)
			if !ok {
				continue
			}
			pos := fset.Position(v.Pos())
			if filepath.Base(pos.Filename) == "errors.go" {
				continue
			}
			switch v.Type().Underlying().(type) {
			case *types.Signature, *types.Interface:
				findings = append(findings, seamFinding{name: n, pkg: name, pos: pos.String()})
			}
		}
	}
	return findings
}

// seamDirs lists every package directory under pkg/ and internal/ -- each
// is its own Go package and is checked independently, mirroring how the
// compiler itself scopes a package-level var.
func seamDirs(t *testing.T, root string) []string {
	t.Helper()

	var dirs []string
	for _, top := range []string{"pkg", "internal"} {
		entries, err := os.ReadDir(filepath.Join(root, top))
		if err != nil {
			t.Fatalf("reading %s: %v", top, err)
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dirs = append(dirs, filepath.Join(root, top, e.Name()))
		}
	}
	return dirs
}

// TestNoNewSeamVars enforces DESIGN.md §E: a package-level var of func or
// interface type, outside errors.go, is a test seam. Every package except
// pkg/luks2 has already folded its seams into an unexported sys struct (or
// has none); pkg/luks2's remaining seams are named in seamAllowlist. Nothing
// outside that allowlist, in any package, is permitted -- a new seam var
// must be a struct field, not a bare package-level var.
func TestNoNewSeamVars(t *testing.T) {
	root := repoRoot(t)

	for _, dir := range seamDirs(t, root) {
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			t.Fatalf("relativizing %s: %v", dir, err)
		}
		pkgName := filepath.Base(dir)

		for _, f := range findSeamVars(t, dir) {
			allowed := pkgName == "luks2" && seamAllowlist[f.name]
			if allowed {
				continue
			}
			t.Errorf("%s: package-level var %q of func/interface type at %s is a seam (DESIGN.md §E); "+
				"fold it into an unexported sys struct, or name it in seamAllowlist if it is a known, "+
				"not-yet-migrated pkg/luks2 seam", rel, f.name, f.pos)
		}
	}
}

// TestSeamAllowlistNamesOnlyRealSeams keeps seamAllowlist honest in the
// other direction: every entry must still exist as an actual seam var in
// pkg/luks2, so the allowlist shrinks as seams are migrated instead of
// silently keeping stale slack that would hide a mistaken re-introduction
// under an old name.
func TestSeamAllowlistNamesOnlyRealSeams(t *testing.T) {
	root := repoRoot(t)
	found := make(map[string]bool)
	for _, f := range findSeamVars(t, filepath.Join(root, "pkg", "luks2")) {
		found[f.name] = true
	}
	for name := range seamAllowlist {
		if !found[name] {
			t.Errorf("seamAllowlist names %q, but it is no longer a seam var in pkg/luks2; remove it from the allowlist", name)
		}
	}
}
