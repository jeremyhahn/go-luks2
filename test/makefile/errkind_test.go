// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package makefile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// errKindFinding is one errs.Error composite literal with no Kind key, or
// with Kind explicitly set to nil.
type errKindFinding struct {
	pos string
}

// errsAliasName reports the local name file imports internal/errs under, or
// "" if it does not import it.
func errsAliasName(file *ast.File) string {
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if !strings.HasSuffix(path, "/internal/errs") {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return "errs"
	}
	return ""
}

// declaresErrorAlias reports whether file declares `type Error = errs.Error`
// (the struct is aliased in every public package), under
// whatever local name file's own import of internal/errs resolves to.
func declaresErrorAlias(file *ast.File, errsLocal string) bool {
	if errsLocal == "" {
		return false
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || !ts.Assign.IsValid() || ts.Name.Name != "Error" {
				continue
			}
			sel, ok := ts.Type.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == errsLocal && sel.Sel.Name == "Error" {
				return true
			}
		}
	}
	return false
}

// findMissingKind type-checks nothing: it is a syntactic scan, because every
// errs.Error literal names its type directly (never through a wider
// interface), so go/ast alone resolves it. It reports every composite
// literal of type errs.Error -- qualified, or the package's own `Error`
// alias of it -- that has no Kind key, or has Kind explicitly set to nil.
func findMissingKind(t *testing.T, dir string) []errKindFinding {
	t.Helper()

	// Build constraints are deliberately ignored: a file for another
	// GOOS/GOARCH (size_other.go) is production code too, and filtering by
	// the host's build.Default let a Kind-less literal in it go unseen.
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", dir, err)
	}

	var findings []errKindFinding
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			errsLocal := errsAliasName(file)
			hasAlias := declaresErrorAlias(file, errsLocal)

			ast.Inspect(file, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				isErr := false
				switch t := cl.Type.(type) {
				case *ast.SelectorExpr:
					if id, ok := t.X.(*ast.Ident); ok && errsLocal != "" && id.Name == errsLocal && t.Sel.Name == "Error" {
						isErr = true
					}
				case *ast.Ident:
					if t.Name == "Error" && hasAlias {
						isErr = true
					}
				}
				if !isErr {
					return true
				}

				hasKind := false
				for _, elt := range cl.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok || key.Name != "Kind" {
						continue
					}
					if ident, ok := kv.Value.(*ast.Ident); ok && ident.Name == "nil" {
						continue // explicit nil counts as missing
					}
					hasKind = true
				}
				if !hasKind {
					findings = append(findings, errKindFinding{pos: fset.Position(cl.Pos()).String()})
				}
				return true
			})
		}
	}
	return findings
}

// errKindDirs lists every package directory under pkg/ and internal/, one
// level deep, mirroring seamDirs: each is checked independently.
func errKindDirs(t *testing.T, root string) []string {
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

// TestKindIsNeverNil enforces that Kind is never nil: every errs.Error literal
// in production code (pkg/ and internal/) sets Kind. There is no allowlist --
// a nil Kind is always a defect, fixed by classifying that site, not by a
// list this test maintains.
func TestKindIsNeverNil(t *testing.T) {
	root := repoRoot(t)

	var all []struct {
		rel string
		errKindFinding
	}
	for _, dir := range errKindDirs(t, root) {
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			t.Fatalf("relativizing %s: %v", dir, err)
		}
		for _, f := range findMissingKind(t, dir) {
			all = append(all, struct {
				rel string
				errKindFinding
			}{rel, f})
		}
	}

	sort.Slice(all, func(i, j int) bool { return all[i].pos < all[j].pos })
	for _, f := range all {
		t.Errorf("%s: errs.Error literal at %s has no Kind (Kind is never nil)", f.rel, f.pos)
	}
}

// TestKindScanSeesEveryBuildVariant proves the guard is not blind to files the
// host's build constraints exclude: a Kind-less literal in a windows-only file
// must be reported even when the tests run on linux.
func TestKindScanSeesEveryBuildVariant(t *testing.T) {
	dir := t.TempDir()
	src := "//go:build windows && arm64\n\npackage fixture\n\nimport \"github.com/jeremyhahn/go-luks2/internal/errs\"\n\n" +
		"func f() error { return &errs.Error{} }\n"
	if err := os.WriteFile(filepath.Join(dir, "size_other.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := findMissingKind(t, dir); len(got) != 1 {
		t.Fatalf("findMissingKind reported %d findings in a build-constrained file, want 1", len(got))
	}
}
