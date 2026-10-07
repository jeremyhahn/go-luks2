// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Entry is one line of an API dump: what kind of declaration it is, its
// exported name, and the file that declares it.
//
// Kind is one of func, method, type, iface, var, const, fields (the exported
// fields of a struct type, as Name{A,B}), ifacemethods (the methods of an
// interface type, as Name{A,B}) and alias (a type declared with `type X =
// Y`, alongside its own "type" entry). Fields, interface methods and the
// alias marker are recorded so a dump shows a struct gaining or losing a
// field or a type becoming an alias, but they are not identifiers of their
// own: a disposition covers them through their type.
type Entry struct {
	Kind string
	Name string
	File string
}

// String renders e as the tab-separated line a dump file holds.
func (e Entry) String() string {
	return e.Kind + "\t" + e.Name + "\t" + e.File
}

// Identifier reports whether e names something a disposition must cover.
func (e Entry) Identifier() bool {
	return e.Kind != "fields" && e.Kind != "ifacemethods" && e.Kind != "alias"
}

// Dump returns the exported API declared by the non-test Go files in dir,
// sorted. Build constraints are ignored on purpose: a declaration that exists
// on any platform is part of the API.
func Dump(dir string) ([]Entry, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}
	fset := token.NewFileSet()
	var out []Entry
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrParse, err)
		}
		out = append(out, fileEntries(file, filepath.Base(path))...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoAPI, dir)
	}
	sortEntries(out)
	return out, nil
}

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].String() < entries[j].String() })
}

func fileEntries(file *ast.File, base string) []Entry {
	var out []Entry
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			out = append(out, funcEntries(d, base)...)
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				out = append(out, specEntries(d.Tok, spec, base)...)
			}
		}
	}
	return out
}

func funcEntries(d *ast.FuncDecl, base string) []Entry {
	if !d.Name.IsExported() {
		return nil
	}
	if d.Recv == nil {
		return []Entry{{Kind: "func", Name: d.Name.Name, File: base}}
	}
	recv := receiverName(d.Recv.List[0].Type)
	if !ast.IsExported(recv) {
		return nil
	}
	return []Entry{{Kind: "method", Name: recv + "." + d.Name.Name, File: base}}
}

// receiverName is the base type name of a method receiver: T for T, *T, T[P]
// and *T[P].
func receiverName(expr ast.Expr) string {
	for {
		switch e := expr.(type) {
		case *ast.StarExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.IndexListExpr:
			expr = e.X
		case *ast.Ident:
			return e.Name
		default:
			return ""
		}
	}
}

func specEntries(tok token.Token, spec ast.Spec, base string) []Entry {
	switch s := spec.(type) {
	case *ast.TypeSpec:
		return typeEntries(s, base)
	case *ast.ValueSpec:
		kind := "var"
		if tok == token.CONST {
			kind = "const"
		}
		var out []Entry
		for _, n := range s.Names {
			if n.IsExported() {
				out = append(out, Entry{Kind: kind, Name: n.Name, File: base})
			}
		}
		return out
	}
	return nil
}

func typeEntries(s *ast.TypeSpec, base string) []Entry {
	if !s.Name.IsExported() {
		return nil
	}
	switch t := s.Type.(type) {
	case *ast.InterfaceType:
		var methods []string
		for _, m := range t.Methods.List {
			for _, n := range m.Names {
				methods = append(methods, n.Name)
			}
		}
		return []Entry{
			{Kind: "iface", Name: s.Name.Name, File: base},
			{Kind: "ifacemethods", Name: s.Name.Name + "{" + strings.Join(methods, ",") + "}", File: base},
		}
	case *ast.StructType:
		out := []Entry{{Kind: "type", Name: s.Name.Name, File: base}}
		var fields []string
		for _, f := range t.Fields.List {
			for _, n := range f.Names {
				if n.IsExported() {
					fields = append(fields, n.Name)
				}
			}
		}
		if len(fields) > 0 {
			out = append(out, Entry{Kind: "fields", Name: s.Name.Name + "{" + strings.Join(fields, ",") + "}", File: base})
		}
		return out
	default:
		out := []Entry{{Kind: "type", Name: s.Name.Name, File: base}}
		if s.Assign.IsValid() {
			// A type alias (type X = Y) has no method set of its own: every
			// method Y declares is X's too, through Go's alias semantics,
			// even though no FuncDecl with receiver X exists in this
			// package's source for this AST-only dump to find. The "alias"
			// marker lets CheckHonored trust the compiler here instead of
			// requiring a syntactic method declaration that an alias is
			// specifically written to avoid needing.
			out = append(out, Entry{Kind: "alias", Name: s.Name.Name, File: base})
		}
		return out
	}
}

// ReadDump parses a dump file written by Dump.
func ReadDump(path string) ([]Entry, error) {
	data, err := os.ReadFile(path) // #nosec G304 G703 -- a dump file the operator names on the command line
	if err != nil {
		return nil, fmt.Errorf("read dump: %w", err)
	}
	var out []Entry
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || fields[0] == "" || fields[1] == "" || fields[2] == "" {
			return nil, fmt.Errorf("%w: %s line %d: %q", ErrMalformed, path, i+1, line)
		}
		out = append(out, Entry{Kind: fields[0], Name: fields[1], File: fields[2]})
	}
	return out, nil
}

// Diff returns the lines of base missing from current (removed) and the lines
// of current missing from base (added). The file column is ignored: a
// declaration moving between files is not an API change.
func Diff(base, current []Entry) (removed, added []Entry) {
	key := func(e Entry) string { return e.Kind + "\t" + e.Name }
	inBase := map[string]bool{}
	for _, e := range base {
		inBase[key(e)] = true
	}
	inCurrent := map[string]bool{}
	for _, e := range current {
		inCurrent[key(e)] = true
		if !inBase[key(e)] {
			added = append(added, e)
		}
	}
	for _, e := range base {
		if !inCurrent[key(e)] {
			removed = append(removed, e)
		}
	}
	return removed, added
}
