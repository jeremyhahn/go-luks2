package luks2

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// inMemoryExports are the exported functions and methods of pkg/luks2 that
// take no ctx because they do no device I/O, take no file lock, run no KDF and
// run no external program, or because they keep a standard-library
// interface's signature (Volume.Close, RecoveryKey.WriteTo).
var inMemoryExports = map[string]bool{
	// Options and pure values.
	"WithLockWait": true, "WithReadOnly": true, "WithRecoveryFormat": true, "WithRecoveryLength": true,
	"DefaultKDFSpec": true, "DefaultKDFType": true,
	"ValidatePassphrase": true, "FormatParams.Validate": true, "KDFParams.Validate": true,
	"NonApprovedKDF.String": true,
	// The handle: Path reads a field; Close keeps io.Closer.
	"Volume.Path": true, "Volume.Close": true,
	// Recovery keys: in memory; WriteTo keeps io.WriterTo onto the caller's writer.
	"NewRecoveryKey": true, "ParseRecoveryKey": true, "ParseRecoveryKeyFormat": true,
	"RecoveryKey.Destroy": true, "RecoveryKey.Format": true, "RecoveryKey.Hash": true,
	"RecoveryKey.WriteTo": true, "RecoveryKeyFormat.String": true,
	// The Header accessors work on a parsed copy.
	"Header.Dropped": true, "Header.Keyslots": true, "Header.Label": true, "Header.MarshalJSON": true,
	"Header.Offset": true, "Header.Requirements": true, "Header.Segments": true, "Header.SequenceID": true,
	"Header.Size": true, "Header.Subsystem": true, "Header.Tokens": true, "Header.UUID": true,
	"Token.MarshalJSON": true, "Token.UnmarshalJSON": true,
	// Error types keep the error interface and its errors.Is/As helpers.
	"FIPSImportRequiredError.Error": true, "FIPSImportRequiredError.Unwrap": true,
	"FIPSMigrationError.Error": true, "FIPSMigrationError.MigrationStage": true, "FIPSMigrationError.Unwrap": true,
	"KDFCostError.Error": true, "KDFCostError.Is": true,
	"OrphanedKeyslotError.Error": true, "OrphanedKeyslotError.Unwrap": true,
}

// TestEveryExportThatDoesIOTakesCtxFirst pins the "ctx comes first"
// invariant of docs/volumes/engineering.md: every exported function and
// method of pkg/luks2 takes context.Context as its first parameter, apart
// from the in-memory ones named in inMemoryExports. A new export without a
// ctx fails here until it takes one or is named there.
func TestEveryExportThatDoesIOTakesCtxFirst(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse pkg/luks2: %v", err)
	}
	var missing []string
	seen := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || !fn.Name.IsExported() {
					continue
				}
				name := fn.Name.Name
				if fn.Recv != nil {
					recv := receiverName(fn.Recv.List[0].Type)
					if !ast.IsExported(recv) {
						continue
					}
					name = recv + "." + name
				}
				seen[name] = true
				if inMemoryExports[name] || firstParamIsContext(fn.Type) {
					continue
				}
				missing = append(missing, name)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("exports that take no ctx first and are not named as in-memory:\n%s", strings.Join(missing, "\n"))
	}
	for name := range inMemoryExports {
		if !seen[name] {
			t.Errorf("inMemoryExports names %s, which pkg/luks2 no longer exports", name)
		}
	}
}

// TestNoCodeReadsAContextDeadline pins the clock invariant of
// docs/volumes/engineering.md: a caller's deadline arrives only through
// ctx.Done(), so no non-test file under pkg/ or internal/ calls Deadline()
// on anything. A wait computed from a deadline would run on the wall clock
// and escape clock.Fake.
func TestNoCodeReadsAContextDeadline(t *testing.T) {
	var found []string
	for _, root := range []string{"../../pkg", "../../internal"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 0 {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Deadline" {
					found = append(found, fset.Position(call.Pos()).String())
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(found) > 0 {
		t.Errorf("code reads a context deadline instead of waiting on ctx.Done():\n%s", strings.Join(found, "\n"))
	}
}

// TestNoExportedFunctionTakesABool pins the configuration rule of
// docs/volumes/engineering.md: no exported function or method of any package
// under pkg/ takes a boolean argument; a choice is a params struct field or a
// functional option.
func TestNoExportedFunctionTakesABool(t *testing.T) {
	var found []string
	err := filepath.WalkDir("../../pkg", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}
			if fn.Recv != nil && !ast.IsExported(receiverName(fn.Recv.List[0].Type)) {
				continue
			}
			for _, p := range fn.Type.Params.List {
				if id, ok := p.Type.(*ast.Ident); ok && id.Name == "bool" {
					found = append(found, fset.Position(fn.Pos()).String()+" "+fn.Name.Name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk pkg: %v", err)
	}
	if len(found) > 0 {
		t.Errorf("exported functions that take a bool:\n%s", strings.Join(found, "\n"))
	}
}

// TestNoPkgPackageHardensTheProcess pins the core-dump rule of
// docs/volumes/engineering.md: process hardening is the binary's decision,
// so no non-test file of any package under pkg/ calls HardenProcess. The
// core closure's wider no-process-state check is
// TestImportingTheCoreChangesNoProcessState; this one covers the packages
// outside that closure too.
func TestNoPkgPackageHardensTheProcess(t *testing.T) {
	var found []string
	err := filepath.WalkDir("../../pkg", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "HardenProcess" {
				found = append(found, fset.Position(sel.Pos()).String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk pkg: %v", err)
	}
	if len(found) > 0 {
		t.Errorf("pkg/ code reaches HardenProcess, which is the binary's call:\n%s", strings.Join(found, "\n"))
	}
}

func receiverName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return receiverName(e.X)
	case *ast.IndexExpr:
		return receiverName(e.X)
	case *ast.Ident:
		return e.Name
	}
	return ""
}

func firstParamIsContext(ft *ast.FuncType) bool {
	if ft.Params == nil || len(ft.Params.List) == 0 {
		return false
	}
	sel, ok := ft.Params.List[0].Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "context" && sel.Sel.Name == "Context"
}
