package luks2

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/jeremyhahn/go-luks2"

// coreForbiddenImports are the packages the rootless, exec-free core must not
// reach: exec, device-mapper, the kernel keyring and every public package
// with a trust boundary of its own.
var coreForbiddenImports = []string{
	"os/exec",
	"github.com/anatol/devmapper.go",
	modulePath + "/pkg/dmcrypt",
	modulePath + "/pkg/loop",
	modulePath + "/pkg/filesystem",
	modulePath + "/pkg/wipe",
	modulePath + "/pkg/keyprovider",
	modulePath + "/internal/dm",
	modulePath + "/internal/keyring",
	modulePath + "/internal/command",
	modulePath + "/internal/cli",
}

// coreClosure returns every in-module package pkg/luks2 reaches when built
// for goos, test files excluded, keyed by import path.
func coreClosure(t *testing.T, goos string) map[string]*build.Package {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx := build.Default
	ctx.GOOS = goos
	ctx.CgoEnabled = false
	seen := map[string]*build.Package{}
	queue := []string{modulePath + "/pkg/luks2"}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if _, ok := seen[pkg]; ok {
			continue
		}
		dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(pkg, modulePath+"/")))
		bp, err := ctx.ImportDir(dir, 0)
		if err != nil {
			t.Fatalf("%s: import %s: %v", goos, pkg, err)
		}
		seen[pkg] = bp
		for _, imp := range bp.Imports {
			if strings.HasPrefix(imp, modulePath+"/") {
				queue = append(queue, imp)
			}
		}
	}
	// Control: the walk must reach the leaf packages, or an empty closure
	// would pass vacuously.
	for _, want := range []string{"/internal/device", "/internal/kdf", "/internal/header"} {
		if _, ok := seen[modulePath+want]; !ok {
			walked := make([]string, 0, len(seen))
			for p := range seen {
				walked = append(walked, p)
			}
			sort.Strings(walked)
			t.Fatalf("%s: closure %v does not reach %s", goos, walked, want)
		}
	}
	return seen
}

// TestTheCoreImportClosureIsRootlessAndExecFree walks every in-module package
// pkg/luks2 reaches, on each OS the core builds for, and fails if any of them
// imports a forbidden package. depguard checks only pkg/luks2's own imports;
// this catches the same import arriving through a leaf package below it.
func TestTheCoreImportClosureIsRootlessAndExecFree(t *testing.T) {
	forbidden := make(map[string]bool, len(coreForbiddenImports))
	for _, p := range coreForbiddenImports {
		forbidden[p] = true
	}
	for _, goos := range []string{"linux", "darwin"} {
		for pkg, bp := range coreClosure(t, goos) {
			for _, imp := range bp.Imports {
				if forbidden[imp] {
					t.Errorf("%s: %s imports %s; the core must stay rootless and exec-free", goos, pkg, imp)
				}
			}
		}
	}
}

// processStateCalls are the calls that change process-wide state the binary,
// not the library, decides: core dumps, dumpability, the locked-memory budget.
var processStateCalls = map[string]bool{
	"HardenProcess": true,
	"SetAllocator":  true,
	"Setrlimit":     true,
	"Prctl":         true,
}

// TestImportingTheCoreChangesNoProcessState pins that importing pkg/luks2
// changes no process state: no package in its closure has an init function,
// and none calls process hardening, the enclave allocator setter, setrlimit
// or prctl. Hardening is the binary's decision, made from its own main.
func TestImportingTheCoreChangesNoProcessState(t *testing.T) {
	files := 0
	for pkg, bp := range coreClosure(t, "linux") {
		for _, name := range bp.GoFiles {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, filepath.Join(bp.Dir, name), nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("%s: %v", pkg, err)
			}
			files++
			for _, decl := range f.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "init" {
					t.Errorf("%s: %s declares an init function", pkg, fset.Position(fn.Pos()))
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && processStateCalls[sel.Sel.Name] {
					t.Errorf("%s: %s calls %s", pkg, fset.Position(call.Pos()), sel.Sel.Name)
				}
				return true
			})
		}
	}
	if files == 0 {
		t.Fatal("parsed no source files; the check proves nothing")
	}
}
