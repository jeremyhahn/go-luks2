// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// integrationTree is the integration suite's source, from this package.
const integrationTree = "../../integration"

// activateUnrecordedAllowed names the functions that may reach dmcrypt.Activate
// outside a Ledger.ActivateRecordedAhead, and why that leaves nothing
// unrecorded. Keyed by file (relative to integrationTree) and function.
var activateUnrecordedAllowed = map[string]string{
	"interop/fipsimport_test.go:runFIPSChild": "runs in the FIPS child, a process with no suite; " +
		"the parent records the mapping before starting it (unlockInFIPSProcessObserved)",
	"dmcrypt/activation_test.go:TestMappingNameTraversalIsRefusedOnTheRealKernel": "Activate(nil, nil, name) " +
		"is refused on the name before any device-mapper call",
}

// auditWriteAhead reports every place in src that creates a loop device or a
// dm mapping without the record that must come first (#348):
//
//   - `losetup -f`/`--find`, which attaches outside harness.SetupLoopDevice
//     and so outside its check that the backing file is below the recorded
//     run root;
//   - loop.Attach outside the loop package's own tests, for the same reason;
//   - dmcrypt.Activate anywhere but inside the function handed to
//     Ledger.ActivateRecordedAhead, unless activateUnrecordedAllowed says why.
func auditWriteAhead(t *testing.T, rel, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", rel, err)
	}

	var findings []string
	var stack []ast.Node
	var fn string
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		if decl, ok := n.(*ast.FuncDecl); ok {
			fn = decl.Name.Name
		}
		at := fset.Position(n.Pos())

		switch n := n.(type) {
		case *ast.CallExpr:
			if isLosetupFind(n) {
				findings = append(findings, fmt.Sprintf("%s: `losetup --find` attaches a loop device the ledger "+
					"may not cover; use harness.SetupLoopDevice, which refuses a file outside the recorded run root", at))
			}
		case *ast.SelectorExpr:
			switch selectorName(n) {
			case "loop.Attach":
				if !strings.HasPrefix(rel, "loop/") {
					findings = append(findings, fmt.Sprintf("%s: loop.Attach bypasses harness.SetupLoopDevice's "+
						"check that the backing file is below the recorded run root", at))
				}
			case "dmcrypt.Activate":
				if insideActivateRecordedAhead(stack) {
					return true
				}
				if _, ok := activateUnrecordedAllowed[rel+":"+fn]; ok {
					return true
				}
				findings = append(findings, fmt.Sprintf("%s: dmcrypt.Activate in %s is not inside "+
					"Ledger.ActivateRecordedAhead; a run killed before it is recorded leaves a mapping the "+
					"next run's reaper refuses on", at, fn))
			}
		}
		return true
	})
	return findings
}

func selectorName(sel *ast.SelectorExpr) string {
	x, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return x.Name + "." + sel.Sel.Name
}

// isLosetupFind reports an exec.Command or exec.CommandContext that runs
// losetup with -f or --find.
func isLosetupFind(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (selectorName(sel) != "exec.Command" && selectorName(sel) != "exec.CommandContext") {
		return false
	}
	losetup := false
	for _, arg := range call.Args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil {
			continue
		}
		switch {
		case v == "losetup":
			losetup = true
		case losetup && (v == "-f" || v == "--find"):
			return true
		}
	}
	return false
}

// insideActivateRecordedAhead reports whether the innermost function literal
// on stack is an argument of a call to ActivateRecordedAhead.
func insideActivateRecordedAhead(stack []ast.Node) bool {
	for i := len(stack) - 1; i > 0; i-- {
		lit, ok := stack[i].(*ast.FuncLit)
		if !ok {
			continue
		}
		call, ok := stack[i-1].(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "ActivateRecordedAhead" {
			return false
		}
		for _, arg := range call.Args {
			if arg == lit {
				return true
			}
		}
		return false
	}
	return false
}

// TestEveryLoopDeviceAndMappingIsRecordedFirst holds the integration suite to
// what docs/volumes/engineering.md says of it: every loop device and mapping
// is in the host-side ledger before it exists (#348).
func TestEveryLoopDeviceAndMappingIsRecordedFirst(t *testing.T) {
	audited := 0
	err := filepath.WalkDir(integrationTree, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		src, err := os.ReadFile(path) // #nosec G304 -- this repository's own integration source
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(integrationTree, path)
		if err != nil {
			return err
		}
		audited++
		for _, f := range auditWriteAhead(t, filepath.ToSlash(rel), string(src)) {
			t.Error(f)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", integrationTree, err)
	}
	if audited == 0 {
		t.Fatalf("found no integration source under %s -- a gate that examined nothing is not a gate", integrationTree)
	}
}

func TestTheWriteAheadAuditCatchesWhatItCovers(t *testing.T) {
	for name, tc := range map[string]struct {
		rel, body string
		findings  int
	}{
		"losetup -f": {"cli/x_test.go",
			`exec.Command("losetup", "-f", "--show", image)`, 1},
		"losetup --find under a context": {"cli/x_test.go",
			`exec.CommandContext(ctx, "losetup", "--find", image)`, 1},
		"losetup -j is a query": {"cli/x_test.go",
			`exec.Command("losetup", "-j", image)`, 0},
		"loop.Attach outside the loop package": {"wipe/x_test.go",
			`loop.Attach(ctx, image)`, 1},
		"loop.Attach in the loop package's own tests": {"loop/x_test.go",
			`loop.Attach(ctx, image)`, 0},
		"Activate, then a record": {"device/x_test.go",
			`m, _ := dmcrypt.Activate(ctx, v, key, name); _ = l.Record(k, name, m.UUID)`, 1},
		"Activate passed as a value": {"interop/x_test.go",
			`activateUnrecorded(ctx, dev, pass, name, dmcrypt.Activate)`, 1},
		"Activate inside ActivateRecordedAhead": {"device/x_test.go",
			`l.ActivateRecordedAhead(rm, dev, name, func() error { _, err := dmcrypt.Activate(ctx, v, key, name); return err })`, 0},
		"Activate in a literal nested inside one": {"device/x_test.go",
			`l.ActivateRecordedAhead(rm, dev, name, func() error { go func() { dmcrypt.Activate(ctx, v, key, name) }(); return nil })`, 1},
		"Activate in a literal handed to something else": {"device/x_test.go",
			`run(func() { dmcrypt.Activate(ctx, v, key, name) })`, 1},
	} {
		t.Run(name, func(t *testing.T) {
			src := "package x\n\nfunc f() {\n\t" + tc.body + "\n}\n"
			if got := auditWriteAhead(t, tc.rel, src); len(got) != tc.findings {
				t.Errorf("findings %q, want %d", got, tc.findings)
			}
		})
	}

	src := "package x\n\nfunc runFIPSChild() { activate = dmcrypt.Activate }\n"
	if got := auditWriteAhead(t, "interop/fipsimport_test.go", src); len(got) != 0 {
		t.Errorf("an allowed function was reported: %q", got)
	}
	if got := auditWriteAhead(t, "interop/other_test.go", src); len(got) != 1 {
		t.Errorf("the allowance is not scoped to its file: %q", got)
	}
}
