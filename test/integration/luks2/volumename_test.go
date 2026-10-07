// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is pkg/luks2/volumename_integration_test.go's mapping-name gate,
// ported to this package: every device-mapper name a call here creates or
// removes must be run-scoped (runVolume), never a literal or constant,
// because device-mapper names are a flat, host-wide namespace a concurrent
// run collides on (#109). See the original for the full history; the
// predicate and the AST walk are unchanged -- calleeName resolves a
// qualified call such as luks2.Unlock(...) to its selector name "Unlock",
// so mappingCalls keys on the same bare names whether the call is qualified
// or not.

// THE PREDICATE: every call that CREATES OR REMOVES a host-global
// device-mapper mapping. The int is which argument carries the name.
var mappingCalls = map[string]int{
	"Unlock":        2, // luks2.Unlock(device, passphrase, name) -- creates
	"Lock":          0, // luks2.Lock(name)                       -- REMOVES
	"releaseVolume": 1, // releaseVolume(t, name)                 -- removes
}

// auditMappingNames reports every mapping call in src whose name argument is
// not run-scoped.
func auditMappingNames(t *testing.T, filename, src string) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", filename, err)
	}

	var findings []string

	good, bad := map[*ast.Object]bool{}, map[*ast.Object]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name == "_" || id.Obj == nil {
				continue
			}
			if len(as.Rhs) != len(as.Lhs) {
				bad[id.Obj] = true
				continue
			}
			if callsRunVolume(as.Rhs[i]) {
				good[id.Obj] = true
			} else {
				bad[id.Obj] = true
			}
		}
		return true
	})

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name, ok := calleeName(call.Fun)
		if !ok {
			return true
		}
		argIdx, watched := mappingCalls[name]
		if !watched || argIdx >= len(call.Args) {
			return true
		}

		at := fset.Position(call.Pos())
		switch arg := call.Args[argIdx].(type) {
		case *ast.CallExpr:
			if !callsRunVolume(arg) {
				findings = append(findings, fmt.Sprintf(
					"%s: %s() takes its volume name from %s, not runVolume", at, name, exprText(arg)))
			}
		case *ast.Ident:
			if arg.Name == "_" {
				return true
			}
			if arg.Obj == nil || !good[arg.Obj] || bad[arg.Obj] {
				findings = append(findings, fmt.Sprintf(
					"%s: %s() takes its volume name from %q, whose binding was never assigned "+
						"from runVolume -- or was also assigned from something else. If it holds a "+
						"literal that name is HOST-GLOBAL and a concurrent run's cleanup will tear "+
						"down this mapping (#109)", at, name, arg.Name))
			}
		case *ast.BasicLit:
			lit := strings.Trim(arg.Value, `"`)
			if lit == "" {
				return true
			}
			findings = append(findings, fmt.Sprintf(
				"%s: %s() is given the literal %q -- a device-mapper name written as a constant "+
					"is HOST-GLOBAL, and two concurrent runs collide on it (#109). Use "+
					"runVolume(t, %q), computed ONCE into a local shared by the creation and "+
					"the teardown.", at, name, lit, lit))
		default:
			findings = append(findings, fmt.Sprintf(
				"%s: %s() takes its volume name from %T, a form this audit cannot trace to "+
					"runVolume. Assign it to a local scoped with runVolume(t, base) first -- an "+
					"unrecognized expression is not evidence the name is run-scoped (#109).",
				at, name, arg))
		}
		return true
	})

	return findings
}

// TestEveryMappingNameIsRunScoped is the gate, run over every test file in
// this package.
func TestEveryMappingNameIsRunScoped(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("found no test files to audit (err %v) -- a gate that examined nothing is not a gate", err)
	}

	for _, path := range files {
		src, err := os.ReadFile(path) // #nosec G304 -- a glob of this package's own source
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, f := range auditMappingNames(t, path, string(src)) {
			t.Error(f)
		}
	}
}

// TestTheGateCatchesEveryCallItCovers derives its cases from the predicate,
// so the gate cannot claim coverage it does not have.
func TestTheGateCatchesEveryCallItCovers(t *testing.T) {
	if len(mappingCalls) == 0 {
		t.Fatal("mappingCalls is empty, so this test would vacuously pass")
	}

	for _, must := range []string{"Unlock", "Lock", "releaseVolume"} {
		if _, ok := mappingCalls[must]; !ok {
			t.Errorf("%s() removes or creates a host-global mapping but is not in mappingCalls, "+
				"so the gate no longer covers it", must)
		}
	}

	for name, argIdx := range mappingCalls {
		t.Run(name, func(t *testing.T) {
			args := make([]string, argIdx+1)
			for i := range args {
				args[i] = "arg"
			}

			args[argIdx] = `"host-global-name"`
			src := "package luks2_test\n\nfunc TestX(t *testing.T) {\n\t" + name + "(" + strings.Join(args, ", ") + ")\n}\n"
			if got := auditMappingNames(t, "x_test.go", src); len(got) == 0 {
				t.Errorf("%s() with a literal name was NOT flagged; the gate does not cover a call it lists", name)
			}

			args[argIdx] = "vol"
			src = "package luks2_test\n\nfunc TestX(t *testing.T) {\n\tvol := \"host-global-name\"\n\t" +
				name + "(" + strings.Join(args, ", ") + ")\n}\n"
			if got := auditMappingNames(t, "x_test.go", src); len(got) == 0 {
				t.Errorf("%s() with a literal via a local was NOT flagged", name)
			}

			for _, form := range []string{"tt.volumeName", "names[0]", "somethingElse()"} {
				args[argIdx] = form
				src = "package luks2_test\n\nfunc TestX(t *testing.T) {\n\t" +
					name + "(" + strings.Join(args, ", ") + ")\n}\n"
				if got := auditMappingNames(t, "x_test.go", src); len(got) == 0 {
					t.Errorf("%s() with the untraceable name %s was NOT flagged; an unrecognized "+
						"expression is not evidence the name is run-scoped", name, form)
				}
			}

			for label, body := range map[string]string{
				"reassigned after scoping": "\tvol := runVolume(t, \"x\")\n\tvol = \"host-global\"\n",
				"scoped after being set":   "\tvol := \"host-global\"\n\tvol = runVolume(t, \"x\")\n",
				"multi-value assignment":   "\tvol, _ := somethingElse()\n",
			} {
				args[argIdx] = "vol"
				src = "package luks2_test\n\nfunc TestX(t *testing.T) {\n" + body + "\t" +
					name + "(" + strings.Join(args, ", ") + ")\n}\n"
				if got := auditMappingNames(t, "x_test.go", src); len(got) == 0 {
					t.Errorf("%s() with a name %s was NOT flagged; an identifier assigned from "+
						"anything other than runVolume is not run-scoped", name, label)
				}
			}

			args[argIdx] = "vol"
			src = "package luks2_test\n\nfunc TestX(t *testing.T, vol string) {\n" +
				"\tt.Run(\"x\", func(t *testing.T) { vol := runVolume(t, \"x\"); _ = vol })\n\t" +
				name + "(" + strings.Join(args, ", ") + ")\n}\n"
			if got := auditMappingNames(t, "x_test.go", src); len(got) == 0 {
				t.Errorf("%s() used an OUTER %q that only an inner closure scoped; a nested "+
					"assignment must not bless an unrelated identifier of the same name", name, "vol")
			}

			args[argIdx] = "vol"
			src = "package luks2_test\n\nfunc TestX(t *testing.T) {\n\tvol := runVolume(t, \"base\")\n\t" +
				name + "(" + strings.Join(args, ", ") + ")\n}\n"
			if got := auditMappingNames(t, "x_test.go", src); len(got) != 0 {
				t.Errorf("%s() with a run-scoped name was flagged: %v", name, got)
			}
		})
	}
}

// TestSanitizeNameTermKeepsNamesLegal pins the character rule at this end
// too, matching test/internal/harness.SanitizeNameTerm's own cases.
func TestSanitizeNameTermKeepsNamesLegal(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"1774-dl4fv4rhvelp", "1774-dl4fv4rhvelp"},
		{"has/slash", "has-slash"},
		{"has space", "has-space"},
		{"tab\there", "tab-here"},
		{"unicode-é", "unicode--"},
	} {
		if got := sanitizeNameTerm(tc.in); got != tc.want {
			t.Errorf("sanitizeNameTerm(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// sanitizeNameTerm mirrors test/internal/harness.SanitizeNameTerm's
// character rule for the test above; this package otherwise reaches the
// real one only indirectly, through runSuite.VolumeName.
func sanitizeNameTerm(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

func callsRunVolume(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	name, ok := calleeName(call.Fun)
	return ok && name == "runVolume"
}

func calleeName(e ast.Expr) (string, bool) {
	switch f := e.(type) {
	case *ast.Ident:
		return f.Name, true
	case *ast.SelectorExpr:
		return f.Sel.Name, true
	}
	return "", false
}

func exprText(e ast.Expr) string {
	if call, ok := e.(*ast.CallExpr); ok {
		if n, ok := calleeName(call.Fun); ok {
			return n + "(...)"
		}
	}
	return "an expression"
}
