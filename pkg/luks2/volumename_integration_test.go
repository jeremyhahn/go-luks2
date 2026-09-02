// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

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

// runVolumeSuffix makes every device-mapper name this suite creates unique to
// the run that created it. TestMain sets it once, from the harness run id.
//
// # Why a constant name is the defect
//
// Device-mapper names are a FLAT, HOST-WIDE namespace. Two runs of this suite
// on one machine -- which is the normal case on a shared CI runner -- contend
// for every hardcoded name, and the loser fails with an error that reads like a
// library defect rather than a collision:
//
//	Unlock failed on cycle 1: volume already unlocked: the device-mapper name
//	"luks-rapid" is already in use - close it first with: luks close luks-rapid
//
// Measured on a shared runner 2026-09-01 WITH A CONTROL: two concurrent
// containers, distinct container names, one passed and one failed on exactly
// that; the same test run twice SEQUENTIALLY on the same host passed both
// times. So it is the concurrency, not the test (#109).
//
// # The worse half: the loser breaks the winner
//
// TestRapidLockUnlock opened with `Lock(volumeName)` to "clean up any leftover
// state from previous test runs". Against a host-global constant that is not a
// cleanup, it is a teardown of whatever currently holds the name -- which under
// concurrency is the SIBLING RUN'S LIVE VOLUME. The collision does not merely
// fail the second run; the second run destroys the first one's mapping and the
// first fails somewhere unrelated. Removing the constant removes the need for
// that line, which is why it goes with it.
//
// # Why the run ledger (#96) does not solve this
//
// The ledger governs CLEANUP -- it records what a run created so a later run
// can remove exactly that. It says nothing about ALLOCATION, and nothing in it
// stops two runs choosing the same name in the first place.
var runVolumeSuffix string

// runVolume returns a device-mapper name unique to this run.
//
// It FAILS THE TEST when the suffix was never set, rather than falling back to
// the bare name. A fallback would be silent and would restore the collision the
// moment someone refactored TestMain -- and it would restore it invisibly,
// because the suite passes either way until two runs happen to overlap. The
// whole defect class here is a global constant that works until it does not.
func runVolume(t *testing.T, base string) string {
	t.Helper()

	if base == "" {
		t.Fatal("runVolume was given an empty base name; a device-mapper name must identify the test that made it")
	}
	if runVolumeSuffix == "" {
		t.Fatalf("runVolume(%q): the run suffix is unset, so this name would be host-global and could "+
			"collide with a concurrent run. TestMain must set runVolumeSuffix before any test runs.", base)
	}
	return base + "-" + runVolumeSuffix
}

// sanitizeRunID keeps the suffix inside what device-mapper accepts.
//
// The harness run id is "<pid>-<base36 nanos>", which is already safe, but this
// does not depend on that: it is the caller of a naming rule's job to enforce
// it, not to inherit it from a producer that may change. Anything outside
// [A-Za-z0-9-] becomes '-'.
func sanitizeRunID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// TestRunVolumeIsScopedToTheRun proves the three properties the fix rests on,
// without creating any host state.
func TestRunVolumeIsScopedToTheRun(t *testing.T) {
	if runVolumeSuffix == "" {
		t.Fatal("TestMain did not set the run suffix; every name this suite creates would be host-global")
	}

	got := runVolume(t, "luks-rapid")
	if got == "luks-rapid" {
		t.Fatalf("runVolume returned the bare name %q -- that is the host-global constant #109 is about", got)
	}
	if !strings.HasPrefix(got, "luks-rapid-") {
		t.Errorf("runVolume = %q, want it to keep the base so a leaked mapping still names its test", got)
	}
	if !strings.HasSuffix(got, runVolumeSuffix) {
		t.Errorf("runVolume = %q, want it to end in this run's suffix %q", got, runVolumeSuffix)
	}

	// Two different tests must not collide with each other either.
	if runVolume(t, "luks-small") == runVolume(t, "luks-large") {
		t.Error("two different base names produced one device-mapper name")
	}

	// device-mapper accepts up to DM_NAME_LEN (128) including the terminator.
	if len(got) >= 128 {
		t.Errorf("name %q is %d bytes, at or past the device-mapper limit", got, len(got))
	}
}

// TestSanitizeRunIDKeepsNamesLegal pins the character rule at this end rather
// than trusting the harness's id format not to change.
func TestSanitizeRunIDKeepsNamesLegal(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"1774-dl4fv4rhvelp", "1774-dl4fv4rhvelp"},
		{"has/slash", "has-slash"},
		{"has space", "has-space"},
		{"tab\there", "tab-here"},
		{"unicode-é", "unicode--"},
	} {
		if got := sanitizeRunID(tc.in); got != tc.want {
			t.Errorf("sanitizeRunID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// THE PREDICATE, stated so the cases can be derived from it rather than from
// whatever the author happened to remember.
//
//	every call that CREATES OR REMOVES a host-global device-mapper mapping
//
// Not "the helpers I fixed". The first version of this gate generalised over
// the wrong axis -- it listed the two helpers whose misuse I had just edited
// and omitted Lock, which is the call whose misuse motivated the whole issue
// (TestRapidLockUnlock opened with Lock(volumeName) as "cleanup"). A guard that
// enumerates instances covers instances; one that enumerates a predicate covers
// what comes next.
//
// The int is which argument carries the name. Adding an entry here is all that
// is needed to extend the gate -- and TestTheGateCatchesEveryCallItCovers will
// fail until the gate actually catches it, so the entry cannot be decorative.
var mappingCalls = map[string]int{
	"Unlock":        2, // Unlock(device, passphrase, name) -- creates
	"Lock":          0, // Lock(name)                       -- REMOVES
	"releaseVolume": 1, // releaseVolume(t, name)           -- removes
}

// auditMappingNames reports every mapping call in src whose name argument is
// not run-scoped. Taking source TEXT rather than a path is what lets the gate's
// own test drive it with synthesised cases.
func auditMappingNames(t *testing.T, filename, src string) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", filename, err)
	}

	var findings []string

	// KEYED ON THE BINDING, NOT THE SPELLING.
	//
	// The parser has already done scope resolution: ast.Ident.Obj points at the
	// declaration a name refers to, so an outer `vol` and a closure's `vol` are
	// DIFFERENT objects. Measured before relying on it -- a parameter `vol` and
	// a nested `vol := ...` produce two distinct Obj pointers.
	//
	// That makes shadowing INEXPRESSIBLE rather than something to detect, and
	// it replaced a hand-rolled walk that tracked function-literal boundaries
	// itself. Rounds six and seven of this PR were both scope questions; asking
	// the parser answers both and deletes the machinery instead of adding to
	// it. Same move as reading lo_device/lo_inode instead of parsing
	// lo_file_name: use the identity the system maintains, not the string that
	// describes it.
	//
	// ast.Object is deprecated in favour of go/types. It is used here because
	// this audit is single-file and needs binding identity only -- not types,
	// not cross-package resolution -- so loading the package through
	// go/packages would buy nothing for a real cost (a new dependency, and a
	// type-check under the integration build tag). If it is ever removed, the
	// migration is types.Info.Uses/Defs keyed on *types.Var, which answers the
	// identical question.
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
			// A multi-value RHS carries no per-name expression to inspect.
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
			// A binding the parser could not resolve is not a binding this
			// audit can vouch for.
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
				return true // the empty name is a test CASE, never a mapping
			}
			findings = append(findings, fmt.Sprintf(
				"%s: %s() is given the literal %q -- a device-mapper name written as a constant "+
					"is HOST-GLOBAL, and two concurrent runs collide on it (#109). Use "+
					"runVolume(t, %q), computed ONCE into a local shared by the creation and "+
					"the teardown.", at, name, lit, lit))
		default:
			// FAIL CLOSED. "I do not recognise this" is not "this is fine".
			findings = append(findings, fmt.Sprintf(
				"%s: %s() takes its volume name from %T, a form this audit cannot trace to "+
					"runVolume. Assign it to a local scoped with runVolume(t, base) first -- an "+
					"unrecognised expression is not evidence the name is run-scoped (#109).",
				at, name, arg))
		}
		return true
	})

	return findings
}

// TestEveryMappingNameIsRunScoped is the GATE, and it is an AST walk rather
// than a grep because a grep cannot see the defect it is looking for.
//
// The shape #109 actually fixed is a literal reaching the API THROUGH A LOCAL:
//
//	volumeName := "luks-rapid"          <- the host-global constant
//	defer releaseVolume(t, volumeName)  <- looks like a variable, is a constant
//	Unlock(dev, pass, volumeName)
//
// A call-site pattern sees two variables and passes. My first version of this
// check was exactly that pattern, and it reported a fixture of the shape above
// as clean -- a check narrower than the class it was checking, which is the
// fourth instance of that error in this one issue and the reason this is an
// AST walk now.
//
// So: for every mapping call, the name argument must be a call to runVolume, or
// an identifier this function assigned from runVolume. Anything else -- a
// literal here or a literal three lines up -- fails, and the message names the
// file and line so the fix is obvious.
// THERE IS NO EXCEPTION LIST, and that is deliberate.
//
// This gate shipped for a while with one: wipe_integration_test.go carried a
// literal that could not be scoped while #91 owned those lines. It was
// text-pinned and fail-closed so it could not go stale unnoticed -- and the
// better outcome was simply to wait for #91 and delete it, which cost a wait
// that was happening anyway.
//
// A mechanism for surviving an exception is worth having when you must ship
// one. Not shipping one is worth more. If you find yourself adding an entry
// here, check first whether the thing blocking you lands this week.
func TestEveryMappingNameIsRunScoped(t *testing.T) {
	files, err := filepath.Glob("*_integration_test.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("found no integration test files to audit (err %v) -- a gate that examined nothing is not a gate", err)
	}

	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, f := range auditMappingNames(t, path, string(src)) {
			t.Error(f)
		}
	}

}

// TestTheGateCatchesEveryCallItCovers derives its cases FROM THE PREDICATE, so
// the gate cannot claim coverage it does not have.
//
// This exists because the previous version of this guard listed two helpers and
// omitted Lock -- the call whose misuse motivated the issue -- and its self-test
// omitted Lock too, so the suite passed BECAUSE the test was written against the
// implementation rather than against the property. Second guard tonight with
// that shape. Iterating mappingCalls means adding an entry there without the
// gate working for it fails here.
func TestTheGateCatchesEveryCallItCovers(t *testing.T) {
	if len(mappingCalls) == 0 {
		t.Fatal("mappingCalls is empty, so this test would vacuously pass")
	}

	// A FLOOR, because iterating the map cannot notice an entry that was
	// DELETED -- the subtest simply stops existing and the suite stays green.
	// These three are the calls this package uses to create or remove a
	// host-global mapping today; removing one from mappingCalls has to fail
	// here rather than silently shrink the gate.
	//
	// It is a list, and a list is what got the previous version wrong. The
	// difference is that this one is a minimum with a stated reason, checked
	// against a predicate stated above it -- not the definition of coverage.
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

			// (a) a bare literal at the call site
			args[argIdx] = `"host-global-name"`
			src := "package luks2\n\nfunc TestX(t *testing.T) {\n\t" + name + "(" + strings.Join(args, ", ") + ")\n}\n"
			if got := auditMappingNames(t, "x_integration_test.go", src); len(got) == 0 {
				t.Errorf("%s() with a literal name was NOT flagged; the gate does not cover a call it lists", name)
			}

			// (b) a literal reaching it through a local -- the shape grep missed
			args[argIdx] = "vol"
			src = "package luks2\n\nfunc TestX(t *testing.T) {\n\tvol := \"host-global-name\"\n\t" +
				name + "(" + strings.Join(args, ", ") + ")\n}\n"
			if got := auditMappingNames(t, "x_integration_test.go", src); len(got) == 0 {
				t.Errorf("%s() with a literal via a local was NOT flagged", name)
			}

			// (b2) a form the auditor cannot trace -- a selector, an index, a
			// function result. It must FAIL CLOSED. The switch previously had
			// no default, so these were silently accepted, and `tt.volumeName`
			// carried the bare name "test" through the gate to a teardown.
			for _, form := range []string{"tt.volumeName", "names[0]", "somethingElse()"} {
				args[argIdx] = form
				src = "package luks2\n\nfunc TestX(t *testing.T) {\n\t" +
					name + "(" + strings.Join(args, ", ") + ")\n}\n"
				if got := auditMappingNames(t, "x_integration_test.go", src); len(got) == 0 {
					t.Errorf("%s() with the untraceable name %s was NOT flagged; an unrecognised "+
						"expression is not evidence the name is run-scoped", name, form)
				}
			}

			// (b3) REASSIGNMENT and SHADOWING. A name scoped once and then
			// overwritten is not scoped -- the first version of this gate
			// recorded "scoped at least once" and never invalidated it, so
			// this exact sequence passed.
			for label, body := range map[string]string{
				"reassigned after scoping": "\tvol := runVolume(t, \"x\")\n\tvol = \"host-global\"\n",
				"scoped after being set":   "\tvol := \"host-global\"\n\tvol = runVolume(t, \"x\")\n",
				"multi-value assignment":   "\tvol, _ := somethingElse()\n",
			} {
				args[argIdx] = "vol"
				src = "package luks2\n\nfunc TestX(t *testing.T) {\n" + body + "\t" +
					name + "(" + strings.Join(args, ", ") + ")\n}\n"
				if got := auditMappingNames(t, "x_integration_test.go", src); len(got) == 0 {
					t.Errorf("%s() with a name %s was NOT flagged; an identifier assigned from "+
						"anything other than runVolume is not run-scoped", name, label)
				}
			}

			// (b4) LEXICAL SCOPE. An inner closure's scoped assignment must not
			// bless an unrelated outer identifier of the same name. The comment
			// on (b3) used to claim shadowing coverage that did not exist --
			// the self-test asserting a property the implementation lacked,
			// which is the same overclaim as a guard whose cases were written
			// from its code.
			args[argIdx] = "vol"
			src = "package luks2\n\nfunc TestX(t *testing.T, vol string) {\n" +
				"\tt.Run(\"x\", func(t *testing.T) { vol := runVolume(t, \"x\"); _ = vol })\n\t" +
				name + "(" + strings.Join(args, ", ") + ")\n}\n"
			if got := auditMappingNames(t, "x_integration_test.go", src); len(got) == 0 {
				t.Errorf("%s() used an OUTER %q that only an inner closure scoped; a nested "+
					"assignment must not bless an unrelated identifier of the same name", name, "vol")
			}

			// (c) the accept side: a run-scoped name must NOT be flagged, or a
			// gate that refuses everything would pass every case above.
			args[argIdx] = "vol"
			src = "package luks2\n\nfunc TestX(t *testing.T) {\n\tvol := runVolume(t, \"base\")\n\t" +
				name + "(" + strings.Join(args, ", ") + ")\n}\n"
			if got := auditMappingNames(t, "x_integration_test.go", src); len(got) != 0 {
				t.Errorf("%s() with a run-scoped name was flagged: %v", name, got)
			}
		})
	}
}

// callsRunVolume reports whether an expression is a runVolume(...) call.
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
