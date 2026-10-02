// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package makefile

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// goFallback is the path the Makefile falls back to when `which go` finds
// nothing on PATH. `sudo make` relies on it: sudo's secure_path usually lacks
// the Go toolchain's directory.
const goFallback = "/usr/local/go/bin/go"

// probeTarget is appended to the real Makefile through a second -f, so the
// variables it prints are exactly the ones every real target expands.
const probeTarget = `
makefile-probe-205:
	@echo 'GO=$(GO)'
	@echo 'GOPATH=$(GOPATH)'
	@echo 'FLAVOR=$(flavor GO) $(flavor GOPATH)'
`

// repoRoot returns the directory holding the Makefile under test.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "Makefile")); err != nil {
		t.Fatalf("no Makefile at the repository root %s: %v", root, err)
	}
	return root
}

// lookPath resolves a tool the test cannot run without. There is no skip: a
// host without make cannot run any gate in this repository, and a test that
// skips there reports green for a check that never ran.
func lookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s is required to test the Makefile: %v", name, err)
	}
	return p
}

// resolveGo is the go the Makefile selects under the current PATH: the go on
// PATH if there is one, else goFallback. The tests compare against it, and run
// `go env` with it, so they hold wherever the Makefile itself works, including
// under sudo's secure_path where only the fallback exists.
func resolveGo(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	if _, err := os.Stat(goFallback); err != nil {
		t.Fatalf("no go on PATH and none at the Makefile's fallback %s: %v", goFallback, err)
	}
	return goFallback
}

// inheritedMakeVars are the variables a parent make exports to its recipes.
// MAKEFLAGS carries the parent's command-line overrides, so a probe that
// inherited it would run with, say, `make GOPATH=/tmp/x test-unit`'s GOPATH
// forced over the environment the test built for it. Every probe environment
// drops them: each child make here is a fresh, top-level invocation.
var inheritedMakeVars = []string{
	"MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEOVERRIDES", "MAKELEVEL",
	"MAKEFILES", "MAKE_TERMOUT", "MAKE_TERMERR",
}

// environ returns the current environment with every name in drop, and every
// variable a parent make passes down, removed and the given overrides appended.
func environ(drop []string, set map[string]string) []string {
	return environFrom(os.Environ(), drop, set)
}

// environFrom is environ over an explicit base environment.
func environFrom(base, drop []string, set map[string]string) []string {
	drop = append(append([]string(nil), drop...), inheritedMakeVars...)
	var env []string
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		skip := false
		for _, d := range drop {
			if name == d {
				skip = true
				break
			}
		}
		if _, overridden := set[name]; overridden || skip {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range set {
		env = append(env, k+"="+v)
	}
	return env
}

// runMake runs make at the repository root with env and returns its stdout and
// stderr separately; the defect under test lives on stderr alone.
func runMake(t *testing.T, env []string, args ...string) (stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(lookPath(t, "make"), args...) // #nosec G204 -- make is resolved from PATH; arguments are test constants
	cmd.Dir = repoRoot(t)
	cmd.Env = env
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("make %s failed: %v\nstdout:\n%s\nstderr:\n%s",
			strings.Join(args, " "), err, out.String(), errOut.String())
	}
	return out.String(), errOut.String()
}

// probe runs the probe target and returns the variables it printed.
func probe(t *testing.T, env []string) (vars map[string]string, stderr string) {
	t.Helper()
	probeFile := filepath.Join(t.TempDir(), "probe.mk")
	if err := os.WriteFile(probeFile, []byte(probeTarget), 0o600); err != nil {
		t.Fatalf("writing the probe makefile: %v", err)
	}
	stdout, stderr := runMake(t, env, "-s", "-f", "Makefile", "-f", probeFile, "makefile-probe-205")
	vars = map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("unexpected probe output line %q in:\n%s", line, stdout)
		}
		vars[k] = v
	}
	return vars, stderr
}

// assertNoEnvDiagnostic fails on the #205 symptom: with GO and GOPATH
// recursively expanded, GNU make 4.4+ ran `env GOPATH` and env reported that
// it could not execute a program called GOPATH.
func assertNoEnvDiagnostic(t *testing.T, stderr string) {
	t.Helper()
	if strings.Contains(stderr, "can't execute") || strings.Contains(stderr, "env: ") {
		t.Errorf("make printed the #205 diagnostic on stderr:\n%s", stderr)
	}
}

// goEnvGOPATH is what the Makefile's GOPATH must agree with under env.
func goEnvGOPATH(t *testing.T, env []string) string {
	t.Helper()
	cmd := exec.Command(resolveGo(t), "env", "GOPATH") // #nosec G204 -- go is resolved as the Makefile resolves it; arguments are constants
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go env GOPATH: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// ownedGOPATH returns an empty GOPATH that belongs to this test and is removed
// with it, whatever the go command leaves inside.
//
// The Makefile runs `$(GO) env GOPATH` at parse time. When that go is older
// than go.mod's go line -- as the goFallback install can be on a host whose
// PATH carries a newer one -- GOTOOLCHAIN=auto downloads the required
// toolchain into the module cache under this GOPATH, and the go command
// writes the module cache read-only. t.TempDir's own RemoveAll then fails
// with "permission denied" and fails the test for something it did not test
// (#230). So the tree is made writable first: t.Cleanup runs cleanups last
// registered first, and this one is registered after t.TempDir's.
func ownedGOPATH(t *testing.T) string {
	t.Helper()
	gopath := t.TempDir()
	t.Cleanup(func() {
		if err := makeTreeWritable(gopath); err != nil {
			t.Errorf("making the test's GOPATH %s removable: %v", gopath, err)
		}
	})
	return gopath
}

// goPathEnv returns set (a new map when nil) with GOPATH set to gopath and
// GOMODCACHE pinned to gopath/pkg/mod. Pinning GOMODCACHE keeps a host's own
// GOMODCACHE, from the environment or `go env -w`, from sending a toolchain
// download outside the directory ownedGOPATH cleans.
func goPathEnv(gopath string, set map[string]string) map[string]string {
	if set == nil {
		set = map[string]string{}
	}
	set["GOPATH"] = gopath
	set["GOMODCACHE"] = filepath.Join(gopath, "pkg", "mod")
	return set
}

// makeTreeWritable adds owner write (and, for directories, owner execute)
// permission to root and everything under it, so os.RemoveAll can delete a
// module cache the go command wrote read-only. Symbolic links are not
// followed: only what is inside the tree is changed.
func makeTreeWritable(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		add := fs.FileMode(0o200)
		if d.IsDir() {
			add = 0o700
		}
		return os.Chmod(path, info.Mode().Perm()|add)
	})
}

// TestGoVariablesAreSimplyExpanded pins the mechanism of the #205 fix and does
// so on every GNU make version. The symptom only appears under make 4.4+,
// which exports environment-origin variables into $(shell ...); a make older
// than that would pass the stderr assertions below against the defect. A
// recursive (=) GO or GOPATH fails here wherever this runs.
func TestGoVariablesAreSimplyExpanded(t *testing.T) {
	vars, stderr := probe(t, environ(nil, goPathEnv(ownedGOPATH(t), nil)))
	assertNoEnvDiagnostic(t, stderr)
	if got, want := vars["FLAVOR"], "simple simple"; got != want {
		t.Errorf("flavor of GO and GOPATH = %q, want %q: a recursive assignment re-enters GOPATH's $(shell) "+
			"while GO is still empty and runs `env GOPATH` under GNU make 4.4+ (#205)", got, want)
	}
}

// TestNoEnvDiagnosticWithGOPATHSet is the issue's own verification: GOPATH in
// the environment, as the build workers have it.
func TestNoEnvDiagnosticWithGOPATHSet(t *testing.T) {
	gopath := ownedGOPATH(t)
	env := environ(nil, goPathEnv(gopath, nil))

	vars, stderr := probe(t, env)
	assertNoEnvDiagnostic(t, stderr)
	if got, want := vars["GO"], resolveGo(t); got != want {
		t.Errorf("GO = %q, want the go the Makefile resolves, %q", got, want)
	}
	if got := vars["GOPATH"]; got != gopath {
		t.Errorf("GOPATH = %q, want the environment's %q", got, gopath)
	}

	// A real target, dry-run: the variables are expanded at parse time, so
	// the diagnostic appeared on every target, not only the probe.
	_, stderr = runMake(t, env, "-n", "build")
	assertNoEnvDiagnostic(t, stderr)
}

// TestGOPATHDefaultsWhenUnset covers the environment without GOPATH: the
// Makefile must still resolve it, to whatever go itself reports.
func TestGOPATHDefaultsWhenUnset(t *testing.T) {
	env := environ([]string{"GOPATH"}, nil)

	vars, stderr := probe(t, env)
	assertNoEnvDiagnostic(t, stderr)
	if got, want := vars["GO"], resolveGo(t); got != want {
		t.Errorf("GO = %q, want the go the Makefile resolves, %q", got, want)
	}
	want := goEnvGOPATH(t, env)
	if want == "" {
		t.Fatalf("go env GOPATH is empty with GOPATH unset; nothing to compare against")
	}
	if got := vars["GOPATH"]; got != want {
		t.Errorf("GOPATH = %q, want go's default %q", got, want)
	}
}

// TestGoFallbackWhenNotOnPATH keeps the `which` fallback the fix had to
// preserve: with no go on PATH, GO is the fixed install path.
func TestGoFallbackWhenNotOnPATH(t *testing.T) {
	env := environ(nil, goPathEnv(ownedGOPATH(t), map[string]string{"PATH": pathWithoutGo(t)}))

	vars, stderr := probe(t, env)
	assertNoEnvDiagnostic(t, stderr)
	if got := vars["GO"]; got != goFallback {
		t.Errorf("GO = %q with no go on PATH, want the fallback %q", got, goFallback)
	}
}

// pathWithoutGo returns a single-directory PATH carrying a link to every
// command on the current PATH except go. The Makefile shells out to ordinary
// tools at parse time, so dropping whole PATH entries would also drop those;
// masking go alone makes `which go` genuinely miss and nothing else.
func pathWithoutGo(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // a PATH entry that does not exist contributes nothing
		}
		for _, e := range entries {
			name := e.Name()
			if name == "go" {
				continue
			}
			link := filepath.Join(bin, name)
			if _, err := os.Lstat(link); err == nil {
				continue // an earlier PATH entry wins, as it does for the shell
			}
			if err := os.Symlink(filepath.Join(dir, name), link); err != nil {
				t.Fatalf("linking %s into the go-less PATH: %v", name, err)
			}
		}
	}
	if _, err := exec.LookPath(filepath.Join(bin, "which")); err != nil {
		t.Fatalf("which is not on PATH; the Makefile's go lookup cannot run: %v", err)
	}
	return bin
}

// TestProbesIgnoreParentMakeOverrides runs the probes with the environment a
// real parent make hands its recipes when invoked as
// `make GOPATH=... GO=go test-unit`: MAKEFLAGS carrying both overrides, and
// the overrides themselves exported. The probes must still see the
// environment the test gave them, not the parent's overrides.
func TestProbesIgnoreParentMakeOverrides(t *testing.T) {
	parentEnv := parentMakeEnviron(t, "GOPATH=/nonexistent-parent-override", "GO=go")
	if !strings.Contains(strings.Join(parentEnv, "\n"), "MAKEFLAGS=") {
		t.Fatalf("the parent make exported no MAKEFLAGS; the test is not exercising what it claims:\n%v", parentEnv)
	}

	gopath := ownedGOPATH(t)
	vars, stderr := probe(t, environFrom(parentEnv, nil, goPathEnv(gopath, nil)))
	assertNoEnvDiagnostic(t, stderr)
	if got, want := vars["FLAVOR"], "simple simple"; got != want {
		t.Errorf("flavor of GO and GOPATH = %q, want %q under a parent make's overrides", got, want)
	}
	if got, want := vars["GO"], resolveGo(t); got != want {
		t.Errorf("GO = %q, want the go the Makefile resolves, %q: the parent make's GO override leaked into the probe", got, want)
	}
	if got := vars["GOPATH"]; got != gopath {
		t.Errorf("GOPATH = %q, want %q: the parent make's GOPATH override leaked into the probe", got, gopath)
	}
}

// parentMakeEnviron runs a throwaway make with the given command-line
// overrides and returns the environment its recipe received.
func parentMakeEnviron(t *testing.T, overrides ...string) []string {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "parent.mk")
	if err := os.WriteFile(parent, []byte("dump:\n\t@env -0\n"), 0o600); err != nil {
		t.Fatalf("writing the parent makefile: %v", err)
	}
	args := append([]string{"-s", "-f", parent}, overrides...)
	stdout, _ := runMake(t, environ(nil, nil), append(args, "dump")...)
	var env []string
	for _, kv := range strings.Split(stdout, "\x00") {
		if kv != "" {
			env = append(env, kv)
		}
	}
	return env
}

// TestMakeTreeWritable checks the helper ownedGOPATH relies on by the modes it
// leaves, not by whether a removal then succeeds: root bypasses permission
// bits, so a removal-based check would pass on a CI runner even if the helper
// did nothing.
func TestMakeTreeWritable(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}

	// A module-cache-shaped tree: read-only directories holding read-only
	// files, and a link out of the tree that must not be followed.
	sub := filepath.Join(root, "pkg", "mod", "golang.org", "toolchain@v0")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(sub, "SECURITY.md")
	if err := os.WriteFile(file, []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(sub, "link")); err != nil {
		t.Fatal(err)
	}
	dirs := []string{sub, filepath.Dir(sub), filepath.Join(root, "pkg", "mod"), filepath.Join(root, "pkg")}
	for _, d := range dirs {
		if err := os.Chmod(d, 0o555); err != nil {
			t.Fatal(err)
		}
	}

	if err := makeTreeWritable(root); err != nil {
		t.Fatalf("makeTreeWritable: %v", err)
	}

	if got := mode(t, file); got != 0o644 {
		t.Errorf("file mode = %o, want 0644 (read-only plus owner write)", got)
	}
	for _, d := range dirs {
		if got := mode(t, d); got != 0o755 {
			t.Errorf("directory %s mode = %o, want 0755", d, got)
		}
	}
	if got := mode(t, outside); got != 0o444 {
		t.Errorf("the symlink's target outside the tree changed to %o; links must not be followed", got)
	}
	// The target is in another TempDir; leave it removable for its own cleanup.
	if err := os.Chmod(outside, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestMakeTreeWritableReportsAMissingRoot is the failure path: a root that
// does not exist is an error, not a silent no-op.
func TestMakeTreeWritableReportsAMissingRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-gopath")
	if err := makeTreeWritable(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("makeTreeWritable(%s) = %v, want fs.ErrNotExist", missing, err)
	}
}

// TestGoPathEnvPinsTheModuleCache checks that the module cache a test's go
// command uses is inside the GOPATH ownedGOPATH cleans, and that the caller's
// other settings are kept.
func TestGoPathEnvPinsTheModuleCache(t *testing.T) {
	got := goPathEnv("/gp", map[string]string{"PATH": "/bin"})
	want := map[string]string{"PATH": "/bin", "GOPATH": "/gp", "GOMODCACHE": filepath.Join("/gp", "pkg", "mod")}
	if len(got) != len(want) {
		t.Fatalf("goPathEnv = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("goPathEnv[%s] = %q, want %q", k, got[k], v)
		}
	}
	if m := goPathEnv("/gp", nil); m["GOPATH"] != "/gp" {
		t.Errorf("goPathEnv with a nil map = %v", m)
	}
}

// mode returns the permission bits of path, following symlinks; path must
// exist.
func mode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}
