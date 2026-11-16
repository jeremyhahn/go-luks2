package makefile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReleasabilityRunsTheGateOverTheCheckout pins `make releasability`, the
// target the public-releasability page names as the gate's entry point: it
// runs test/tools/releasability-gate over the checkout root and fails
// whenever the gate does. A stand-in go records its arguments and exits with
// the gate's code, so the test needs no index of its own.
func TestReleasabilityRunsTheGateOverTheCheckout(t *testing.T) {
	const want = "run ./test/tools/releasability-gate ."
	stubbed := func(t *testing.T, exit int) (stdout, stderr, args string, err error) {
		t.Helper()
		dir := t.TempDir()
		argsFile := filepath.Join(dir, "args")
		script := fmt.Sprintf("#!/bin/sh\n[ \"$1\" = run ] || exit 0\necho \"$@\" > %q\nexit %d\n", argsFile, exit)
		fakeGo := filepath.Join(dir, "go")
		if werr := os.WriteFile(fakeGo, []byte(script), 0o700); werr != nil { // #nosec G306 -- test stub must be executable
			t.Fatalf("write stub: %v", werr)
		}
		stdout, stderr, err = runMakeErr(t, environ(nil, nil), "releasability", "GO="+fakeGo)
		got, _ := os.ReadFile(argsFile) // #nosec G304 -- path built from t.TempDir
		return stdout, stderr, strings.TrimSpace(string(got)), err
	}

	for _, exit := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("gate exits %d", exit), func(t *testing.T) {
			stdout, stderr, args, err := stubbed(t, exit)
			if args != want {
				t.Errorf("go args = %q, want %q", args, want)
			}
			if exit == 0 && err != nil {
				t.Errorf("make releasability failed although the gate passed: %v\n%s%s", err, stdout, stderr)
			}
			if exit != 0 && err == nil {
				t.Errorf("make releasability passed although the gate exited %d:\n%s%s", exit, stdout, stderr)
			}
		})
	}
}
