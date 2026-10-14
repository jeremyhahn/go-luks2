// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package keyprovider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// NOTHING HERE TOUCHES A PHYSICAL AUTHENTICATOR, and that is a hard
// constraint rather than a convenience: a production security key may be
// attached to the machine these run on, and enrolling against it is
// forbidden. Every helper is a script written into t.TempDir that emits
// fixture lines in the documented format.
//
// That is not a mock of the system under test. The system under test is the
// EXEC SEAM -- run a program, take a line of its output, decode it, refuse
// it when it is wrong -- and a script is the honest way to drive it. What is
// not covered by it is whether a real authenticator emits those exact lines,
// which is recorded at fido2AssertSecretLine and cannot be settled here.

// mustDestroy destroys e now and fails the test if go-enclave reports the
// release as anything but clean.
func mustDestroy(tb testing.TB, e *enclave.Memory) {
	tb.Helper()
	if err := e.Destroy(); err != nil {
		tb.Errorf("releasing a test enclave was reported: %v", err)
	}
}

// openSecret copies the material out of an enclave so a test can assert on
// it. Production code must never do this; a test has to look at the bytes to
// prove anything about them.
func openSecret(t *testing.T, e *enclave.Memory) []byte {
	t.Helper()

	var out []byte
	if err := e.WithBytes(func(b []byte) error {
		out = append([]byte(nil), b...)
		return nil
	}); err != nil {
		t.Fatalf("could not read a test enclave: %v", err)
	}
	return out
}

// helperScript writes an executable shell script that prints body verbatim
// on stdout and returns it.
// privateDir returns a fresh t.TempDir() that only this user can write.
// t.TempDir creates its directory with mode 0777 less the umask, so under a
// umask of 0002 it is group-writable and Command rightly refuses a helper in
// it; every trusted helper location in this package comes from here.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("failed to make %s private: %v", dir, err)
	}
	return dir
}

func helperScript(t *testing.T, name, body string) string {
	t.Helper()
	return helperScriptWith(t, name, body, "", 0)
}

// helperScriptWith writes an executable shell script emitting stdout, then
// stderr, then exiting with code.
func helperScriptWith(t *testing.T, name, stdout, stderr string, code int) string {
	t.Helper()

	path := filepath.Join(privateDir(t), name)
	script := "#!/bin/sh\n"
	if stdout != "" {
		script += fmt.Sprintf("printf '%%s' %s\n", shellQuote(stdout))
	}
	if stderr != "" {
		script += fmt.Sprintf("printf '%%s' %s >&2\n", shellQuote(stderr))
	}
	script += fmt.Sprintf("exit %d\n", code)

	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("failed to write helper %s: %v", path, err)
	}
	return path
}

// shellQuote renders s as a single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// echoingHelper writes a script that records its stdin and arguments, so a
// test can assert on the protocol the package speaks rather than only on
// what it reads back.
func echoingHelper(t *testing.T, name, stdout string) (path, argsFile, stdinFile string) {
	t.Helper()

	dir := privateDir(t)
	path = filepath.Join(dir, name)
	argsFile = filepath.Join(dir, "args")
	stdinFile = filepath.Join(dir, "stdin")

	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %s\ncat > %s\nprintf '%%s' %s\n",
		shellQuote(argsFile), shellQuote(stdinFile), shellQuote(stdout))
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("failed to write helper %s: %v", path, err)
	}
	return path, argsFile, stdinFile
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return string(b)
}
