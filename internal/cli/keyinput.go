// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/subtle"
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/term"

	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// maxKeyFileSize bounds a key file, or a line read from standard input, at
// cryptsetup's own key-file limit.
const maxKeyFileSize = 8 << 20

// stdinKeyFile is the --key-file value that names standard input, as
// cryptsetup spells it.
const stdinKeyFile = "-"

const keyFileHelp = "  --key-file <path|->  Read the passphrase from a file, or standard input (-)\n"

// terminal is the real-terminal boundary; ReadPassword's buffer is adopted into an enclave and wiped by Custody.Adopt.
type terminal interface {
	ReadPassword(fd int) ([]byte, error)
	IsTerminal(fd int) bool
}

type defaultTerminal struct{}

func (defaultTerminal) ReadPassword(fd int) ([]byte, error) { return term.ReadPassword(fd) }
func (defaultTerminal) IsTerminal(fd int) bool              { return term.IsTerminal(fd) }

// keySource is where a credential comes from: --key-file's value.
type keySource struct {
	// path is the --key-file argument: a filesystem path, stdinKeyFile for
	// standard input, or "" when the flag was not given.
	path string

	// given reports whether the flag appeared, so --key-file "" is refused.
	given func() bool
}

// keyFileFlag declares --key-file (or another name, for addkey's
// --new-key-file) on f.
func keyFileFlag(f *flags, name string) *keySource {
	src := &keySource{given: func() bool { return f.Given(name) }}
	f.strings[name] = &src.path
	f.order = append(f.order, name)
	return src
}

// readPassphrase reads a credential from --key-file or stdin, a pipe, or a prompt; the caller releases it through e.custody.
func readPassphrase(e *env, prompt string, confirm bool, src keySource) (enclave.ByteAccess, error) {
	switch {
	case src.path == "" && src.given != nil && src.given():
		return nil, &KeyInputError{Op: "read key file", Source: `""`, Err: &Error{Kind: ErrEmptyKeyFilePath}}

	case src.path == stdinKeyFile:
		return readKeyFile(e.custody, e.stdin, "standard input", maxKeyFileSize)

	case src.path != "":
		f, err := os.Open(src.path)
		if err != nil {
			return nil, &KeyInputError{Op: "open key file", Source: src.path, Err: err}
		}
		defer func() { _ = f.Close() }()
		return readKeyFile(e.custody, f, src.path, maxKeyFileSize)

	case !stdinIsTerminal(e):
		return readKeyLine(e.custody, e.stdin, maxKeyFileSize)

	default:
		return promptPassphrase(e, prompt, confirm)
	}
}

func stdinIsTerminal(e *env) bool {
	fd := e.getStdinFd()
	if fd < 0 {
		return false
	}
	return e.term.IsTerminal(fd)
}

// promptPassphrase reads a passphrase from the terminal, with echo
// disabled, and optionally asks for and checks a confirmation.
func promptPassphrase(e *env, prompt string, confirm bool) (enclave.ByteAccess, error) {
	_, _ = fmt.Fprint(e.stdout, prompt)

	fd := e.getStdinFd()
	raw, err := e.term.ReadPassword(fd)
	_, _ = fmt.Fprintln(e.stdout)
	if err != nil {
		return nil, &KeyInputError{Op: "read passphrase", Source: "terminal", Err: err}
	}
	pass, err := e.custody.Adopt("passphrase", raw)
	if err != nil {
		return nil, &KeyInputError{Op: "read passphrase", Source: "terminal", Err: err}
	}

	if !confirm {
		return pass, nil
	}

	_, _ = fmt.Fprint(e.stdout, "Confirm passphrase: ")
	rawConfirm, err := e.term.ReadPassword(fd)
	_, _ = fmt.Fprintln(e.stdout)
	if err != nil {
		e.custody.Release(pass)
		return nil, &KeyInputError{Op: "read confirmation", Source: "terminal", Err: err}
	}
	confirmation, err := e.custody.Adopt("passphrase confirmation", rawConfirm)
	if err != nil {
		e.custody.Release(pass)
		return nil, &KeyInputError{Op: "read confirmation", Source: "terminal", Err: err}
	}
	defer e.custody.Release(confirmation)

	match, err := enclavesEqual(pass, confirmation)
	if err != nil {
		e.custody.Release(pass)
		return nil, &KeyInputError{Op: "confirm passphrase", Source: "terminal", Err: err}
	}
	if !match {
		e.custody.Release(pass)
		return nil, &KeyInputError{Op: "confirm passphrase", Source: "terminal", Err: &Error{Kind: ErrPassphraseMismatch}}
	}

	return pass, nil
}

// enclavesEqual compares two enclaves' contents in constant time.
func enclavesEqual(a, b enclave.ByteAccess) (bool, error) {
	var equal bool
	err := secret.Borrow("compare credentials", a, func(ab []byte) error {
		return secret.Borrow("compare credentials", b, func(bb []byte) error {
			equal = subtle.ConstantTimeCompare(ab, bb) == 1
			return nil
		})
	})
	return equal, err
}

// readKeyFile reads r to EOF into locked memory, trailing newline included, refusing anything over limit.
func readKeyFile(custody secret.Custody, r io.Reader, source string, limit int) (enclave.ByteAccess, error) {
	buf := newEnclaveBuffer(custody, "read key file", 64)
	one := make([]byte, 1)
	defer enclave.Wipe(one)

	for {
		n, err := r.Read(one)
		if n > 0 {
			if buf.len() >= limit {
				buf.release()
				return nil, &KeyInputError{Op: "read key file", Source: source, Err: &Error{Kind: ErrKeyFileTooLarge}}
			}
			if aerr := buf.append(one[0]); aerr != nil {
				return nil, &KeyInputError{Op: "read key file", Source: source, Err: aerr}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			buf.release()
			return nil, &KeyInputError{Op: "read key file", Source: source, Err: err}
		}
	}

	result, err := buf.finish()
	if err != nil {
		return nil, &KeyInputError{Op: "read key file", Source: source, Err: err}
	}
	return result, nil
}

// readKeyLine reads one line from r into locked memory, refusing anything over limit.
func readKeyLine(custody secret.Custody, r io.Reader, limit int) (enclave.ByteAccess, error) {
	buf := newEnclaveBuffer(custody, "read passphrase", 64)
	one := make([]byte, 1)
	defer enclave.Wipe(one)

	for {
		n, err := r.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				result, ferr := buf.finish()
				if ferr != nil {
					return nil, &KeyInputError{Op: "read passphrase", Source: "standard input", Err: ferr}
				}
				return result, nil
			}
			if buf.len() >= limit {
				buf.release()
				return nil, &KeyInputError{Op: "read passphrase", Source: "standard input", Err: &Error{Kind: ErrKeyFileTooLarge}}
			}
			if aerr := buf.append(one[0]); aerr != nil {
				return nil, &KeyInputError{Op: "read passphrase", Source: "standard input", Err: aerr}
			}
		}
		if err == io.EOF {
			result, ferr := buf.finish()
			if ferr != nil {
				return nil, &KeyInputError{Op: "read passphrase", Source: "standard input", Err: ferr}
			}
			return result, nil
		}
		if err != nil {
			buf.release()
			return nil, &KeyInputError{Op: "read passphrase", Source: "standard input", Err: err}
		}
	}
}
