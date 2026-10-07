// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// maxConfirmationLine bounds how much readConfirmation will buffer before
// giving up: nobody types a YES/no answer longer than this.
const maxConfirmationLine = 256

// absPath resolves arg to an absolute path, naming command in any usage
// error so an operator sees which argument was wrong.
func absPath(command, arg string) (string, error) {
	if arg == "" {
		return "", &UsageError{Command: command, Detail: "an empty path"}
	}
	abs, err := filepath.Abs(arg)
	if err != nil {
		return "", &UsageError{Command: command, Detail: fmt.Sprintf("cannot resolve %q: %v", arg, err)}
	}
	return abs, nil
}

// confirmDestructive asks the operator to type YES before a destructive
// operation proceeds, unless batch is true (--batch-mode or --yes).
// Anything but the literal answer YES is refused.
func confirmDestructive(e *env, prompt string, batch bool) error {
	if batch {
		return nil
	}
	_, _ = fmt.Fprint(e.stdout, prompt)

	answer, err := readConfirmation(e.stdin)
	_, _ = fmt.Fprintln(e.stdout)
	switch {
	case err != nil:
		return &ConfirmationError{Err: err}
	case answer != "YES":
		return &ConfirmationError{Err: &Error{Kind: ErrNotConfirmed}}
	}
	return nil
}

// readConfirmation reads one line, with no secrecy requirement: a
// confirmation answer is not a credential.
func readConfirmation(r io.Reader) (string, error) {
	var (
		line []byte
		one  = make([]byte, 1)
	)
	for len(line) <= maxConfirmationLine {
		n, err := r.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return strings.TrimSuffix(string(line), "\r"), nil
			}
			line = append(line, one[0])
		}
		if errors.Is(err, io.EOF) {
			if len(line) == 0 {
				return "", io.ErrUnexpectedEOF
			}
			return string(line), nil
		}
		if err != nil {
			return "", err
		}
	}
	return string(line), nil
}

// refuseUnconfirmed reports a canceled confirmation to stderr and returns
// the exit code for it.
// refuseUnconfirmed reports a canceled confirmation to stderr and returns
// err unchanged, so the caller can propagate it as its own result.
func refuseUnconfirmed(e *env, what string, err error) error {
	_, _ = fmt.Fprintf(e.stderr, "%s canceled: %v\n", what, err)
	return err
}
