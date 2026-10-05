// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
)

// Non-interactive key input.
//
// # The problem this exists for
//
// Every credential this tool read used to come from term.ReadPassword, which
// requires a TTY. There was no path for a script, a systemd unit or a timer:
// the canonical unattended workload -- unlock a LUKS target, rsync a backup to
// it, lock it again -- could not use this tool at all.
//
// # What cryptsetup does, MEASURED
//
// The behavior below is not inferred from documentation. It was measured
// against cryptsetup 2.7.0 using `luksOpen --test-passphrase` on file
// containers, and the tests in keyinput_test.go re-derive it on every run
// rather than restating it:
//
//	--key-file <path>	the WHOLE FILE is the passphrase, trailing newline
//				INCLUDED. A file holding "hunter2\n" does not open a
//				container whose passphrase is "hunter2".
//	--key-file -		the whole of standard input, same rule.
//	no --key-file, stdin	the FIRST LINE of standard input. The newline
//	is a pipe		terminates it and is not part of it; anything
//				after it is ignored.
//	no --key-file, stdin	the interactive prompt, unchanged.
//	is a terminal
//
// The first rule is the classic surprise -- "it works when I type it but not
// from a file" -- and it is the reason `echo secret > key` produces a key file
// that does not match the passphrase "secret". `printf %s secret > key` does.
// The flag help says so, because the operator hits this before they read any
// documentation.
//
// A NUL byte is ordinary content: a key file of "abc\x00def" is a seven-byte
// passphrase, measured the same way. Nothing here truncates at one.
//
// # Where this deliberately DIFFERS from cryptsetup
//
// An EMPTY key file is refused, by the library's ValidatePassphrase rather than
// here. cryptsetup accepts it and fails later with "No key available with this
// passphrase", which is the same message a wrong passphrase produces -- and an
// empty key file is almost always a path that does not hold what the operator
// thinks it holds.

// maxKeyFileSize is the largest key file this tool will read.
//
// It is cryptsetup's bound, not this tool's preference: 8 MiB is where
// cryptsetup 2.7.0 answers "Maximum keyfile size exceeded", measured. A tool
// that accepted a larger file would produce a credential cryptsetup cannot
// reproduce, which is the same failure as getting the newline wrong.
const maxKeyFileSize = 8 << 20

// stdinKeyFile is the --key-file argument that means standard input. It is
// cryptsetup's spelling.
const stdinKeyFile = "-"

// KeySource names where one command's credential comes from.
//
// The zero value means "ask": the interactive prompt when standard input is a
// terminal, and the first line of standard input when it is not.
type KeySource struct {
	// Path is the --key-file argument: a filesystem path, stdinKeyFile for
	// standard input, or "" when the flag was not given.
	Path string

	// given reports whether the flag appeared on the command line, so an
	// EMPTY path -- `--key-file ""`, or a variable that expanded to nothing
	// -- is refused rather than read as "no key file", which would quietly
	// fall back to a prompt or to standard input (#246 D18). nil when the
	// source was not declared through keyFileFlag.
	given func() bool
}

// keyFileFlag declares --key-file on a subcommand and returns the KeySource it
// fills in.
//
// It is one function so that every command spells the flag the same way and
// describes it the same way. `luks2 help` is where an operator looks for the
// newline rule.
func keyFileFlag(o *options, name string) *KeySource {
	src := &KeySource{given: func() bool { return o.Given(name) }}
	o.strings[name] = &src.Path
	o.order = append(o.order, name)
	return src
}

// readPassphrase obtains a credential from wherever src says, falling back to
// the terminal.
//
// confirm is honored ONLY on the interactive path. There is nothing to confirm
// a key file against -- re-reading the same bytes proves nothing -- and a piped
// passphrase has no second line to compare with. cryptsetup makes the same
// choice under --batch-mode.
func (c *CLI) readPassphrase(prompt string, confirm bool, src KeySource) ([]byte, error) {
	switch {
	case src.Path == "" && src.given != nil && src.given():
		return nil, &KeyInputError{Op: "read key file", Source: `""`, Err: ErrEmptyKeyFilePath}

	case src.Path == stdinKeyFile:
		return readKeyFile(c.Stdin, "standard input")

	case src.Path != "":
		f, err := c.FS.Open(src.Path)
		if err != nil {
			return nil, &KeyInputError{Op: "open key file", Source: src.Path, Err: err}
		}
		defer func() { _ = f.Close() }()
		return readKeyFile(f, src.Path)

	case !c.stdinIsTerminal():
		return readKeyLine(c.Stdin)

	default:
		return c.promptPassphrase(prompt, confirm)
	}
}

// stdinIsTerminal reports whether standard input is a terminal, which is what
// decides between prompting and reading.
//
// It asks about the FILE DESCRIPTOR rather than about c.Stdin, because the
// descriptor is what term.ReadPassword would put into raw mode. A CLI whose
// Stdin has been replaced for a test still has fd 0 underneath it, and the
// Terminal seam is how a test says which answer it wants.
func (c *CLI) stdinIsTerminal() bool {
	fd := c.stdinFd
	if c.getStdinFd != nil {
		fd = c.getStdinFd()
	}
	return c.Terminal.IsTerminal(fd)
}

// readKeyFile returns everything r holds, which is what cryptsetup treats as
// the passphrase: no trimming, no newline stripping, NUL bytes included.
func readKeyFile(r io.Reader, source string) ([]byte, error) {
	buf, err := readAllSecret(r, maxKeyFileSize+1)
	if err != nil {
		ClearBytes(buf)
		return nil, &KeyInputError{Op: "read key file", Source: source, Err: err}
	}
	if len(buf) > maxKeyFileSize {
		ClearBytes(buf)
		return nil, &KeyInputError{Op: "read key file", Source: source, Err: ErrKeyFileTooLarge}
	}
	return buf, nil
}

// readKeyLine returns the first line of r, without its terminator.
//
// It reads ONE BYTE AT A TIME and stops at the newline, so that whatever
// follows on the same stream is still there for the next reader. A buffered
// reader would be faster and would swallow it -- and `luks2 create` reads a
// volume label from the same stream immediately afterwards, so the fast version
// would silently eat the operator's next answer.
//
// A stream that ends without a newline is a complete passphrase, not a
// truncated one: `printf %s secret | luks2 open ...` is a reasonable thing to
// write and the shell is under no obligation to add a newline.
func readKeyLine(r io.Reader) ([]byte, error) {
	var (
		line = newKeyBuffer(64)
		one  = make([]byte, 1)
	)
	defer ClearBytes(one)

	for len(line) <= maxKeyFileSize {
		n, err := r.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return line, nil
			}
			// Grown by hand rather than by append, so the outgrown buffer
			// -- a prefix of the passphrase -- is wiped instead of left on
			// the heap for the collector (#246 D16).
			if len(line) == cap(line) {
				grown := newKeyBuffer(2 * cap(line))[:len(line)]
				copy(grown, line)
				ClearBytes(line)
				line = grown
			}
			line = append(line, one[0])
		}
		if err == io.EOF {
			return line, nil
		}
		if err != nil {
			ClearBytes(line)
			return nil, &KeyInputError{Op: "read passphrase", Source: "standard input", Err: err}
		}
	}

	ClearBytes(line)
	return nil, &KeyInputError{Op: "read passphrase", Source: "standard input", Err: ErrKeyFileTooLarge}
}

// newKeyBuffer allocates an empty buffer of capacity n for passphrase bytes.
// A seam: a test records every buffer readKeyLine holds, to prove each one it
// let go of was wiped. Unexported, substituted only by this package's tests.
var newKeyBuffer = func(n int) []byte { return make([]byte, 0, n) }

// readAllSecret reads r to EOF, or until limit bytes have arrived, ZEROING
// every intermediate buffer it outgrows.
//
// io.ReadAll would do the same job and leave a trail of abandoned copies of the
// passphrase on the heap for the collector to release unwiped. That is the same
// reasoning that makes promptPassphrase clear its confirmation buffer even on
// the error path: a secret that was copied is a secret that has to be erased,
// and "it will be garbage collected" is not erasure.
func readAllSecret(r io.Reader, limit int) ([]byte, error) {
	buf := make([]byte, 0, 4096)

	for len(buf) < limit {
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), min(cap(buf)*2, limit))
			copy(grown, buf)
			ClearBytes(buf)
			buf = grown
		}

		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return buf, err
		}
	}

	return buf, nil
}

// keyFileHelp is the --key-file help text, written once so that every command
// describes the flag the same way.
//
// The newline sentence is in the HELP and not only in the documentation
// because that is where an operator whose key file does not work will look
// first, and because `echo` is what they will have used to make it.
const keyFileHelp = `  --key-file <path>  Read the passphrase from a file instead of prompting.
                     "-" means standard input. THE WHOLE FILE IS THE
                     PASSPHRASE, trailing newline included -- this is
                     cryptsetup's rule. Use 'printf %s secret > key', not
                     'echo secret > key'.
                     Without this flag, a passphrase piped to standard input is
                     read as one line and its newline is discarded.
`

// promptLabel asks for an optional volume label, and does not ask when there is
// nobody to answer.
//
// Reading it with Fscanln from a stream a script is feeding would consume
// whatever that script sent next -- and on the key-file path the operator has
// already said they are not present. An unattended create gets no label rather
// than a stolen line.
func (c *CLI) promptLabel(src KeySource) string {
	if src.Path != "" || !c.stdinIsTerminal() {
		return ""
	}

	_, _ = fmt.Fprint(c.Stdout, "Enter volume label (optional, press Enter to skip): ")
	var label string
	_, _ = fmt.Fscanln(c.Stdin, &label)
	return label
}
