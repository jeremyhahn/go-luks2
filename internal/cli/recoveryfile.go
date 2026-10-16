// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/secret"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// readRecoveryCredential obtains a recovery credential either from a file
// (the first line that is not blank or a # comment) or from wherever a
// passphrase would come from -- the terminal or a pipe. Either way,
// surrounding whitespace is stripped and nothing else is changed: the
// dashes and letter case in a recovery key's rendering are part of it.
func readRecoveryCredential(e *env, path string) (enclave.ByteAccess, error) {
	if path != "" {
		f, err := os.Open(path) // #nosec G304 -- the operator's own --recovery-file argument
		if err != nil {
			return nil, &KeyInputError{Op: "open recovery key file", Source: path, Err: err}
		}
		defer func() { _ = f.Close() }()
		return readRecoveryKeyFile(e.custody, f, path, maxKeyFileSize)
	}

	typed, err := readPassphrase(e, "Enter the recovery key: ", false, keySource{})
	if err != nil {
		return nil, err
	}
	defer e.custody.Release(typed)
	return trimEnclave(e.custody, "recovery key", typed)
}

// readRecoveryKeyFile reads r -- bounded the same way a key file is -- and
// returns the first line that is not blank or a # comment, trimmed of
// surrounding whitespace.
func readRecoveryKeyFile(custody secret.Custody, r io.Reader, source string, limit int) (enclave.ByteAccess, error) {
	raw, err := readKeyFile(custody, r, source, limit)
	if err != nil {
		return nil, err
	}
	defer custody.Release(raw)

	var out enclave.ByteAccess
	err = secret.Borrow("recovery key", raw, func(b []byte) error {
		for _, line := range bytes.Split(b, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			var cerr error
			out, cerr = custody.Clone("recovery key", line)
			return cerr
		}
		return &Error{Kind: ErrEmptyCredential}
	})
	if err != nil {
		return nil, &KeyInputError{Op: "read recovery key file", Source: source, Err: err}
	}
	return out, nil
}

// trimEnclave returns a new enclave holding e's content with leading and
// trailing whitespace removed, without ever copying it outside protected
// memory: the trim happens on a borrowed view, and the result is cloned
// straight from that view.
func trimEnclave(custody secret.Custody, op string, e enclave.ByteAccess) (enclave.ByteAccess, error) {
	var out enclave.ByteAccess
	err := secret.Borrow(op, e, func(b []byte) error {
		var cerr error
		out, cerr = custody.Clone(op, bytes.TrimSpace(b))
		return cerr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// showRecoveryKey displays a recovery key ONCE, exactly as it will open the
// volume: dashes and letter case included. The credential is materialized
// here, at the point of display, and nowhere else.
func showRecoveryKey(e *env, rk *luks2.RecoveryKey) error {
	_, _ = fmt.Fprintln(e.stdout, "")
	_, _ = fmt.Fprintln(e.stdout, "=================== RECOVERY KEY ===================")
	// The one write whose failure matters: a key line that did not reach
	// the operator is a key nobody holds.
	if _, err := rk.WriteTo(e.stdout); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(e.stdout); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(e.stdout, "====================================================")
	_, _ = fmt.Fprintln(e.stdout, "Write this down NOW. It is shown once and cannot be")
	_, _ = fmt.Fprintln(e.stdout, "recovered from the volume.")
	_, _ = fmt.Fprintln(e.stdout, "")
	_, _ = fmt.Fprintln(e.stdout, "THE LINE ABOVE IS THE PASSPHRASE. Type or paste it")
	_, _ = fmt.Fprintln(e.stdout, "exactly as shown -- dashes and letter case included --")
	_, _ = fmt.Fprintln(e.stdout, "at any prompt that asks for one, including:")
	_, _ = fmt.Fprintln(e.stdout, "  cryptsetup open <device> <name>")
	_, _ = fmt.Fprintf(e.stdout, "Checksum (not secret): %s\n", rk.Hash())
	return nil
}

// recoveryFileMeta is the context recorded in a --output file's comment
// lines, alongside the key itself.
type recoveryFileMeta struct {
	UUID    string
	Keyslot int
	Token   int
}

// saveRecoveryKey writes rk to path as a comment preamble (the volume UUID,
// keyslot and token when known, and the checksum) followed by the
// credential text. The file is created exclusively at mode 0400: it is
// refused rather than silently overwritten if path already exists, and is
// never briefly readable at a wider mode.
func saveRecoveryKey(path string, rk *luks2.RecoveryKey, meta recoveryFileMeta) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) // #nosec G304 -- the operator's own --output argument
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	var preamble strings.Builder
	preamble.WriteString("# LUKS2 recovery key\n")
	preamble.WriteString("# IMPORTANT: store this somewhere safe and away from the volume.\n")
	preamble.WriteString("#\n")
	if meta.UUID != "" {
		fmt.Fprintf(&preamble, "# Volume UUID: %s\n", meta.UUID)
		fmt.Fprintf(&preamble, "# Keyslot: %d\n", meta.Keyslot)
		fmt.Fprintf(&preamble, "# Token: %d\n", meta.Token)
	}
	fmt.Fprintf(&preamble, "# Checksum (SHA-256, not secret): %s\n", rk.Hash())
	preamble.WriteString("#\n")
	preamble.WriteString("# The line below IS the passphrase. Type or paste it exactly as shown,\n")
	preamble.WriteString("# dashes and letter case included:\n")
	preamble.WriteString("#\n")
	preamble.WriteString("#   cryptsetup open <device> <name>\n")
	preamble.WriteString("#\n")

	if _, err := f.WriteString(preamble.String()); err != nil {
		return err
	}
	if _, err := rk.WriteTo(f); err != nil {
		return err
	}
	if _, err := f.WriteString("\n"); err != nil {
		return err
	}
	return f.Sync()
}

// parseRecoveryFormat is --format's parser. An unknown name, including an
// empty one, is a usage error raised before the passphrase prompt.
func parseRecoveryFormat(command, name string) (luks2.RecoveryKeyFormat, error) {
	format, err := luks2.ParseRecoveryKeyFormat(name)
	if err != nil {
		return 0, &UsageError{Command: command, Detail: fmt.Sprintf("unknown recovery key format %q for --format: use dashed, hex or base64", name)}
	}
	return format, nil
}
