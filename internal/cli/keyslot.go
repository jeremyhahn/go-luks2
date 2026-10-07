// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func testkeyCommand() *command {
	return &command{
		name:     "testkey",
		synopsis: "Check that a passphrase opens a volume",
		usage: "Usage: luks2 testkey [options] <device>\n\n" +
			"Verify that a passphrase opens a volume. Nothing is changed.\n\n" +
			"Options:\n" + keyFileHelp,
		run: runTestKey,
	}
}

func runTestKey(ctx context.Context, e *env, args []string) error {
	f := newFlags("testkey")
	keyFile := keyFileFlag(f, "key-file")
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) < 1 {
		return &UsageError{Command: "testkey", Detail: "want <device>"}
	}
	device, err := absPath("testkey", positional[0])
	if err != nil {
		return err
	}

	pass, err := readPassphrase(e, "Enter passphrase: ", false, *keyFile)
	if err != nil {
		return err
	}
	defer e.custody.Release(pass)

	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return err
	}
	key.Destroy()

	_, _ = fmt.Fprintf(e.stdout, "The passphrase opens %s\n", device)
	return nil
}

func keyslotsCommand() *command {
	return &command{
		name:     "keyslots",
		synopsis: "List the keyslots on a volume",
		usage:    "Usage: luks2 keyslots <device>\n\nList the keyslots on a volume, in the order an unlock attempts them.\n",
		run:      runKeyslots,
	}
}

func runKeyslots(ctx context.Context, e *env, args []string) error {
	if len(args) < 1 {
		return &UsageError{Command: "keyslots", Detail: "want <device>"}
	}
	device, err := absPath("keyslots", args[0])
	if err != nil {
		return err
	}

	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	hdr, err := v.Header(ctx)
	if err != nil {
		return err
	}

	slots := hdr.Keyslots()
	if len(slots) == 0 {
		// Not an error the operator caused, and it must not be reported as
		// one: a container with no usable keyslot is a container nobody can
		// open, and that is told plainly rather than shown an empty table.
		_, _ = fmt.Fprintf(e.stderr, "%s has NO keyslots. Nothing can open this volume.\n", device)
		return &errs.Error{Kind: luks2.ErrNoKeyslots, Detail: fmt.Sprintf("%s has no keyslots", device)}
	}

	_, _ = fmt.Fprintln(e.stdout, "Slot  Type     Key size  KDF        Encryption")
	for _, s := range slots {
		_, _ = fmt.Fprintf(e.stdout, "%-5d %-8s %-9d %-10s %s\n", s.ID, s.Type, s.KeySize, s.KDF.Type, s.Encryption)
	}
	return nil
}
