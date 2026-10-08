// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// openUsage is also printed directly to stdout by runOpen when the
// <device> or <name> argument is missing, matching the pre-rewrite CLI
// (docs/volumes/cli.md#open).
const openUsage = "Usage: luks2 open [options] <device> <name>\n" +
	"Example: luks2 open /dev/sdb1 my-encrypted-disk\n\n" +
	"Options:\n" + keyFileHelp

func openCommand() *command {
	return &command{
		name:     "open",
		synopsis: "Unlock and open a LUKS volume",
		usage:    openUsage,
		run:      runOpen,
	}
}

func runOpen(ctx context.Context, e *env, args []string) error {
	f := newFlags("open")
	key := keyFileFlag(f, "key-file")
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) < 2 {
		_, _ = fmt.Fprint(e.stdout, openUsage)
		return &UsageError{Command: "open", Detail: "want <device> <name>"}
	}

	device, err := absPath("open", positional[0])
	if err != nil {
		return err
	}
	name := positional[1]

	pass, err := readPassphrase(e, "Enter passphrase: ", false, *key)
	if err != nil {
		return err
	}
	defer e.custody.Release(pass)

	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	key2, err := v.Unlock(ctx, pass)
	if err != nil {
		return err
	}
	defer key2.Destroy()

	m, err := e.host.activator.activate(ctx, v, key2, name)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "Volume unlocked successfully: %s\n", m.path())
	return nil
}

// closeUsage is also printed directly to stdout by runClose when <name> is
// missing, matching the pre-rewrite CLI (docs/volumes/cli.md#close).
const closeUsage = "Usage: luks2 close <name>\nExample: luks2 close my-encrypted-disk\n"

func closeCommand() *command {
	return &command{
		name:     "close",
		synopsis: "Lock and close a LUKS volume",
		usage:    closeUsage,
		run:      runClose,
	}
}

func runClose(ctx context.Context, e *env, args []string) error {
	if len(args) < 1 {
		_, _ = fmt.Fprint(e.stdout, closeUsage)
		return &UsageError{Command: "close", Detail: "want <name>"}
	}
	name := args[0]

	// Mount state is checked by the mapping's DEVICE, not a guessed path:
	// a name that resolves through the mapper is trusted only once Lookup
	// confirms the mapping exists (#250, C10).
	m, err := e.host.activator.lookup(ctx, name)
	if err != nil {
		_, _ = fmt.Fprintf(e.stderr, "Failed to lock volume: %v\n", err)
		return err
	}
	mounted, err := e.host.mounter.deviceMounted(ctx, m.major, m.minor)
	if err != nil {
		_, _ = fmt.Fprintf(e.stderr, "Failed to lock volume: %v\n", err)
		return err
	}
	if mounted {
		return &UsageError{Command: "close", Detail: "volume is still mounted; unmount it first"}
	}

	if err := e.host.activator.deactivate(ctx, name); err != nil {
		_, _ = fmt.Fprintf(e.stderr, "Failed to lock volume: %v\n", err)
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "Volume locked successfully: %s\n", name)
	return nil
}

func isluksCommand() *command {
	return &command{
		name:     "isluks",
		synopsis: "Exit 0 if the device holds a LUKS container",
		usage: "Usage: luks2 isluks [--luks2] [-v|--verbose] <device>\n\n" +
			"Exit 0 if the device holds a LUKS header, 1 if it does not.\n" +
			"--luks2 narrows the question to LUKS2 specifically.\n" +
			"-v, --verbose prints the reason for a no on stderr.\n",
		run: runIsLUKS,
	}
}

func runIsLUKS(ctx context.Context, e *env, args []string) error {
	f := newFlags("isluks")
	luks2Only := f.Bool("luks2")
	verbose := f.Bool("verbose")
	verboseShort := f.Bool("v")
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) < 1 {
		return &UsageError{Command: "isluks", Detail: "want <device>"}
	}
	device, err := absPath("isluks", positional[0])
	if err != nil {
		return err
	}

	kind := "LUKS"
	if *luks2Only {
		kind = "LUKS2"
	}

	// notLUKS answers no. Under --verbose the reason goes to stderr, as
	// cryptsetup isLuks -v reports it; the exit status is 1 either way.
	notLUKS := func(reason error) error {
		_, _ = fmt.Fprintf(e.stdout, "%s is not a %s device\n", device, kind)
		if *verbose || *verboseShort {
			_, _ = fmt.Fprintf(e.stderr, "%s: %v\n", device, reason)
		}
		// Deliberately not reason itself: isluks's contract is exit 0/1 (§F),
		// and its sentinel could otherwise land it on exitTable's 2-5.
		return &Error{Kind: errNotLUKSDevice}
	}

	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		return notLUKS(err)
	}
	defer func() { _ = v.Close() }()

	// Without --luks2, a header this package cannot fully parse because
	// it is LUKS1 still answers "yes, it is LUKS": the question asked was
	// about the magic, not the version. --luks2 requires Header to
	// succeed outright.
	_, herr := v.Header(ctx)
	is := herr == nil || (!*luks2Only && errors.Is(herr, luks2.ErrNotLUKS2))
	if !is {
		return notLUKS(herr)
	}

	_, _ = fmt.Fprintf(e.stdout, "%s is a %s device\n", device, kind)
	return nil
}

// infoUsage is also printed directly to stdout by runInfo when <device> is
// missing, matching the pre-rewrite CLI (docs/volumes/cli.md#info).
const infoUsage = "Usage: luks2 info <device>\nExample: luks2 info /srv/data.luks\n"

func infoCommand() *command {
	return &command{
		name:     "info",
		synopsis: "Show a summary of a volume's header",
		usage:    infoUsage,
		run:      runInfo,
	}
}

func runInfo(ctx context.Context, e *env, args []string) error {
	if len(args) < 1 {
		_, _ = fmt.Fprint(e.stdout, infoUsage)
		return &UsageError{Command: "info", Detail: "want <device>"}
	}
	device, err := absPath("info", args[0])
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(e.stdout, "LUKS2 Volume Manager")
	_, _ = fmt.Fprintln(e.stdout, "Pure Go LUKS2 Implementation")
	_, _ = fmt.Fprintf(e.stdout, "Volume Information: %s\n", device)
	_, _ = fmt.Fprintln(e.stdout, "===========================================================")

	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		_, _ = fmt.Fprintf(e.stderr, "\nFailed to read volume: %v\n", err)
		return err
	}
	defer func() { _ = v.Close() }()

	hdr, err := v.Header(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(e.stderr, "\nFailed to read volume: %v\n", err)
		return err
	}
	warnAboutDroppedEntries(e, device, hdr)

	var cipher string
	var sectorSize int
	if segs := hdr.Segments(); len(segs) > 0 {
		cipher = segs[0].Encryption
		sectorSize = segs[0].SectorSize
	}

	slots := hdr.Keyslots()
	ids := make([]int, len(slots))
	for i, s := range slots {
		ids[i] = s.ID
	}

	_, _ = fmt.Fprintf(e.stdout, "\nUUID:           %s\n", hdr.UUID())
	_, _ = fmt.Fprintf(e.stdout, "Label:          %s\n", hdr.Label())
	_, _ = fmt.Fprintln(e.stdout, "Version:        LUKS2")
	_, _ = fmt.Fprintf(e.stdout, "Cipher:         %s\n", cipher)
	_, _ = fmt.Fprintf(e.stdout, "Sector Size:    %d bytes\n", sectorSize)
	_, _ = fmt.Fprintf(e.stdout, "Active Keyslots: %v\n", ids)

	if len(slots) > 0 {
		_, _ = fmt.Fprintln(e.stdout, "\nKeyslot Details:")
		for _, s := range slots {
			_, _ = fmt.Fprintf(e.stdout, "  Slot %d: %s (key size: %d bytes)\n", s.ID, s.KDF.Type, s.KeySize)
		}
	}

	_, _ = fmt.Fprintln(e.stdout, "\nVolume is valid and accessible")
	return nil
}
