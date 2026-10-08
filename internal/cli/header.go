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

func headerCommand() *command {
	return &command{
		name:     "header",
		synopsis: "Inspect or repair a LUKS2 header",
		usage: "Usage: luks2 header <show|secondary|restore> <device>\n\n" +
			"show       Show the primary header\n" +
			"secondary  Show the secondary header copy\n" +
			"restore    Overwrite the primary header from the secondary\n",
		sub: map[string]*command{
			"show": {
				name:     "header show",
				synopsis: "Show the primary header",
				usage:    "Usage: luks2 header show <device>\nExample: luks2 header show /dev/sdb1\n",
				run:      runHeaderShow,
			},
			"secondary": {
				name:     "header secondary",
				synopsis: "Show the secondary header copy",
				usage:    "Usage: luks2 header secondary <device>\nExample: luks2 header secondary /dev/sdb1\n",
				run:      runHeaderSecondary,
			},
			"restore": {
				name:     "header restore",
				synopsis: "Overwrite the primary header from the secondary copy",
				usage: "Usage: luks2 header restore [--batch-mode|--yes] [--force] <device>\n\n" +
					"Asks for YES unless --batch-mode or --yes.\n" +
					"--force restores over an intact primary that is not older.\n",
				run: runHeaderRestore,
			},
		},
	}
}

func runHeaderRestore(ctx context.Context, e *env, args []string) error {
	f := newFlags("header restore")
	batch := batchFlags(f)
	force := f.Bool("force")
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) < 1 {
		return &UsageError{Command: "header restore", Detail: "want <device>"}
	}
	device, err := absPath("header restore", positional[0])
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "This overwrites the PRIMARY header on %s with the secondary copy.\n", device)
	_, _ = fmt.Fprintln(e.stdout, "If the secondary copy is older, changes recorded only in the primary are lost.")
	if *force {
		_, _ = fmt.Fprintln(e.stdout, "--force: the primary is restored over even when it is intact and current.")
		_, _ = fmt.Fprintln(e.stdout, "That ROLLS THE VOLUME BACK: a passphrase removed since may open it again.")
	}

	if err := confirmDestructive(e, "Type 'YES' to restore the primary header: ", batch()); err != nil {
		return err
	}

	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	if *force {
		err = v.ReplacePrimaryHeader(ctx)
	} else {
		err = v.RestorePrimaryHeader(ctx)
	}
	if err != nil {
		if errors.Is(err, luks2.ErrPrimaryHeaderCurrent) {
			_, _ = fmt.Fprintln(e.stderr, "The primary is intact and not older than the secondary. Pass --force to roll back anyway.")
		}
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "The primary header on %s was restored from the secondary copy.\n", device)
	return nil
}

func runHeaderShow(ctx context.Context, e *env, args []string) error {
	return showHeader(ctx, e, args, "header show", func(ctx context.Context, v *luks2.Volume) (*luks2.Header, error) {
		return v.Header(ctx)
	})
}

func runHeaderSecondary(ctx context.Context, e *env, args []string) error {
	return showHeader(ctx, e, args, "header secondary", func(ctx context.Context, v *luks2.Volume) (*luks2.Header, error) {
		return v.SecondaryHeader(ctx)
	})
}

// showHeader reads one header copy and prints it, labeled by the copy it
// is. `header show` prints the current copy, which is the secondary when the
// primary is damaged or older, so the label and offset come from the copy
// read (Header.Offset), never from the command that asked for it.
func showHeader(ctx context.Context, e *env, args []string, command string, read func(context.Context, *luks2.Volume) (*luks2.Header, error)) error {
	if len(args) < 1 {
		return &UsageError{Command: command, Detail: "want <device>"}
	}
	device, err := absPath(command, args[0])
	if err != nil {
		return err
	}

	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	hdr, err := read(ctx, v)
	if err != nil {
		return err
	}
	warnAboutDroppedEntries(e, device, hdr)

	offset := hdr.Offset()
	which := "Primary"
	if offset != 0 {
		which = "Secondary"
		if command == "header show" {
			_, _ = fmt.Fprintf(e.stderr, "%s: the primary header copy is damaged or older than the secondary; showing the secondary\n", device)
		}
	}

	_, _ = fmt.Fprintf(e.stdout, "%s header: %s\n", which, device)
	_, _ = fmt.Fprintln(e.stdout, "===========================================================")
	_, _ = fmt.Fprintln(e.stdout, "Version:        LUKS2")
	_, _ = fmt.Fprintf(e.stdout, "UUID:           %s\n", hdr.UUID())
	_, _ = fmt.Fprintf(e.stdout, "Label:          %s\n", hdr.Label())
	_, _ = fmt.Fprintf(e.stdout, "Subsystem:      %s\n", hdr.Subsystem())
	_, _ = fmt.Fprintf(e.stdout, "Header size:    %d bytes\n", hdr.Size())
	_, _ = fmt.Fprintf(e.stdout, "Header offset:  %d\n", offset)
	_, _ = fmt.Fprintln(e.stdout, "Checksum algo:  sha256")
	_, _ = fmt.Fprintf(e.stdout, "Sequence ID:    %d\n", hdr.SequenceID())

	_, _ = fmt.Fprintf(e.stdout, "\nKeyslots:       %d\n", len(hdr.Keyslots()))
	_, _ = fmt.Fprintf(e.stdout, "Tokens:         %d\n", len(hdr.Tokens()))
	_, _ = fmt.Fprintf(e.stdout, "Segments:       %d\n", len(hdr.Segments()))
	return nil
}

// warnAboutDroppedEntries tells the operator when the header on disk
// carried keyslot or token entries written as JSON null, which the library
// removed while reading it. It goes to stderr because the report on stdout
// is something people pipe, and a warning that a container is damaged does
// not belong in the middle of it.
func warnAboutDroppedEntries(e *env, device string, hdr *luks2.Header) {
	dropped := hdr.Dropped()
	if len(dropped) == 0 {
		return
	}
	suffix := "y"
	if len(dropped) != 1 {
		suffix = "ies"
	}
	_, _ = fmt.Fprintf(e.stderr, "\nWARNING: the header on %s carries %d entr%s written as JSON null:\n", device, len(dropped), suffix)
	for _, entry := range dropped {
		_, _ = fmt.Fprintf(e.stderr, "  %s\n", entry)
	}
	_, _ = fmt.Fprintln(e.stderr, "They are not usable and are ignored. Any command that writes this header")
	_, _ = fmt.Fprintln(e.stderr, "will remove them from the device permanently. Back the header up first:")
	_, _ = fmt.Fprintf(e.stderr, "  cryptsetup luksHeaderBackup %s --header-backup-file <file>\n", device)
}
