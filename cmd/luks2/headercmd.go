// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Header inspection and repair.
//
// A LUKS2 container carries TWO copies of its header, and the second one is not
// a backup an operator has to remember to take -- it is written every time the
// first one is. These commands are how the second copy becomes useful: read it,
// compare it, and put it back over a primary that no longer parses.

// headerUsage is the group's own help.
func (c *CLI) headerUsage() int {
	_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 header <subcommand> <device>")
	_, _ = fmt.Fprintln(c.Stdout, "")
	_, _ = fmt.Fprintln(c.Stdout, "Subcommands:")
	_, _ = fmt.Fprintln(c.Stdout, "  show <device>        Show the primary header")
	_, _ = fmt.Fprintln(c.Stdout, "  secondary <device>   Show the secondary header copy")
	_, _ = fmt.Fprintln(c.Stdout, "  restore <device>     Overwrite the primary header with the secondary copy")
	_, _ = fmt.Fprintln(c.Stdout, "                       (--batch-mode or --yes skips the confirmation;")
	_, _ = fmt.Fprintln(c.Stdout, "                       --force restores over an intact primary that is not older)")
	_, _ = fmt.Fprintln(c.Stdout, "")
	_, _ = fmt.Fprintln(c.Stdout, "Examples:")
	_, _ = fmt.Fprintln(c.Stdout, "  luks2 header show /dev/sdb1")
	_, _ = fmt.Fprintln(c.Stdout, "  luks2 header secondary /dev/sdb1")
	_, _ = fmt.Fprintln(c.Stdout, "  luks2 header restore /dev/sdb1")
	return 1
}

// cmdHeader dispatches the header subcommands.
func (c *CLI) cmdHeader() int {
	if len(c.Args) < 4 {
		return c.headerUsage()
	}

	o := newOptions("header " + c.Args[2])
	batch := func() bool { return false }
	force := new(bool)
	if c.Args[2] == "restore" {
		batch = batchFlags(o)
		force = o.Bool("force")
	}
	args, err := o.parse(c.Args[3:])
	if err != nil {
		return c.usageError(err)
	}
	if len(args) < 1 {
		return c.headerUsage()
	}
	device, err := absPath("header "+c.Args[2], args[0])
	if err != nil {
		return c.usageError(err)
	}

	switch c.Args[2] {
	case "show":
		return c.showHeader(device, "Primary", c.Luks.ReadHeader)
	case "secondary":
		return c.showHeader(device, "Secondary", c.Luks.ReadSecondaryHeader)
	case "restore":
		return c.cmdHeaderRestore(device, batch(), luks2.RestoreHeaderOptions{Force: *force})
	default:
		_, _ = fmt.Fprintf(c.Stderr, "Unknown header subcommand: %s\n\n", c.Args[2])
		return c.headerUsage()
	}
}

// headerReader is either ReadHeader or ReadSecondaryHeader. The two produce the
// same shape and are reported the same way, so the report is written once.
type headerReader func(device string) (*luks2.LUKS2BinaryHeader, *luks2.LUKS2Metadata, error)

func (c *CLI) showHeader(device, which string, read headerReader) int {
	hdr, metadata, err := read(device)
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Failed to read the %s header on %s: %v\n", strings.ToLower(which), device, err)
		return 1
	}

	c.warnAboutDroppedEntries(device, metadata)

	_, _ = fmt.Fprintf(c.Stdout, "%s header: %s\n", which, device)
	_, _ = fmt.Fprintln(c.Stdout, "===========================================================")
	_, _ = fmt.Fprintf(c.Stdout, "Version:        LUKS%d\n", hdr.Version)
	_, _ = fmt.Fprintf(c.Stdout, "UUID:           %s\n", trimNUL(hdr.UUID[:]))
	_, _ = fmt.Fprintf(c.Stdout, "Label:          %s\n", trimNUL(hdr.Label[:]))
	_, _ = fmt.Fprintf(c.Stdout, "Subsystem:      %s\n", trimNUL(hdr.SubsystemLabel[:]))
	_, _ = fmt.Fprintf(c.Stdout, "Header size:    %d bytes\n", hdr.HeaderSize)
	_, _ = fmt.Fprintf(c.Stdout, "Header offset:  %d\n", hdr.HeaderOffset)
	_, _ = fmt.Fprintf(c.Stdout, "Checksum algo:  %s\n", trimNUL(hdr.ChecksumAlgorithm[:]))

	// The SEQUENCE ID is the reason to look at both copies. Whichever header
	// carries the higher one was written last; a secondary that is AHEAD of the
	// primary means the primary is stale, which is what a restore is for.
	_, _ = fmt.Fprintf(c.Stdout, "Sequence ID:    %d\n", hdr.SequenceID)

	_, _ = fmt.Fprintf(c.Stdout, "\nKeyslots:       %d\n", len(metadata.Keyslots))
	_, _ = fmt.Fprintf(c.Stdout, "Tokens:         %d\n", len(metadata.Tokens))
	_, _ = fmt.Fprintf(c.Stdout, "Segments:       %d\n", len(metadata.Segments))
	_, _ = fmt.Fprintf(c.Stdout, "Digests:        %d\n", len(metadata.Digests))

	return 0
}

// cmdHeaderRestore overwrites the primary header with the secondary copy.
//
// Without --force the library refuses an intact primary that is not older
// than the secondary (ErrPrimaryHeaderCurrent): that restore is a ROLLBACK,
// not a repair. --force asks for it anyway, and still needs the typed YES or
// --batch-mode -- forcing is what makes the confirmation matter most.
func (c *CLI) cmdHeaderRestore(device string, batch bool, opts luks2.RestoreHeaderOptions) int {
	_, _ = fmt.Fprintf(c.Stdout, "This overwrites the PRIMARY header on %s with the secondary copy.\n", device)
	_, _ = fmt.Fprintln(c.Stdout, "If the secondary copy is older, changes recorded only in the primary")
	_, _ = fmt.Fprintln(c.Stdout, "header -- a keyslot added since, a token written since -- are lost.")
	_, _ = fmt.Fprintln(c.Stdout, "Compare them first with 'luks2 header show' and 'luks2 header secondary'.")
	if opts.Force {
		_, _ = fmt.Fprintln(c.Stdout, "")
		_, _ = fmt.Fprintln(c.Stdout, "--force: the primary is restored over even when it is intact and current.")
		_, _ = fmt.Fprintln(c.Stdout, "That ROLLS THE VOLUME BACK: a passphrase removed since may open it again.")
	}

	// Anything but YES cancels, and a canceled restore exits non-zero.
	if err := c.confirmDestructive("Type 'YES' to restore the primary header: ", batch); err != nil {
		return c.refuseUnconfirmed("Restore", err)
	}

	if err := c.Luks.RestorePrimaryHeader(device, opts); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Failed to restore the primary header: %v\n", err)
		if errors.Is(err, luks2.ErrPrimaryHeaderCurrent) {
			_, _ = fmt.Fprintln(c.Stderr, "The primary is intact and not older than the secondary, so restoring would roll it back.")
			_, _ = fmt.Fprintln(c.Stderr, "If that is what you want, pass --force.")
		}
		return 1
	}

	_, _ = fmt.Fprintf(c.Stdout, "The primary header on %s was restored from the secondary copy.\n", device)
	return 0
}

// cmdIsLUKS answers whether a device holds a LUKS container, in its exit code.
//
// The exit code IS the answer, as `cryptsetup isLuks` does it: 0 for yes, 1 for
// no. A script asking the question wants to branch on it, not to parse a
// sentence -- and an error reading the device is also "no", but is reported on
// stderr so that "there is no container here" and "this device could not be
// read" are distinguishable to a person.
func (c *CLI) cmdIsLUKS() int {
	o := newOptions("isluks")
	luks2Only := o.Bool("luks2")
	args, err := o.parse(c.Args[2:])
	if err != nil {
		return c.usageError(err)
	}
	if len(args) < 1 {
		_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 isluks [--luks2] <device>")
		_, _ = fmt.Fprintln(c.Stdout, "")
		_, _ = fmt.Fprintln(c.Stdout, "Exit 0 if the device holds a LUKS container, 1 if it does not.")
		_, _ = fmt.Fprintln(c.Stdout, "--luks2 narrows the question to LUKS2 specifically.")
		_, _ = fmt.Fprintln(c.Stdout, "")
		_, _ = fmt.Fprintln(c.Stdout, "Examples:")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 isluks /dev/sdb1")
		_, _ = fmt.Fprintln(c.Stdout, "  luks2 isluks --luks2 /dev/sdb1")
		return 1
	}

	device, err := absPath("isluks", args[0])
	if err != nil {
		return c.usageError(err)
	}

	var (
		is   bool
		kind = "LUKS"
	)
	if *luks2Only {
		kind = "LUKS2"
		is, err = c.Luks.IsLUKS2(device)
	} else {
		is, err = c.Luks.IsLUKS(device)
	}
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Could not read %s: %v\n", device, err)
		return 1
	}
	if !is {
		_, _ = fmt.Fprintf(c.Stdout, "%s is not a %s device\n", device, kind)
		return 1
	}

	_, _ = fmt.Fprintf(c.Stdout, "%s is a %s device\n", device, kind)
	return 0
}

// trimNUL renders a fixed-size C string field from the binary header.
func trimNUL(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
