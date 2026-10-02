// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Recovery keys: a full-strength credential, generated rather than chosen, for
// the case where the passphrase is gone.
//
// # The printed key is THE key
//
// A recovery key is displayed EXACTLY ONCE, on stdout, and is never written
// anywhere else unless the operator asks for it with --output. It is not
// logged, not echoed back on a later command, and not recoverable from the
// volume: the whole point of it is that the volume cannot produce it.
//
// # The printed string IS the passphrase
//
// What is on the screen is the credential itself, not an encoding of one. It
// opens the volume from any rescue system with stock cryptsetup and nothing
// else -- paste it at `cryptsetup open` -- which is the only thing that makes a
// printed page in a safe a recovery path rather than a souvenir.
//
// So the dashes and the letter case are part of it. Nothing in this file may
// reformat, re-case or re-wrap it on the way out, and the round trip is
// asserted against real cryptsetup rather than against this package's own
// opinion of itself.

// recoveryUsage is the group's own help.
func (c *CLI) recoveryUsage() int {
	_, _ = fmt.Fprintln(c.Stdout, "Usage: luks2 recovery <subcommand> [options]")
	_, _ = fmt.Fprintln(c.Stdout, "")
	_, _ = fmt.Fprintln(c.Stdout, "Subcommands:")
	_, _ = fmt.Fprintln(c.Stdout, "  generate                 Generate a recovery key without touching a volume")
	_, _ = fmt.Fprintln(c.Stdout, "  add <device>             Generate one and add it to a volume's keyslot")
	_, _ = fmt.Fprintln(c.Stdout, "  verify <device>          Check that a recovery key still opens a volume")
	_, _ = fmt.Fprintln(c.Stdout, "")
	_, _ = fmt.Fprintln(c.Stdout, "Options:")
	_, _ = fmt.Fprintln(c.Stdout, "  --format <name>          dashed (default), hex or base64")
	_, _ = fmt.Fprintln(c.Stdout, "  --length <n>             Key length in bytes (default 32)")
	_, _ = fmt.Fprintln(c.Stdout, "  --output <path>          Write the key to a file as well as showing it")
	_, _ = fmt.Fprintln(c.Stdout, "  --recovery-file <path>   Read a recovery key from a file (verify)")
	_, _ = fmt.Fprintln(c.Stdout, "")
	_, _ = fmt.Fprintln(c.Stdout, "Examples:")
	_, _ = fmt.Fprintln(c.Stdout, "  luks2 recovery add /dev/sdb1")
	_, _ = fmt.Fprintln(c.Stdout, "  luks2 recovery add --format hex --output /root/recovery.txt /dev/sdb1")
	_, _ = fmt.Fprintln(c.Stdout, "  luks2 recovery verify --recovery-file /root/recovery.txt /dev/sdb1")
	return 1
}

// cmdRecovery dispatches the recovery subcommands.
func (c *CLI) cmdRecovery() int {
	if len(c.Args) < 3 {
		return c.recoveryUsage()
	}

	switch c.Args[2] {
	case "generate":
		return c.cmdRecoveryGenerate()
	case "add":
		return c.cmdRecoveryAdd()
	case "verify":
		return c.cmdRecoveryVerify()
	default:
		_, _ = fmt.Fprintf(c.Stderr, "Unknown recovery subcommand: %s\n\n", c.Args[2])
		return c.recoveryUsage()
	}
}

// recoveryOptions parses the options the generate and add subcommands share.
func recoveryOptions(command string) (*options, *string, *int, *string) {
	o := newOptions(command)
	format := o.String("format", string(luks2.RecoveryKeyFormatDashed))
	length := o.Int("length", luks2.RecoveryKeyLength)
	output := o.String("output", "")
	return o, format, length, output
}

// cmdRecoveryGenerate produces a recovery key without touching a volume.
//
// This is deliberately possible: an operator provisioning a fleet wants the key
// before the container exists, and generating one is not the same act as
// enrolling it.
func (c *CLI) cmdRecoveryGenerate() int {
	o, format, length, output := recoveryOptions("recovery generate")
	if _, err := o.parse(c.Args[3:]); err != nil {
		return c.usageError(err)
	}

	key, err := c.Luks.GenerateRecoveryKey(*length, luks2.RecoveryKeyFormat(*format))
	if err != nil {
		return c.fail(err)
	}
	defer key.Clear()

	if err := c.showRecoveryKey(key); err != nil {
		return c.fail(err)
	}

	if *output != "" {
		if err := c.Luks.SaveRecoveryKey(key, *output); err != nil {
			_, _ = fmt.Fprintf(c.Stderr, "The key was NOT saved to %s: %v\n", *output, err)
			return 1
		}
		_, _ = fmt.Fprintf(c.Stdout, "Saved to %s\n", *output)
	}

	return 0
}

// cmdRecoveryAdd generates a recovery key and puts it in a keyslot.
func (c *CLI) cmdRecoveryAdd() int {
	o, format, length, output := recoveryOptions("recovery add")
	key := keyFileFlag(o, "key-file")
	slot := o.Int("slot", -1)
	args, err := o.parse(c.Args[3:])
	if err != nil {
		return c.usageError(err)
	}
	if len(args) < 1 {
		return c.recoveryUsage()
	}

	device := args[0]

	existing, err := c.readPassphrase("Enter an existing passphrase: ", false, *key)
	if err != nil {
		return c.fail(err)
	}
	defer ClearBytes(existing)

	opts := &luks2.RecoveryKeyOptions{
		Length:     *length,
		Format:     luks2.RecoveryKeyFormat(*format),
		OutputPath: *output,
	}
	if *slot >= 0 {
		requested := *slot
		opts.Keyslot = &requested
	}

	recovery, err := c.Luks.AddRecoveryKey(device, existing, opts)
	if err != nil {
		return c.fail(err)
	}
	defer recovery.Clear()

	if err := c.showRecoveryKey(recovery); err != nil {
		return c.fail(err)
	}

	// The keyslot number comes from AddRecoveryKey, which reads it from where
	// the library CHOSE it rather than inferring it from the header afterwards
	// (#42). It is written into the saved file and outlives the process, so an
	// operator retiring this key months from now destroys the right one.
	_, _ = fmt.Fprintf(c.Stdout, "\nAdded to keyslot %d on %s\n", recovery.Keyslot, device)
	if recovery.TokenID >= 0 {
		// The token is what tells cryptsetup, systemd and the next person that
		// this slot is a recovery key rather than somebody's passphrase.
		_, _ = fmt.Fprintf(c.Stdout, "Recorded as token %d (type systemd-recovery)\n", recovery.TokenID)
	}

	// A save failure is NOT fatal and must not be silent: the key is live in a
	// keyslot either way, and an operator who believes it is on disk when it is
	// not has a volume with a credential nobody holds.
	if recovery.SaveError != nil {
		_, _ = fmt.Fprintf(c.Stderr, "\nWARNING: the key is live in keyslot %d but was NOT saved: %v\n", recovery.Keyslot, recovery.SaveError)
		_, _ = fmt.Fprintln(c.Stderr, "Copy it from the screen now. It cannot be shown again.")
		return 1
	}
	if *output != "" {
		_, _ = fmt.Fprintf(c.Stdout, "Saved to %s\n", *output)
	}

	return 0
}

// cmdRecoveryVerify checks that a recovery key still opens a volume.
//
// Reading it back is the only way to find out that a key written down a year
// ago was transcribed correctly, and it is a read-only operation on the volume.
func (c *CLI) cmdRecoveryVerify() int {
	o := newOptions("recovery verify")
	file := o.String("recovery-file", "")
	args, err := o.parse(c.Args[3:])
	if err != nil {
		return c.usageError(err)
	}
	if len(args) < 1 {
		return c.recoveryUsage()
	}

	device := args[0]

	key, err := c.recoveryKeyInput(*file)
	if err != nil {
		return c.fail(err)
	}
	defer c.releaseCredential(key)

	valid, err := c.Luks.VerifyRecoveryKey(device, key)
	if err != nil {
		return c.fail(err)
	}
	if !valid {
		_, _ = fmt.Fprintf(c.Stderr, "That recovery key does NOT open %s\n", device)
		return 1
	}

	_, _ = fmt.Fprintf(c.Stdout, "The recovery key opens %s\n", device)
	return 0
}

// releaseCredential destroys a credential the library handed this command and
// tells the operator when go-enclave reports the release as anything but clean.
//
// The library drops its own release reports (pkg/luks2 releaseSecret: it can
// neither act on them nor log), and says an application sees the same
// conditions on the enclaves it is handed. This is that application. Both
// reports describe the HOST, not this command: enclave.ErrReleasedWithoutWipe
// means a sandbox denied the mprotect a wipe needs, and
// enclave.ErrLockedMemoryUnavailable means the kernel refused to take the pages
// back. Neither leaks the key -- the pages were mlock'd throughout, the kernel
// zeroes them before reuse, and pages still held go when this process exits --
// so the warning goes to stderr and the exit status stays the command's own: a
// verification that answered is not made to look as though it did not.
func (c *CLI) releaseCredential(key *enclave.MemoryEnclave) {
	destroy := c.destroyEnclave
	if destroy == nil {
		destroy = (*enclave.MemoryEnclave).Destroy
	}
	if err := destroy(key); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Warning: the recovery key's protected memory was not released cleanly: %v\n", err)
	}
}

// recoveryKeyInput obtains a recovery credential from a file, or from wherever a
// passphrase would come from.
//
// The two paths are different library calls, not one with a flag:
// LoadRecoveryCredential reads the file this tool WROTE, with its header and its
// checksum line, while RecoveryCredential takes the bare string a person types
// or a script pipes. Both return the credential VERBATIM -- neither re-cases it
// nor strips its dashes, because those are part of it.
//
// A recovery key enrolled BEFORE the credential became the printed text is not
// verified by this command: those keyslots hold the decoded bytes, and the
// library keeps ParseRecoveryKey and LoadRecoveryKey for exactly that case. It
// is not tried here as a second attempt, because a command that quietly tests
// something other than what it was asked about is worse than one that says no.
func (c *CLI) recoveryKeyInput(file string) (*enclave.MemoryEnclave, error) {
	if file != "" {
		return c.Luks.LoadRecoveryCredential(file)
	}

	typed, err := c.readPassphrase("Enter the recovery key: ", false, KeySource{})
	if err != nil {
		return nil, err
	}
	defer ClearBytes(typed)

	// string(typed) copies the rendering into immutable memory that can never
	// be zeroed, and that is not an oversight: ParseRecoveryKey takes a string,
	// and its signature has consumers outside this repository. The buffer this
	// command owns is still wiped; what cannot be wiped is the copy the library
	// boundary forces. The window is one call long and the material is a
	// rendering the operator has just read off a screen, which is the least bad
	// place for it -- but it is a real exposure and it is recorded here rather
	// than hidden by the conversion looking incidental.
	return c.Luks.RecoveryCredential(string(typed))
}

// showRecoveryKey displays a recovery key ONCE.
//
// The credential is materialized here, at the point of display, and nowhere
// else: it lives in protected memory precisely so that it is not sitting in an
// ordinary Go string for the lifetime of the process. What is printed is the
// credential character for character -- see the note at the top of this file.
func (c *CLI) showRecoveryKey(key *luks2.RecoveryKey) error {
	formatted, err := key.FormattedString()
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(c.Stdout, "")
	_, _ = fmt.Fprintln(c.Stdout, "=================== RECOVERY KEY ===================")
	_, _ = fmt.Fprintln(c.Stdout, formatted)
	_, _ = fmt.Fprintln(c.Stdout, "====================================================")
	_, _ = fmt.Fprintln(c.Stdout, "Write this down NOW. It is shown once and cannot be")
	_, _ = fmt.Fprintln(c.Stdout, "recovered from the volume.")
	_, _ = fmt.Fprintln(c.Stdout, "")
	_, _ = fmt.Fprintln(c.Stdout, "THE LINE ABOVE IS THE PASSPHRASE. Type or paste it")
	_, _ = fmt.Fprintln(c.Stdout, "exactly as shown -- dashes and letter case included --")
	_, _ = fmt.Fprintln(c.Stdout, "at any prompt that asks for one, including:")
	_, _ = fmt.Fprintln(c.Stdout, "  cryptsetup open <device> <name>")
	_, _ = fmt.Fprintf(c.Stdout, "Checksum (not secret): %s\n", key.CredentialHash)

	return nil
}
