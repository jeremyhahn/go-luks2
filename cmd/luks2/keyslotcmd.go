// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strconv"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Keyslot management: the credentials a container can be opened with.
//
// Every command here that changes a keyslot needs TWO credentials -- one to
// authenticate with and, where a credential is being added or replaced, the new
// one. They are separate flags (--key-file and --new-key-file) because a script
// has to be able to supply both without a terminal, and because supplying only
// one and being prompted for the other is the shape that hangs a systemd unit.

// cmdTestKey verifies that a passphrase opens the volume.
//
// A failure here is not necessarily "wrong passphrase": the library
// distinguishes a keyslot that judged the credential and rejected it from one
// that could not be tried at all, and the message it returns carries that
// distinction. Flattening it into "wrong passphrase" would send an operator
// looking for a typo when the container is damaged.
func (c *CLI) cmdTestKey() int {
	o := newOptions("testkey")
	key := keyFileFlag(o, "key-file")
	args, err := o.parse(c.Args[2:])
	if err != nil {
		return c.usageError(err)
	}
	if len(args) < 1 {
		return c.usage("testkey", "luks2 testkey [options] <device>",
			"Verify that a passphrase opens a volume. Nothing is changed.",
			"  luks2 testkey /dev/sdb1",
			"  luks2 testkey --key-file /etc/luks/backup.key /dev/sdb1")
	}

	device := args[0]

	passphrase, err := c.readPassphrase("Enter passphrase: ", false, *key)
	if err != nil {
		return c.fail(err)
	}
	defer ClearBytes(passphrase)

	if err := c.Luks.TestKey(device, passphrase); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "The passphrase did not open %s: %v\n", device, err)
		return 1
	}

	_, _ = fmt.Fprintf(c.Stdout, "The passphrase opens %s\n", device)
	return 0
}

// cmdAddKey adds a second credential to a volume.
func (c *CLI) cmdAddKey() int {
	o := newOptions("addkey")
	key := keyFileFlag(o, "key-file")
	newKey := keyFileFlag(o, "new-key-file")
	slot := o.Int("slot", -1)
	kdf := o.String("kdf", "")
	args, err := o.parse(c.Args[2:])
	if err != nil {
		return c.usageError(err)
	}
	if len(args) < 1 {
		return c.usage("addkey", "luks2 addkey [options] <device>",
			"Add another passphrase to a volume. The existing passphrase is needed\n"+
				"to unwrap the volume key; the new one goes into a free keyslot.",
			"  luks2 addkey /dev/sdb1",
			"  luks2 addkey --key-file /etc/luks/current.key --new-key-file /etc/luks/next.key /dev/sdb1",
			"",
			"Options:",
			"  --slot <n>              Use this keyslot instead of the first free one",
			"  --kdf <name>            argon2id (default), argon2i or pbkdf2",
			"  --new-key-file <path>   Read the NEW passphrase from a file")
	}

	device := args[0]

	existing, err := c.readPassphrase("Enter an existing passphrase: ", false, *key)
	if err != nil {
		return c.fail(err)
	}
	defer ClearBytes(existing)

	added, err := c.readPassphrase("Enter the new passphrase: ", true, *newKey)
	if err != nil {
		return c.fail(err)
	}
	defer ClearBytes(added)

	opts := &luks2.AddKeyOptions{KDFType: *kdf}
	if *slot >= 0 {
		requested := *slot
		opts.Keyslot = &requested
	}

	if err := c.Luks.AddKey(device, existing, added, opts); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Failed to add the passphrase: %v\n", err)
		return 1
	}

	// The slot number is deliberately NOT reported here. AddKey does not say
	// which slot it used, and inferring it from the header afterwards gives the
	// wrong answer on any container whose active slots are not contiguous from
	// zero -- which is every container that has ever had a credential revoked
	// (#42). A number that is wrong in the direction of "destroy the other
	// credential" is worse than no number, so the listing is what says.
	_, _ = fmt.Fprintln(c.Stdout, "Passphrase added.")
	_, _ = fmt.Fprintf(c.Stdout, "Run 'luks2 keyslots %s' to see which keyslot it went to.\n", device)
	return 0
}

// cmdRemoveKey removes the keyslot a passphrase itself opens.
func (c *CLI) cmdRemoveKey() int {
	o := newOptions("removekey")
	key := keyFileFlag(o, "key-file")
	args, err := o.parse(c.Args[2:])
	if err != nil {
		return c.usageError(err)
	}
	if len(args) < 2 {
		return c.usage("removekey", "luks2 removekey [options] <device> <keyslot>",
			"Remove a keyslot. The passphrase given must be THE ONE IN THAT SLOT;\n"+
				"use killslot to remove a slot with a different credential.",
			"  luks2 removekey /dev/sdb1 2")
	}

	device := args[0]
	slot, err := parseKeyslot("removekey", args[1])
	if err != nil {
		return c.usageError(err)
	}

	passphrase, err := c.readPassphrase("Enter the passphrase for that keyslot: ", false, *key)
	if err != nil {
		return c.fail(err)
	}
	defer ClearBytes(passphrase)

	if err := c.Luks.RemoveKey(device, passphrase, slot); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Failed to remove keyslot %d: %v\n", slot, err)
		return 1
	}

	_, _ = fmt.Fprintf(c.Stdout, "Keyslot %d removed.\n", slot)
	return 0
}

// cmdKillSlot removes a keyslot, authenticating with any credential.
func (c *CLI) cmdKillSlot() int {
	o := newOptions("killslot")
	key := keyFileFlag(o, "key-file")
	args, err := o.parse(c.Args[2:])
	if err != nil {
		return c.usageError(err)
	}
	if len(args) < 2 {
		return c.usage("killslot", "luks2 killslot [options] <device> <keyslot>",
			"Remove a keyslot, authenticating with ANY valid passphrase. This is how\n"+
				"a lost or compromised credential is revoked by someone who still has\n"+
				"a working one.",
			"  luks2 killslot /dev/sdb1 3")
	}

	device := args[0]
	slot, err := parseKeyslot("killslot", args[1])
	if err != nil {
		return c.usageError(err)
	}

	passphrase, err := c.readPassphrase("Enter any valid passphrase: ", false, *key)
	if err != nil {
		return c.fail(err)
	}
	defer ClearBytes(passphrase)

	// Destroying a credential is irreversible and the operator names the slot
	// by number, so the number is echoed back before anything happens.
	_, _ = fmt.Fprintf(c.Stdout, "Removing keyslot %d from %s. The credential in it will no longer open the volume.\n", slot, device)

	if err := c.Luks.KillSlot(device, passphrase, slot); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Failed to remove keyslot %d: %v\n", slot, err)
		return 1
	}

	_, _ = fmt.Fprintf(c.Stdout, "Keyslot %d removed.\n", slot)
	return 0
}

// cmdChangeKey replaces the passphrase in one keyslot.
func (c *CLI) cmdChangeKey() int {
	o := newOptions("changekey")
	key := keyFileFlag(o, "key-file")
	newKey := keyFileFlag(o, "new-key-file")
	args, err := o.parse(c.Args[2:])
	if err != nil {
		return c.usageError(err)
	}
	if len(args) < 2 {
		return c.usage("changekey", "luks2 changekey [options] <device> <keyslot>",
			"Replace the passphrase in a keyslot, in place. The old passphrase must be\n"+
				"the one in that slot.",
			"  luks2 changekey /dev/sdb1 0",
			"  luks2 changekey --key-file old.key --new-key-file new.key /dev/sdb1 0")
	}

	device := args[0]
	slot, err := parseKeyslot("changekey", args[1])
	if err != nil {
		return c.usageError(err)
	}

	old, err := c.readPassphrase("Enter the current passphrase: ", false, *key)
	if err != nil {
		return c.fail(err)
	}
	defer ClearBytes(old)

	replacement, err := c.readPassphrase("Enter the new passphrase: ", true, *newKey)
	if err != nil {
		return c.fail(err)
	}
	defer ClearBytes(replacement)

	if err := c.Luks.ChangeKey(device, old, replacement, slot); err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Failed to change keyslot %d: %v\n", slot, err)
		return 1
	}

	_, _ = fmt.Fprintf(c.Stdout, "Keyslot %d now holds the new passphrase.\n", slot)
	return 0
}

// cmdKeyslots lists the keyslots a container carries.
func (c *CLI) cmdKeyslots() int {
	o := newOptions("keyslots")
	args, err := o.parse(c.Args[2:])
	if err != nil {
		return c.usageError(err)
	}
	if len(args) < 1 {
		return c.usage("keyslots", "luks2 keyslots <device>",
			"List the keyslots on a volume, in the order an unlock attempts them.",
			"  luks2 keyslots /dev/sdb1")
	}

	slots, err := c.Luks.ListKeyslots(args[0])
	if err != nil {
		_, _ = fmt.Fprintf(c.Stderr, "Failed to read keyslots: %v\n", err)
		return 1
	}

	if len(slots) == 0 {
		// Not an error, and it must not be reported as one: a container with no
		// usable keyslot is a container nobody can open, and an operator needs
		// to be told that plainly rather than shown an empty table.
		_, _ = fmt.Fprintf(c.Stderr, "%s has NO keyslots. Nothing can open this volume.\n", args[0])
		return 1
	}

	_, _ = fmt.Fprintln(c.Stdout, "Slot  Type     Key size  KDF        Encryption")
	for _, s := range slots {
		_, _ = fmt.Fprintf(c.Stdout, "%-5d %-8s %-9d %-10s %s\n", s.ID, s.Type, s.KeySize, s.KDFType, s.Encryption)
	}
	return 0
}

// parseKeyslot converts an operator's keyslot argument, refusing anything that
// is not a slot this container can have.
//
// The bound is checked HERE as well as in the library because the number is
// about to be printed back in a sentence describing what is going to be
// destroyed, and "keyslot 99" in that sentence is worse than an error.
func parseKeyslot(command, arg string) (int, error) {
	slot, err := strconv.Atoi(arg)
	if err != nil {
		return 0, &UsageError{Command: command, Detail: fmt.Sprintf("%q is not a keyslot number", arg)}
	}
	if slot < 0 || slot >= luks2.MaxKeyslots {
		return 0, &UsageError{
			Command: command,
			Detail:  fmt.Sprintf("keyslot %d is out of range (0-%d)", slot, luks2.MaxKeyslots-1),
		}
	}
	return slot, nil
}
