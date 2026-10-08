// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// slotKDFHelp is the KDF help for addkey and changekey. Unlike create, giving
// no KDF option leaves the cost to the library: the volume's own Argon2 cost
// when it has one, the default otherwise.
const slotKDFHelp = "\nKDF options (none given: the volume's existing cost, else the default):\n" + kdfFlagsHelp

func addkeyCommand() *command {
	return &command{
		name:     "addkey",
		synopsis: "Add another passphrase to a volume",
		usage: "Usage: luks2 addkey [options] <device>\n\n" +
			"Add another passphrase to a volume. The existing passphrase is needed\n" +
			"to unwrap the volume key; the new one goes into a free keyslot.\n\n" +
			"Options:\n" + keyFileHelp +
			"  --new-key-file <path>   Read the NEW passphrase from a file\n" +
			"  --slot <n>              Use this keyslot instead of the first free one\n" +
			slotKDFHelp,
		run: runAddKey,
	}
}

func runAddKey(ctx context.Context, e *env, args []string) error {
	f := newFlags("addkey")
	key := keyFileFlag(f, "key-file")
	newKey := keyFileFlag(f, "new-key-file")
	slot := f.Int("slot", -1)
	kdfOpts := declareKDFFlags(f)
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) < 1 {
		return &UsageError{Command: "addkey", Detail: "want <device>"}
	}

	// Judged before either passphrase is asked for: an operator should not
	// type two credentials to learn the KDF was never going to be written.
	kdf, err := kdfOpts.resolveOptional()
	if err != nil {
		reportKDFRefusal(e, err)
		return err
	}
	if err := kdf.Validate(); err != nil {
		reportKDFRefusal(e, err)
		return err
	}

	device, err := absPath("addkey", positional[0])
	if err != nil {
		return err
	}

	existing, err := readPassphrase(e, "Enter an existing passphrase: ", false, *key)
	if err != nil {
		return err
	}
	defer e.custody.Release(existing)

	added, err := readPassphrase(e, "Enter the new passphrase: ", true, *newKey)
	if err != nil {
		return err
	}
	defer e.custody.Release(added)

	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	volumeKey, err := v.Unlock(ctx, existing)
	if err != nil {
		return err
	}
	defer volumeKey.Destroy()

	params := luks2.KeyslotParams{Priority: luks2.PriorityNormal, KDF: kdf}
	if *slot >= 0 {
		requested := *slot
		params.Slot = &requested
	}

	if _, err := v.AddKeyslot(ctx, volumeKey, added, params); err != nil {
		return err
	}

	// The slot number is not reported: a correct one needs AddKeyslot's
	// return value is already read for other things here, but printing it
	// is not part of this change's scope; the listing is what says.
	_, _ = fmt.Fprintln(e.stdout, "Passphrase added.")
	_, _ = fmt.Fprintf(e.stdout, "Run 'luks2 keyslots %s' to see which keyslot it went to.\n", device)
	return nil
}

func changekeyCommand() *command {
	return &command{
		name:     "changekey",
		synopsis: "Replace the passphrase in a keyslot",
		usage: "Usage: luks2 changekey [options] <device> <slot>\n\n" +
			"Replace the passphrase in a keyslot, in place. The old passphrase must be\n" +
			"the one in that slot.\n\n" +
			"Options:\n" + keyFileHelp +
			"  --new-key-file <path>   Read the NEW passphrase from a file\n" +
			slotKDFHelp,
		run: runChangeKey,
	}
}

func runChangeKey(ctx context.Context, e *env, args []string) error {
	f := newFlags("changekey")
	key := keyFileFlag(f, "key-file")
	newKey := keyFileFlag(f, "new-key-file")
	kdfOpts := declareKDFFlags(f)
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) < 2 {
		return &UsageError{Command: "changekey", Detail: "want <device> <slot>"}
	}
	kdf, err := kdfOpts.resolveOptional()
	if err != nil {
		reportKDFRefusal(e, err)
		return err
	}
	if err := kdf.Validate(); err != nil {
		reportKDFRefusal(e, err)
		return err
	}
	device, err := absPath("changekey", positional[0])
	if err != nil {
		return err
	}
	slot, err := parseKeyslot("changekey", positional[1])
	if err != nil {
		return err
	}

	old, err := readPassphrase(e, "Enter the current passphrase: ", false, *key)
	if err != nil {
		return err
	}
	defer e.custody.Release(old)

	replacement, err := readPassphrase(e, "Enter the new passphrase: ", true, *newKey)
	if err != nil {
		return err
	}
	defer e.custody.Release(replacement)

	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	volumeKey, err := v.UnlockKeyslot(ctx, slot, old)
	if err != nil {
		return err
	}
	defer volumeKey.Destroy()

	// KeyslotParams's zero Priority is PriorityDefault, so ChangeKeyslot keeps
	// the slot's existing priority -- prefer, normal or ignore -- exactly as
	// it was: a passphrase change does not re-prioritize the slot. kdf is
	// zero unless a KDF option was given, so the slot keeps its cost unless
	// the operator asked for a new one, as with luksChangeKey.
	if _, err := v.ChangeKeyslot(ctx, volumeKey, replacement, luks2.KeyslotParams{KDF: kdf}); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "Keyslot %d now holds the new passphrase.\n", slot)
	return nil
}

func removekeyCommand() *command {
	return &command{
		name:     "removekey",
		synopsis: "Remove a keyslot, authenticating with its own passphrase",
		usage: "Usage: luks2 removekey [options] <device> <slot>\n\n" +
			"Remove a keyslot. The passphrase given must be THE ONE IN THAT SLOT;\n" +
			"use killslot to remove a slot with a different credential.\n\n" +
			"Options:\n" + keyFileHelp,
		run: runRemoveKey,
	}
}

func runRemoveKey(ctx context.Context, e *env, args []string) error {
	f := newFlags("removekey")
	key := keyFileFlag(f, "key-file")
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) < 2 {
		return &UsageError{Command: "removekey", Detail: "want <device> <slot>"}
	}
	device, err := absPath("removekey", positional[0])
	if err != nil {
		return err
	}
	slot, err := parseKeyslot("removekey", positional[1])
	if err != nil {
		return err
	}

	pass, err := readPassphrase(e, "Enter the passphrase for that keyslot: ", false, *key)
	if err != nil {
		return err
	}
	defer e.custody.Release(pass)

	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	volumeKey, err := v.UnlockKeyslot(ctx, slot, pass)
	if err != nil {
		return err
	}
	volumeKey.Destroy()

	if err := v.RemoveKeyslot(ctx, slot); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "Keyslot %d removed.\n", slot)
	return nil
}

func killslotCommand() *command {
	return &command{
		name:     "killslot",
		synopsis: "Remove a keyslot, authenticating with any valid passphrase",
		usage: "Usage: luks2 killslot [options] <device> <slot>\n\n" +
			"Remove a keyslot, authenticating with ANY valid passphrase. This is how\n" +
			"a lost or compromised credential is revoked by someone who still has\n" +
			"a working one.\n\n" +
			"Options:\n" + keyFileHelp,
		run: runKillSlot,
	}
}

func runKillSlot(ctx context.Context, e *env, args []string) error {
	f := newFlags("killslot")
	key := keyFileFlag(f, "key-file")
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) < 2 {
		return &UsageError{Command: "killslot", Detail: "want <device> <slot>"}
	}
	device, err := absPath("killslot", positional[0])
	if err != nil {
		return err
	}
	slot, err := parseKeyslot("killslot", positional[1])
	if err != nil {
		return err
	}

	pass, err := readPassphrase(e, "Enter any valid passphrase: ", false, *key)
	if err != nil {
		return err
	}
	defer e.custody.Release(pass)

	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	volumeKey, err := v.Unlock(ctx, pass)
	if err != nil {
		return err
	}
	volumeKey.Destroy()

	// Destroying a credential is irreversible and the operator names the
	// slot by number, so the number is echoed back before anything happens.
	_, _ = fmt.Fprintf(e.stdout, "Removing keyslot %d from %s. The credential in it will no longer open the volume.\n", slot, device)

	if err := v.RemoveKeyslot(ctx, slot); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(e.stdout, "Keyslot %d removed.\n", slot)
	return nil
}

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
