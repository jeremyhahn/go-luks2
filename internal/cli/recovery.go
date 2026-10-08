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

// Recovery keys: a full-strength credential, generated rather than chosen,
// for the case where the passphrase is gone. The printed line IS the
// passphrase -- see showRecoveryKey -- and recovery-key file I/O lives
// here, not in pkg/luks2 (DESIGN.md §F).

func recoveryCommand() *command {
	return &command{
		name:     "recovery",
		synopsis: "Generate, add or verify a recovery key",
		usage: "Usage: luks2 recovery <generate|add|verify> [options]\n\n" +
			"generate   Generate a recovery key without touching a volume\n" +
			"add        Generate one and add it to a volume's keyslot\n" +
			"verify     Check that a recovery key still opens a volume\n",
		sub: map[string]*command{
			"generate": {
				name:     "recovery generate",
				synopsis: "Generate a recovery key without touching a volume",
				usage: "Usage: luks2 recovery generate [--format <name>] [--length <n>] [--output <path>]\n\n" +
					"Options:\n" +
					"  --format <name>   dashed (default), hex or base64\n" +
					"  --length <n>      Key length in bytes (default 32)\n" +
					"  --output <path>   Write the key to a file as well as showing it\n",
				run: runRecoveryGenerate,
			},
			"add": {
				name:     "recovery add",
				synopsis: "Generate a recovery key and add it to a volume's keyslot",
				usage: "Usage: luks2 recovery add [options] <device>\n\n" +
					"Options:\n" +
					"  --format <name>   dashed (default), hex or base64\n" +
					"  --length <n>      Key length in bytes (default 32)\n" +
					"  --slot <n>        Use this keyslot instead of the first free one\n" +
					"  --output <path>   Write the key to a file as well as showing it\n" +
					"  --key-file <path|->  The EXISTING passphrase\n" +
					kdfFlagsHelp,
				run: runRecoveryAdd,
			},
			"verify": {
				name:     "recovery verify",
				synopsis: "Check that a recovery key still opens a volume",
				usage: "Usage: luks2 recovery verify [--recovery-file <path>] <device>\n\n" +
					"Read-only. Exit 0 if the key opens the volume, 2 if it does not (as for\n" +
					"a wrong passphrase); any other failure exits with its own status.\n",
				run: runRecoveryVerify,
			},
		},
	}
}

func runRecoveryGenerate(_ context.Context, e *env, args []string) error {
	f := newFlags("recovery generate")
	formatName := f.String("format", "dashed")
	length := f.Int("length", luks2.DefaultRecoveryKeyLength)
	output := f.String("output", "")
	if _, err := f.parse(args); err != nil {
		return err
	}

	format, err := parseRecoveryFormat("recovery generate", *formatName)
	if err != nil {
		return err
	}

	rk, err := luks2.NewRecoveryKey(luks2.WithRecoveryFormat(format), luks2.WithRecoveryLength(*length))
	if err != nil {
		return err
	}
	defer rk.Destroy()

	if err := showRecoveryKey(e, rk); err != nil {
		return err
	}

	if *output != "" {
		if err := saveRecoveryKey(*output, rk, recoveryFileMeta{}); err != nil {
			_, _ = fmt.Fprintf(e.stderr, "The key was NOT saved to %s: %v\n", *output, err)
			return err
		}
		_, _ = fmt.Fprintf(e.stdout, "Saved to %s\n", *output)
	}

	return nil
}

func runRecoveryAdd(ctx context.Context, e *env, args []string) error {
	f := newFlags("recovery add")
	key := keyFileFlag(f, "key-file")
	formatName := f.String("format", "dashed")
	length := f.Int("length", luks2.DefaultRecoveryKeyLength)
	slot := f.Int("slot", -1)
	output := f.String("output", "")
	kdf := declareKDFFlags(f)
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) < 1 {
		return &UsageError{Command: "recovery add", Detail: "want <device>"}
	}

	format, err := parseRecoveryFormat("recovery add", *formatName)
	if err != nil {
		return err
	}

	// Settled before the passphrase prompt, for the reason create's KDF
	// resolution is: a choice this mode refuses must stop the command
	// before anything is read or written.
	kdfParams, _, err := kdf.resolve()
	if err != nil {
		reportKDFRefusal(e, err)
		return err
	}

	device, err := absPath("recovery add", positional[0])
	if err != nil {
		return err
	}

	existing, err := readPassphrase(e, "Enter an existing passphrase: ", false, *key)
	if err != nil {
		return err
	}
	defer e.custody.Release(existing)

	rk, err := luks2.NewRecoveryKey(luks2.WithRecoveryFormat(format), luks2.WithRecoveryLength(*length))
	if err != nil {
		return err
	}
	defer rk.Destroy()

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

	params := luks2.KeyslotParams{Priority: luks2.PriorityNormal, KDF: kdfParams}
	if *slot >= 0 {
		requested := *slot
		params.Slot = &requested
	}

	enrollment, err := v.AddRecoveryKey(ctx, volumeKey, rk, params)
	if err != nil {
		return err
	}

	if err := showRecoveryKey(e, rk); err != nil {
		return unshownRecoveryKey(ctx, e, v, device, enrollment, err)
	}

	_, _ = fmt.Fprintf(e.stdout, "\nAdded to keyslot %d on %s\n", enrollment.Keyslot.ID, device)
	_, _ = fmt.Fprintf(e.stdout, "Recorded as token %d (type %s)\n", enrollment.Token, luks2.TokenTypeRecovery)

	if *output != "" {
		meta := recoveryFileMeta{Keyslot: enrollment.Keyslot.ID, Token: enrollment.Token}
		if hdr, herr := v.Header(ctx); herr == nil {
			meta.UUID = hdr.UUID()
		}
		if err := saveRecoveryKey(*output, rk, meta); err != nil {
			_, _ = fmt.Fprintf(e.stderr, "\nWARNING: the key is live in keyslot %d but was NOT saved: %v\n", enrollment.Keyslot.ID, err)
			_, _ = fmt.Fprintln(e.stderr, "Copy it from the screen now. It cannot be shown again.")
			return err
		}
		_, _ = fmt.Fprintf(e.stdout, "Saved to %s\n", *output)
	}

	return nil
}

// unshownRecoveryKey handles a recovery key that was enrolled and could not
// be shown: a live credential nobody has seen. Its keyslot and token are
// removed again -- the --output save, if any, only ever happens after a
// successful show, so an unshown key was never saved either. What could
// not be removed is named, with the command that removes it.
func unshownRecoveryKey(ctx context.Context, e *env, v *luks2.Volume, device string, enrollment luks2.Enrollment, cause error) error {
	_, _ = fmt.Fprintf(e.stderr, "Error: the recovery key could not be shown: %v\n", cause)

	if err := v.RemoveKeyslot(ctx, enrollment.Keyslot.ID); err != nil {
		_, _ = fmt.Fprintf(e.stderr, "WARNING: the key is LIVE in keyslot %d on %s and nobody has seen it, and removing it failed: %v\n",
			enrollment.Keyslot.ID, device, err)
		_, _ = fmt.Fprintf(e.stderr, "Remove it with: luks2 killslot %s %d\n", device, enrollment.Keyslot.ID)
		return cause
	}
	if err := v.RemoveToken(ctx, enrollment.Token); err != nil {
		_, _ = fmt.Fprintf(e.stderr, "Keyslot %d was removed, but its token %d was not: %v\n", enrollment.Keyslot.ID, enrollment.Token, err)
		_, _ = fmt.Fprintf(e.stderr, "Remove it with: luks2 token remove %s %d\n", device, enrollment.Token)
		return cause
	}
	_, _ = fmt.Fprintf(e.stderr, "Keyslot %d was removed again, so no key nobody has seen is left on %s.\n", enrollment.Keyslot.ID, device)
	return cause
}

func runRecoveryVerify(ctx context.Context, e *env, args []string) error {
	f := newFlags("recovery verify")
	file := f.String("recovery-file", "")
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) < 1 {
		return &UsageError{Command: "recovery verify", Detail: "want <device>"}
	}
	device, err := absPath("recovery verify", positional[0])
	if err != nil {
		return err
	}

	cred, err := readRecoveryCredential(e, *file)
	if err != nil {
		return err
	}
	defer e.custody.Release(cred)

	normalized, err := luks2.ParseRecoveryKey(cred)
	if err != nil {
		return err
	}
	defer e.custody.Release(normalized)

	v, err := luks2.Open(ctx, device, luks2.WithReadOnly())
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	key, err := v.Unlock(ctx, normalized)
	if err != nil {
		// Only a verdict on the key gets the verdict line; a failure that never
		// tried it (a lock, an unreadable keyslot) is reported as itself.
		if errors.Is(err, luks2.ErrWrongKey) {
			_, _ = fmt.Fprintf(e.stderr, "That recovery key does NOT open %s\n", device)
		}
		return err
	}
	key.Destroy()

	_, _ = fmt.Fprintf(e.stdout, "The recovery key opens %s\n", device)
	return nil
}
