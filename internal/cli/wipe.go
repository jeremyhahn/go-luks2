// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/pkg/wipe"
)

const maxWipePasses = 100

// wipeUsage is also printed directly to stdout by runWipe when <device> is
// missing, matching the pre-rewrite CLI (docs/wipe/cli.md).
const wipeUsage = "Usage: luks2 wipe [--full] [options] <device>\n\n" +
	"Without --full, zeroes the header and keyslot areas (a crypto-erase).\n" +
	"With --full, overwrites the entire device.\n\n" +
	"Options:\n" +
	"  --full             Overwrite the whole device instead of just the header\n" +
	"  --passes N         Number of overwrite passes (default: 1); --full only\n" +
	"  --random           Use random data instead of zeros; --full only\n" +
	"  --trim             Issue TRIM/DISCARD after wipe (for SSDs); --full only\n" +
	"  --standard <name>  Use a named wipe standard: nist, dod3, dod7; --full only\n" +
	"  --verify           Enable verification; --full only\n" +
	"  --no-verify        Disable verification (overrides --standard); --full only\n" +
	"  --batch-mode, --yes  Do not ask for confirmation\n"

func wipeCommand() *command {
	return &command{
		name:     "wipe",
		synopsis: "Overwrite a device's header, or the whole device",
		usage:    wipeUsage,
		run:      runWipe,
	}
}

func runWipe(ctx context.Context, e *env, args []string) error {
	f := newFlags("wipe")
	full := f.Bool("full")
	random := f.Bool("random")
	trim := f.Bool("trim")
	verify := f.Bool("verify")
	noVerify := f.Bool("no-verify")
	passes := f.String("passes", "1")
	standardName := f.String("standard", "")
	batch := batchFlags(f)
	positional, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		_, _ = fmt.Fprint(e.stdout, wipeUsage)
		return &UsageError{Command: "wipe", Detail: "want exactly one device path"}
	}
	device, err := absPath("wipe", positional[0])
	if err != nil {
		return err
	}

	// --passes and --standard are validated whether or not --full is given
	// (docs/wipe/cli.md): an operator who mistyped one should see that
	// before anything is destroyed, not be told it was silently ignored.
	n, err := strconv.Atoi(*passes)
	if err != nil || n < 1 || n > maxWipePasses {
		return &UsageError{Command: "wipe", Detail: fmt.Sprintf("--passes wants 1-%d, not %q", maxWipePasses, *passes)}
	}
	var standard wipe.Standard
	switch *standardName {
	case "":
	case "nist":
		standard = wipe.NIST
	case "dod3":
		standard = wipe.DoD3Pass
	case "dod7":
		standard = wipe.DoD7Pass
	default:
		return &UsageError{Command: "wipe", Detail: fmt.Sprintf("unknown --standard %q (want nist, dod3 or dod7)", *standardName)}
	}

	if !*full {
		// A header-only wipe overwrites no data area, so a flag that shapes
		// the overwrite would be silently ignored.
		for _, name := range []string{"random", "passes", "standard", "verify", "no-verify", "trim"} {
			if f.Given(name) {
				return &UsageError{Command: "wipe", Detail: fmt.Sprintf("--%s only applies with --full", name)}
			}
		}
		return runWipeHeaderOnly(ctx, e, device, batch())
	}

	p := wipe.Params{Discard: *trim, Standard: standard}
	if p.Standard == wipe.NoStandard {
		pattern := wipe.Zeros
		if *random {
			pattern = wipe.Random
		}
		p.Patterns = make([]wipe.Pattern, n)
		for i := range p.Patterns {
			p.Patterns[i] = pattern
		}
	}
	switch {
	case *noVerify:
		p.Verify = wipe.VerifyNever
	case *verify:
		p.Verify = wipe.VerifyAlways
	}

	_, _ = fmt.Fprintln(e.stdout, "*** WARNING: DESTRUCTIVE OPERATION ***")
	_, _ = fmt.Fprintf(e.stdout, "This will PERMANENTLY DESTROY all data on: %s\n", device)

	if err := confirmDestructive(e, "Type 'YES' to confirm wipe: ", batch()); err != nil {
		return refuseUnconfirmed(e, "Wipe", err)
	}

	_, _ = fmt.Fprintln(e.stdout, "Wiping entire device (this may take a while)...")

	if err := wipe.Sanitize(ctx, device, p); err != nil {
		return err
	}

	_, _ = fmt.Fprintln(e.stdout, "Volume wiped successfully.")
	return nil
}

// runWipeHeaderOnly is wipe's default mode: a crypto-erase of the header and
// keyslot areas, leaving the data segment itself untouched but
// undecryptable (docs/wipe/cli.md).
func runWipeHeaderOnly(ctx context.Context, e *env, device string, batch bool) error {
	_, _ = fmt.Fprintln(e.stdout, "*** WARNING: DESTRUCTIVE OPERATION ***")
	_, _ = fmt.Fprintf(e.stdout, "This wipes the LUKS2 header and keyslot areas on: %s\n", device)
	_, _ = fmt.Fprintln(e.stdout, "This is a crypto-erase: the data segment is left in place, but nothing")
	_, _ = fmt.Fprintln(e.stdout, "can derive its key afterwards. A header backup taken before this no")
	_, _ = fmt.Fprintln(e.stdout, "longer opens the volume.")

	if err := confirmDestructive(e, "Type 'YES' to confirm wipe: ", batch); err != nil {
		return refuseUnconfirmed(e, "Wipe", err)
	}

	v, err := luks2.Open(ctx, device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	if err := v.Erase(ctx); err != nil {
		return err
	}

	_, _ = fmt.Fprintln(e.stdout, "Volume wiped successfully.")
	return nil
}
