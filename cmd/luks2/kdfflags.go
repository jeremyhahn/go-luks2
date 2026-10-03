// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/fips140"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// The KDF options `create` and `recovery add` share (#237).
//
// They are named as cryptsetup names them, so an operator who knows one tool
// knows the other: --pbkdf, --hash, --iter-time, --pbkdf-force-iterations,
// --pbkdf-memory and --pbkdf-parallel. --pbkdf-force-iterations means what it
// means there too -- the PBKDF2 iteration count, or the Argon2 time cost.
//
// Before #237 `create` hard-coded Argon2id and `recovery add` left the KDF to a
// library default that was Argon2id in every mode, so under
// GODEBUG=fips140=only neither could create a keyslot and there was no flag to
// choose one that could.

const (
	// pbkdfArgon2id and pbkdfPBKDF2 are the values --pbkdf accepts. argon2i is
	// not offered: cryptsetup's default and this tool's are Argon2id, and a
	// second Argon2 variant would be a choice with nothing to recommend it.
	pbkdfArgon2id = "argon2id"
	pbkdfPBKDF2   = "pbkdf2"

	// defaultPBKDF2Hash is the hash --pbkdf pbkdf2 uses when --hash is not
	// given: the hash of the library's FIPS-mode default, so `--pbkdf pbkdf2`
	// alone writes the same keyslot a FIPS-mode default would.
	defaultPBKDF2Hash = "sha512"
)

// pbkdf2Hashes are the hashes --hash accepts. SHA-1 is not among them: it is
// accepted for reading legacy headers only and is refused in FIPS mode, and
// nothing new should be written with it (docs/FIPS.md).
var pbkdf2Hashes = []string{"sha256", "sha384", "sha512"}

// kdfFlagsHelp is the help text for the KDF options, shared by every command
// that declares them.
const kdfFlagsHelp = `  --pbkdf <name>                  argon2id or pbkdf2. Default: pbkdf2 (SHA-512) in
                                  FIPS 140-3 mode, argon2id otherwise. argon2id is
                                  refused in FIPS 140-3 mode.
  --hash <name>                   PBKDF2 hash: sha256, sha384 or sha512 (default)
  --iter-time <ms>                PBKDF2 time budget to calibrate to (default 2000);
                                  never below the hash's iteration floor
  --pbkdf-force-iterations <n>    PBKDF2 iteration count, or Argon2 time cost
  --pbkdf-memory <KiB>            Argon2 memory cost
  --pbkdf-parallel <n>            Argon2 parallelism
`

// kdfFlags holds the KDF options as given. Every value is kept as text, and
// whether it was given at all is asked of the parser, so "not given", "given
// as 0" and "given empty" stay distinguishable: an explicit zero or an empty
// value is refused rather than read as "use the default".
type kdfFlags struct {
	command         string
	given           func(name string) bool
	pbkdf           *string
	hash            *string
	iterTime        *string
	forceIterations *string
	memory          *string
	parallel        *string
}

// declareKDFFlags declares the KDF options on o.
func declareKDFFlags(o *options) *kdfFlags {
	return &kdfFlags{
		command:         o.command,
		given:           o.Given,
		pbkdf:           o.String("pbkdf", ""),
		hash:            o.String("hash", ""),
		iterTime:        o.String("iter-time", ""),
		forceIterations: o.String("pbkdf-force-iterations", ""),
		memory:          o.String("pbkdf-memory", ""),
		parallel:        o.String("pbkdf-parallel", ""),
	}
}

// kdfChoice is what the KDF options resolve to: the library KDF type to create
// the keyslot with and the costs to give it. A zero cost is unset and leaves
// the library's default -- or, for Argon2 on recovery add, the container's
// inherited cost -- in place.
type kdfChoice struct {
	// KDFType is never empty: it is the type the flags chose or, when --pbkdf
	// was not given, the library's default for this mode.
	KDFType string

	// Label names the KDF for the operator, for example "PBKDF2-SHA512".
	Label string

	PBKDFIterTime   int
	PBKDFIterations int
	Argon2Time      int
	Argon2Memory    int
	Argon2Parallel  int
}

// resolve validates the options against the process's mode and the library's
// default KDF for it. Nothing has been read, created or written when it
// returns an error, which is the point of calling it first.
func (f *kdfFlags) resolve() (kdfChoice, error) {
	return f.resolveFor(fips140.Enabled(), luks2.DefaultKDFType())
}

// resolveFor is resolve for a given mode and default. Both are parameters so
// every branch is tested in every run: a process's FIPS mode is fixed when it
// starts.
//
// An Argon2id request in FIPS mode is refused here with the library's typed
// ErrFIPSNotApproved -- the same error the library would return, but before
// the operator has typed a passphrase or `create` has made a file.
func (f *kdfFlags) resolveFor(fipsMode bool, defaultKDF string) (kdfChoice, error) {
	// An option given an empty value -- `--hash=` or `--hash ""` -- is a
	// mistake, not a request for the default: refused, so an empty
	// --pbkdf-memory cannot slip past the check that it does not apply.
	for _, opt := range []struct {
		name  string
		value *string
	}{
		{"pbkdf", f.pbkdf}, {"hash", f.hash}, {"iter-time", f.iterTime},
		{"pbkdf-force-iterations", f.forceIterations}, {"pbkdf-memory", f.memory}, {"pbkdf-parallel", f.parallel},
	} {
		if f.given(opt.name) && *opt.value == "" {
			return kdfChoice{}, f.usage("--%s requires a value", opt.name)
		}
	}

	family := *f.pbkdf
	switch family {
	case "":
		family = pbkdfArgon2id
		if strings.HasPrefix(defaultKDF, pbkdfPBKDF2) {
			family = pbkdfPBKDF2
		}
	case pbkdfArgon2id, pbkdfPBKDF2:
	default:
		return kdfChoice{}, f.usage("--pbkdf must be %s or %s, not %q", pbkdfArgon2id, pbkdfPBKDF2, family)
	}

	if family == pbkdfArgon2id && fipsMode {
		return kdfChoice{}, &luks2.CryptoError{Op: pbkdfArgon2id, Err: luks2.ErrFIPSNotApproved}
	}

	forced, err := f.positive("pbkdf-force-iterations", *f.forceIterations)
	if err != nil {
		return kdfChoice{}, err
	}

	if family == pbkdfArgon2id {
		return f.argon2Choice(forced)
	}
	return f.pbkdf2Choice(defaultKDF, forced)
}

// argon2Choice resolves the options for an Argon2id keyslot. The PBKDF2-only
// options are refused rather than ignored: an operator who gave --iter-time
// believes it took effect.
func (f *kdfFlags) argon2Choice(timeCost int) (kdfChoice, error) {
	if *f.hash != "" {
		return kdfChoice{}, f.usage("--hash applies to pbkdf2 only; add --pbkdf pbkdf2")
	}
	if *f.iterTime != "" {
		return kdfChoice{}, f.usage("--iter-time applies to pbkdf2 only; add --pbkdf pbkdf2 " +
			"(an argon2id cost is set with --pbkdf-force-iterations, --pbkdf-memory and --pbkdf-parallel)")
	}
	memory, err := f.positive("pbkdf-memory", *f.memory)
	if err != nil {
		return kdfChoice{}, err
	}
	parallel, err := f.positive("pbkdf-parallel", *f.parallel)
	if err != nil {
		return kdfChoice{}, err
	}
	return kdfChoice{
		KDFType:        luks2.KDFTypeArgon2id,
		Label:          "Argon2id",
		Argon2Time:     timeCost,
		Argon2Memory:   memory,
		Argon2Parallel: parallel,
	}, nil
}

// pbkdf2Choice resolves the options for a PBKDF2 keyslot. The hash is --hash,
// or the one the library's default names when that default is PBKDF2, or
// defaultPBKDF2Hash.
func (f *kdfFlags) pbkdf2Choice(defaultKDF string, iterations int) (kdfChoice, error) {
	if *f.memory != "" || *f.parallel != "" {
		return kdfChoice{}, f.usage("--pbkdf-memory and --pbkdf-parallel apply to argon2id only")
	}

	hash := defaultPBKDF2Hash
	if named, ok := strings.CutPrefix(defaultKDF, pbkdfPBKDF2+"-"); ok {
		hash = named
	}
	if *f.hash != "" {
		hash = strings.ToLower(*f.hash)
		if !slices.Contains(pbkdf2Hashes, hash) {
			return kdfChoice{}, f.usage("--hash must be one of %s, not %q", strings.Join(pbkdf2Hashes, ", "), *f.hash)
		}
	}

	iterTime, err := f.positive("iter-time", *f.iterTime)
	if err != nil {
		return kdfChoice{}, err
	}
	return kdfChoice{
		KDFType:         pbkdfPBKDF2 + "-" + hash,
		Label:           "PBKDF2-" + strings.ToUpper(hash),
		PBKDFIterTime:   iterTime,
		PBKDFIterations: iterations,
	}, nil
}

// positive parses an option that, when given, must be a whole number above
// zero. An absent option is zero, which every consumer reads as "unset".
func (f *kdfFlags) positive(name, value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		return 0, f.usage("--%s requires a whole number above zero, not %q", name, value)
	}
	return n, nil
}

func (f *kdfFlags) usage(format string, args ...any) error {
	return &UsageError{Command: f.command, Detail: fmt.Sprintf(format, args...)}
}

// kdfRefused reports a KDF the options cannot have and returns the exit
// status. A FIPS refusal says what to use instead.
func (c *CLI) kdfRefused(err error) int {
	_, _ = fmt.Fprintf(c.Stderr, "Error: %v\n", err)
	if errors.Is(err, luks2.ErrFIPSNotApproved) {
		_, _ = fmt.Fprintln(c.Stderr, "In FIPS 140-3 mode use --pbkdf pbkdf2, or omit --pbkdf for the FIPS default (PBKDF2-SHA512).")
	}
	return 1
}
