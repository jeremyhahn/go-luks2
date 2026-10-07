// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// The KDF options create and recovery add share, named as cryptsetup names
// them: --pbkdf, --hash, --iter-time, --pbkdf-force-iterations,
// --pbkdf-memory and --pbkdf-parallel (docs/volumes/cli.md#kdf-options).
// addkey takes a single --kdf flag instead; see parseAddKeyKDF.

// pbkdf2Hashes are the hashes --hash accepts. SHA-1 is not among them: it is
// accepted for reading legacy headers only, never for writing a new one.
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
  --pbkdf-memory <KiB>             Argon2 memory cost
  --pbkdf-parallel <n>             Argon2 parallelism
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

// declareKDFFlags declares the KDF options on f.
func declareKDFFlags(f *flags) *kdfFlags {
	return &kdfFlags{
		command:         f.command,
		given:           f.Given,
		pbkdf:           f.String("pbkdf", ""),
		hash:            f.String("hash", ""),
		iterTime:        f.String("iter-time", ""),
		forceIterations: f.String("pbkdf-force-iterations", ""),
		memory:          f.String("pbkdf-memory", ""),
		parallel:        f.String("pbkdf-parallel", ""),
	}
}

// resolve validates the options and returns the KDFParams they resolve to,
// plus a label for the operator ("Argon2id", "PBKDF2-SHA512"). Nothing has
// been read, created or written when it returns an error, which is the
// point of calling it before any device is touched or passphrase is asked
// for.
func (f *kdfFlags) resolve() (luks2.KDFParams, string, error) {
	for _, opt := range []struct {
		name  string
		value *string
	}{
		{"pbkdf", f.pbkdf}, {"hash", f.hash}, {"iter-time", f.iterTime},
		{"pbkdf-force-iterations", f.forceIterations}, {"pbkdf-memory", f.memory}, {"pbkdf-parallel", f.parallel},
	} {
		if f.given(opt.name) && *opt.value == "" {
			return luks2.KDFParams{}, "", f.usage("--%s requires a value", opt.name)
		}
	}

	family := *f.pbkdf
	switch family {
	case "":
		family = string(luks2.DefaultKDFType())
	case string(luks2.KDFArgon2id), string(luks2.KDFPBKDF2):
	default:
		return luks2.KDFParams{}, "", f.usage("--pbkdf must be %s or %s, not %q", luks2.KDFArgon2id, luks2.KDFPBKDF2, family)
	}

	forced, err := f.positive("pbkdf-force-iterations", *f.forceIterations)
	if err != nil {
		return luks2.KDFParams{}, "", err
	}

	var p luks2.KDFParams
	var label string
	if family == string(luks2.KDFArgon2id) {
		p, label, err = f.argon2Choice(forced)
	} else {
		p, label, err = f.pbkdf2Choice(forced)
	}
	if err != nil {
		return luks2.KDFParams{}, "", err
	}

	if err := p.Validate(); err != nil {
		return luks2.KDFParams{}, "", err
	}
	return p, label, nil
}

// argon2Choice resolves the options for an Argon2id keyslot. The PBKDF2-only
// options are refused rather than ignored: an operator who gave --iter-time
// believes it took effect.
func (f *kdfFlags) argon2Choice(timeCost int) (luks2.KDFParams, string, error) {
	if *f.hash != "" {
		return luks2.KDFParams{}, "", f.usage("--hash applies to pbkdf2 only; add --pbkdf pbkdf2")
	}
	if *f.iterTime != "" {
		return luks2.KDFParams{}, "", f.usage("--iter-time applies to pbkdf2 only; add --pbkdf pbkdf2 " +
			"(an argon2id cost is set with --pbkdf-force-iterations, --pbkdf-memory and --pbkdf-parallel)")
	}
	memory, err := f.positive("pbkdf-memory", *f.memory)
	if err != nil {
		return luks2.KDFParams{}, "", err
	}
	parallel, err := f.positive("pbkdf-parallel", *f.parallel)
	if err != nil {
		return luks2.KDFParams{}, "", err
	}
	return luks2.KDFParams{
		Type:      luks2.KDFArgon2id,
		Time:      timeCost,
		MemoryKiB: memory,
		Parallel:  parallel,
	}, "Argon2id", nil
}

// pbkdf2Choice resolves the options for a PBKDF2 keyslot. The hash is
// --hash, or sha512 when it is not given.
func (f *kdfFlags) pbkdf2Choice(iterations int) (luks2.KDFParams, string, error) {
	if *f.memory != "" || *f.parallel != "" {
		return luks2.KDFParams{}, "", f.usage("--pbkdf-memory and --pbkdf-parallel apply to argon2id only")
	}

	hashName := "sha512"
	if *f.hash != "" {
		hashName = strings.ToLower(*f.hash)
		if !slices.Contains(pbkdf2Hashes, hashName) {
			return luks2.KDFParams{}, "", f.usage("--hash must be one of %s, not %q", strings.Join(pbkdf2Hashes, ", "), *f.hash)
		}
	}
	hash, err := hashFromName(hashName)
	if err != nil {
		return luks2.KDFParams{}, "", f.usage("%v", err)
	}

	iterTime, err := f.positive("iter-time", *f.iterTime)
	if err != nil {
		return luks2.KDFParams{}, "", err
	}
	return luks2.KDFParams{
		Type:       luks2.KDFPBKDF2,
		Hash:       hash,
		IterTime:   time.Duration(iterTime) * time.Millisecond,
		Iterations: iterations,
	}, "PBKDF2-" + strings.ToUpper(hashName), nil
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

// hashFromName maps a --hash value to its crypto.Hash.
func hashFromName(name string) (crypto.Hash, error) {
	switch name {
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("unknown hash %q", name)}
	}
}

// addKeyKDFNames are the --kdf values addkey accepts.
var addKeyKDFNames = []string{"argon2id", "argon2i", "pbkdf2", "pbkdf2-sha256", "pbkdf2-sha384", "pbkdf2-sha512"}

// parseAddKeyKDF resolves addkey's single --kdf flag, which names the KDF
// with cryptsetup's combined spelling ("pbkdf2-sha512") rather than the
// separate --pbkdf/--hash pair create and recovery add use
// (docs/keyslots/cli.md#addkey). An empty name resolves to a zero
// KDFParams, which AddKeyslot reads as "the library default, or the
// container's inherited Argon2 cost".
func parseAddKeyKDF(command, name string) (luks2.KDFParams, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "":
		return luks2.KDFParams{}, nil
	case "argon2id":
		return luks2.KDFParams{Type: luks2.KDFArgon2id}, nil
	case "argon2i":
		return luks2.KDFParams{Type: luks2.KDFArgon2i}, nil
	case "pbkdf2", "pbkdf2-sha256":
		return luks2.KDFParams{Type: luks2.KDFPBKDF2, Hash: crypto.SHA256}, nil
	case "pbkdf2-sha384":
		return luks2.KDFParams{Type: luks2.KDFPBKDF2, Hash: crypto.SHA384}, nil
	case "pbkdf2-sha512":
		return luks2.KDFParams{Type: luks2.KDFPBKDF2, Hash: crypto.SHA512}, nil
	case "pbkdf2-sha1":
		return luks2.KDFParams{}, &UsageError{Command: command, Detail: "--kdf pbkdf2-sha1: no keyslot is created with SHA-1; " +
			"use pbkdf2 (SHA-256), pbkdf2-sha384, pbkdf2-sha512 or argon2id"}
	default:
		return luks2.KDFParams{}, &UsageError{Command: command, Detail: fmt.Sprintf("--kdf must be one of %s, not %q",
			strings.Join(addKeyKDFNames, ", "), name)}
	}
}

// reportKDFRefusal prints a hint to stderr when a KDF choice was refused
// because the process runs in FIPS 140-3 mode. The command still returns
// the error itself, which Run prints and maps to an exit code.
func reportKDFRefusal(e *env, err error) {
	if errors.Is(err, luks2.ErrFIPSNotApproved) {
		_, _ = fmt.Fprintln(e.stderr, "In FIPS 140-3 mode use --pbkdf pbkdf2, or omit --pbkdf for the FIPS default (PBKDF2-SHA512).")
	}
}
