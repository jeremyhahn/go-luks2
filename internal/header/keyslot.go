// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package header

import (
	"fmt"
	"math"
	"strconv"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/kdf"
)

// Per-keyslot geometry validation: every failure wraps ErrInvalidKeyslot so the scan skips only that slot; limits match cryptsetup 2.7.0.
const (
	// MaxKeyslotKeySize is the largest volume key, in BYTES, this package will
	// accept from a keyslot read off a device.
	//
	// cryptsetup 2.7.0 will not FORMAT a volume with anything but a 256- or
	// 512-bit key in XTS mode -- it refuses outright with "Key size in XTS mode
	// must be 256 or 512 bits" -- so 64 bytes is the largest key it writes, and
	// XTS is the only mode this package implements. This is sixteen times that,
	// which leaves room for a mode or a cipher with a larger key without
	// leaving room for an attack.
	MaxKeyslotKeySize = 1024

	// MaxKeyslotAreaSize bounds how much of the device a single keyslot may
	// claim, matching cryptsetup's LUKS2_MAX_KEYSLOTS_SIZE (128 MiB).
	MaxKeyslotAreaSize = 128 << 20

	// MaxKeyslotStripes is the largest anti-forensic stripe count accepted,
	// matching the LUKS1/LUKS2 fixed value.
	MaxKeyslotStripes = AFStripes
)

// ValidateKeyslot checks one keyslot's declared geometry, and is called for
// every keyslot as the metadata is parsed.
//
// Its job is to make the metadata SAFE TO ACT ON: nothing downstream should
// have to re-establish that a field is present, parses, or describes an amount
// of work worth doing. It is not a check that the keyslot will open -- that is
// the passphrase's job, and a keyslot may be perfectly well-formed and simply
// hold a credential nobody has.
//
// Keyslot types other than "luks2" are checked only against the limits that
// apply to any keyslot. LUKS2 defines a "reencrypt" type alongside "luks2"; it
// carries no anti-forensic object and its area is a checksum region rather than
// raw key material, so imposing the luks2 rules on it would make a container in
// the middle of a reencryption unreadable -- including by GetVolumeInfo, which
// is exactly what an operator reaches for when something is wrong.
//
// The id names the keyslot in every message. It may be empty, for a keyslot
// reached by something other than its position in the header -- the phrasing
// degrades to "a keyslot" rather than to `keyslot ""`.
func ValidateKeyslot(id string, keyslot *Keyslot) error {
	label := "a keyslot"
	if id != "" {
		label = fmt.Sprintf("keyslot %q", id)
	}

	if keyslot == nil {
		return &errs.Error{Kind: errs.ErrInvalidKeyslot, Detail: fmt.Sprintf("%s is null", label)}
	}

	// The area bounds both a ciphertext buffer and a locked plaintext region, so it is bounded here.
	if keyslot.Area == nil {
		return &errs.Error{Kind: errs.ErrInvalidKeyslot, Detail: fmt.Sprintf("%s has no area object", label)}
	}
	areaOffset, err := parseSize(keyslot.Area.Offset)
	if err != nil {
		return &errs.Error{
			Kind:   errs.ErrInvalidKeyslot,
			Detail: fmt.Sprintf("%s declares an area offset %q that is not a number", label, keyslot.Area.Offset),
		}
	}
	// A negative offset is refused.
	if areaOffset < 0 {
		return &errs.Error{
			Kind:   errs.ErrInvalidKeyslot,
			Detail: fmt.Sprintf("%s declares a negative area offset %d", label, areaOffset),
		}
	}
	areaSize, err := parseSize(keyslot.Area.Size)
	if err != nil {
		return &errs.Error{
			Kind:   errs.ErrInvalidKeyslot,
			Detail: fmt.Sprintf("%s declares an area size %q that is not a number", label, keyslot.Area.Size),
		}
	}
	if areaSize <= 0 || areaSize > MaxKeyslotAreaSize {
		return &errs.Error{
			Kind: errs.ErrInvalidKeyslot,
			Detail: fmt.Sprintf("%s declares an area of %d bytes, outside the range a LUKS2 keyslot may occupy",
				label, areaSize),
		}
	}
	// Checked before the addition so no sum wraps.
	if areaOffset > math.MaxInt64-areaSize {
		return &errs.Error{
			Kind: errs.ErrInvalidKeyslot,
			Detail: fmt.Sprintf("%s declares an area at offset %d of %d bytes, which runs past the end of the address space",
				label, areaOffset, areaSize),
		}
	}

	if keyslot.Type != "luks2" {
		return nil
	}

	if keyslot.KDF == nil {
		return &errs.Error{
			Kind:   errs.ErrInvalidKeyslot,
			Detail: fmt.Sprintf("luks2 %s has no kdf object", label),
		}
	}
	if keyslot.AF == nil {
		return &errs.Error{
			Kind:   errs.ErrInvalidKeyslot,
			Detail: fmt.Sprintf("luks2 %s has no anti-forensic object", label),
		}
	}

	if keyslot.KeySize <= 0 || keyslot.KeySize > MaxKeyslotKeySize {
		return &errs.Error{
			Kind: errs.ErrInvalidKeyslot,
			Detail: fmt.Sprintf("luks2 %s declares a %d-byte volume key; the accepted range is 1..%d bytes",
				label, keyslot.KeySize, MaxKeyslotKeySize),
		}
	}
	if keyslot.AF.Stripes <= 0 || keyslot.AF.Stripes > MaxKeyslotStripes {
		return &errs.Error{
			Kind: errs.ErrInvalidKeyslot,
			Detail: fmt.Sprintf("luks2 %s declares %d anti-forensic stripes; the accepted range is 1..%d",
				label, keyslot.AF.Stripes, MaxKeyslotStripes),
		}
	}

	// The anti-forensic material has to fit the area that holds it.
	afBytes := int64(keyslot.KeySize) * int64(keyslot.AF.Stripes)
	if afBytes > areaSize {
		return &errs.Error{
			Kind: errs.ErrInvalidKeyslot,
			Detail: fmt.Sprintf("luks2 %s needs %d bytes of anti-forensic material but declares an area of only %d",
				label, afBytes, areaSize),
		}
	}

	return nil
}

// KDF cost ceilings, bounding what a HEADER may ask a single derivation to
// spend. See internal/kdf for where the numbers come from.
const (
	MinKDFIterations = kdf.MinKDFIterations
	MaxKDFIterations = kdf.MaxKDFIterations

	MinArgon2Time = kdf.MinArgon2Time
	MaxArgon2Time = kdf.MaxArgon2Time

	MinArgon2Memory = kdf.MinArgon2Memory
	MaxArgon2Memory = kdf.MaxArgon2Memory // KiB, i.e. 4 GiB -- cryptsetup's exact ceiling

	MinArgon2Parallel = kdf.MinArgon2Parallel
	MaxArgon2Parallel = kdf.MaxArgon2Parallel
)

// ToKDFParams copies k's fields into a kdf.Params. Salt is carried as the
// stored base64 string, so this conversion cannot fail: only the derive path
// decodes it, and a cost-only caller (ValidateKDFCost, DerivationWork) never
// touches it at all. Callers check k for nil themselves, matching each
// original function's own nil handling.
func ToKDFParams(k *KDF) kdf.Params {
	return kdf.Params{
		Type:       k.Type,
		Hash:       k.Hash,
		Salt:       k.Salt,
		Iterations: k.Iterations,
		Time:       k.Time,
		Memory:     k.Memory,
		CPUs:       k.CPUs,
	}
}

// ValidateKDFCost checks what running this KDF would cost, before any of it is
// spent.
//
// It returns an UNCLASSIFIED error on purpose. The same excessive cost means
// different things depending on where the KDF came from -- a keyslot's own KDF
// makes that keyslot unusable, a digest's makes that digest unusable -- and only
// the caller knows which. Each caller wraps the sentinel that routes an operator
// to the right remedy; classifying here would force one answer on both and
// misattribute the other.
func ValidateKDFCost(k *KDF) error {
	if k == nil {
		return &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "no KDF object"}
	}
	return kdf.ValidateCost(ToKDFParams(k))
}

// parseSize parses a size string (e.g., "512", "4096") to int64. It is a
// private copy of pkg/luks2's helper of the same name: both packages need it,
// and header must not import luks2 to reach the one luks2 already has.
func parseSize(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
