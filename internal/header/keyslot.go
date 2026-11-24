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
	// MaxKeyslotKeySize is the largest volume key, in bytes, accepted from a keyslot: sixteen times XTS's 64.
	MaxKeyslotKeySize = 1024

	// MaxKeyslotAreaSize bounds how much of the device a single keyslot may
	// claim, matching cryptsetup's LUKS2_MAX_KEYSLOTS_SIZE (128 MiB).
	MaxKeyslotAreaSize = 128 << 20

	// MaxKeyslotStripes is the largest anti-forensic stripe count accepted,
	// matching the LUKS1/LUKS2 fixed value.
	MaxKeyslotStripes = AFStripes
)

// ValidateKeyslot makes one keyslot's metadata safe to act on; non-luks2 types get only the general limits; id may be empty.
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

// ToKDFParams copies k's fields into a kdf.Params, salt as the stored base64; callers check k for nil.
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

// ValidateKDFCost checks what running this KDF would cost; the error is unclassified so each caller wraps its own sentinel.
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
