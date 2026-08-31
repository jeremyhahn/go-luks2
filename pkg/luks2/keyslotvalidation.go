// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import "fmt"

// Validation of the keyslot geometry a device declares about itself.
//
// # What a bad keyslot does without this
//
// A keyslot's declared fields are dereferenced and used as sizes. Measured
// against this package before the check existed, driving each shape through the
// real unlock path:
//
//	key_size = 0     PANIC  pkbdf2: keyLength must be larger than 0
//	key_size = -1    PANIC  pkbdf2: keyLength must be larger than 0
//	no kdf object    PANIC  nil pointer dereference
//	no area object   PANIC  nil pointer dereference
//	key_size = 1MiB  HANG   still in PBKDF2 at a 3-minute timeout
//
// The two key_size panics came from golang.org/x/crypto/pbkdf2.Key, which
// panics on any error out of crypto/pbkdf2, and the stdlib errors on
// keyLength <= 0 -- so a function whose signature promises an error crashed the
// process instead. That shim is no longer used; derivePBKDF2 calls crypto/pbkdf2
// directly and handles the error, which is a second guard behind this one. That mattered less when LUKS2 work meant shelling out to
// cryptsetup, where a crash was a child process's exit code. It is consumed IN
// PROCESS now, so the same byte of crafted JSON is a storage-daemon crash.
//
// The hang is the same field used as a cost multiplier: PBKDF2's work scales
// with the requested output length, and the result is then moved into a locked
// region, so key_size is both a CPU multiplier and a claim on the process's
// RLIMIT_MEMLOCK. None of it requires knowing a passphrase, because the
// derivation is what authentication is built on and therefore runs first.
//
// # Why this is per-keyslot, and NOT a refusal of the whole header
//
// It was written as a header refusal first -- validate every keyslot as the
// metadata is parsed, fail the read on the first bad one -- because that
// guarantees no consumer can skip it. That is wrong, and measurably so: a
// container with one intact keyslot and one damaged keyslot then stopped
// reading and stopped opening, through the intact keyslot, at all.
//
// A LUKS2 container carries up to 32 keyslots precisely so that damage to one
// is survivable. Bit rot in an unused slot, or a slot left half-written by an
// interrupted AddKey, must cost that slot and nothing else; converting it into
// an unopenable volume is permanent data loss manufactured by a safety check.
// This package has already reproduced data loss of that shape once (#37).
//
// So every failure here wraps ErrInvalidKeyslot, which is the value the keyslot
// scan reads as "this slot is unusable, try the next one". A failure typed
// anything else -- ErrInvalidHeader, a bare ErrInvalidSize -- would abort the
// whole unlock and deny a volume its good keyslots can still open. The same
// reasoning, and the same conclusion, as validateKeyslotShape on the
// issue/3-secure-buffer branch.
//
// The cost of that choice is that the check must be invoked at every entry
// point rather than once at the parse. There are four -- unlockKeyslot,
// wipeKeyslotArea, the reference-keyslot pick in AddKey and
// calculateNextKeyslotOffset -- and each calls THIS function rather than
// restating a bound. Restating is what went wrong before: unlockKeyslot bounded
// key_size*stripes 46 lines after the derivation that the same field had
// already paid for, so a bound existed and was useless.
//
// # Where the limits come from
//
// Every limit here is measured against cryptsetup 2.7.0 rather than invented,
// because a bound that refuses a container another implementation can open is
// its own kind of defect.
const (
	// MaxKeyslotKeySize is the largest volume key, in BYTES, this package will
	// accept from a keyslot read off a device.
	//
	// cryptsetup 2.7.0 will not FORMAT a volume with anything but a 256- or
	// 512-bit key in XTS mode -- it refuses outright with "Key size in XTS mode
	// must be 256 or 512 bits" -- so 64 bytes is the largest key it writes, and
	// XTS is the only mode this package implements. This is sixteen times that,
	// which leaves room for a mode or a cipher with a larger key without
	// leaving room for an attack: at 1024 bytes PBKDF2 produces 32 SHA-256
	// blocks per iteration chain and the derived key occupies 1 KiB of locked
	// memory, both negligible.
	//
	// It is deliberately NOT set to 64. cryptsetup's own parser does not bound
	// this field at all -- luksDump renders a keyslot declaring a 1 MiB key
	// quite happily -- and matching its writer exactly would make this package
	// refuse to so much as INSPECT a container cryptsetup can still describe.
	// The exact requirement that a keyslot key be a legal AES-XTS key (32, 48
	// or 64 bytes) is left where the cipher lives, in xts.NewCipher, which now
	// rejects it after a derivation bounded to 1 KiB instead of an unbounded
	// one.
	MaxKeyslotKeySize = 1024

	// maxKeyslotAreaSize bounds how much of the device a single keyslot may
	// claim.
	//
	// area.size decides the size of two allocations on the unlock path -- an
	// ordinary buffer for the ciphertext and a LOCKED region for the plaintext
	// -- so an unbounded value would let a crafted header exhaust the process's
	// locked memory and, because this package fails closed, take down every
	// other unlock in the process rather than only its own.
	//
	// The ceiling matches cryptsetup's LUKS2_MAX_KEYSLOTS_SIZE (128 MiB), so no
	// container cryptsetup will write is refused by it. A default 512-bit
	// keyslot needs 256 KiB.
	maxKeyslotAreaSize = 128 << 20

	// maxKeyslotStripes is the largest anti-forensic stripe count accepted.
	//
	// The LUKS1 and LUKS2 formats both fix this at 4000 -- the af object's
	// stripes field is documented as "always 4000" and cryptsetup writes
	// nothing else -- so the spec value is also the bound. Stripes multiply
	// both the hashing done by an AF merge and the bytes read off the device.
	maxKeyslotStripes = AFStripes
)

// validateKeyslot checks one keyslot's declared geometry, and is called for
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
func validateKeyslot(id string, keyslot *Keyslot) error {
	label := "a keyslot"
	if id != "" {
		label = fmt.Sprintf("keyslot %q", id)
	}

	if keyslot == nil {
		return fmt.Errorf("%w: %s is null", ErrInvalidKeyslot, label)
	}

	// The area is where the keyslot lives on the device and every keyslot type
	// has one, so it is checked for all of them. Its size bounds two
	// allocations -- an ordinary buffer for the ciphertext and a LOCKED region
	// for the plaintext -- which is why it is bounded here and not merely
	// parsed.
	if keyslot.Area == nil {
		return fmt.Errorf("%w: %s has no area object", ErrInvalidKeyslot, label)
	}
	if _, err := parseSize(keyslot.Area.Offset); err != nil {
		return fmt.Errorf("%w: %s declares an area offset %q that is not a number",
			ErrInvalidKeyslot, label, keyslot.Area.Offset)
	}
	areaSize, err := parseSize(keyslot.Area.Size)
	if err != nil {
		return fmt.Errorf("%w: %s declares an area size %q that is not a number",
			ErrInvalidKeyslot, label, keyslot.Area.Size)
	}
	if areaSize <= 0 || areaSize > maxKeyslotAreaSize {
		return fmt.Errorf("%w: %s declares an area of %d bytes, outside the range a LUKS2 keyslot may occupy",
			ErrInvalidKeyslot, label, areaSize)
	}

	if keyslot.Type != "luks2" {
		return nil
	}

	if keyslot.KDF == nil {
		return fmt.Errorf("%w: luks2 %s has no kdf object", ErrInvalidKeyslot, label)
	}
	if keyslot.AF == nil {
		return fmt.Errorf("%w: luks2 %s has no anti-forensic object", ErrInvalidKeyslot, label)
	}

	if keyslot.KeySize <= 0 || keyslot.KeySize > MaxKeyslotKeySize {
		return fmt.Errorf("%w: luks2 %s declares a %d-byte volume key; the accepted range is 1..%d bytes",
			ErrInvalidKeyslot, label, keyslot.KeySize, MaxKeyslotKeySize)
	}
	if keyslot.AF.Stripes <= 0 || keyslot.AF.Stripes > maxKeyslotStripes {
		return fmt.Errorf("%w: luks2 %s declares %d anti-forensic stripes; the accepted range is 1..%d",
			ErrInvalidKeyslot, label, keyslot.AF.Stripes, maxKeyslotStripes)
	}

	// The anti-forensic material has to fit the area that holds it. Measured
	// against cryptsetup 2.7.0: a container violating this is refused there too
	// -- luksOpen reports "Keyslot open failed" -- so enforcing it costs no
	// container any implementation can open, while removing the case where this
	// package reads and decrypts a whole area only to find the merge cannot be
	// satisfied.
	//
	// Both factors are already bounded above, so the product cannot overflow
	// here. afSplitBytes checks that anyway, because it is also reachable with
	// a keyslot a caller constructed rather than read.
	afBytes := int64(keyslot.KeySize) * int64(keyslot.AF.Stripes)
	if afBytes > areaSize {
		return fmt.Errorf("%w: luks2 %s needs %d bytes of anti-forensic material but declares an area of only %d",
			ErrInvalidKeyslot, label, afBytes, areaSize)
	}

	return nil
}

// KDF cost ceilings, bounding what a HEADER may ask a single derivation to
// spend.
//
// # Why these are separate from the shape checks above
//
// validateKeyslot bounds what a keyslot IS; these bound what running its KDF
// would COST. The distinction is not cosmetic -- it decides where they are
// called from. A keyslot with a deliberately expensive KDF is still a perfectly
// good template for a new keyslot, so AddKey's reference pick screens shape and
// not cost. Cost is checked at the two places a header-supplied KDF is actually
// RUN: the keyslot's own KDF in unlockKeyslot, and the digest KDF in
// verifyMasterKey.
//
// They are deliberately NOT enforced inside deriveKeyPlain, which looks like the
// right home because it is the one place a KDF is executed. It is not. That
// function serves two TRUST DOMAINS: Format, AddKey, ChangeKey and the exported
// DeriveKey all derive from parameters the CALLER chose, and an untrusted-input
// ceiling there rejects a caller's own deliberate hardening -- after the master
// key has been generated, with an error shaped like a malformed header. The
// narrowest common point is where the two domains merge, which is exactly why it
// is the wrong place to tell them apart. This is prior art from the
// issue/3-secure-buffer branch, which enforced it there, found this, and moved
// it out.
//
// # Where the numbers come from -- measured against cryptsetup 2.7.0
//
// Each was probed by formatting a real container and reading back what landed in
// the header:
//
//	PBKDF2 iterations   999 REFUSED, 1000 accepted; NO upper refusal -- 4294967295
//	                    was accepted and still running when a 10-minute probe timed
//	                    out, which is the attack itself
//	Argon2 memory       31 KiB REFUSED, 32 KiB accepted, 4194304 KiB accepted,
//	                    4194305 KiB REFUSED -- a hard ceiling at 4 GiB
//	Argon2 time         0 and 1 REFUSED, 4 accepted, and 100 WRITTEN into a header
//	                    (verified by reading "Time cost: 100" back); no upper refusal
//	Argon2 parallelism  every value accepted, but cryptsetup CLAMPS what it writes
//	                    to the host CPU count, so a header never carries more
//
// Only memory has a third-party ceiling, and it is adopted exactly. The others
// have none, so they are denial-of-service ceilings with headroom over observed
// practice, chosen so that no container cryptsetup can create is refused.
//
// # This diverges from the prior art, deliberately
//
// issue/3-secure-buffer uses maxArgon2Time = 64. That would refuse a container
// cryptsetup CAN create: --pbkdf-force-iterations 100 writes "Time cost: 100",
// measured above. A bound that rejects a legal container is its own defect, so
// the ceiling here is 10000 -- a hundred times the largest value cryptsetup was
// observed to write.
//
// # What these do NOT bound
//
// They are PER-DERIVATION. An unlock derives once per usable keyslot and once
// per digest per keyslot, and neither multiplier is bounded at parse, so total
// work is still unbounded by these values alone. That is a different fix with a
// different failure mode -- a whole-unlock deadline refuses a legitimately slow
// volume on slow hardware, and an expensive KDF is a SECURITY FEATURE -- and it
// is tracked in #26 rather than guessed at here.
//
// Nor do they make a maximally-costly LEGAL header cheap. A keyslot at
// cryptsetup's own 4 GiB memory ceiling still allocates 4 GiB when it is opened.
// Refusing that would refuse a container cryptsetup writes; capping the total is
// #26's problem, not this one's. What these ceilings remove is the UNBOUNDED
// case: the four-billion-iteration header, and the negative value that wraps.
const (
	// minKDFIterations is deliberately 1 and not cryptsetup's 1000. Being more
	// permissive at the CHEAP end costs nothing -- a low iteration count is a
	// weak keyslot, not a denial of service -- while refusing it would make an
	// old container unreadable.
	minKDFIterations = 1
	maxKDFIterations = 100_000_000

	minArgon2Time = 1
	maxArgon2Time = 10_000

	// minArgon2Memory is 8 rather than cryptsetup's 32: argon2 itself clamps
	// memory up to 2*syncPoints*threads, so anything at or above 8 is safe for
	// the primitive, and the same permissive-at-the-cheap-end reasoning applies.
	minArgon2Memory = 8
	maxArgon2Memory = 4 << 20 // KiB, i.e. 4 GiB -- cryptsetup's exact ceiling

	// Argon2 parallelism is a uint8 in the primitive. cryptsetup never writes
	// more than the host CPU count, so this refuses nothing it produces.
	minArgon2Parallel = 1
	maxArgon2Parallel = 255
)

// validateKDFCost checks what running this KDF would cost, before any of it is
// spent.
//
// It returns an UNCLASSIFIED error on purpose. The same excessive cost means
// different things depending on where the KDF came from -- a keyslot's own KDF
// makes that keyslot unusable, a digest's makes that digest unusable -- and only
// the caller knows which. Each caller wraps the sentinel that routes an operator
// to the right remedy; classifying here would force one answer on both and
// misattribute the other.
//
// Whichever sentinel a caller chooses, it must be one the keyslot scan treats as
// entry-level, so that a crafted slot costs its own keyslot and not the volume.
func validateKDFCost(kdf *KDF) error {
	if kdf == nil {
		return fmt.Errorf("no KDF object")
	}

	kdfType := normalizeKDFType(kdf.Type)

	switch {
	case kdfType == KDFTypeArgon2i || kdfType == KDFTypeArgon2id:
		// Negative values are the sharpest form of this. Time, Memory and CPUs
		// are signed ints out of JSON and are converted with uint32/uint8 at the
		// call site, so -1 does not fail -- it wraps to 4294967295, and Argon2
		// is then asked for a four-terabyte matrix. Checking against a positive
		// minimum is what catches that; checking only the ceiling would not.
		if kdf.Time == nil || kdf.Memory == nil || kdf.CPUs == nil {
			return fmt.Errorf("argon2 KDF is missing its time, memory or cpus cost")
		}
		if *kdf.Time < minArgon2Time || *kdf.Time > maxArgon2Time {
			return fmt.Errorf("argon2 time cost %d is outside %d..%d",
				*kdf.Time, minArgon2Time, maxArgon2Time)
		}
		if *kdf.Memory < minArgon2Memory || *kdf.Memory > maxArgon2Memory {
			return fmt.Errorf("argon2 memory cost %d KiB is outside %d..%d",
				*kdf.Memory, minArgon2Memory, maxArgon2Memory)
		}
		if *kdf.CPUs < minArgon2Parallel || *kdf.CPUs > maxArgon2Parallel {
			return fmt.Errorf("argon2 parallelism %d is outside %d..%d",
				*kdf.CPUs, minArgon2Parallel, maxArgon2Parallel)
		}

	case isPBKDF2Type(kdfType):
		// Iterations drive CPU only -- nothing allocated scales with them -- so
		// this ceiling is about not hanging on a crafted header rather than
		// about memory.
		if kdf.Iterations == nil {
			return fmt.Errorf("pbkdf2 KDF is missing its iteration count")
		}
		if *kdf.Iterations < minKDFIterations || *kdf.Iterations > maxKDFIterations {
			return fmt.Errorf("pbkdf2 iteration count %d is outside %d..%d",
				*kdf.Iterations, minKDFIterations, maxKDFIterations)
		}

	default:
		// An unsupported type must SAY unsupported type. Treating everything
		// non-argon2 as pbkdf2 reports a header claiming type "sha256-crypt" as
		// "missing its iteration count", naming a field that type never claimed
		// to have and sending the reader after a value that was never meant to
		// be there.
		return fmt.Errorf("unsupported KDF type %q", kdf.Type)
	}

	return nil
}
