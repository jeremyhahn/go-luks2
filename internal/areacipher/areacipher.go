// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package areacipher is the cipher over a LUKS2 keyslot area: AES in XTS or
// CBC mode, sector by sector, with the IV generators cryptsetup writes.
//
// The plaintext of a keyslot area is the AF stripes, which are the master key
// spread wide, so the decrypting direction writes straight into an enclave the
// caller's custody allocates. The ciphertext is ordinary memory on purpose:
// those bytes are what is on the device, byte for byte, and locking a copy of
// something already public only doubles the RLIMIT_MEMLOCK an operation needs.
//
// RESIDUAL EXPOSURE (internal/secret, entry 4): x/crypto/xts and crypto/aes
// hold the expanded AES round keys on the ordinary heap for the life of the
// cipher and offer no way to place them elsewhere or wipe them. A round-key
// schedule is a deterministic expansion of the key, so recovering it recovers
// the key. Nothing this package can do closes that; it is the stdlib crypto
// boundary.
package areacipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/crypto/xts"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// mode is the block cipher mode a keyslot area is encrypted in.
type mode int

const (
	modeXTS mode = iota
	modeCBC
)

// ivGen is how a sector's IV (or XTS tweak) is generated from the sector's
// index, counted from the start of the area as cryptsetup counts it.
type ivGen int

const (
	// ivPlain64 is the index, little-endian, 64 bits.
	ivPlain64 ivGen = iota
	// ivPlain is the index truncated to 32 bits.
	ivPlain
	// ivESSIVSHA256 is the 64-bit index encrypted with AES under
	// SHA-256(area key) -- dm-crypt's essiv:sha256.
	ivESSIVSHA256
)

// direction is which way a transform runs.
type direction int

const (
	encrypt direction = iota
	decrypt
)

// Transform is the cipher a keyslot's area.encryption names. The algorithm is
// always AES; Parse is the only way to obtain one.
type Transform struct {
	mode mode
	iv   ivGen
	fips fips.Mode // see WithFIPS
}

// WriteSpec is the ONLY area encryption this module writes to a keyslot:
// AES-XTS tweaked on the 64-bit sector index. It is deliberately not the
// container's DATA cipher, which describes the data segment and says nothing
// about how keyslots are wrapped.
const WriteSpec = "aes-xts-plain64"

// Default is the transform WriteSpec names: the one every keyslot this module
// writes is encrypted with.
func Default() Transform { return transforms[WriteSpec] }

// The area.encryption spellings Parse accepts.
const (
	specXTSPlain64 = WriteSpec
	specXTSPlain   = "aes-xts-plain"
	specCBCESSIV   = "aes-cbc-essiv:sha256"
	specCBCPlain64 = "aes-cbc-plain64"
	specCBCPlain   = "aes-cbc-plain"
)

// transforms maps each accepted spec to what it runs.
var transforms = map[string]Transform{
	specXTSPlain64: {mode: modeXTS, iv: ivPlain64},
	specXTSPlain:   {mode: modeXTS, iv: ivPlain},
	specCBCESSIV:   {mode: modeCBC, iv: ivESSIVSHA256},
	specCBCPlain64: {mode: modeCBC, iv: ivPlain64},
	specCBCPlain:   {mode: modeCBC, iv: ivPlain},
}

// Parse reads a keyslot's area.encryption as the full cipher spec it is --
// "<algorithm>-<mode>-<iv>" -- and reports the transform it names, and
// whether this module can run it.
//
// # The mode is consumed, not discarded (#106)
//
// This used to be a split that kept the algorithm and threw the rest away, and
// the transform then ran AES-XTS whatever the header said. A keyslot declaring
// "aes-cbc-essiv:sha256" over XTS material therefore opened perfectly here and
// in no conforming implementation. Honoring the mode on read is what makes a
// wrong declaration a test failure instead of a container only this library
// can open: such a keyslot is now decrypted as the CBC it claims, fails its
// digest as it does in cryptsetup, and a genuine CBC keyslot opens.
//
// # The accepted set is exact and closed
//
// It is an enumeration of the area transforms cryptsetup writes for AES, not a
// grammar:
//
//	aes-xts-plain64       the default of this module and of cryptsetup
//	aes-xts-plain         --keyslot-cipher, and carried over from LUKS1
//	aes-cbc-essiv:sha256  LUKS1's long-time default, kept by `cryptsetup
//	                      convert`, and what cryptsetup writes for a volume
//	                      formatted with that data cipher
//	aes-cbc-plain64       --keyslot-cipher, or a data cipher of that name
//	aes-cbc-plain
//
// "plain" truncates the sector index to 32 bits, "plain64" does not; the two
// differ only for a sector index of 2^32 or more, and a keyslot area's
// decrypted length is bounded at about 4 MiB by header validation, so for
// every keyslot that is admitted they name the same bytes.
//
// Everything else is refused: another algorithm, another mode or IV generator
// (ecb, lrw, benbi, plain64be, null, essiv over XTS), a spec with the mode
// missing, and any other casing or decoration. Matching is exact because the
// kernel's crypto API names are case-sensitive and cryptsetup passes them
// through unchanged.
func Parse(spec string) (Transform, bool) {
	t, ok := transforms[spec]
	return t, ok
}

// Specs lists the specs Parse accepts, for messages.
func Specs() string {
	return strings.Join([]string{specXTSPlain64, specXTSPlain, specCBCESSIV, specCBCPlain64, specCBCPlain}, ", ")
}

// XTS reports whether t runs AES-XTS.
func (t Transform) XTS() bool { return t.mode == modeXTS }

// ValidateKeySize reports whether an area key of n bytes keys this transform:
// XTS takes two AES keys (32, 48 or 64 bytes), CBC one (16, 24 or 32).
func (t Transform) ValidateKeySize(n int) error {
	if t.mode == modeXTS {
		return ValidateXTSKeySize(n)
	}
	switch n {
	case 16, 24, 32:
		return nil
	default:
		return &errs.Error{
			Kind:   errs.ErrInvalidArgument,
			Detail: fmt.Sprintf("area key of %d bytes cannot key AES-CBC; the accepted sizes are 16, 24 and 32 bytes", n),
		}
	}
}

// SectorSize is the sector a keyslot area is transformed in. It is a property
// of the LUKS2 format -- key material is always processed in 512-byte
// sectors, independent of the data segment's sector size -- and the sector
// index, counted from the start of the area, is the IV or tweak.
const SectorSize = 512

// run transforms src into dst in sectorSize sectors. Scratch for a trailing
// partial XTS sector comes from c.
func (t Transform) run(c secret.Custody, dst, src, key []byte, sectorSize int, dir direction) error {
	if t.mode == modeXTS {
		if err := t.requireXTSKey(key); err != nil {
			return err
		}
		// XTS tweaks on the 64-bit index; plain's 32-bit truncation names the
		// same bytes for every area that is admitted (see Parse).
		return xtsSectors(c, dst, src, key, sectorSize, dir)
	}
	return cbcSectors(t.iv, dst, src, key, sectorSize, dir)
}

// WithFIPS returns t bound to FIPS mode m. In FIPS 140-3 mode an AES-XTS key
// whose two halves -- the data key and the tweak key -- are equal is refused
// in both directions, as SP 800-38E and FIPS 140-3 IG C.I require and as the
// kernel's xts_verify_key does. Outside FIPS mode such a key is still used,
// again as the kernel does, so a container that opens under cryptsetup opens
// here.
func (t Transform) WithFIPS(m fips.Mode) Transform {
	t.fips = m
	return t
}

// requireXTSKey is WithFIPS's check, made before the cipher is keyed. The
// halves are compared in constant time: they are key material.
func (t Transform) requireXTSKey(key []byte) error {
	if !t.fips {
		return nil
	}
	half := len(key) / 2
	if subtle.ConstantTimeCompare(key[:half], key[half:]) == 1 {
		return &errs.Error{Kind: fips.ErrNotApproved, Detail: "an AES-XTS key whose two halves are equal"}
	}
	return nil
}

// EncryptEnclave encrypts AF-split key material held in an enclave with a key
// held in an enclave, borrowing both for the duration of the transform and no
// longer, and returns the ciphertext as ordinary memory (see the package
// documentation for why).
func (t Transform) EncryptEnclave(c secret.Custody, data, key *enclave.Memory) ([]byte, error) {
	plainLen := data.Size()
	paddedLen := plainLen
	if rem := paddedLen % SectorSize; rem != 0 {
		paddedLen += SectorSize - rem
	}

	// cryptsetup processes a keyslot area in whole SectorSize sectors: a
	// final sector that is not itself a sector multiple is padded with zero
	// before it is encrypted, and the ciphertext written covers the WHOLE
	// padded sector. Returning only plainLen bytes left that trailing
	// ciphertext off the device, with on-disk zero padding standing in its
	// place instead -- not what cryptsetup writes for the same bytes.
	plainSrc := data
	if paddedLen != plainLen {
		// The padding sits beside key material in the same buffer, so it is
		// built in custody rather than on the ordinary heap.
		padded, err := c.New("af stripes, sector-padded", paddedLen)
		if err != nil {
			return nil, err
		}
		defer c.Release(padded)

		if err := secret.Borrow("af stripes", data, func(plain []byte) error {
			return secret.Borrow("af stripes, sector-padded", padded, func(dst []byte) error {
				copy(dst, plain)
				return nil
			})
		}); err != nil {
			return nil, err
		}
		plainSrc = padded
	}

	var encrypted []byte
	err := secret.Borrow("af stripes", plainSrc, func(plain []byte) error {
		return secret.Borrow("keyslot encryption key", key, func(k []byte) error {
			out := make([]byte, paddedLen)
			if err := t.run(c, out, plain, k, SectorSize, encrypt); err != nil {
				return err
			}
			encrypted = out
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

// DecryptEnclave decrypts keyslot material read off the device into an
// enclave c allocates, with the key borrowed from its own enclave.
//
// The direction is what makes this necessary: the plaintext is the AF
// stripes, which are the master key, so it may not be produced onto the
// ordinary heap even transiently. The destination enclave is allocated first
// and the cipher writes straight into its locked pages. data is ciphertext
// read from the device and is deliberately NOT enclaved.
func (t Transform) DecryptEnclave(c secret.Custody, data []byte, key *enclave.Memory) (*enclave.Memory, error) {
	if len(data) == 0 {
		return nil, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "no key material to decrypt"}
	}

	plaintext, err := c.New("decrypted keyslot material", len(data))
	if err != nil {
		return nil, err
	}

	err = secret.Borrow("decrypted keyslot material", plaintext, func(dst []byte) error {
		return secret.Borrow("keyslot encryption key", key, func(k []byte) error {
			return t.run(c, dst, data, k, SectorSize, decrypt)
		})
	})
	if err != nil {
		c.Release(plaintext)
		return nil, err
	}

	return plaintext, nil
}

// ValidateXTSKeySize reports whether a key of this length can key AES-XTS.
//
// XTS splits its key in half and gives each half to AES, so the length must be
// twice a legal AES key size: 32, 48 or 64 bytes. xts.NewCipher refuses
// anything else -- which means a keyslot declaring "key_size": 40 is
// well-formed by every other measure and can never yield a master key. That is
// exactly the shape a removal guard must not count, and it could not see it
// while the rejection lived only inside the cipher constructor.
func ValidateXTSKeySize(n int) error {
	switch n {
	case 32, 48, 64:
		return nil
	default:
		return &errs.Error{
			Kind:   errs.ErrInvalidArgument,
			Detail: fmt.Sprintf("volume key of %d bytes cannot key AES-XTS; the accepted sizes are 32, 48 and 64 bytes", n),
		}
	}
}

// ValidateVolumeKeySize reports whether a volume key of n bytes keys an AES
// data cipher: one AES key (16, 24 or 32 bytes, CBC and the like) or two
// (32, 48 or 64, XTS). The volume key of a dm-integrity volume also carries
// the integrity key, and is refused here; such a volume is not activated
// either.
func ValidateVolumeKeySize(n int) error {
	switch n {
	case 16, 24, 32, 48, 64:
		return nil
	default:
		return &errs.Error{
			Kind:   errs.ErrInvalidArgument,
			Detail: fmt.Sprintf("volume key of %d bytes keys no AES data cipher; the accepted sizes are 16, 24, 32, 48 and 64 bytes", n),
		}
	}
}

// WritableAreaKeySize is the area key size a keyslot this module writes uses
// for a volume key of n bytes: n itself when it keys AES-XTS, so the keyslot
// is wrapped as strongly as the data, and otherwise 64 -- AES-256-XTS, the
// keyslot cipher cryptsetup falls back to for a volume key its default cannot
// take (DEFAULT_LUKS2_KEYSLOT_KEYBITS).
func WritableAreaKeySize(n int) int {
	if ValidateXTSKeySize(n) == nil {
		return n
	}
	return 64
}

// xtsSectors runs AES-XTS over src into dst, one sector at a time, with the
// sector index as the tweak. It is the single implementation behind both
// directions and both the enclave and the plain wrappers, so the two can never
// drift into producing containers this library can write but not read.
//
// dst and src must be the same length. Whole sectors are transformed IN PLACE
// between the two buffers: a previous form copied every sector through two
// freshly allocated 512-byte scratch buffers, which for a default keyslot meant
// ~1000 heap allocations holding AF-split master key material per operation --
// on exactly the material the enclave work exists to keep off the heap. Only a
// trailing PARTIAL sector still needs scratch, because XTS is run over a
// zero-padded full sector there, and that scratch is locked.
func xtsSectors(c secret.Custody, dst, src, key []byte, sectorSize int, dir direction) error {
	// A callable validator rather than an inline literal: the keyslot screen
	// has to be able to ask the same question off metadata alone, before a
	// derivation is paid for and before a removal guard counts the keyslot as
	// a survivor (#45).
	if err := ValidateXTSKeySize(len(key)); err != nil {
		return err
	}
	if len(dst) != len(src) {
		return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "key material buffer size mismatch"}
	}
	if sectorSize <= 0 {
		return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "sector size must be positive"}
	}

	// XTS splits the key internally: the first half for the cipher, the
	// second for the tweak.
	xtsCipher, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "failed to create XTS cipher", Err: err}
	}

	numSectors := (len(src) + sectorSize - 1) / sectorSize

	for i := 0; i < numSectors; i++ {
		start := i * sectorSize
		end := min(start+sectorSize, len(src))

		if end-start == sectorSize {
			xtsSector(xtsCipher, dst[start:end], src[start:end], uint64(i), dir) // #nosec G115 - loop counter bounded by data length
			continue
		}

		if err := xtsPartialSector(c, dst[start:end], src[start:end], xtsCipher, sectorSize, i, dir); err != nil {
			return err
		}
	}

	return nil
}

func xtsSector(c *xts.Cipher, dst, src []byte, index uint64, dir direction) {
	if dir == decrypt {
		c.Decrypt(dst, src, index)
		return
	}
	c.Encrypt(dst, src, index)
}

// xtsPartialSector transforms a final sector shorter than sectorSize by padding
// it out to a whole sector, which is what the on-disk format requires and what
// this module has always done.
//
// The two scratch buffers are LOCKED even for the encrypt direction, because
// one of them holds plaintext key material in both directions -- the padded
// input when encrypting, the padded output when decrypting -- and this path
// runs at most once per operation, so the cost is one page pair rather than one
// per sector.
func xtsPartialSector(c secret.Custody, dst, src []byte, xtsCipher *xts.Cipher, sectorSize, index int, dir direction) error {
	scratch, err := c.New("key material sector", 2*sectorSize)
	if err != nil {
		return err
	}
	defer c.Release(scratch)

	return secret.Borrow("key material sector", scratch, func(buf []byte) error {
		in, out := buf[:sectorSize], buf[sectorSize:]
		copy(in, src)
		xtsSector(xtsCipher, out, in, uint64(index), dir) // #nosec G115 - loop counter bounded by data length
		copy(dst, out[:len(dst)])
		return nil
	})
}

// cbcSectors runs AES-CBC over whole sectors with the IV generator iv, as
// dm-crypt and cryptsetup's userspace keyslot path do: each sector is chained
// on its own, from its own IV. The ESSIV salt is cleared as soon as its key
// schedule exists.
func cbcSectors(iv ivGen, dst, src, key []byte, sectorSize int, dir direction) error {
	if err := (Transform{mode: modeCBC}).ValidateKeySize(len(key)); err != nil {
		return err
	}
	if len(dst) != len(src) {
		return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "key material buffer size mismatch"}
	}
	if sectorSize <= 0 || sectorSize%aes.BlockSize != 0 || len(src)%sectorSize != 0 {
		return &errs.Error{
			Kind: errs.ErrInvalidArgument,
			Detail: fmt.Sprintf("AES-CBC runs over whole sectors: %d bytes is not a whole number of %d-byte sectors",
				len(src), sectorSize),
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "failed to create AES cipher", Err: err}
	}
	var essiv cipher.Block
	if iv == ivESSIVSHA256 {
		salt := sha256.Sum256(key)
		essiv, err = aes.NewCipher(salt[:])
		clear(salt[:])
		if err != nil {
			return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "failed to create the ESSIV cipher", Err: err}
		}
	}

	sectorIV := make([]byte, aes.BlockSize)
	for start := 0; start < len(src); start += sectorSize {
		index := uint64(start / sectorSize) // #nosec G115 -- bounded by the buffer length
		clear(sectorIV)
		if iv == ivPlain {
			binary.LittleEndian.PutUint32(sectorIV, uint32(index)) // #nosec G115 -- plain truncates to 32 bits by definition
		} else {
			binary.LittleEndian.PutUint64(sectorIV, index)
		}
		if essiv != nil {
			essiv.Encrypt(sectorIV, sectorIV)
		}
		end := start + sectorSize
		if dir == decrypt {
			cipher.NewCBCDecrypter(block, sectorIV).CryptBlocks(dst[start:end], src[start:end])
		} else {
			cipher.NewCBCEncrypter(block, sectorIV).CryptBlocks(dst[start:end], src[start:end])
		}
	}
	return nil
}
