// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package areacipher is the AES-XTS/CBC cipher over a LUKS2 keyslot area; plaintext goes into an enclave, and stdlib round keys stay on the heap (residual).
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

// WriteSpec is the only area encryption this module writes: AES-XTS on the 64-bit sector index, independent of the data cipher.
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

// Parse reads area.encryption as an exact spec from a closed set (aes-xts-plain64, aes-xts-plain, aes-cbc-essiv:sha256, aes-cbc-plain64, aes-cbc-plain) and reports its transform.
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

// SectorSize is the 512-byte sector a keyslot area is transformed in; the sector index from the area start is the IV or tweak.
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

// WithFIPS returns t bound to FIPS mode m, which refuses an AES-XTS key with equal halves (SP 800-38E).
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

// EncryptEnclave encrypts enclave-held key material with an enclave-held key and returns ordinary-memory ciphertext.
func (t Transform) EncryptEnclave(c secret.Custody, data, key enclave.ByteAccess) ([]byte, error) {
	plainLen := data.Size()
	paddedLen := plainLen
	if rem := paddedLen % SectorSize; rem != 0 {
		paddedLen += SectorSize - rem
	}

	// Encrypt whole zero-padded sectors and return all of the ciphertext, as cryptsetup writes it.
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

// DecryptEnclave decrypts keyslot ciphertext straight into an enclave c allocates, since the plaintext is the master key.
func (t Transform) DecryptEnclave(c secret.Custody, data []byte, key enclave.ByteAccess) (enclave.ByteAccess, error) {
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

// ValidateXTSKeySize reports whether a key of this length can key AES-XTS: 32, 48 or 64 bytes.
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

// ValidateVolumeKeySize reports whether n bytes keys an AES data cipher (16, 24, 32, or XTS 32, 48, 64); dm-integrity keys are refused.
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

// WritableAreaKeySize is n when n keys AES-XTS, otherwise 64 (AES-256-XTS, cryptsetup's fallback).
func WritableAreaKeySize(n int) int {
	if ValidateXTSKeySize(n) == nil {
		return n
	}
	return 64
}

// xtsSectors runs AES-XTS sector by sector in place between src and dst (same length); only a trailing partial sector uses locked scratch.
func xtsSectors(c secret.Custody, dst, src, key []byte, sectorSize int, dir direction) error {
	// A callable validator so the keyslot screen can ask the same question from metadata alone.
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

// xtsPartialSector transforms a short final sector padded to a whole sector, using locked scratch in both directions.
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

// cbcSectors runs AES-CBC over whole sectors, each chained from its own IV; the ESSIV salt is cleared once its schedule exists.
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
