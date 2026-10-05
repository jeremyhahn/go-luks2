// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// areaMode is the block cipher mode a keyslot area is encrypted in.
type areaMode int

const (
	areaModeXTS areaMode = iota
	areaModeCBC
)

// areaIV is how a keyslot area sector's IV (or XTS tweak) is generated from
// the sector's index, counted from the start of the area as cryptsetup counts
// it.
type areaIV int

const (
	// areaIVPlain64 is the index, little-endian, 64 bits.
	areaIVPlain64 areaIV = iota
	// areaIVPlain is the index truncated to 32 bits.
	areaIVPlain
	// areaIVESSIVSHA256 is the 64-bit index encrypted with AES under
	// SHA-256(area key) -- dm-crypt's essiv:sha256.
	areaIVESSIVSHA256
)

// areaTransform is the transform a keyslot area's area.encryption names. The
// algorithm is always AES; parseKeyslotAreaEncryption is the only constructor.
type areaTransform struct {
	mode areaMode
	iv   areaIV
}

// validateKeySize reports whether an area key of n bytes keys this transform:
// XTS takes two AES keys (32, 48 or 64 bytes), CBC one (16, 24 or 32).
func (t areaTransform) validateKeySize(n int) error {
	if t.mode == areaModeXTS {
		return validateXTSKeySize(n)
	}
	switch n {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("area key of %d bytes cannot key AES-CBC; the accepted sizes are 16, 24 and 32 bytes", n)
	}
}

// keyslotAreaSectors runs the transform over src into dst, one sectorSize
// sector at a time, the sector index counted from the start of the area.
func keyslotAreaSectors(t areaTransform, dst, src, key []byte, sectorSize int, decrypt bool) error {
	if t.mode == areaModeXTS {
		// XTS tweaks on the 64-bit index; plain's 32-bit truncation names the
		// same bytes for every area the screen admits (see
		// parseKeyslotAreaEncryption).
		return xtsSectors(dst, src, key, DefaultCipher, sectorSize, decrypt)
	}
	return cbcSectors(t.iv, dst, src, key, sectorSize, decrypt)
}

// cbcSectors runs AES-CBC over whole sectors with the IV generator iv, as
// dm-crypt and cryptsetup's userspace keyslot path do: each sector is chained
// on its own, from its own IV.
//
// RESIDUAL EXPOSURE, the same as xtsSectors': the AES key schedules -- the
// area key's, and for ESSIV the one of SHA-256(area key) -- live on the
// ordinary heap inside crypto/aes and cannot be wiped (enclave.go, entry 4).
// The ESSIV salt itself is cleared as soon as its schedule exists.
func cbcSectors(iv areaIV, dst, src, key []byte, sectorSize int, decrypt bool) error {
	if err := (areaTransform{mode: areaModeCBC}).validateKeySize(len(key)); err != nil {
		return err
	}
	if len(dst) != len(src) {
		return fmt.Errorf("key material buffer size mismatch")
	}
	if sectorSize <= 0 || sectorSize%aes.BlockSize != 0 || len(src)%sectorSize != 0 {
		return fmt.Errorf("AES-CBC runs over whole sectors: %d bytes is not a whole number of %d-byte sectors", len(src), sectorSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	var essiv cipher.Block
	if iv == areaIVESSIVSHA256 {
		salt := sha256.Sum256(key)
		essiv, err = aes.NewCipher(salt[:])
		clear(salt[:])
		if err != nil {
			return fmt.Errorf("failed to create the ESSIV cipher: %w", err)
		}
	}

	sectorIV := make([]byte, aes.BlockSize)
	for start := 0; start < len(src); start += sectorSize {
		index := uint64(start / sectorSize) // #nosec G115 -- bounded by the buffer length
		clear(sectorIV)
		if iv == areaIVPlain {
			binary.LittleEndian.PutUint32(sectorIV, uint32(index)) // #nosec G115 -- plain truncates to 32 bits by definition
		} else {
			binary.LittleEndian.PutUint64(sectorIV, index)
		}
		if essiv != nil {
			essiv.Encrypt(sectorIV, sectorIV)
		}
		end := start + sectorSize
		if decrypt {
			cipher.NewCBCDecrypter(block, sectorIV).CryptBlocks(dst[start:end], src[start:end])
		} else {
			cipher.NewCBCEncrypter(block, sectorIV).CryptBlocks(dst[start:end], src[start:end])
		}
	}
	return nil
}

// validateVolumeKeySize reports whether a volume key of n bytes keys an AES
// data cipher: one AES key (16, 24 or 32 bytes, CBC and the like) or two
// (32, 48 or 64, XTS). The volume key of a dm-integrity volume also carries
// the integrity key, and is refused here; such a volume is not activated
// either (activationSegment).
func validateVolumeKeySize(n int) error {
	switch n {
	case 16, 24, 32, 48, 64:
		return nil
	default:
		return fmt.Errorf("volume key of %d bytes keys no AES data cipher; the accepted sizes are 16, 24, 32, 48 and 64 bytes", n)
	}
}

// writableAreaKeySize is the area key size a keyslot this package writes uses
// for a volume key of n bytes: n itself when it keys AES-XTS, so the keyslot
// is wrapped as strongly as the data, and otherwise 64 -- AES-256-XTS, the
// keyslot cipher cryptsetup falls back to for a volume key its default cannot
// take (DEFAULT_LUKS2_KEYSLOT_KEYBITS).
func writableAreaKeySize(n int) int {
	if validateXTSKeySize(n) == nil {
		return n
	}
	return 64
}
