// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/aes"
	"fmt"
	"os"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/crypto/xts"
)

// Format creates a new LUKS2 volume
func Format(opts FormatOptions) error {
	// Validate options
	if err := ValidateFormatOptions(opts); err != nil {
		return err
	}

	// Acquire file lock for exclusive access
	lock, err := AcquireFileLock(opts.Device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Set defaults
	if opts.Cipher == "" {
		opts.Cipher = DefaultCipher
	}
	if opts.CipherMode == "" {
		opts.CipherMode = DefaultCipherMode
	}
	if opts.KeySize == 0 {
		opts.KeySize = DefaultKeySize
	}
	if opts.HashAlgo == "" {
		opts.HashAlgo = DefaultHashAlgo
	}
	if opts.SectorSize == 0 {
		opts.SectorSize = DefaultSectorSize
	}

	// Open device
	f, err := openDevice("format the device", opts.Device, os.O_RDWR)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// Generate the master key DIRECTLY into locked memory. It is drawn inside
	// the enclave's borrow window, so the volume's whole secret never exists on
	// the ordinary heap -- not even for the instant between rand.Read and a
	// move, which is a window no later wipe can close because the collector may
	// already have copied the bytes.
	masterKeySize := opts.KeySize / 8 // Convert bits to bytes
	masterKey, err := randomSecret("master key", masterKeySize)
	if err != nil {
		return err
	}
	defer masterKey.Destroy()

	// Create binary header
	hdr, err := CreateBinaryHeader(opts)
	if err != nil {
		return err
	}

	// Create KDF for keyslot 0
	kdf, err := CreateKDF(opts, masterKeySize)
	if err != nil {
		return err
	}

	// Derive key from passphrase. opts.Passphrase is the caller's unprotected
	// memory and stays that way -- see DeriveKeyEnclave -- but what is derived
	// from it is held locked from here on.
	passphraseKey, err := DeriveKeyEnclave(opts.Passphrase, kdf, masterKeySize)
	if err != nil {
		return err
	}
	defer passphraseKey.Destroy()

	// Create digest KDF and digest
	digestKDF, digestValue, err := createDigest(masterKey, opts.HashAlgo)
	if err != nil {
		return err
	}

	// Apply anti-forensic split to master key. The stripes are the master key
	// spread over keySize*AFStripes bytes and are held locked accordingly; see
	// antiforensic.go.
	afData, err := afSplitEnclave(masterKey, AFStripes, opts.HashAlgo)
	if err != nil {
		return err
	}
	defer afData.Destroy()

	// Encrypt AF-split key material with passphrase-derived key.
	//
	// The RESULT is deliberately plain memory. These bytes are the AF stripes
	// under the passphrase-derived key and they are about to be written to the
	// device in exactly this form, so locking them would protect a copy of
	// something already on disk while doubling the locked memory this call
	// needs. Both inputs are borrowed from their enclaves for the transform.
	encryptedKeyMaterial, err := encryptKeyMaterialEnclave(afData, passphraseKey, opts.Cipher)
	if err != nil {
		return err
	}
	defer clearBytes(encryptedKeyMaterial)

	// Calculate offsets and sizes
	const keyslotAreaStart = 0x8000 // 32KB (after both headers)
	keyMaterialSize := len(encryptedKeyMaterial)
	alignedKeyMaterialSize := alignTo(int64(keyMaterialSize), 4096)

	// Match cryptsetup's LUKS2 defaults for maximum compatibility:
	// - LUKS2_DEFAULT_HDR_SIZE = 16 MiB (total metadata area)
	// - data_offset = 2 * metadata_size + keyslots_size
	// - Each keyslot needs: volume_key_size * 4000 bytes (AF stripes), 4KB aligned
	// - For 512-bit key: 64 * 4000 = 256KB per keyslot
	// - Maximum 32 keyslots (LUKS2MaxKeyslots) supported
	//
	// cryptsetup formula: keyslots_size = LUKS2_DEFAULT_HDR_SIZE - 2 * metadata_size
	// With default 16 KiB metadata: keyslots_size ≈ 16 MiB (LUKS2DefaultKeyslotsSize)
	//
	// We use keyslotAreaStart (0x8000 = 32KB) which accounts for 2 header copies,
	// so keyslots area starts at 32KB and data_offset = 32KB + keyslotsAreaSize
	keyslotsAreaSize := alignedKeyMaterialSize
	if keyslotsAreaSize < LUKS2DefaultKeyslotsSize {
		keyslotsAreaSize = LUKS2DefaultKeyslotsSize
	}

	dataOffset := keyslotAreaStart + keyslotsAreaSize

	// Create metadata structure
	// keyslot0Size is the actual size of keyslot 0's area
	// keyslotsAreaSize is the total reserved space for keyslots (allows adding more keys)
	metadata := createMetadata(kdf, digestKDF, digestValue, opts, masterKeySize,
		keyslotAreaStart, int(alignedKeyMaterialSize), int(keyslotsAreaSize), int(dataOffset))

	// Write headers
	if err := writeHeaderInternal(opts.Device, hdr, metadata); err != nil {
		return err
	}

	// Write encrypted key material
	if _, err := f.Seek(int64(keyslotAreaStart), 0); err != nil {
		return fmt.Errorf("failed to seek to keyslot area: %w", err)
	}
	if _, err := f.Write(encryptedKeyMaterial); err != nil {
		return fmt.Errorf("failed to write key material: %w", err)
	}

	// Pad to aligned size
	padding := make([]byte, alignedKeyMaterialSize-int64(keyMaterialSize))
	if _, err := f.Write(padding); err != nil {
		return fmt.Errorf("failed to write padding: %w", err)
	}

	return f.Sync()
}

// createMetadata creates the JSON metadata structure
// keyslot0Size is the actual size of keyslot 0's area
// keyslotsAreaSize is the total reserved space for all keyslots (for Config.KeyslotsSize)
func createMetadata(kdf, digestKDF *KDF, digestValue string, opts FormatOptions,
	masterKeySize, keyslotOffset, keyslot0Size, keyslotsAreaSize, dataOffset int) *LUKS2Metadata {

	// Create keyslot
	keyslots := make(map[string]*Keyslot)
	priority := 1
	keyslots["0"] = &Keyslot{
		Type:     "luks2",
		KeySize:  masterKeySize,
		Priority: &priority,
		Area: &KeyslotArea{
			Type:    "raw",
			KeySize: masterKeySize,
			Offset:  formatSize(int64(keyslotOffset)),
			Size:    formatSize(int64(keyslot0Size)),
			// The KEYSLOT AREA cipher, which is not the container's data
			// cipher and was written as though it were.
			//
			// A caller may format with any cipher dm-crypt supports, and that
			// choice describes the SEGMENT below. Keyslot key material is
			// wrapped by encryptKeyMaterialEnclave with AES-XTS regardless --
			// so copying opts.Cipher+opts.CipherMode here declared, for any
			// non-XTS choice, an encryption the material does not have. The
			// container then opened for this package, whose read path consults
			// only the algorithm, and for nothing else.
			//
			// Unchanged for the default aes/xts-plain64, where the two strings
			// were the same by coincidence -- which is why it survived.
			Encryption: KeyslotAreaEncryption,
		},
		KDF: kdf,
		AF: &AntiForensic{
			Type:    "luks1",
			Stripes: AFStripes,
			Hash:    opts.HashAlgo,
		},
	}

	// Create segments
	segments := make(map[string]*Segment)
	segments["0"] = &Segment{
		Type:       "crypt",
		Offset:     formatSize(int64(dataOffset)),
		Size:       "dynamic",
		IVTweak:    "0",
		Encryption: opts.Cipher + "-" + opts.CipherMode,
		SectorSize: opts.SectorSize,
	}

	// Create digests
	digests := make(map[string]*Digest)
	digests["0"] = &Digest{
		Type:       "pbkdf2",
		Keyslots:   []string{"0"},
		Segments:   []string{"0"},
		Hash:       digestKDF.Hash,
		Iterations: *digestKDF.Iterations,
		Salt:       digestKDF.Salt,
		Digest:     digestValue,
	}

	// Create config.
	//
	// config.keyslots_size is the SIZE OF THE KEYSLOTS AREA ALONE, not the
	// offset at which that area ends. Writing keyslotOffset + keyslotsAreaSize
	// made the two indistinguishable for the default geometry only by accident
	// of arithmetic, and cryptsetup reads it as a size:
	//
	//	keyslots_size is too large 16777216 (bytes).
	//	Data offset: 16777216, keyslots offset: 32768
	//
	// The bound cryptsetup enforces is keyslots_size <= data_offset -
	// keyslots_offset, i.e. 16777216 - 32768 = 16744448 for the geometry this
	// library writes. Measured against cryptsetup 2.7.0; see #28.
	jsonSize := LUKS2DefaultSize
	config := &Config{
		JSONSize:     formatSize(int64(jsonSize)),
		KeyslotsSize: formatSize(int64(keyslotsAreaSize)),
	}

	return &LUKS2Metadata{
		Keyslots: keyslots,
		// tokens is mandatory in LUKS2 and a container with no tokens carries
		// an empty object, so it is constructed empty rather than left nil.
		Tokens:   make(map[string]*Token),
		Segments: segments,
		Digests:  digests,
		Config:   config,
	}
}

// createDigest creates a digest for master key verification.
//
// The master key is passed as an ENCLAVE and this package never copies it out:
// the derivation borrows it through deriveKeySecret rather than opening it into
// a slice of ours.
//
// That is NOT the same as the key staying in protected memory, and an earlier
// version of this comment claimed it did. The borrowed slice goes to
// crypto/pbkdf2.Key, which stringifies it -- see exposure 2 in enclave.go. Every
// format puts the master key into an unwipeable Go string for the duration of
// this derivation. Nothing here can prevent that; what it can do is not pretend
// otherwise.
//
// What this returns -- the salt and the base64 digest -- are cleartext LUKS2
// header fields and are not secret; the digest is a one-way function of the
// key, and the whole point of writing it to the header is that anyone can check
// a candidate key against it.
func createDigest(masterKey *enclave.MemoryEnclave, hashAlgo string) (*KDF, string, error) {
	// The cost is DigestIterations itself, not a second copy of its value, so
	// what Format writes sits behind the assertion on that constant rather than
	// reaching it through a separate test that happened to keep two spellings
	// equal.
	//
	// That assertion is weaker than it sounds and the difference matters: it is
	// a >= 100000 floor checked when the tests run, not a lock on 600000 and not
	// anything enforced at runtime. Setting this constant to 100000 passes the
	// whole suite today.
	digestIterations := DigestIterations

	salt, err := randomBytes(32)
	if err != nil {
		return nil, "", err
	}

	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       hashAlgo,
		Salt:       encodeBase64(salt),
		Iterations: &digestIterations,
	}

	// The digest is the master key derived to the OUTPUT LENGTH OF THE HASH the
	// digest declares -- 64 bytes for sha512, 32 for sha256 -- not to a fixed
	// 32. Writing 32 bytes under a "sha512" label produced a digest no other
	// LUKS2 implementation derives the same way, which is the write half of #73.
	//
	// The read half is deliberately NOT symmetric: verifyMasterKey derives to
	// the length STORED in the header, not to this one, so containers written
	// before this change still open.
	digestLen, err := hashOutputLen(hashAlgo)
	if err != nil {
		return nil, "", err
	}

	digest, err := deriveKeySecret(masterKey, kdf, digestLen)
	if err != nil {
		return nil, "", err
	}
	defer digest.Destroy()

	var encoded string
	if err := borrowSecret("master key digest", digest, func(b []byte) error {
		encoded = encodeBase64(b)
		return nil
	}); err != nil {
		return nil, "", err
	}

	return kdf, encoded, nil
}

// encryptKeyMaterialEnclave encrypts AF-split key material held in an enclave
// with a key held in an enclave, borrowing both for the duration of the
// transform and no longer.
//
// It returns the CIPHERTEXT as plain memory on purpose. Those bytes are what
// gets written into the keyslot area of the device, byte for byte, so an
// attacker who can read this heap can read the device instead; locking them
// would protect a copy of something already public while doubling the
// RLIMIT_MEMLOCK the operation needs. The plaintext -- the stripes -- never
// leaves its enclave.
func encryptKeyMaterialEnclave(data, key *enclave.MemoryEnclave, cipherAlgo string) ([]byte, error) {
	var encrypted []byte
	err := borrowSecret("af stripes", data, func(plain []byte) error {
		return borrowSecret("keyslot encryption key", key, func(k []byte) error {
			var err error
			encrypted, err = encryptKeyMaterial(plain, k, cipherAlgo)
			return err
		})
	})
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

// decryptKeyMaterialEnclave decrypts keyslot material read off the device into
// PROTECTED memory, with the decryption key borrowed from its own enclave.
//
// This is the only decryption path any production call uses, and the direction
// is what makes it necessary: the plaintext here is the AF stripes, which are
// the master key, so it may not be produced onto the ordinary heap even
// transiently. The destination enclave is allocated first and the cipher writes
// straight into its locked pages.
//
// data is ciphertext read from the device and is deliberately NOT enclaved; see
// encryptKeyMaterialEnclave.
func decryptKeyMaterialEnclave(data []byte, key *enclave.MemoryEnclave, cipherAlgo string, sectorSize int) (*enclave.MemoryEnclave, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no key material to decrypt")
	}

	plaintext, err := newSecretEnclave("decrypted keyslot material", len(data))
	if err != nil {
		return nil, err
	}

	err = borrowSecret("decrypted keyslot material", plaintext, func(dst []byte) error {
		return borrowSecret("keyslot encryption key", key, func(k []byte) error {
			return xtsSectors(dst, data, k, cipherAlgo, sectorSize, true)
		})
	})
	if err != nil {
		plaintext.Destroy()
		return nil, err
	}

	return plaintext, nil
}

// encryptKeyMaterial encrypts the key material using AES-XTS.
//
// key must be a slice borrowed from an enclave on every production path; this
// function does not own it and does not clear it. The returned ciphertext is
// ordinary memory, which is the documented decision in
// encryptKeyMaterialEnclave.
func encryptKeyMaterial(data, key []byte, cipherAlgo string) ([]byte, error) {
	encrypted := make([]byte, len(data))
	if err := xtsSectors(encrypted, data, key, cipherAlgo, 512, false); err != nil {
		return nil, err
	}
	return encrypted, nil
}

// decryptKeyMaterial decrypts the key material using AES-XTS onto the ordinary
// heap.
//
// No production path calls this: every decryption of real keyslot material goes
// through decryptKeyMaterialEnclave, because the plaintext is the master key in
// AF-split form. It survives as a plain-memory helper for the unit tests that
// exercise the transform itself over synthetic data.
// -tags=integration, so `unused` fires on a function the default build exercises.
//
//nolint:unused // Test-only helper: the tests that call it are excluded under
func decryptKeyMaterial(data, key []byte, cipherAlgo string, sectorSize int) ([]byte, error) {
	decrypted := make([]byte, len(data))
	if err := xtsSectors(decrypted, data, key, cipherAlgo, sectorSize, true); err != nil {
		return nil, err
	}
	return decrypted, nil
}

// validateAreaCipher reports whether this package can run the named cipher over
// a keyslot area.
//
// AES-XTS is the only mode implemented, so "aes" is the only accepted algorithm.
// It is a function rather than a comparison written where it is needed because
// [screenKeyslot] must reach the same verdict from the header alone: a keyslot
// declaring `"encryption": "serpent-xts-plain64"` cannot open the volume, and a
// removal guard that does not know that will count it as a survivor.
func validateAreaCipher(cipherAlgo string) error {
	if cipherAlgo != "aes" {
		return fmt.Errorf("unsupported cipher: %s", cipherAlgo)
	}
	return nil
}

// validateXTSKeySize reports whether a volume key of this length can be used as
// an AES-XTS key.
//
// XTS splits its key in half and gives each half to AES, so the length must be
// twice a legal AES key size: 32, 48 or 64 bytes. xts.NewCipher refuses anything
// else -- which means a keyslot declaring `"key_size": 40` is well-formed by
// every other measure and can never yield a master key. That is exactly the
// shape the removal guard must not count, and it could not see it while the
// rejection lived only inside the cipher constructor.
//
// The bound is deliberately NOT MaxKeyslotKeySize's 1024, which asks a different
// question: what a header may DECLARE without sizing an allocation out of
// proportion. This asks what the cipher will actually accept.
func validateXTSKeySize(keySize int) error {
	switch keySize {
	case 32, 48, 64:
		return nil
	default:
		return fmt.Errorf("volume key of %d bytes cannot key AES-XTS; the accepted sizes are 32, 48 and 64 bytes", keySize)
	}
}

// KeyslotAreaEncryption is the ONLY area encryption this package writes to a
// keyslot, and it is exact rather than a family.
//
// Keyslot key material goes through encryptKeyMaterialEnclave with
// DefaultCipher, which is AES, and xtsSectors, which is XTS tweaked on a uint64
// sector index -- that is plain64 and nothing else. It is deliberately NOT the
// container's DATA cipher: a caller may format a volume with any cipher
// dm-crypt supports, and that choice describes the data segment. It says
// nothing about how the keyslots are wrapped, which this package does one way.
const KeyslotAreaEncryption = DefaultCipher + "-" + DefaultCipherMode

// There is deliberately no validateKeyslotAreaEncryption. It existed to screen a
// TEMPLATE keyslot whose area cipher AddKey was about to copy, and AddKey no
// longer copies one: both writers state KeyslotAreaEncryption directly, so there
// is nothing left to validate -- the value is a constant, and a validator over a
// constant is a guard against a state the code cannot reach.
//
// Its removal is also what repairs legacy containers: screening the template
// rejected every keyslot of any volume whose keyslot area carried the old
// data-cipher label, and AddKey then refused to add a credential to a volume it
// could unlock. See addKey.

// xtsSectors runs AES-XTS over src into dst, one sector at a time, with the
// sector index as the tweak. It is the single implementation behind both
// directions and both the enclave and the plain wrappers, so the two can never
// drift into producing containers this library can write but not read.
//
// dst and src must be the same length. Whole sectors are transformed IN PLACE
// between the two buffers: the previous form copied every sector through two
// freshly allocated 512-byte scratch buffers, which for a default keyslot meant
// ~1000 heap allocations holding AF-split master key material per operation --
// on exactly the material the enclave work exists to keep off the heap. Only a
// trailing PARTIAL sector still needs scratch, because XTS is run over a
// zero-padded full sector there, and that scratch is locked.
//
// The output is unchanged: for a whole sector, copying into a 512-byte buffer
// and transforming that is identical to transforming the sector directly.
func xtsSectors(dst, src, key []byte, cipherAlgo string, sectorSize int, decrypt bool) error {
	// Both of these are CALLABLE VALIDATORS rather than the inline literals
	// they used to be, and that is the point of them: the keyslot screen has to
	// be able to ask the same two questions off metadata alone, before a
	// derivation is paid for and before a removal guard counts the keyslot as a
	// survivor. An inline literal here is a condition nothing else can consult,
	// which is how the guard came to miss both (#45). See keyslotscreen.go.
	if err := validateAreaCipher(cipherAlgo); err != nil {
		return err
	}
	if err := validateXTSKeySize(len(key)); err != nil {
		return err
	}
	if len(dst) != len(src) {
		return fmt.Errorf("key material buffer size mismatch")
	}
	if sectorSize <= 0 {
		return fmt.Errorf("sector size must be positive")
	}

	// XTS requires key length to be 32, 64 bytes (for AES-128-XTS, AES-256-XTS)
	// The key is already the correct size (64 bytes for 512-bit keys)
	// XTS will internally split it: first half for cipher, second half for tweak
	//
	// RESIDUAL EXPOSURE: the returned *xts.Cipher holds the expanded AES round
	// keys for both halves on the ordinary heap, and neither x/crypto/xts nor
	// crypto/aes offers a way to place them elsewhere or to wipe them. The round
	// keys are a deterministic expansion of this key, so recovering them
	// recovers it. Nothing this package can do closes that; it is the stdlib
	// crypto boundary.
	xtsCipher, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return fmt.Errorf("failed to create XTS cipher: %w", err)
	}

	numSectors := (len(src) + sectorSize - 1) / sectorSize

	for i := 0; i < numSectors; i++ {
		start := i * sectorSize
		end := start + sectorSize
		if end > len(src) {
			end = len(src)
		}

		if end-start == sectorSize {
			if decrypt {
				xtsCipher.Decrypt(dst[start:end], src[start:end], uint64(i)) // #nosec G115 - loop counter bounded by data length
			} else {
				xtsCipher.Encrypt(dst[start:end], src[start:end], uint64(i)) // #nosec G115 - loop counter bounded by data length
			}
			continue
		}

		if err := xtsPartialSector(dst[start:end], src[start:end], xtsCipher, sectorSize, i, decrypt); err != nil {
			return err
		}
	}

	return nil
}

// xtsPartialSector transforms a final sector shorter than sectorSize by padding
// it out to a whole sector, which is what the on-disk format requires and what
// this package has always done.
//
// The two scratch buffers are LOCKED even for the encrypt direction, because
// one of them holds plaintext key material in both directions -- the padded
// input when encrypting, the padded output when decrypting -- and this path
// runs at most once per operation, so the cost is one page pair rather than one
// per sector.
func xtsPartialSector(dst, src []byte, xtsCipher *xts.Cipher, sectorSize, index int, decrypt bool) error {
	scratch, err := newSecretEnclave("key material sector", 2*sectorSize)
	if err != nil {
		return err
	}
	defer scratch.Destroy()

	return borrowSecret("key material sector", scratch, func(buf []byte) error {
		in, out := buf[:sectorSize], buf[sectorSize:]
		copy(in, src)

		if decrypt {
			xtsCipher.Decrypt(out, in, uint64(index)) // #nosec G115 - loop counter bounded by data length
		} else {
			xtsCipher.Encrypt(out, in, uint64(index)) // #nosec G115 - loop counter bounded by data length
		}

		copy(dst, out[:len(dst)])
		return nil
	})
}
