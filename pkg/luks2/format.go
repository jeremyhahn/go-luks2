// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/aes"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"slices"
	"strings"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/crypto/xts"
)

// Errors Format and ValidateFormatOptions refuse with before the device is
// touched (#248).
var (
	// ErrUnsupportedCipher indicates a Cipher, CipherMode and KeySize that are
	// not a combination Format writes: aes-xts-plain64 with a 256- or 512-bit
	// key, or aes-cbc-essiv:sha256 with a 256-bit key.
	ErrUnsupportedCipher = errors.New("unsupported cipher, mode and key size combination")

	// ErrInvalidLabel indicates a Label or Subsystem that does not fit the
	// 48-byte header field with its NUL terminator, or that contains a NUL.
	ErrInvalidLabel = errors.New("label must be at most 47 bytes and contain no NUL byte")

	// ErrDeviceTooSmall indicates a device with no room for the header copies,
	// the keyslots area and at least one encryption sector of data.
	ErrDeviceTooSmall = errors.New("device is too small for a LUKS2 container")
)

// maxLabelLength is the longest label or subsystem the 48-byte header field
// holds with the NUL terminator LUKS2 requires. cryptsetup refuses a longer one
// (LUKS2_hdr_labels) and reads only the first 47 bytes of the field.
const maxLabelLength = 47

// formatCiphers lists every data-segment cipher Format writes, and the key
// sizes in bits each is written with.
//
// It is an allow-list because the segment cipher is a device-mapper
// specification and anything else was written blind (#248): a CipherMode of
// "xts-plain64 x" formatted a container no reader would open, and aes-cbc with
// a 512-bit key formatted one dm-crypt cannot set up. CBC-ESSIV takes one AES
// key, so it has no 512-bit form; XTS splits its key in two, which is why
// 512 bits is AES-256-XTS. Both are what cryptsetup writes for the same
// options.
var formatCiphers = map[string][]int{
	"aes-xts-plain64":      {256, 512},
	"aes-cbc-essiv:sha256": {256},
}

// validateFormatChoices refuses a cipher combination outside formatCiphers and
// a label or subsystem that does not fit its header field. Empty values are
// judged as the defaults Format substitutes for them.
func validateFormatChoices(opts FormatOptions) error {
	cipher, mode, keySize := opts.Cipher, opts.CipherMode, opts.KeySize
	if cipher == "" {
		cipher = DefaultCipher
	}
	if mode == "" {
		mode = DefaultCipherMode
	}
	if keySize == 0 {
		keySize = DefaultKeySize
	}
	spec := cipher + "-" + mode
	if sizes, ok := formatCiphers[spec]; !ok || !slices.Contains(sizes, keySize) {
		return &detailError{Kind: ErrUnsupportedCipher, Detail: fmt.Sprintf(
			"%s with a %d-bit key; Format writes aes-xts-plain64 (256 or 512 bits) and aes-cbc-essiv:sha256 (256 bits)", spec, keySize)}
	}
	for _, field := range []struct{ name, value string }{{"label", opts.Label}, {"subsystem", opts.Subsystem}} {
		if len(field.value) > maxLabelLength || strings.IndexByte(field.value, 0) >= 0 {
			return &detailError{Kind: ErrInvalidLabel, Detail: fmt.Sprintf("the %s is %d bytes", field.name, len(field.value))}
		}
	}
	return nil
}

// requireSameDevice refuses unless locked and opened are descriptors of one
// file -- the same st_dev, st_ino AND st_rdev -- so the lock held is the lock on
// what is about to be written. op says what the second open was for.
//
// It exists for the opens the kernel grants only BY PATH: an O_EXCL in-use
// claim on a block device cannot be taken on a descriptor already open. The
// path is resolved again for it, and a symlink re-pointed since the lock was
// taken -- a /dev/disk/by-* link, a /dev/mapper entry -- would otherwise put
// the lock on one device and the writes on another. Every caller checks before
// its first write and refuses with ErrDeviceChanged.
func requireSameDevice(locked, opened *os.File, device, op string) error {
	var a, b unix.Stat_t
	if err := unix.Fstat(int(locked.Fd()), &a); err != nil {
		return &DeviceError{Device: device, Op: "stat the locked descriptor", Err: err}
	}
	if err := unix.Fstat(int(opened.Fd()), &b); err != nil {
		return &DeviceError{Device: device, Op: "stat the descriptor opened to " + op, Err: err}
	}
	if a.Dev != b.Dev || a.Ino != b.Ino || a.Rdev != b.Rdev {
		return &DeviceError{Device: device, Op: op, Err: &detailError{Kind: ErrDeviceChanged,
			Detail: "the path resolved to a different file between taking its lock and opening it to " + op}}
	}
	return nil
}

// formatLayout is where Format puts each part of a new container.
type formatLayout struct {
	keyslotsOffset int64 // the keyslots area starts after both header copies
	keyslotsSize   int64 // the keyslots area, up to the data
	dataOffset     int64 // the data segment
}

// newFormatLayout lays a container out the way cryptsetup does: two header
// copies of metadataSize bytes (0 for the 16 KiB default), the keyslots area,
// and the data segment at 16 MiB -- or later, if one keyslot of keyBytes of
// key material would not fit before it.
//
// MEASURED against cryptsetup 2.7.0 (#47): --luks2-metadata-size 16k gives
// keyslots_size 16744448, 32k gives 16711680 and 4m gives 8388608, with the
// data segment at 16 MiB in every case.
func newFormatLayout(metadataSize, keyBytes int) formatLayout {
	area := int64(metadataSize)
	if area == 0 {
		area = LUKS2HeaderMinSize
	}
	keyslotsOffset := 2 * area
	keyslotsSize := max(int64(LUKS2HeaderDefaultSize)-keyslotsOffset, alignTo(int64(keyBytes)*AFStripes, 4096))
	return formatLayout{
		keyslotsOffset: keyslotsOffset,
		keyslotsSize:   keyslotsSize,
		dataOffset:     keyslotsOffset + keyslotsSize,
	}
}

// checkFormatDeviceSize refuses a device that cannot hold the layout plus at
// least one sector of data, or whose data area is not a whole number of
// sectors -- BEFORE anything is written. Format used to write the header first
// and fail later, or, on a regular file, silently grow it into a container with
// an empty data segment.
//
// The data size is rounded down to 512 bytes first, as a loop device presents a
// file, so only a sector size above 512 adds an alignment requirement.
func checkFormatDeviceSize(f *os.File, device string, layout formatLayout, sectorSize int) error {
	size, err := measureDeviceSize(f)
	if err != nil {
		return &DeviceError{Device: device, Op: "measure the device", Err: err}
	}
	data := size - layout.dataOffset
	if data < int64(sectorSize) {
		return &detailError{Kind: ErrDeviceTooSmall, Detail: fmt.Sprintf(
			"%s is %d bytes; the header copies and keyslots area end at %d, and the data needs at least one %d-byte sector after that",
			device, size, layout.dataOffset, sectorSize)}
	}
	if usable := data - data%LUKS2SectorSize; usable%int64(sectorSize) != 0 {
		return &detailError{Kind: ErrInvalidSize, Detail: fmt.Sprintf(
			"%s leaves %d bytes of data after the keyslots area, which is not a whole number of %d-byte sectors", device, usable, sectorSize)}
	}
	return nil
}

// Format creates a new LUKS2 volume.
//
// The device is opened O_EXCL. For a block device the kernel then refuses the
// open with EBUSY while the device is mounted, mapped by device-mapper or held
// by another exclusive opener, and Format returns ErrDeviceInUse rather than
// overwriting something in use. On a regular file O_EXCL without O_CREAT has
// no effect.
func Format(opts FormatOptions) error {
	// Validate options
	if err := ValidateFormatOptions(opts); err != nil {
		return err
	}

	// Acquire file lock for exclusive access
	lock, err := AcquireFileLock(opts.Device)
	if err != nil {
		return &DeviceError{Device: opts.Device, Op: "lock", Err: err}
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
	// The keyslot's KDF is created from the options AS THE CALLER GAVE THEM,
	// before HashAlgo is defaulted below. HashAlgo names the digest and AF hash
	// AND overrides the hash a KDF alias names, so defaulting it first turned
	// every "pbkdf2-sha512" -- the FIPS-mode default (DefaultKDFType) among
	// them -- into PBKDF2-SHA256 (#237). A caller who sets HashAlgo still gets
	// it for the KDF as well, as before.
	kdfOpts := opts
	if opts.HashAlgo == "" {
		opts.HashAlgo = DefaultHashAlgo
	}
	// HashAlgo is also the new keyslot's anti-forensic hash and its digest's,
	// so it must be one a keyslot may be WRITTEN with -- never SHA-1 (#236,
	// #239), nor a pbkdf2-sha1 KDF -- and that is refused here, before the KDF
	// is paid for and before the device is touched.
	if err := refuseSHA1ForCreation(opts.KDFType, opts.HashAlgo); err != nil {
		return err
	}
	if _, err := getHashFunc(opts.HashAlgo); err != nil {
		return err
	}
	if opts.SectorSize == 0 {
		opts.SectorSize = DefaultSectorSize
	}

	// Open device, exclusively: see the function comment. The locks above were
	// taken first, as the cryptsetup lock order requires, on a descriptor of
	// their own; this one must be the SAME file, or a path retargeted between
	// the two opens would have the locks held on one device while the format
	// writes another. Every write below goes through f.
	f, err := openDevice("format the device", opts.Device, os.O_RDWR|os.O_EXCL)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := requireSameDevice(lock.file, f, opts.Device, "format it"); err != nil {
		return err
	}

	masterKeySize := opts.KeySize / 8 // Convert bits to bytes

	// The whole layout is known now, before the KDF is paid for and before a
	// byte is written, so a device that cannot hold it is refused untouched.
	layout := newFormatLayout(opts.MetadataSize, masterKeySize)
	if err := checkFormatDeviceSize(f, opts.Device, layout, opts.SectorSize); err != nil {
		return err
	}

	// Generate the master key DIRECTLY into locked memory. It is drawn inside
	// the enclave's borrow window, so the volume's whole secret never exists on
	// the ordinary heap -- not even for the instant between rand.Read and a
	// move, which is a window no later wipe can close because the collector may
	// already have copied the bytes.
	masterKey, err := randomSecret("master key", masterKeySize)
	if err != nil {
		return err
	}
	defer releaseSecret(masterKey)

	// Create binary header
	hdr, err := CreateBinaryHeader(opts)
	if err != nil {
		return err
	}

	// Create KDF for keyslot 0
	kdf, err := CreateKDF(kdfOpts, masterKeySize)
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
	defer releaseSecret(passphraseKey)

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
	defer releaseSecret(afData)

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

	// The keyslots area starts where the two header copies end, at twice the
	// header area size, never at a fixed 0x8000: with MetadataSize at 32 KiB
	// the second header copy occupies 0x8000..0xFFFF (#47). See newFormatLayout.
	keyslotAreaStart := layout.keyslotsOffset
	keyMaterialSize := len(encryptedKeyMaterial)
	alignedKeyMaterialSize := alignTo(int64(keyMaterialSize), 4096)
	keyslotsAreaSize := layout.keyslotsSize
	dataOffset := layout.dataOffset

	// Create metadata structure
	// keyslot0Size is the actual size of keyslot 0's area
	// keyslotsAreaSize is the total reserved space for keyslots (allows adding more keys)
	metadata := createMetadata(kdf, digestKDF, digestValue, opts, masterKeySize,
		int(keyslotAreaStart), int(alignedKeyMaterialSize), int(keyslotsAreaSize), int(dataOffset))

	// Write headers, through the exclusively opened descriptor.
	if err := writeHeaderTo(f, hdr, metadata); err != nil {
		return err
	}

	// Write encrypted key material
	if _, err := f.Seek(keyslotAreaStart, 0); err != nil {
		return &DeviceError{Device: opts.Device, Op: "seek to keyslot area", Err: err}
	}
	if _, err := f.Write(encryptedKeyMaterial); err != nil {
		return &DeviceError{Device: opts.Device, Op: "write key material", Err: err}
	}

	// FILL THE REST OF THE KEYSLOTS AREA WITH CSPRNG DATA, from the end of
	// keyslot 0's material to the start of the data segment. That is two
	// distinct ranges and both used to be zeroes:
	//
	//	the tail of keyslot 0's own declared area   2 KiB
	//	the region no keyslot occupies yet          ~15.7 MiB
	//
	// Zeroes there are an INFORMATION DISCLOSURE. Encrypted key material is
	// indistinguishable from random, so a region of random says nothing; a
	// region of zeroes says "no keyslot has ever been written here". On a
	// stolen or discarded drive that hands the holder the container's key
	// management history for free -- how many keys exist, where they sit, and
	// which slots were used and later destroyed -- without breaking anything.
	// cryptsetup fills the whole area at format for exactly this reason, and
	// the same reasoning is why wipeKeyslotArea now fills with random rather
	// than zeroing (keyslot.go).
	//
	// It is not a conformance requirement: cryptsetup opens a container whose
	// unallocated area is zeroed. MEASURED over 20 formats of a 64 MiB image,
	// it costs 20ms on top of 375ms -- the CSPRNG is not the cost, writing 16
	// MiB and syncing it is -- and the image is no longer sparse.
	if err := writeRandom(f, dataOffset-(keyslotAreaStart+int64(keyMaterialSize))); err != nil {
		return &DeviceError{Device: opts.Device, Op: "fill the keyslots area", Err: err}
	}

	return f.Sync()
}

// createMetadata creates the JSON metadata structure
// keyslot0Size is the actual size of keyslot 0's area
// keyslotsAreaSize is the total reserved space for all keyslots (for Config.KeyslotsSize)
func createMetadata(kdf, digestKDF *KDF, digestValue string, opts FormatOptions,
	masterKeySize, keyslotOffset, keyslot0Size, keyslotsAreaSize, dataOffset int) *LUKS2Metadata {

	// Create keyslot.
	//
	// PRIORITY IS DELIBERATELY NOT SET. LUKS2 makes the member optional and an
	// ABSENT priority means "normal" -- so writing `"priority":1` states the
	// default the reader already assumes. MEASURED against cryptsetup 2.7.0:
	// luksFormat and luksAddKey emit no priority member at all, and
	// `cryptsetup config --priority normal` DELETES it rather than writing 1.
	// Omitting it is what every LUKS2 writer does, and it is what lets a
	// formatted container's JSON be byte-identical to cryptsetup's.
	//
	// The field stays declared and omitempty on Keyslot: a caller that sets a
	// non-default priority still writes it, and a foreign container's priority
	// still round-trips untouched.
	keyslots := make(map[string]*Keyslot)
	keyslots["0"] = &Keyslot{
		Type:    "luks2",
		KeySize: masterKeySize,
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
			// container then opened for this package, whose read path consulted
			// only the algorithm, and for nothing else. Since #106 the read path
			// honors the mode, so such a keyslot is refused everywhere.
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

// digestIterationsFor is the digest calibration, behind a seam.
//
// The seam exists for the same reason cryptoRand and newUUID do and no other:
// a calibrated value differs on every machine, so with no way to fix it no test
// can compare two headers -- and the conformance suite's guarded exclusion for
// this field needs to be able to assert a pinned value rather than skip it.
//
// FormatOptions.PBKDFIterations deliberately does NOT pin this. Pinning the
// keyslot count and the digest count with one knob is exactly what
// cryptsetup's --pbkdf-force-iterations does, and that conflation is what
// produced a confounded measurement, a wrong ruling and a revert here. They are
// independent parameters defending different things -- one a human-chosen
// passphrase, the other nothing at all -- and the API says so by keeping them
// apart. It is unexported and has no setter, so no caller can weaken the digest
// through it.
var digestIterationsFor = calibrateDigestIterations

// calibrateDigestIterations returns the digest iteration count for a hash on
// this machine.
//
// It reuses BenchmarkPBKDF2 rather than adding a second calibration mechanism.
// One consequence is worth naming: BenchmarkPBKDF2 applies the keyslot
// iteration floor scaled to the requested budget, which at a 100ms target is
// ~10500 for sha512 rather than the 1000 LUKS2 requires. That floor is meant
// for a parameter this one is not, so it is over-strict here -- but it binds
// only on a machine roughly thirty times slower than current hardware, where it
// costs a few milliseconds, and one calibration path is worth more than a
// second one tuned for a value that defends nothing.
func calibrateDigestIterations(hashAlgo string) (int, error) {
	return digestIterationsTimedBy(hashAlgo, wallClockPBKDF2)
}

// digestIterationsTimedBy is the digest calibration with its timer supplied:
// the digest's target and benchmark length, through the one calibration path.
// calibrateDigestIterations passes the wall clock; a test passes a known rate.
func digestIterationsTimedBy(hashAlgo string, timer pbkdf2Timer) (int, error) {
	hashFunc, err := getPBKDF2HashFunc(hashAlgo)
	if err != nil {
		return 0, err
	}
	return calibratePBKDF2(hashFunc, hashAlgo, DigestCalibrationKeyLen, DigestIterationTargetMs,
		pbkdf2ProbeFloor, pbkdf2ProbeCeiling, timer)
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
	// A digest is written, so it is never PBKDF2-SHA1 (#239).
	if err := refuseSHA1ForCreation("", hashAlgo); err != nil {
		return nil, "", err
	}
	// CALIBRATED, not a constant. See DigestIterationTargetMs (security.go) for
	// what this parameter is, what it is not, and why 100ms -- and for the
	// --pbkdf-force-iterations measurement trap that makes cryptsetup look as
	// though it hardcodes this.
	digestIterations, err := digestIterationsFor(hashAlgo)
	if err != nil {
		return nil, "", err
	}

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
	defer releaseSecret(digest)

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
		releaseSecret(plaintext)
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
// Its removal also stopped AddKey refusing legacy containers whose keyslot area
// carried the old data-cipher label. Those keyslots are now refused one step
// earlier instead, by the read path, which honors the declared mode (#106):
// see parseKeyslotAreaEncryption.

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
	defer releaseSecret(scratch)

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
