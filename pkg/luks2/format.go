// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/internal/af"
	"github.com/jeremyhahn/go-luks2/internal/areacipher"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/secret"
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
		return &errs.Error{Kind: ErrUnsupportedCipher, Detail: fmt.Sprintf(
			"%s with a %d-bit key; Format writes aes-xts-plain64 (256 or 512 bits) and aes-cbc-essiv:sha256 (256 bits)", spec, keySize)}
	}
	for _, field := range []struct{ name, value string }{{"label", opts.Label}, {"subsystem", opts.Subsystem}} {
		if len(field.value) > maxLabelLength || strings.IndexByte(field.value, 0) >= 0 {
			return &errs.Error{Kind: ErrInvalidLabel, Detail: fmt.Sprintf("the %s is %d bytes", field.name, len(field.value))}
		}
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
		return &errs.Error{Kind: ErrDeviceTooSmall, Detail: fmt.Sprintf(
			"%s is %d bytes; the header copies and keyslots area end at %d, and the data needs at least one %d-byte sector after that",
			device, size, layout.dataOffset, sectorSize)}
	}
	if usable := data - data%LUKS2SectorSize; usable%int64(sectorSize) != 0 {
		return &errs.Error{Kind: ErrInvalidSize, Detail: fmt.Sprintf(
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
	if err := af.ValidateWriteHash(opts.HashAlgo); err != nil {
		return err
	}
	if opts.SectorSize == 0 {
		opts.SectorSize = DefaultSectorSize
	}

	// Claim the device exclusively: see Format's doc comment. The claim
	// reopens the descriptor the lock above is held on, via its /proc/self/fd
	// entry, so it targets by construction the exact file that was locked --
	// a path retargeted between the two opens cannot put the lock on one
	// device and the writes on another. Every write below goes through f.
	claimed, err := lock.locked.Claim("format the device", os.O_RDWR|os.O_EXCL, openFileFunc)
	if err != nil {
		return err
	}
	f := claimed.File()
	defer func() { _ = f.Close() }()

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
	masterKey, err := custody.Random("master key", masterKeySize, cryptoRand)
	if err != nil {
		return err
	}
	defer custody.Release(masterKey)

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
	defer custody.Release(passphraseKey)

	// Create digest KDF and digest
	digestKDF, digestValue, err := createDigest(masterKey, opts.HashAlgo)
	if err != nil {
		return err
	}

	// Apply anti-forensic split to master key. The stripes are the master key
	// spread over keySize*AFStripes bytes and are held locked accordingly; see
	// internal/af.
	afData, err := afCodec().Split(masterKey, af.Params{Stripes: AFStripes, Hash: opts.HashAlgo})
	if err != nil {
		return err
	}
	defer custody.Release(afData)

	// Encrypt AF-split key material with passphrase-derived key.
	//
	// The RESULT is deliberately plain memory. These bytes are the AF stripes
	// under the passphrase-derived key and they are about to be written to the
	// device in exactly this form, so locking them would protect a copy of
	// something already on disk while doubling the locked memory this call
	// needs. Both inputs are borrowed from their enclaves for the transform.
	encryptedKeyMaterial, err := areacipher.Default().EncryptEnclave(custody, afData, passphraseKey)
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
			// wrapped by areacipher.Default (AES-XTS) regardless --
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
// crypto/pbkdf2.Key, which stringifies it -- see exposure 2 in internal/secret. Every
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
	defer custody.Release(digest)

	var encoded string
	if err := secret.Borrow("master key digest", digest, func(b []byte) error {
		encoded = encodeBase64(b)
		return nil
	}); err != nil {
		return nil, "", err
	}

	return kdf, encoded, nil
}

// KeyslotAreaEncryption is the ONLY area encryption this package writes to a
// keyslot, and it is exact rather than a family.
//
// Keyslot key material is encrypted with areacipher.Default, which is AES-XTS
// tweaked on a uint64 sector index -- that is plain64 and nothing else. It is deliberately NOT the
// container's DATA cipher: a caller may format a volume with any cipher
// dm-crypt supports, and that choice describes the data segment. It says
// nothing about how the keyslots are wrapped, which this package does one way.
const KeyslotAreaEncryption = areacipher.WriteSpec
