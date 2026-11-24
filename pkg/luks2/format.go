// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/af"
	"github.com/jeremyhahn/go-luks2/internal/areacipher"
	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/secret"
)

// maxLabelLength is the longest label or subsystem the 48-byte header field
// holds with the NUL terminator LUKS2 requires. cryptsetup refuses a longer one
// (LUKS2_hdr_labels) and reads only the first 47 bytes of the field.
const maxLabelLength = 47

// formatCiphers lists every data-segment cipher Format writes and its key sizes in bits.
var formatCiphers = map[string][]int{
	"aes-xts-plain64":      {256, 512},
	"aes-cbc-essiv:sha256": {256},
}

// validateFormatChoices refuses a cipher combination outside formatCiphers and
// a label or subsystem that does not fit its header field. Empty values are
// judged as the defaults Format substitutes for them.
func validateFormatChoices(opts formatOptionsForTest) error {
	cipher, mode, keySize := opts.Cipher, opts.CipherMode, opts.KeySize
	if cipher == "" {
		cipher = defaultCipherAlgo
	}
	if mode == "" {
		mode = defaultCipherMode
	}
	if keySize == 0 {
		keySize = DefaultKeySize
	}
	spec := cipher + "-" + mode
	if sizes, ok := formatCiphers[spec]; !ok || !slices.Contains(sizes, keySize) {
		return &errs.Error{Kind: ErrUnsupported, Detail: fmt.Sprintf(
			"%s with a %d-bit key; Format writes aes-xts-plain64 (256 or 512 bits) and aes-cbc-essiv:sha256 (256 bits)", spec, keySize)}
	}
	for _, field := range []struct{ name, value string }{{"label", opts.Label}, {"subsystem", opts.Subsystem}} {
		if len(field.value) > maxLabelLength || strings.IndexByte(field.value, 0) >= 0 {
			return &errs.Error{Kind: ErrInvalidArgument, Detail: fmt.Sprintf("the %s is %d bytes", field.name, len(field.value))}
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

// newFormatLayout lays a container out as cryptsetup 2.7.0 does: two header copies, the keyslots area, data at 16 MiB or later.
func newFormatLayout(metadataSize, keyBytes int) formatLayout {
	area := int64(metadataSize)
	if area == 0 {
		area = header.HeaderMinSize
	}
	keyslotsOffset := 2 * area
	keyslotsSize := max(int64(header.HeaderDefaultSize)-keyslotsOffset, alignTo(int64(keyBytes)*header.AFStripes, 4096))
	return formatLayout{
		keyslotsOffset: keyslotsOffset,
		keyslotsSize:   keyslotsSize,
		dataOffset:     keyslotsOffset + keyslotsSize,
	}
}

// checkFormatDeviceSize refuses, before writing, a device too small for the layout plus one sector or with a partial data sector.
func checkFormatDeviceSize(f *os.File, device string, layout formatLayout, sectorSize int, measureDeviceSize func(*os.File) (int64, error)) error {
	size, err := measureDeviceSize(f)
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "measure the device " + device, Err: err}
	}
	data := size - layout.dataOffset
	if data < int64(sectorSize) {
		return &errs.Error{Kind: ErrInvalidArgument, Detail: fmt.Sprintf(
			"%s is %d bytes; the header copies and keyslots area end at %d, and the data needs at least one %d-byte sector after that",
			device, size, layout.dataOffset, sectorSize)}
	}
	if usable := data - data%header.SectorSize; usable%int64(sectorSize) != 0 {
		return &errs.Error{Kind: ErrInvalidArgument, Detail: fmt.Sprintf(
			"%s leaves %d bytes of data after the keyslots area, which is not a whole number of %d-byte sectors", device, usable, sectorSize)}
	}
	return nil
}

// wipeOldHeaderCopies zeroes the binary header at the primary and every legal secondary offset, then syncs, before Format writes.
func wipeOldHeaderCopies(f *os.File, device string, sync func(*os.File) error) error {
	zero := make([]byte, header.HeaderSize)
	for _, at := range append([]int64{header.PrimaryHeaderOffset}, header.LegalHeaderAreaSizes()...) {
		if _, err := f.WriteAt(zero, at); err != nil {
			return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: fmt.Sprintf("wipe the header copy at %d on %s", at, device), Err: err}
		}
	}
	if err := sync(f); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "sync the wiped header copies " + device, Err: err}
	}
	return nil
}

// formatWithSys creates a new LUKS2 volume with injectable seams; O_EXCL makes an in-use block device fail with ErrDeviceInUse.
func formatWithSys(opts formatOptionsForTest, sys volumeSys) error {
	ctx := context.Background()
	// Validate options
	if err := validateFormatOptionsForTest(opts); err != nil {
		return err
	}

	// Acquire file lock for exclusive access
	lock, err := acquireFileLock(ctx, opts.Device, DefaultLockWait, sys.clock, sys)
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "lock " + opts.Device, Err: err}
	}
	defer func() { _ = lock.Release() }()

	// Set defaults
	if opts.Cipher == "" {
		opts.Cipher = defaultCipherAlgo
	}
	if opts.CipherMode == "" {
		opts.CipherMode = defaultCipherMode
	}
	if opts.KeySize == 0 {
		opts.KeySize = DefaultKeySize
	}
	// Create the keyslot KDF from the options as given, before HashAlgo is defaulted.
	kdfOpts := opts
	if opts.HashAlgo == "" {
		opts.HashAlgo = defaultHashAlgo
	}
	// HashAlgo must be writable (never SHA-1); refused before the KDF or the device.
	if err := refuseSHA1ForCreation(opts.KDFType, opts.HashAlgo, sys.fipsMode()); err != nil {
		return err
	}
	if err := af.ValidateWriteHash(opts.HashAlgo); err != nil {
		return err
	}
	if opts.SectorSize == 0 {
		opts.SectorSize = DefaultSectorSize
	}

	// Claim the device exclusively by reopening the locked descriptor through /proc/self/fd.
	claimed, err := lock.locked.Claim(ctx, "format the device", os.O_RDWR|os.O_EXCL, sys.openFile)
	if err != nil {
		return err
	}
	f := claimed.File()
	defer func() { _ = f.Close() }()

	return formatCore(ctx, f, opts.Device, opts, kdfOpts, sys, func(kdf *header.KDF, keySize int) (enclave.ByteAccess, error) {
		return sys.passphraseKDF(ctx, opts.Passphrase, kdf, keySize)
	})
}

// formatCore writes a new container to the claimed descriptor f with fully resolved options; deriveAreaKey derives keyslot 0's area key.
func formatCore(ctx context.Context, f *os.File, device string, opts, kdfOpts formatOptionsForTest, sys volumeSys,
	deriveAreaKey func(kdf *header.KDF, keySize int) (enclave.ByteAccess, error)) error {
	masterKeySize := opts.KeySize / 8 // Convert bits to bytes

	// The whole layout is known now, before the KDF is paid for and before a
	// byte is written, so a device that cannot hold it is refused untouched.
	layout := newFormatLayout(opts.MetadataSize, masterKeySize)
	if err := checkFormatDeviceSize(f, device, layout, opts.SectorSize, sys.measureDeviceSize); err != nil {
		return err
	}

	// Generate the master key directly into locked memory.
	masterKey, err := custody.Random("master key", masterKeySize, sys.cryptoRand)
	if err != nil {
		return err
	}
	defer custody.Release(masterKey)

	// Create binary header
	hdr, err := createBinaryHeader(opts, sys)
	if err != nil {
		return err
	}

	// Create KDF for keyslot 0
	kdf, err := createKDF(kdfOpts, masterKeySize, callerSuppliedCredential, sys.fipsMode, sys.calibratedCountFloor, sys.cryptoRand)
	if err != nil {
		return err
	}

	// Derive key from passphrase. The passphrase is the caller's memory and
	// stays that way -- see deriveKeyEnclave -- but what is derived from it is
	// held locked from here on.
	passphraseKey, err := deriveAreaKey(kdf, masterKeySize)
	if err != nil {
		return err
	}
	defer custody.Release(passphraseKey)

	// Create digest KDF and digest
	digestKDF, digestValue, err := createDigest(masterKey, opts.HashAlgo, sys)
	if err != nil {
		return err
	}

	// Apply anti-forensic split to master key. The stripes are the master key
	// spread over keySize*header.AFStripes bytes and are held locked accordingly; see
	// internal/af.
	afData, err := afCodec(sys).Split(masterKey, af.Params{Stripes: header.AFStripes, Hash: opts.HashAlgo})
	if err != nil {
		return err
	}
	defer custody.Release(afData)

	// Encrypt the AF-split key material with the passphrase-derived key; the result is plain memory because it goes to disk as is.
	encryptedKeyMaterial, err := areacipher.Default().WithFIPS(sys.fipsMode()).EncryptEnclave(custody, afData, passphraseKey)
	if err != nil {
		return err
	}
	defer clearBytes(encryptedKeyMaterial)

	// The keyslots area starts at twice the header area size; see newFormatLayout.
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

	// Write and sync keyslot 0 and the area filler first, the header copies last as the commit point; old header copies go before everything.
	if err := wipeOldHeaderCopies(f, device, sys.syncDevice); err != nil {
		return err
	}

	// Write encrypted key material
	if _, err := f.Seek(keyslotAreaStart, 0); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "seek to keyslot area " + device, Err: err}
	}
	if _, err := f.Write(encryptedKeyMaterial); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "write key material " + device, Err: err}
	}

	// Fill the rest of the keyslots area with CSPRNG data, as cryptsetup does, so it does not disclose keyslot history.
	if err := writeRandom(ctx, f, dataOffset-(keyslotAreaStart+int64(keyMaterialSize)), sys.cryptoRand); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "fill the keyslots area " + device, Err: err}
	}
	if err := sys.syncKeyslotArea(f); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "sync the keyslots area " + device, Err: err}
	}

	// The commit point. The header writer syncs each copy before returning.
	return writeHeaderTo(f, hdr, metadata, sys.syncDevice)
}

// DefaultCipher is the cipher dm-crypt is configured with when
// FormatParams.Cipher names none: AES-XTS with a 512-bit key (two 256-bit
// half-keys) -- cryptsetup's own default, and the strongest combination
// formatCiphers allows.
const DefaultCipher = "aes-xts-plain64"

// DefaultHash is the digest and anti-forensic hash Format uses when
// FormatParams.Hash names none.
const DefaultHash = crypto.SHA256

// FormatParams is a new LUKS2 container's parameters.
//
// Cipher is one cryptsetup spec ("aes-xts-plain64"), unlike the internal
// formatOptionsForTest.Cipher/CipherMode pair, because that is the form dm-crypt's
// table entry takes and a caller who knows cryptsetup's option already
// knows it. Hash is FormatParams' own digest and anti-forensic hash; it is
// independent of KDF.Hash, the keyslot's PBKDF2 PRF -- the two were one
// conflated formatOptionsForTest.HashAlgo field before this type, with an alias
// spelling in KDFType breaking the tie when a caller set only one of them.
// A FormatParams caller sets each the API names for.
type FormatParams struct {
	Cipher       string      // cryptsetup spec; zero: DefaultCipher
	KeySize      int         // bits; zero: DefaultKeySize
	Hash         crypto.Hash // digest + AF hash; zero: DefaultHash
	SectorSize   int         // zero: DefaultSectorSize
	MetadataSize int         // zero: 16 KiB header area

	Label, Subsystem string

	KDF KDFParams
}

// Validate refuses a FormatParams Format cannot write: a cipher, mode and
// key size outside formatCiphers, a label or subsystem that does not fit
// its header field, a key or sector size outside the sizes this
// package supports, a metadata size outside cryptsetup's power-of-two range,
// and everything KDFParams.Validate refuses on p.KDF -- including,
// in FIPS 140-3 mode, an Argon2 KDF named or implied by a nonzero Argon2
// cost. Nothing is read, created or written on p's device when this
// returns an error.
func (p FormatParams) Validate() error {
	return p.validateWith(fips.Probe)
}

func (p FormatParams) validateWith(fipsMode func() fips.Mode) error {
	if err := p.KDF.validateWith(fipsMode); err != nil {
		return err
	}

	keySize := p.KeySize
	if keySize != 0 && keySize != minKeySize && keySize != maxKeySize {
		return ErrInvalidArgument
	}
	if p.SectorSize != 0 && p.SectorSize != minSectorSize && p.SectorSize != maxSectorSize {
		return ErrInvalidArgument
	}
	if err := validateMetadataSize(p.MetadataSize); err != nil {
		return err
	}

	cipher, mode := splitCipherSpec(cipherSpecOrDefault(p.Cipher))
	if err := validateFormatChoices(formatOptionsForTest{
		Cipher: cipher, CipherMode: mode, KeySize: keySize,
		Label: p.Label, Subsystem: p.Subsystem,
	}); err != nil {
		return err
	}

	if keySize > 0 {
		keyBytes := keySize / 8
		afSize := keyBytes * header.AFStripes
		if afSize/header.AFStripes != keyBytes {
			return ErrInvalidArgument
		}
	}
	return nil
}

// cipherSpecOrDefault is spec, or DefaultCipher when spec is empty.
func cipherSpecOrDefault(spec string) string {
	if spec == "" {
		return DefaultCipher
	}
	return spec
}

// splitCipherSpec splits "aes-xts-plain64" into ("aes", "xts-plain64"); a spec with no "-" returns (spec, "").
func splitCipherSpec(spec string) (cipher, mode string) {
	cipher, mode, _ = strings.Cut(spec, "-")
	return cipher, mode
}

// hashAlgoName names h as the HashAlgo fields spell it: lowercase, no hyphen.
func hashAlgoName(h crypto.Hash) string {
	switch h {
	case 0:
		return ""
	case crypto.SHA1:
		return "sha1"
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	default:
		return strings.ToLower(h.String())
	}
}

// toFormatOptions converts a validated p into the internal digest and KDF option sets.
func (p FormatParams) toFormatOptions(device string, fipsMode fips.Mode) (opts, kdfOpts formatOptionsForTest) {
	cipher, mode := splitCipherSpec(cipherSpecOrDefault(p.Cipher))
	keySize := p.KeySize
	if keySize == 0 {
		keySize = DefaultKeySize
	}
	sectorSize := p.SectorSize
	if sectorSize == 0 {
		sectorSize = DefaultSectorSize
	}
	hash := p.Hash
	if hash == 0 {
		hash = DefaultHash
	}

	opts = formatOptionsForTest{
		Device:       device,
		Label:        p.Label,
		Subsystem:    p.Subsystem,
		Cipher:       cipher,
		CipherMode:   mode,
		KeySize:      keySize,
		HashAlgo:     hashAlgoName(hash),
		SectorSize:   sectorSize,
		MetadataSize: p.MetadataSize,
	}

	kdfType, kdfHash := p.KDF.resolved(fipsMode)
	kdfOpts = formatOptionsForTest{
		Device:          device,
		KeySize:         keySize,
		KDFType:         string(kdfType),
		HashAlgo:        hashAlgoName(kdfHash),
		PBKDFIterTime:   int(p.KDF.IterTime / time.Millisecond),
		PBKDFIterations: p.KDF.Iterations,
		Argon2Time:      p.KDF.Time,
		Argon2Memory:    p.KDF.MemoryKiB,
		Argon2Parallel:  p.KDF.Parallel,
	}
	return opts, kdfOpts
}

// Format creates a new LUKS2 container on v's device,
// writing exactly what the package-level Format writes, through v's own
// pinned descriptor and exclusive lock rather than reopening the path a
// second time. pass is the caller's enclave and stays the caller's: it is
// only ever borrowed, for the passphrase derivation.
func (v *Volume) Format(ctx context.Context, pass enclave.ByteAccess, p FormatParams) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.checkOpen("Volume.Format"); err != nil {
		return err
	}
	if err := v.checkWritable("Volume.Format"); err != nil {
		return err
	}

	const op = "Volume.Format"
	if err := p.validateWith(v.sys.fipsMode); err != nil {
		return errAt(op, v.path, err)
	}

	opts, kdfOpts := p.toFormatOptions(v.path, v.sys.fipsMode())

	// Refuse a SHA-1 KDF or an unwritable AF/digest hash before locking the device.
	if err := refuseSHA1ForCreation(kdfOpts.KDFType, kdfOpts.HashAlgo, v.sys.fipsMode()); err != nil {
		return errAt(op, v.path, err)
	}
	if err := af.ValidateWriteHash(opts.HashAlgo); err != nil {
		return errAt(op, v.path, err)
	}

	if err := secret.Borrow(op, pass, validatePassphraseBytes); err != nil {
		return errAt(op, v.path, err)
	}

	locked, err := v.lockFor(ctx, device.LockExclusive)
	if err != nil {
		return errAt(op, v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	claimed, err := locked.Claim(ctx, "format the device", os.O_RDWR|os.O_EXCL, v.sys.openFile)
	if err != nil {
		return errAt(op, v.path, err)
	}
	defer func() { _ = claimed.Close() }()

	// The passphrase is borrowed for the derivation alone, not across the
	// format: the 16 MiB of keyslot-area I/O that follows never runs with the
	// caller's enclave open.
	deriveAreaKey := func(kdf *header.KDF, keySize int) (enclave.ByteAccess, error) {
		var key enclave.ByteAccess
		err := secret.Borrow(op, pass, func(b []byte) error {
			var derr error
			key, derr = v.sys.passphraseKDF(ctx, b, kdf, keySize)
			return derr
		})
		if err != nil {
			v.sys.custody.Release(key)
			return nil, err
		}
		return key, nil
	}
	if err := formatCore(ctx, claimed.File(), v.path, opts, kdfOpts, v.sys, deriveAreaKey); err != nil {
		return errAt(op, v.path, err)
	}
	return nil
}

// createMetadata creates the JSON metadata structure
// keyslot0Size is the actual size of keyslot 0's area
// keyslotsAreaSize is the total reserved space for all keyslots (for Config.KeyslotsSize)
func createMetadata(kdf, digestKDF *header.KDF, digestValue string, opts formatOptionsForTest,
	masterKeySize, keyslotOffset, keyslot0Size, keyslotsAreaSize, dataOffset int) *header.Metadata {

	// Create the keyslot; priority stays unset, as cryptsetup writes it.
	keyslots := make(map[string]*header.Keyslot)
	keyslots["0"] = &header.Keyslot{
		Type:    "luks2",
		KeySize: masterKeySize,
		Area: &header.KeyslotArea{
			Type:    "raw",
			KeySize: masterKeySize,
			Offset:  formatSize(int64(keyslotOffset)),
			Size:    formatSize(int64(keyslot0Size)),
			// The keyslot area cipher is areacipher.Default (AES-XTS), not the data cipher.
			Encryption: keyslotAreaEncryption,
		},
		KDF: kdf,
		AF: &header.AntiForensic{
			Type:    "luks1",
			Stripes: header.AFStripes,
			Hash:    opts.HashAlgo,
		},
	}

	// Create segments
	segments := make(map[string]*header.Segment)
	segments["0"] = &header.Segment{
		Type:       "crypt",
		Offset:     formatSize(int64(dataOffset)),
		Size:       "dynamic",
		IVTweak:    "0",
		Encryption: opts.Cipher + "-" + opts.CipherMode,
		SectorSize: opts.SectorSize,
	}

	// Create digests
	digests := make(map[string]*header.Digest)
	digests["0"] = &header.Digest{
		Type:       "pbkdf2",
		Keyslots:   []string{"0"},
		Segments:   []string{"0"},
		Hash:       digestKDF.Hash,
		Iterations: *digestKDF.Iterations,
		Salt:       digestKDF.Salt,
		Digest:     digestValue,
	}

	// config.keyslots_size is the keyslots area size alone, not its end offset.
	jsonSize := header.DefaultSize
	config := &header.Config{
		JSONSize:     formatSize(int64(jsonSize)),
		KeyslotsSize: formatSize(int64(keyslotsAreaSize)),
	}

	return &header.Metadata{
		Keyslots: keyslots,
		// tokens is mandatory in LUKS2 and a container with no tokens carries
		// an empty object, so it is constructed empty rather than left nil.
		Tokens:   make(map[string]*LegacyToken),
		Segments: segments,
		Digests:  digests,
		Config:   config,
	}
}

// digestIterationsFor is the digest calibration; PBKDFIterations does not pin it.

// calibrateDigestIterations returns the digest iteration count for a hash on this machine, via BenchmarkPBKDF2.
func calibrateDigestIterations(hashAlgo string) (int, error) {
	return digestIterationsTimedBy(hashAlgo, wallClockPBKDF2)
}

// digestIterationsTimedBy is the digest calibration with its timer supplied:
// the digest's target and benchmark length, through the one calibration path.
// calibrateDigestIterations passes the wall clock; a test passes a known rate.
func digestIterationsTimedBy(hashAlgo string, timer pbkdf2Timer) (int, error) {
	hashFunc, err := getPBKDF2HashFunc(hashAlgo, fips.Probe)
	if err != nil {
		return 0, err
	}
	return calibratePBKDF2(hashFunc, hashAlgo, digestCalibrationKeyLen, digestIterationTargetMs,
		pbkdf2ProbeFloor, pbkdf2ProbeCeiling, timer)
}

// createDigest creates the master-key digest; crypto/pbkdf2 still makes a heap string of the borrowed key. The salt and digest are public header fields.
func createDigest(masterKey enclave.ByteAccess, hashAlgo string, sys volumeSys) (*header.KDF, string, error) {
	// A digest is never PBKDF2-SHA1.
	if err := refuseSHA1ForCreation("", hashAlgo, sys.fipsMode()); err != nil {
		return nil, "", err
	}
	// Calibrated, not a constant; see DigestIterationTargetMs.
	digestIterations, err := sys.digestIterationsFor(hashAlgo)
	if err != nil {
		return nil, "", err
	}

	salt, err := randomBytes(32, sys.cryptoRand)
	if err != nil {
		return nil, "", err
	}

	kdf := &header.KDF{
		Type:       "pbkdf2",
		Hash:       hashAlgo,
		Salt:       encodeBase64(salt),
		Iterations: &digestIterations,
	}

	// Derive to the digest hash's output length; verifyMasterKey derives to the stored length.
	digestLen, err := hashOutputLen(hashAlgo)
	if err != nil {
		return nil, "", err
	}

	// context.Background(): this derivation always runs to completion; see evaluateDigest.
	digest, err := deriveKeySecret(context.Background(), masterKey, kdf, digestLen, sys)
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

// keyslotAreaEncryption is the only keyslot area encryption written: AES-XTS plain64, independent of the data cipher.
const keyslotAreaEncryption = areacipher.WriteSpec
