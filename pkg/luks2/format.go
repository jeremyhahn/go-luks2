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

// checkFormatDeviceSize refuses a device that cannot hold the layout plus at
// least one sector of data, or whose data area is not a whole number of
// sectors -- BEFORE anything is written. Format used to write the header first
// and fail later, or, on a regular file, silently grow it into a container with
// an empty data segment.
//
// The data size is rounded down to 512 bytes first, as a loop device presents a
// file, so only a sector size above 512 adds an alignment requirement.
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

// wipeOldHeaderCopies zeroes the binary header at the primary's offset and at
// every legal secondary offset, and syncs, before Format writes anything
// else: the part of cryptsetup's LUKS2_wipe_header_areas that a reader sees.
// Without it a crash between the new primary and the new secondary left the
// old secondary -- valid, and at a higher sequence id than a fresh header's
// -- for ReadCurrentHeader to choose, or to find by probing when the new
// primary was torn. Every legal offset lies below any layout's data offset
// (newFormatLayout), inside the range cryptsetup zeroes.
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

// formatWithSys creates a new LUKS2 volume, parameterized by sys so this
// package's tests can inject a seam (digestIterationsFor, measureDeviceSize,
// ...).
//
// The device is opened O_EXCL. For a block device the kernel then refuses the
// open with EBUSY while the device is mounted, mapped by device-mapper or held
// by another exclusive opener, and formatWithSys returns ErrDeviceInUse rather
// than overwriting something in use. On a regular file O_EXCL without O_CREAT
// has no effect.
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
	// The keyslot's KDF is created from the options AS THE CALLER GAVE THEM,
	// before HashAlgo is defaulted below. HashAlgo names the digest and AF hash
	// AND overrides the hash a KDF alias names, so defaulting it first turned
	// every "pbkdf2-sha512" -- the FIPS-mode default (DefaultKDFSpec) among
	// them -- into PBKDF2-SHA256 (#237). A caller who sets HashAlgo still gets
	// it for the KDF as well, as before.
	kdfOpts := opts
	if opts.HashAlgo == "" {
		opts.HashAlgo = defaultHashAlgo
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
	claimed, err := lock.locked.Claim(ctx, "format the device", os.O_RDWR|os.O_EXCL, sys.openFile)
	if err != nil {
		return err
	}
	f := claimed.File()
	defer func() { _ = f.Close() }()

	return formatCore(ctx, f, opts.Device, opts, kdfOpts, sys, func(kdf *header.KDF, keySize int) (*enclave.MemoryEnclave, error) {
		return sys.passphraseKDF(ctx, opts.Passphrase, kdf, keySize)
	})
}

// formatCore writes a new LUKS2 container to f, an already-claimed,
// exclusively open descriptor on device. opts and kdfOpts are fully
// resolved -- every default Format or (*Volume).Format applies has already
// been applied, and a KDF or hash that must never be WRITTEN has already
// been refused -- so this does nothing but lay the container out: opts
// carries the digest and anti-forensic hash (HashAlgo), kdfOpts the
// keyslot's KDF (KDFType, HashAlgo and its cost fields), the same split
// Format has always made between kdfOpts and opts so that HashAlgo can
// answer two independent questions.
//
// It is the body of the old Format from the point every option is resolved,
// extracted so (*Volume).Format -- which claims its own descriptor through
// v's pinned Volume rather than reopening the path itself -- writes a
// byte-identical container through the same code, the same way
// restorePrimaryHeaderCore is Volume.RestorePrimaryHeader's and the old
// RestorePrimaryHeader's shared core.
//
// deriveAreaKey derives keyslot 0's area key from the caller's passphrase. It
// is handed in rather than opts.Passphrase being read here so Volume.Format can
// open its passphrase enclave for exactly that derivation and no longer: the
// passphrase is not borrowed across the device writes that follow.
func formatCore(ctx context.Context, f *os.File, device string, opts, kdfOpts formatOptionsForTest, sys volumeSys,
	deriveAreaKey func(kdf *header.KDF, keySize int) (*enclave.MemoryEnclave, error)) error {
	masterKeySize := opts.KeySize / 8 // Convert bits to bytes

	// The whole layout is known now, before the KDF is paid for and before a
	// byte is written, so a device that cannot hold it is refused untouched.
	layout := newFormatLayout(opts.MetadataSize, masterKeySize)
	if err := checkFormatDeviceSize(f, device, layout, opts.SectorSize, sys.measureDeviceSize); err != nil {
		return err
	}

	// Generate the master key DIRECTLY into locked memory. It is drawn inside
	// the enclave's borrow window, so the volume's whole secret never exists on
	// the ordinary heap -- not even for the instant between rand.Read and a
	// move, which is a window no later wipe can close because the collector may
	// already have copied the bytes.
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

	// Encrypt AF-split key material with passphrase-derived key.
	//
	// The RESULT is deliberately plain memory. These bytes are the AF stripes
	// under the passphrase-derived key and they are about to be written to the
	// device in exactly this form, so locking them would protect a copy of
	// something already on disk while doubling the locked memory this call
	// needs. Both inputs are borrowed from their enclaves for the transform.
	encryptedKeyMaterial, err := areacipher.Default().WithFIPS(sys.fipsMode()).EncryptEnclave(custody, afData, passphraseKey)
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

	// THE KEYSLOT IS DURABLE BEFORE ANY HEADER NAMES IT. Keyslot 0's
	// material and the area filler are written and synced first, and the two
	// header copies last, as the commit point: a crash before the header write
	// leaves no LUKS2 header naming this keyslot, and a crash after it leaves
	// a header whose keyslot is on the device. Writing the headers first -- as
	// this once did -- left a durable header naming an area that might never
	// be written. Every write goes through the exclusively opened descriptor.
	//
	// The old header copies go first of all, so that no crash from here on
	// leaves one for a reader to choose.
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
// its header field (#248), a key or sector size outside the sizes this
// package supports, a metadata size outside cryptsetup's power-of-two range
// (#47), and everything KDFParams.Validate refuses on p.KDF -- including,
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

// splitCipherSpec splits a cryptsetup cipher spec into the base cipher and
// its mode, the pair formatOptionsForTest still carries separately:
// "aes-xts-plain64" splits to ("aes", "xts-plain64"), which
// validateFormatChoices rejoins with one "-" to look up in formatCiphers. A
// spec with no "-" splits to (spec, ""), which no formatCiphers entry
// matches, so it is refused there as ErrUnsupported rather than
// panicking here.
func splitCipherSpec(spec string) (cipher, mode string) {
	cipher, mode, _ = strings.Cut(spec, "-")
	return cipher, mode
}

// hashAlgoName names h the way this package's HashAlgo fields spell a hash:
// lowercase, no hyphen. It is the only place FormatParams.Hash and
// KDFParams.Hash cross into the legacy string-keyed format internals; an h
// this package does not write is named anyway and left to the checks those
// internals already make (af.ValidateWriteHash, getPBKDF2HashFunc) to
// refuse, rather than duplicating their allow-lists here.
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

// toFormatOptions converts p, already validated, into the
// formatOptionsForTest the format internals still take: opts carries the digest
// and anti-forensic hash, kdfOpts the keyslot's KDF. The two are
// independent fields on FormatParams/KDFParams, so, unlike the legacy
// Format, nothing here infers one hash from the other or from an alias
// spelling.
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
func (v *Volume) Format(ctx context.Context, pass *enclave.MemoryEnclave, p FormatParams) error {
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

	// Refused here, before the device is locked or claimed, exactly as the
	// package-level Format refuses them before its own exclusive claim:
	// never SHA-1 for the KDF (#239), and never an anti-forensic/digest hash
	// af.ValidateWriteHash does not write.
	if err := refuseSHA1ForCreation(kdfOpts.KDFType, kdfOpts.HashAlgo); err != nil {
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
	deriveAreaKey := func(kdf *header.KDF, keySize int) (*enclave.MemoryEnclave, error) {
		var key *enclave.MemoryEnclave
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
	keyslots := make(map[string]*header.Keyslot)
	keyslots["0"] = &header.Keyslot{
		Type:    "luks2",
		KeySize: masterKeySize,
		Area: &header.KeyslotArea{
			Type:    "raw",
			KeySize: masterKeySize,
			Offset:  formatSize(int64(keyslotOffset)),
			Size:    formatSize(int64(keyslot0Size)),
			// The KEYSLOT AREA cipher, which is not the container's data
			// cipher and was written as though it were.
			//
			// A caller may format with any cipher dm-crypt supports, and that
			// choice describes the SEGMENT below. header.Keyslot key material is
			// wrapped by areacipher.Default (AES-XTS) regardless --
			// so copying opts.Cipher+opts.CipherMode here declared, for any
			// non-XTS choice, an encryption the material does not have. The
			// container then opened for this package, whose read path consulted
			// only the algorithm, and for nothing else. Since #106 the read path
			// honors the mode, so such a keyslot is refused everywhere.
			//
			// Unchanged for the default aes/xts-plain64, where the two strings
			// were the same by coincidence -- which is why it survived.
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

// digestIterationsFor (volumeSys.digestIterationsFor) is the digest
// calibration.
//
// formatOptionsForTest.PBKDFIterations deliberately does NOT pin this. Pinning the
// keyslot count and the digest count with one knob is exactly what
// cryptsetup's --pbkdf-force-iterations does, and that conflation is what
// produced a confounded measurement, a wrong ruling and a revert here. They are
// independent parameters defending different things -- one a human-chosen
// passphrase, the other nothing at all -- and the API says so by keeping them
// apart.

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
	hashFunc, err := getPBKDF2HashFunc(hashAlgo, fips.Probe)
	if err != nil {
		return 0, err
	}
	return calibratePBKDF2(hashFunc, hashAlgo, digestCalibrationKeyLen, digestIterationTargetMs,
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
func createDigest(masterKey *enclave.MemoryEnclave, hashAlgo string, sys volumeSys) (*header.KDF, string, error) {
	// A digest is written, so it is never PBKDF2-SHA1 (#239).
	if err := refuseSHA1ForCreation("", hashAlgo); err != nil {
		return nil, "", err
	}
	// CALIBRATED, not a constant. See DigestIterationTargetMs (security.go) for
	// what this parameter is, what it is not, and why 100ms -- and for the
	// --pbkdf-force-iterations measurement trap that makes cryptsetup look as
	// though it hardcodes this.
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

	// context.Background(), not the caller's ctx: this derivation decides
	// WHICH digest a key belongs to and must always run to completion -- see
	// evaluateDigest. Only the slow, cancellable passphrase KDF (sys.passphraseKDF
	// / deriveKeyEnclave) observes ctx, and only before it starts: a
	// derivation in flight is never interrupted.
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

// keyslotAreaEncryption is the ONLY area encryption this package writes to a
// keyslot, and it is exact rather than a family.
//
// header.Keyslot key material is encrypted with areacipher.Default, which is AES-XTS
// tweaked on a uint64 sector index -- that is plain64 and nothing else. It is deliberately NOT the
// container's DATA cipher: a caller may format a volume with any cipher
// dm-crypt supports, and that choice describes the data segment. It says
// nothing about how the keyslots are wrapped, which this package does one way.
const keyslotAreaEncryption = areacipher.WriteSpec
