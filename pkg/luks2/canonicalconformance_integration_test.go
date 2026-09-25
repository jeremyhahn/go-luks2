// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// BYTE-FOR-BYTE conformance against cryptsetup 2.7.0.
//
// The conformance tests in conformance_test.go establish that cryptsetup
// ACCEPTS what this library writes and vice versa. Acceptance is a weak
// property: a header can be accepted by every implementation and still be
// encoded differently by all of them, and a difference that is tolerated today
// is a difference that has to be defended forever. These tests assert the
// stronger thing -- that the bytes are the SAME bytes -- and enumerate, with a
// reason for each, the handful of places where they legitimately are not.
//
// # Why this is in the INTEGRATION tier
//
// It shells out to cryptsetup and HARD-FAILS when the binary is absent, the
// same decision and for the same reason as TestCryptsetupCannotReachAn-
// UnaddressableTokenID: a conformance measurement that reports success on a
// host with no third party to check against converts "unverified" into
// "verified" (#90). A hard failure is only correct where the binary is a
// DECLARED dependency, and in this tier it is -- test/integration/Dockerfile
// installs cryptsetup-bin. The unit tier's conformance_test.go skips instead,
// because there the binary is not declared.

const (
	// conformanceUUID is stamped into both containers so the 40 UUID bytes of
	// the binary header can be compared rather than excluded. cryptsetup takes
	// it with --uuid; this library takes it through the newUUID seam.
	conformanceUUID = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"

	// canonicalPassphrase is used on both sides. It is not compared -- nothing
	// derived from it is deterministic across the two implementations -- but
	// both containers must be openable with it for the comparison to be about
	// a real container.
	canonicalPassphrase = "conformance-test-passphrase"

	// canonicalImageSize leaves a data segment past the 16 MiB metadata and
	// keyslots area both implementations lay out.
	canonicalImageSize = 64 << 20

	// canonicalArgon2MemoryKB caps the Argon2 memory cost ON BOTH SIDES.
	//
	// It is the ONLY cost pinned from outside, and it is a limit rather than a
	// bypass: cryptsetup still CALIBRATES the time cost against it, exactly as
	// it does whenever an operator's memory limit binds. Left to itself
	// cryptsetup would pick up to 1 GiB, which is slow and hostile to a CI
	// container; 64 MiB is also this package's enforced minimum
	// (ValidateFormatOptions), so it is the smallest value both sides accept.
	canonicalArgon2MemoryKB = 65536

	// canonicalCheapIterations is for containers this package formats FOR
	// ITSELF -- the ones a test then mutates, whose bytes are never compared
	// against cryptsetup's. It is the sha512 floor, the cheapest keyslot
	// forcedPBKDF2Iterations will write, because the cost is pure test latency
	// here and buys nothing.
	//
	// It is deliberately NOT used for the conformance pair: those costs come
	// from cryptsetup's own calibration. See canonicalKDF.
	canonicalCheapIterations = 210_000
)

// canonicalKDF is one keyslot KDF shape, expressed for both implementations.
//
// BOTH SHAPES ARE COVERED BECAUSE ONE DECLARATION SERVES BOTH. The KDF struct
// carries the pbkdf2 members and the argon2 members together, each set
// omitempty, so which members appear is decided by which are populated -- and a
// key order that is right for one shape can be wrong for the other. A
// conformance claim measured only on pbkdf2 says nothing about the argon2id
// containers this stack actually formats.
//
// # CRYPTSETUP FORMATS FIRST AND THIS PACKAGE MIRRORS IT
//
// Not the other way round, and NOT with --pbkdf-force-iterations on the
// cryptsetup side. That flag looks like a way to make the comparison
// deterministic and is a trap: it pins the DIGEST cost as well as the keyslot
// cost, so a suite built on it compares a container no operator ever creates,
// and reports agreement about a code path real usage does not take. Measured on
// this host -- default pbkdf2 gives a keyslot at 6017652 iterations and a
// digest at 304464, default argon2id gives time 218 and a digest at 381577,
// while --pbkdf-force-iterations 1000 gives 1000 for BOTH in either shape.
//
// So cryptsetup calibrates, freely, the way it would on an operator's machine;
// this package is then told the numbers it chose. mirror is what does the
// telling.
type canonicalKDF struct {
	name string

	// cryptsetupArgs are appended to luksFormat. They select the KDF and cap
	// the Argon2 memory; nothing here pins a calibrated cost.
	cryptsetupArgs []string

	// mirror copies the costs cryptsetup CHOSE into this package's options, so
	// the two containers differ in nothing that either side got to decide.
	mirror func(t *testing.T, opts *FormatOptions, theirs *KDF)
}

func canonicalKDFs() []canonicalKDF {
	return []canonicalKDF{
		{
			name:           "pbkdf2",
			cryptsetupArgs: []string{"--pbkdf", "pbkdf2", "--hash", "sha512"},
			mirror: func(t *testing.T, opts *FormatOptions, theirs *KDF) {
				t.Helper()
				if theirs.Iterations == nil {
					t.Fatalf("cryptsetup's pbkdf2 keyslot has no iteration count: %+v", theirs)
				}
				opts.KDFType = KDFTypePBKDF2
				opts.PBKDFIterations = *theirs.Iterations
			},
		},
		{
			name: "argon2id",
			cryptsetupArgs: []string{
				"--pbkdf", "argon2id",
				"--hash", "sha512",
				"--pbkdf-memory", fmt.Sprint(canonicalArgon2MemoryKB),
			},
			mirror: func(t *testing.T, opts *FormatOptions, theirs *KDF) {
				t.Helper()
				if theirs.Time == nil || theirs.Memory == nil || theirs.CPUs == nil {
					t.Fatalf("cryptsetup's argon2id keyslot is missing a cost member: %+v", theirs)
				}
				opts.KDFType = KDFTypeArgon2id
				opts.Argon2Time = *theirs.Time
				opts.Argon2Memory = *theirs.Memory
				opts.Argon2Parallel = *theirs.CPUs
			},
		},
	}
}

// Binary header field offsets, from the LUKS2 On-Disk Format specification and
// matching LUKS2BinaryHeader. Named here because the comparison below excludes
// three of them and an unnamed 104:168 tells a reader nothing; hdr_size and
// hdr_offset are named because the secondary header is located and identified
// by them.
const (
	hdrSizeStart       = 8
	hdrSizeEnd         = 16
	hdrSequenceIDStart = 16
	hdrSequenceIDEnd   = 24
	hdrSaltStart       = 104
	hdrSaltEnd         = 168
	hdrOffsetStart     = 256
	hdrOffsetEnd       = 264
	hdrChecksumStart   = 448
	hdrChecksumEnd     = 512
)

func requireCryptsetupDeclared(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Fatalf("cryptsetup is not installed (%v). This tier DECLARES it -- "+
			"test/integration/Dockerfile installs cryptsetup-bin -- so its absence is a broken "+
			"environment, not a reason to report success. Nothing here was verified against a "+
			"third-party LUKS2 implementation.", err)
	}
}

// canonicalImage creates a sparse image of the standard size.
func canonicalImage(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	f, err := os.Create(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to create %s: %v", path, err)
	}
	if err := f.Truncate(canonicalImageSize); err != nil {
		_ = f.Close()
		t.Fatalf("failed to size %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close %s: %v", path, err)
	}
	return path
}

// formatWithCryptsetup formats path, letting cryptsetup calibrate every cost it
// normally calibrates. See canonicalKDF for why nothing is forced.
func formatWithCryptsetup(t *testing.T, path string, kdf canonicalKDF) {
	t.Helper()

	args := []string{"luksFormat",
		"--type", "luks2",
		"--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--sector-size", "512",
		"--uuid", conformanceUUID,
		"--batch-mode",
	}
	args = append(args, kdf.cryptsetupArgs...)
	args = append(args, path)

	cmd := exec.Command("cryptsetup", args...) // #nosec G204 -- arguments are test constants
	cmd.Stdin = strings.NewReader(canonicalPassphrase)

	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("cryptsetup luksFormat exited %d\n%s", exitErr.ExitCode(), out)
		}
		t.Fatalf("failed to run cryptsetup luksFormat: %v\n%s", err, out)
	}
}

// formatWithCryptsetupCheap formats a cryptsetup container for a test that does
// NOT compare bytes.
//
// It uses --pbkdf-force-iterations, which buildCanonicalPair must never do. The
// distinction is the whole lesson of this file: that flag pins the DIGEST cost
// as well as the keyslot cost, so a container made with it is not the container
// an operator's machine produces, and a byte baseline taken from one measures
// the wrong thing. It is harmless where the KDF cost is irrelevant to the
// assertion -- the priority tests are about a member no cost touches -- and it
// removes cryptsetup's ~2s calibration from each fixture.
func formatWithCryptsetupCheap(t *testing.T, path string) {
	t.Helper()
	formatWithCryptsetupForced(t, path, canonicalCheapIterations)
}

// formatWithCryptsetupForced formats with an exact pbkdf2 iteration count.
//
// It is also the only way to produce a container carrying a count BELOW this
// package's floor, which no caller of this package can create and which an
// imported container legitimately has.
func formatWithCryptsetupForced(t *testing.T, path string, iterations int) {
	t.Helper()

	cmd := exec.Command("cryptsetup", "luksFormat", // #nosec G204 -- arguments are test constants
		"--type", "luks2",
		"--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--hash", "sha512",
		"--sector-size", "512",
		"--pbkdf", "pbkdf2",
		"--pbkdf-force-iterations", fmt.Sprint(iterations),
		"--uuid", conformanceUUID,
		"--batch-mode",
		path,
	)
	cmd.Stdin = strings.NewReader(canonicalPassphrase)

	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("cryptsetup luksFormat exited %d\n%s", exitErr.ExitCode(), out)
		}
		t.Fatalf("failed to run cryptsetup luksFormat: %v\n%s", err, out)
	}
}

// canonicalPair is one cryptsetup container and one this package wrote to match
// it: same parameters, same UUID, same keyslot costs.
type canonicalPair struct {
	oursJSON, theirsJSON     []byte
	oursHeader, theirsHeader []byte
	// oursSecondary and theirsSecondary are the 4096-byte binary header of
	// the SECOND copy, read from the offset each primary records.
	oursSecondary, theirsSecondary []byte
	oursKDF, theirsKDF             *KDF
	oursKeyslot                    *Keyslot
	theirsKeyslot                  *Keyslot
	oursDigest, theirsDigest       *Digest
}

// buildCanonicalPair formats both containers and returns their bytes.
//
// The ORDER is the point: cryptsetup goes first and freely, then its chosen
// costs are read out of its header and handed to this package's Format. Doing
// it the other way -- formatting ours and forcing cryptsetup to match -- is
// what --pbkdf-force-iterations invites, and it changes cryptsetup's behavior
// (it pins the digest too), so the reference side would no longer be the
// reference.
//
// It is memoized per KDF shape. A calibrated format is ~2s on each side and
// three tests want the same pair; the bytes are immutable, so building them
// once per process is the whole saving with none of the risk.
func buildCanonicalPair(t *testing.T, kdf canonicalKDF) *canonicalPair {
	t.Helper()

	canonicalPairOnce.Do(func() { canonicalPairs = map[string]*canonicalPair{} })

	canonicalPairMu.Lock()
	defer canonicalPairMu.Unlock()

	if pair, ok := canonicalPairs[kdf.name]; ok {
		return pair
	}

	theirs := canonicalImage(t, "cryptsetup.img")
	formatWithCryptsetup(t, theirs, kdf)

	_, theirMetadata, err := ReadHeader(theirs)
	if err != nil {
		t.Fatalf("this package cannot read cryptsetup's own header: %v", err)
	}
	theirKeyslot := theirMetadata.Keyslots["0"]
	if theirKeyslot == nil || theirKeyslot.KDF == nil {
		t.Fatal("cryptsetup's container has no keyslot 0 with a KDF")
	}
	theirDigest := theirMetadata.Digests["0"]
	if theirDigest == nil {
		t.Fatal("cryptsetup's container has no digest 0")
	}

	opts := FormatOptions{
		Device:     canonicalImage(t, "library.img"),
		Passphrase: []byte(canonicalPassphrase),
		Cipher:     "aes",
		CipherMode: "xts-plain64",
		KeySize:    512,
		HashAlgo:   "sha512",
		SectorSize: 512,
	}
	kdf.mirror(t, &opts, theirKeyslot.KDF)

	// The DIGEST cost is mirrored too, through the digestIterationsFor seam --
	// FormatOptions deliberately has no knob for it. cryptsetup still
	// calibrates freely; this package is told the count it chose, exactly as
	// it is told the keyslot costs. Letting this package run a second
	// calibration of its own would put two wall-clock measurements, taken
	// moments apart on a host that is also running a test suite, into a
	// comparison about ENCODING -- and under load they land 2x apart and fail
	// a correct tree (#209).
	pinDigestIterations(t, theirDigest.Iterations)
	pinCryptoRand(t, 0x9c)
	pinUUID(t, conformanceUUID)
	if err := Format(opts); err != nil {
		t.Fatalf("Format failed mirroring cryptsetup's %s costs: %v", kdf.name, err)
	}

	_, ourMetadata, err := ReadHeader(opts.Device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	ourKeyslot := ourMetadata.Keyslots["0"]
	if ourKeyslot == nil || ourKeyslot.KDF == nil {
		t.Fatal("the formatted container has no keyslot 0 with a KDF")
	}

	// The mirroring has to have taken effect, or every comparison below would
	// be excusing a difference this helper was supposed to remove. Asserted
	// from the HEADERS, because what is on disk is the question.
	assertKDFCostsMatch(t, ourKeyslot.KDF, theirKeyslot.KDF)
	ourDigest := ourMetadata.Digests["0"]
	if ourDigest == nil {
		t.Fatal("the formatted container has no digest 0")
	}
	if ourDigest.Iterations != theirDigest.Iterations {
		t.Fatalf("digest iterations differ: ours %d, cryptsetup %d -- the digest pin did not take",
			ourDigest.Iterations, theirDigest.Iterations)
	}

	pair := &canonicalPair{
		oursJSON:        readJSONArea(t, opts.Device),
		theirsJSON:      readJSONArea(t, theirs),
		oursHeader:      readBinaryHeader(t, opts.Device),
		theirsHeader:    readBinaryHeader(t, theirs),
		oursSecondary:   readSecondaryBinaryHeader(t, opts.Device),
		theirsSecondary: readSecondaryBinaryHeader(t, theirs),
		oursKDF:         ourKeyslot.KDF,
		theirsKDF:       theirKeyslot.KDF,
		oursKeyslot:     ourKeyslot,
		theirsKeyslot:   theirKeyslot,
		oursDigest:      ourDigest,
		theirsDigest:    theirDigest,
	}
	canonicalPairs[kdf.name] = pair
	return pair
}

var (
	canonicalPairOnce sync.Once
	canonicalPairMu   sync.Mutex
	canonicalPairs    map[string]*canonicalPair
)

// formatWithLibraryCheap formats a container for a test that will MUTATE it.
//
// It is deliberately separate from buildCanonicalPair: that one is memoized and
// its bytes are compared against cryptsetup's, so handing it to a test that
// adds a keyslot would corrupt every later comparison. Nothing formatted here
// is byte-compared, so the keyslot cost is pinned at the floor.
func formatWithLibraryCheap(t *testing.T, path string) {
	t.Helper()

	pinCryptoRand(t, 0x9c)
	pinUUID(t, conformanceUUID)

	if err := Format(FormatOptions{
		Device:          path,
		Passphrase:      []byte(canonicalPassphrase),
		Cipher:          "aes",
		CipherMode:      "xts-plain64",
		KeySize:         512,
		HashAlgo:        "sha512",
		SectorSize:      512,
		KDFType:         KDFTypePBKDF2,
		PBKDFIterations: canonicalCheapIterations,
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
}

// assertKDFCostsMatch fails unless the two keyslot KDFs cost the same. Every
// member is compared except the salt, which is two independent random draws.
func assertKDFCostsMatch(t *testing.T, ours, theirs *KDF) {
	t.Helper()

	if ours.Type != theirs.Type || ours.Hash != theirs.Hash {
		t.Fatalf("KDF type/hash differ: ours %s/%s, cryptsetup %s/%s", ours.Type, ours.Hash, theirs.Type, theirs.Hash)
	}
	for _, cost := range []struct {
		name         string
		ours, theirs *int
	}{
		{"iterations", ours.Iterations, theirs.Iterations},
		{"time", ours.Time, theirs.Time},
		{"memory", ours.Memory, theirs.Memory},
		{"cpus", ours.CPUs, theirs.CPUs},
	} {
		switch {
		case cost.ours == nil && cost.theirs == nil:
		case cost.ours == nil || cost.theirs == nil:
			t.Fatalf("%s is present on one side only: ours %v, cryptsetup %v", cost.name, cost.ours, cost.theirs)
		case *cost.ours != *cost.theirs:
			t.Fatalf("%s differs: ours %d, cryptsetup %d -- the mirroring did not take", cost.name, *cost.ours, *cost.theirs)
		}
	}
}

// readJSONArea returns the JSON of a header copy, without its NUL terminator or
// the zero padding that follows.
func readJSONArea(t *testing.T, path string) []byte {
	t.Helper()

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, LUKS2DefaultSize)
	if _, err := f.ReadAt(buf, LUKS2HeaderSize); err != nil {
		t.Fatalf("failed to read the JSON area of %s: %v", path, err)
	}
	end := bytes.IndexByte(buf, 0)
	if end < 0 {
		t.Fatalf("the JSON area of %s has no NUL terminator", path)
	}
	return buf[:end]
}

func readBinaryHeader(t *testing.T, path string) []byte {
	t.Helper()

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, LUKS2HeaderSize)
	if _, err := f.ReadAt(buf, 0); err != nil {
		t.Fatalf("failed to read the binary header of %s: %v", path, err)
	}
	return buf
}

// readSecondaryBinaryHeader returns the 4096-byte binary header of the second
// header copy.
//
// It is located from the hdr_size the PRIMARY records rather than from a
// constant, because that is how every reader finds it, and it is then checked
// to BE a secondary header: the secondary magic, and a hdr_offset naming the
// offset it was read from. Without that check a wrong offset would read two
// runs of zeroes -- or two copies of keyslot area -- and compare them equal.
func readSecondaryBinaryHeader(t *testing.T, path string) []byte {
	t.Helper()

	primary := readBinaryHeader(t, path)
	offset := binary.BigEndian.Uint64(primary[hdrSizeStart:hdrSizeEnd])
	if offset < LUKS2HeaderSize || offset > canonicalImageSize-LUKS2HeaderSize {
		t.Fatalf("the primary header of %s records hdr_size %d, which cannot locate a secondary header", path, offset)
	}

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, LUKS2HeaderSize)
	if _, err := f.ReadAt(buf, int64(offset)); err != nil {
		t.Fatalf("failed to read the secondary binary header of %s at %d: %v", path, offset, err)
	}
	if got := string(buf[:LUKS2MagicLen]); got != LUKS2SecondaryMagic {
		t.Fatalf("the header at %d in %s has magic %q, not the secondary magic %q", offset, path, got, LUKS2SecondaryMagic)
	}
	if got := binary.BigEndian.Uint64(buf[hdrOffsetStart:hdrOffsetEnd]); got != offset {
		t.Fatalf("the secondary header of %s was read at %d but records hdr_offset %d", path, offset, got)
	}
	return buf
}

// TestCanonicalJSONReencodesCryptsetupsHeaderByteForByte is the encoder claim in
// its purest form, and the one that depends on nothing random.
//
// cryptsetup's own JSON goes in, this package's decoder and encoder run over it,
// and the bytes that come out must be identical. Nothing is excluded and
// nothing is normalized: every salt, digest and count in the comparison is
// cryptsetup's own, so a single difference is a difference in HOW this package
// encodes, not in what it chose to encode.
//
// This is what makes the exclusions in the format-to-format tests below
// defensible. Those must exclude the values two independent RNGs cannot agree
// on; this one has no such values and therefore no such excuse.
//
// # THE CAP ON THIS CLAIM
//
// Byte-identity holds for UP TO TEN entries in any of keyslots, tokens,
// segments or digests, and the fixtures here have one. Go's encoding/json sorts
// object keys as strings while json-c preserves insertion order, so at eleven
// keyslots cryptsetup writes 0,1,...,9,10 and this package writes
// 0,1,10,2,...,9 -- measured, not projected. A second difference in the same
// class: encoding/json escapes U+2028 and U+2029 even with SetEscapeHTML off,
// which json-c does not, and which no field written today can carry. Both are
// spec-conformant on either side, since JSON objects are unordered and both
// escapings parse to the same string. See marshalCanonicalJSON.
func TestCanonicalJSONReencodesCryptsetupsHeaderByteForByte(t *testing.T) {
	requireCryptsetupDeclared(t)

	for _, kdf := range canonicalKDFs() {
		t.Run(kdf.name, func(t *testing.T) {
			// cryptsetup's half of the shared pair. It is the same container
			// the format comparison uses, and a calibrated one.
			original := buildCanonicalPair(t, kdf).theirsJSON

			var metadata LUKS2Metadata
			if err := json.Unmarshal(original, &metadata); err != nil {
				t.Fatalf("this package cannot parse cryptsetup's own metadata: %v\n%s", err, original)
			}

			reencoded, err := marshalCanonicalJSON(&metadata)
			if err != nil {
				t.Fatalf("marshalCanonicalJSON failed: %v", err)
			}

			if !bytes.Equal(original, reencoded) {
				t.Fatalf("this package does not re-encode cryptsetup's %s metadata byte for byte\n"+
					"cryptsetup (%d bytes):\n%s\n\nthis package (%d bytes):\n%s",
					kdf.name, len(original), original, len(reencoded), reencoded)
			}
		})
	}
}

// TestFormattedJSONMatchesCryptsetupByteForByte compares two containers
// FORMATTED INDEPENDENTLY, which is the claim an operator cares about.
//
// ONE class of value is substituted, and it is not a divergence this package
// chose: the salts and the digest value. Two separate processes' CSPRNG draws,
// and the digest is a one-way function of a master key that is itself an
// independent draw. Making them agree would mean the two containers shared key
// material.
//
// The DIGEST iteration count is NOT substituted, and no longer compared as two
// calibrations either. It used to be: both sides calibrated it independently
// and a 0.5x-2x band guarded the substitution. That band compared two
// wall-clock measurements taken moments apart on a loaded CI host, so it
// measured the scheduler rather than this code, and failed a correct tree at
// 0.48x (#209). buildCanonicalPair now reads cryptsetup's calibrated count out
// of its header and pins this package's digest to it -- cryptsetup itself
// still calibrates freely; see canonicalKDF for why --pbkdf-force-iterations
// is not the way to make the counts agree -- so the count is compared byte for
// byte like everything else.
//
// What the band was really guarding -- that this package's calibration TARGET
// has not drifted from cryptsetup's -- is a property of two constants, and is
// asserted on those constants, deterministically, by
// assertDigestCalibrationTargetIsCryptsetups. That the real calibration meets
// its target on this machine is TestDigestCalibrationTargetsItsBudget's job.
//
// A keyslot's `priority` used to be substituted here as well and is not any
// more: neither side writes the member now, which is asserted rather than
// worked around.
//
// Everything else -- every offset, size, cipher string, hash name, stripe
// count, sector size, keyslot cost, object key and cross-reference, and the
// ORDER they are written in -- is compared byte for byte.
//
// # WHAT THIS DOES NOT CLAIM
//
// Byte-identity holds for UP TO TEN entries in any of keyslots, tokens,
// segments or digests. Go's encoding/json sorts object keys as strings while
// json-c preserves insertion order, so at eleven keyslots cryptsetup writes
// 0,1,...,9,10 and this package writes 0,1,10,2,...,9. Both are conformant --
// JSON objects are unordered -- and both parse identically; only a byte
// comparison sees it. The fixtures here have one keyslot, so the cap is stated
// rather than exercised. See marshalCanonicalJSON for this and for the
// U+2028/U+2029 escaping difference in the same class.
func TestFormattedJSONMatchesCryptsetupByteForByte(t *testing.T) {
	requireCryptsetupDeclared(t)

	for _, kdf := range canonicalKDFs() {
		t.Run(kdf.name, func(t *testing.T) { formattedJSONMatchesCryptsetup(t, kdf) })
	}
}

func formattedJSONMatchesCryptsetup(t *testing.T, kdf canonicalKDF) {
	t.Helper()

	pair := buildCanonicalPair(t, kdf)

	var ourMetadata LUKS2Metadata
	if err := json.Unmarshal(pair.oursJSON, &ourMetadata); err != nil {
		t.Fatalf("failed to parse this package's own metadata: %v", err)
	}
	var theirMetadata LUKS2Metadata
	if err := json.Unmarshal(pair.theirsJSON, &theirMetadata); err != nil {
		t.Fatalf("failed to parse cryptsetup's metadata: %v", err)
	}

	ourKeyslot, theirKeyslot := ourMetadata.Keyslots["0"], theirMetadata.Keyslots["0"]
	ourDigest, theirDigest := ourMetadata.Digests["0"], theirMetadata.Digests["0"]
	if ourKeyslot == nil || theirKeyslot == nil || ourDigest == nil || theirDigest == nil {
		t.Fatal("one of the two containers is missing keyslot 0 or digest 0")
	}

	// (1) the independent random material
	ourKeyslot.KDF.Salt = theirKeyslot.KDF.Salt
	ourDigest.Salt = theirDigest.Salt
	ourDigest.Digest = theirDigest.Digest

	// (2) the digest iteration count is NOT substituted: buildCanonicalPair
	// pinned it to cryptsetup's, so it is compared in the bytes below. The
	// guard against a drifted calibration target is a check of the constants
	// that define the target, not a comparison of two timings (#209).
	assertDigestCalibrationTargetIsCryptsetups(t)
	if theirDigest.Iterations < minPBKDF2Iterations {
		t.Fatalf("cryptsetup wrote its digest with %d iterations, below the LUKS2 minimum of %d",
			theirDigest.Iterations, minPBKDF2Iterations)
	}

	// Neither side may write a priority member. Asserted, not substituted: it
	// is now a property of what this package writes.
	if ourKeyslot.Priority != nil {
		t.Errorf("this package wrote priority %d on a normal keyslot; cryptsetup writes no member", *ourKeyslot.Priority)
	}
	if theirKeyslot.Priority != nil {
		t.Errorf("cryptsetup wrote priority %d, so the expectation above is wrong for this version", *theirKeyslot.Priority)
	}

	got, err := marshalCanonicalJSON(&ourMetadata)
	if err != nil {
		t.Fatalf("marshalCanonicalJSON failed: %v", err)
	}

	// Length first, and separately: an equal length with unequal bytes is an
	// ordering difference, while an unequal length is a field one side writes
	// and the other does not. The two need different investigations and the
	// message should say which happened.
	if len(pair.theirsJSON) != len(got) {
		t.Errorf("the metadata is %d bytes and cryptsetup's is %d; a field differs, not merely its encoding",
			len(got), len(pair.theirsJSON))
	}
	if !bytes.Equal(pair.theirsJSON, got) {
		t.Fatalf("the formatted metadata is not byte-identical to cryptsetup's outside the substituted classes\n"+
			"cryptsetup (%d bytes):\n%s\n\nthis package (%d bytes):\n%s",
			len(pair.theirsJSON), pair.theirsJSON, len(got), got)
	}
}

// cryptsetupDigestTargetMs and cryptsetupDigestKeyLen are cryptsetup 2.7.0's
// digest calibration: it benchmarks a 64-byte PBKDF2 derivation to 100ms.
// Measured, not taken from its documentation -- see DigestIterationTargetMs and
// DigestCalibrationKeyLen (security.go) for the 14-container measurement.
const (
	cryptsetupDigestTargetMs = 100
	cryptsetupDigestKeyLen   = 64
)

// assertDigestCalibrationTargetIsCryptsetups is the drift guard for the digest
// cost, stated on the CONSTANTS that define the calibration rather than on two
// calibrations' results.
//
// The failure it exists to catch is the one the old 0.5x-2x band caught when
// the host was quiet: a target changed by a factor of ten, a derivation length
// that doubles the sha256 cost, a floor that silently binds. Each of those is a
// change to a constant, so comparing the constants catches it every time and
// cannot be failed by a busy scheduler (#209).
func assertDigestCalibrationTargetIsCryptsetups(t *testing.T) {
	t.Helper()

	if DigestIterationTargetMs != cryptsetupDigestTargetMs {
		t.Errorf("DigestIterationTargetMs is %d; cryptsetup calibrates its digest to %dms, "+
			"so this package's digest cost has drifted from cryptsetup's",
			DigestIterationTargetMs, cryptsetupDigestTargetMs)
	}
	if DigestCalibrationKeyLen != cryptsetupDigestKeyLen {
		t.Errorf("DigestCalibrationKeyLen is %d; cryptsetup benchmarks a %d-byte derivation whatever the hash, "+
			"so the sha256 digest cost has drifted from cryptsetup's",
			DigestCalibrationKeyLen, cryptsetupDigestKeyLen)
	}
	if minPBKDF2Iterations != 1000 {
		t.Errorf("minPBKDF2Iterations is %d; the LUKS2 floor cryptsetup enforces is 1000", minPBKDF2Iterations)
	}
}

// TestFormattedBinaryHeaderMatchesCryptsetup compares the 4096-byte binary
// header of two independently formatted containers.
//
// Three ranges are excluded, and all three for reasons that are properties of
// the format rather than of this implementation:
//
//   - THE CHECKSUM (448..512) is derived. It is sha256 over the header and the
//     whole JSON area, both of which contain the salts and digest that cannot
//     agree, so it cannot agree either. Comparing it would restate the
//     exclusions below rather than add anything.
//
//   - THE HEADER SALT (104..168) is 64 bytes of CSPRNG output that feeds the
//     checksum. The spec fixes no value for it and two independent formats draw
//     independently.
//
//   - THE SEQUENCE ID (16..24, bytes 0x10..0x17) is a MONOTONIC COUNTER, not a
//     format constant. The spec says it is increased on update, so its value
//     records a container's write history and nothing else. cryptsetup writes 3
//     after luksFormat -- its format is internally three header writes -- and
//     this package writes 1. Two volumes with different write histories
//     legitimately hold different values here, so faking a 3 would be
//     fabricating a history rather than conforming to anything. What the field
//     must actually do is asserted in
//     TestSequenceIDRecordsTheContainersWriteHistory.
//
// Everything else is compared: both magics, the version, the header size, the
// label and subsystem fields, the checksum algorithm name, the UUID (pinned to
// the same value on both sides), the recorded header offset, and all 3768 bytes
// of reserved space and padding.
func TestFormattedBinaryHeaderMatchesCryptsetup(t *testing.T) {
	requireCryptsetupDeclared(t)

	// Run for both KDF shapes even though the binary header holds no KDF
	// parameters. That independence is the claim; asserting it costs one extra
	// format and turns an assumption into a measurement.
	for _, kdf := range canonicalKDFs() {
		t.Run(kdf.name, func(t *testing.T) { formattedBinaryHeaderMatchesCryptsetup(t, kdf) })
	}
}

func formattedBinaryHeaderMatchesCryptsetup(t *testing.T, kdf canonicalKDF) {
	t.Helper()

	pair := buildCanonicalPair(t, kdf)
	assertBinaryHeaderMatches(t, "primary", pair.oursHeader, pair.theirsHeader)
}

// comparedBinaryHeaderBytes is how many of the 4096 binary-header bytes the
// comparison covers: everything but sequence_id, the header salt and the
// checksum.
const comparedBinaryHeaderBytes = LUKS2HeaderSize -
	(hdrSequenceIDEnd - hdrSequenceIDStart) -
	(hdrSaltEnd - hdrSaltStart) -
	(hdrChecksumEnd - hdrChecksumStart)

// excludedFromBinaryHeaderComparison reports whether offset i is one of the
// three ranges TestFormattedBinaryHeaderMatchesCryptsetup documents as
// legitimately different between two independently formatted containers.
func excludedFromBinaryHeaderComparison(i int) bool {
	switch {
	case i >= hdrSequenceIDStart && i < hdrSequenceIDEnd:
		return true
	case i >= hdrSaltStart && i < hdrSaltEnd:
		return true
	case i >= hdrChecksumStart && i < hdrChecksumEnd:
		return true
	default:
		return false
	}
}

// differingBinaryHeaderBytes returns every compared offset at which got and
// want disagree.
func differingBinaryHeaderBytes(got, want []byte) []int {
	var differing []int
	for i := range want {
		if !excludedFromBinaryHeaderComparison(i) && got[i] != want[i] {
			differing = append(differing, i)
		}
	}
	return differing
}

// assertBinaryHeaderMatches is the comparison both header copies are held to:
// byte-equality outside the three excluded ranges, and excluded ranges that
// are excluded because they hold values that cannot agree -- never because
// they are empty.
func assertBinaryHeaderMatches(t *testing.T, copyName string, got, want []byte) {
	t.Helper()

	if len(got) != LUKS2HeaderSize || len(want) != LUKS2HeaderSize {
		t.Fatalf("the %s binary headers are %d and %d bytes; both must be %d",
			copyName, len(got), len(want), LUKS2HeaderSize)
	}

	if differing := differingBinaryHeaderBytes(got, want); len(differing) > 0 {
		limit := len(differing)
		if limit > 32 {
			limit = 32
		}
		t.Fatalf("%d of the %d compared %s binary-header bytes differ from cryptsetup's; first offsets %v\n"+
			"ours[%d]=%#x theirs[%d]=%#x",
			len(differing), comparedBinaryHeaderBytes, copyName,
			differing[:limit], differing[0], got[differing[0]], differing[0], want[differing[0]])
	}

	// The excluded ranges must not be excluded because they are EMPTY.
	for _, name := range allZeroExcludedRanges(got) {
		t.Errorf("this package wrote an all-zero %s %s", copyName, name)
	}
}

// allZeroExcludedRanges names every range excluded from the binary-header
// comparison that holds only zeroes. A sequence_id, salt or checksum of zeroes
// would pass the comparison by vacuity and would mean something is badly
// wrong: sequence_id starts at 1 on format, the salt is random and the
// checksum is a hash.
func allZeroExcludedRanges(hdr []byte) []string {
	var zero []string
	for _, r := range []struct {
		name       string
		start, end int
	}{
		{"sequence_id", hdrSequenceIDStart, hdrSequenceIDEnd},
		{"header salt", hdrSaltStart, hdrSaltEnd},
		{"header checksum", hdrChecksumStart, hdrChecksumEnd},
	} {
		if bytes.Equal(hdr[r.start:r.end], make([]byte, r.end-r.start)) {
			zero = append(zero, r.name)
		}
	}
	return zero
}

// TestSecondaryHeaderMatchesCryptsetup holds the SECOND header copy to the
// same byte comparison as the primary (#167).
//
// The secondary is not a restatement of the primary. Its magic is different
// ("SKUL\xba\xbe"), its hdr_offset names its own position, and its salt and
// checksum are its own -- so a primary that matches cryptsetup says nothing
// about whether the copy a reader falls back to does. The exclusions are the
// primary's, for the primary's reasons: sequence_id records write history,
// and the salt and checksum are random and derived respectively.
func TestSecondaryHeaderMatchesCryptsetup(t *testing.T) {
	requireCryptsetupDeclared(t)

	for _, kdf := range canonicalKDFs() {
		t.Run(kdf.name, func(t *testing.T) {
			pair := buildCanonicalPair(t, kdf)
			assertBinaryHeaderMatches(t, "secondary", pair.oursSecondary, pair.theirsSecondary)
		})
	}

	// The comparison must be able to FAIL. A test that reads the wrong
	// region, or excludes more than it says, passes against any container;
	// corrupting one byte of cryptsetup's own secondary header and requiring
	// the diff to name that byte and only that byte rules both out.
	t.Run("detects-one-corrupted-byte", func(t *testing.T) {
		pair := buildCanonicalPair(t, canonicalKDFs()[0])
		for _, offset := range []int{
			0,                    // the secondary magic
			hdrSizeStart + 7,     // hdr_size
			hdrOffsetStart + 6,   // hdr_offset, the field only the secondary sets non-zero
			hdrSaltEnd,           // first UUID byte, just past an excluded range
			hdrChecksumStart - 1, // last reserved byte before the checksum
			LUKS2HeaderSize - 1,  // the final padding byte
		} {
			corrupted := bytes.Clone(pair.theirsSecondary)
			corrupted[offset] ^= 0xff
			differing := differingBinaryHeaderBytes(corrupted, pair.theirsSecondary)
			if len(differing) != 1 || differing[0] != offset {
				t.Errorf("corrupting secondary-header byte %d was reported as differing offsets %v", offset, differing)
			}
		}
	})

	// The non-zero guard on the excluded ranges must be able to fail too:
	// zeroing any one of them in an otherwise valid secondary header must be
	// reported, and by that range's name alone.
	t.Run("rejects-zeroed-excluded-range", func(t *testing.T) {
		pair := buildCanonicalPair(t, canonicalKDFs()[0])
		if zero := allZeroExcludedRanges(pair.oursSecondary); len(zero) != 0 {
			t.Fatalf("the unmodified secondary header already has all-zero excluded ranges %v", zero)
		}
		for _, r := range []struct {
			name       string
			start, end int
		}{
			{"sequence_id", hdrSequenceIDStart, hdrSequenceIDEnd},
			{"header salt", hdrSaltStart, hdrSaltEnd},
			{"header checksum", hdrChecksumStart, hdrChecksumEnd},
		} {
			zeroed := bytes.Clone(pair.oursSecondary)
			clear(zeroed[r.start:r.end])
			if got := allZeroExcludedRanges(zeroed); len(got) != 1 || got[0] != r.name {
				t.Errorf("zeroing the secondary %s was reported as all-zero ranges %v", r.name, got)
			}
		}
	})
}

// TestSequenceIDRecordsTheContainersWriteHistory is the semantic assertion the
// byte comparison above deliberately does not make.
//
// The LUKS2 specification describes sequence_id as increased on update, and the
// higher of the two copies is the current header. That is a statement about
// BEHAVIOR, and it is the only thing about the field a conformance test can
// legitimately require -- the absolute value after a format is an artifact of
// how many times that implementation happened to write the header.
func TestSequenceIDRecordsTheContainersWriteHistory(t *testing.T) {
	requireCryptsetupDeclared(t)

	path := canonicalImage(t, "seqid.img")
	formatWithLibraryCheap(t, path)

	primary, _, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	secondary, _, err := ReadSecondaryHeader(path)
	if err != nil {
		t.Fatalf("ReadSecondaryHeader failed: %v", err)
	}

	// Both copies are written by one operation and describe one state, so they
	// carry one sequence id. A reader that picks the higher copy would
	// otherwise be choosing between two descriptions of the same container.
	if primary.SequenceID != secondary.SequenceID {
		t.Fatalf("the two header copies carry sequence ids %d and %d after a single format",
			primary.SequenceID, secondary.SequenceID)
	}
	if primary.SequenceID == 0 {
		t.Fatal("sequence_id is 0 after format; the counter never started")
	}

	// A mutation must advance it. This is the property cryptsetup's higher-copy
	// rule depends on: without it, a torn write leaves two copies a reader
	// cannot order.
	before := primary.SequenceID
	if _, err := AddKey(path, []byte(canonicalPassphrase), []byte("a-second-credential"), &AddKeyOptions{
		KDFType:       KDFTypePBKDF2,
		Hash:          "sha512",
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}

	after, _, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader after AddKey failed: %v", err)
	}
	if after.SequenceID <= before {
		t.Fatalf("sequence_id is %d after a keyslot was added, was %d; it must increase on update",
			after.SequenceID, before)
	}

	// And cryptsetup must still read the result, which is what makes the
	// counter's value a conformance question rather than an internal one.
	out, err := exec.Command("cryptsetup", "luksDump", path).CombinedOutput() // #nosec G204 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("cryptsetup luksDump failed after the sequence id advanced: %v\n%s", err, out)
	}
}
