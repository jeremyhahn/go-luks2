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

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// Byte-for-byte conformance against cryptsetup 2.7.0; integration tier, so a missing cryptsetup fails.

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

	// canonicalArgon2MemoryKB caps Argon2 memory on both sides at this package's 64 MiB minimum; cryptsetup still calibrates time.
	canonicalArgon2MemoryKB = 65536

	// canonicalCheapIterations is the cheapest keyslot cost, for containers that are mutated and never byte-compared.
	canonicalCheapIterations = 210_000
)

// canonicalKDF is one keyslot KDF shape for both implementations; cryptsetup calibrates freely and this package mirrors its costs.
type canonicalKDF struct {
	name string

	// cryptsetupArgs are appended to luksFormat. They select the header.KDF and cap
	// the Argon2 memory; nothing here pins a calibrated cost.
	cryptsetupArgs []string

	// mirror copies the costs cryptsetup chose into this package's options.
	mirror func(t *testing.T, opts *formatOptionsForTest, theirs *header.KDF)
}

func canonicalKDFs() []canonicalKDF {
	return []canonicalKDF{
		{
			name:           "pbkdf2",
			cryptsetupArgs: []string{"--pbkdf", "pbkdf2", "--hash", "sha512"},
			mirror: func(t *testing.T, opts *formatOptionsForTest, theirs *header.KDF) {
				t.Helper()
				if theirs.Iterations == nil {
					t.Fatalf("cryptsetup's pbkdf2 keyslot has no iteration count: %+v", theirs)
				}
				opts.KDFType = kdfTypePBKDF2
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
			mirror: func(t *testing.T, opts *formatOptionsForTest, theirs *header.KDF) {
				t.Helper()
				if theirs.Time == nil || theirs.Memory == nil || theirs.CPUs == nil {
					t.Fatalf("cryptsetup's argon2id keyslot is missing a cost member: %+v", theirs)
				}
				opts.KDFType = kdfTypeArgon2id
				opts.Argon2Time = *theirs.Time
				opts.Argon2Memory = *theirs.Memory
				opts.Argon2Parallel = *theirs.CPUs
			},
		},
	}
}

// Binary header field offsets, from the LUKS2 On-Disk Format specification and
// matching header.BinaryHeader. Named here because the comparison below excludes
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
			"the integration stage of build/docker/devcontainer/Dockerfile installs cryptsetup-bin -- so its absence is a broken "+
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

// formatWithCryptsetupCheap formats a container with --pbkdf-force-iterations for a test that does not compare bytes.
func formatWithCryptsetupCheap(t *testing.T, path string) {
	t.Helper()
	formatWithCryptsetupForced(t, path, canonicalCheapIterations)
}

// formatWithCryptsetupForced formats with an exact pbkdf2 iteration count, including one below this package's floor.
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
	// oursSecondary and theirsSecondary are the second copy's 4096-byte binary header.
	oursSecondary, theirsSecondary []byte
	oursKDF, theirsKDF             *header.KDF
	oursKeyslot                    *header.Keyslot
	theirsKeyslot                  *header.Keyslot
	oursDigest, theirsDigest       *header.Digest
}

// buildCanonicalPair formats cryptsetup's container first, mirrors its costs into Format, and memoizes the pair per KDF shape.
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

	_, theirMetadata, err := readHeaderForTest(theirs)
	if err != nil {
		t.Fatalf("this package cannot read cryptsetup's own header: %v", err)
	}
	theirKeyslot := theirMetadata.Keyslots["0"]
	if theirKeyslot == nil || theirKeyslot.KDF == nil {
		t.Fatal("cryptsetup's container has no keyslot 0 with a header.KDF")
	}
	theirDigest := theirMetadata.Digests["0"]
	if theirDigest == nil {
		t.Fatal("cryptsetup's container has no digest 0")
	}

	opts := formatOptionsForTest{
		Device:     canonicalImage(t, "library.img"),
		Passphrase: []byte(canonicalPassphrase),
		Cipher:     "aes",
		CipherMode: "xts-plain64",
		KeySize:    512,
		HashAlgo:   "sha512",
		SectorSize: 512,
	}
	kdf.mirror(t, &opts, theirKeyslot.KDF)

	// The digest cost is mirrored too, through the digestIterationsFor seam.
	sys := defaultVolumeSys()
	sys.digestIterationsFor = pinDigestIterations(theirDigest.Iterations)
	sys.cryptoRand = pinCryptoRand(0x9c)
	sys.newUUID = pinUUID(t, conformanceUUID)
	if err := formatWithSys(opts, sys); err != nil {
		t.Fatalf("Format failed mirroring cryptsetup's %s costs: %v", kdf.name, err)
	}

	_, ourMetadata, err := readHeaderForTest(opts.Device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	ourKeyslot := ourMetadata.Keyslots["0"]
	if ourKeyslot == nil || ourKeyslot.KDF == nil {
		t.Fatal("the formatted container has no keyslot 0 with a header.KDF")
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

// formatWithLibraryCheap formats a container a test will mutate; never byte-compared.
func formatWithLibraryCheap(t *testing.T, path string) {
	t.Helper()

	sys := defaultVolumeSys()
	sys.cryptoRand = pinCryptoRand(0x9c)
	sys.newUUID = pinUUID(t, conformanceUUID)

	if err := formatWithSys(formatOptionsForTest{
		Device:          path,
		Passphrase:      []byte(canonicalPassphrase),
		Cipher:          "aes",
		CipherMode:      "xts-plain64",
		KeySize:         512,
		HashAlgo:        "sha512",
		SectorSize:      512,
		KDFType:         kdfTypePBKDF2,
		PBKDFIterations: canonicalCheapIterations,
	}, sys); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
}

// assertKDFCostsMatch fails unless the two keyslot KDFs cost the same. Every
// member is compared except the salt, which is two independent random draws.
func assertKDFCostsMatch(t *testing.T, ours, theirs *header.KDF) {
	t.Helper()

	if ours.Type != theirs.Type || ours.Hash != theirs.Hash {
		t.Fatalf("header.KDF type/hash differ: ours %s/%s, cryptsetup %s/%s", ours.Type, ours.Hash, theirs.Type, theirs.Hash)
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

	buf := make([]byte, header.DefaultSize)
	if _, err := f.ReadAt(buf, header.HeaderSize); err != nil {
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

	buf := make([]byte, header.HeaderSize)
	if _, err := f.ReadAt(buf, 0); err != nil {
		t.Fatalf("failed to read the binary header of %s: %v", path, err)
	}
	return buf
}

// readSecondaryBinaryHeader returns the second copy's binary header, located from the primary's hdr_size and checked to be a secondary.
func readSecondaryBinaryHeader(t *testing.T, path string) []byte {
	t.Helper()

	primary := readBinaryHeader(t, path)
	offset := binary.BigEndian.Uint64(primary[hdrSizeStart:hdrSizeEnd])
	if offset < header.HeaderSize || offset > canonicalImageSize-header.HeaderSize {
		t.Fatalf("the primary header of %s records hdr_size %d, which cannot locate a secondary header", path, offset)
	}

	f, err := os.Open(path) // #nosec G304 -- path is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, header.HeaderSize)
	if _, err := f.ReadAt(buf, int64(offset)); err != nil {
		t.Fatalf("failed to read the secondary binary header of %s at %d: %v", path, offset, err)
	}
	if got := string(buf[:header.MagicLen]); got != header.SecondaryMagic {
		t.Fatalf("the header at %d in %s has magic %q, not the secondary magic %q", offset, path, got, header.SecondaryMagic)
	}
	if got := binary.BigEndian.Uint64(buf[hdrOffsetStart:hdrOffsetEnd]); got != offset {
		t.Fatalf("the secondary header of %s was read at %d but records hdr_offset %d", path, offset, got)
	}
	return buf
}

// TestCanonicalJSONReencodesCryptsetupsHeaderByteForByte re-encodes cryptsetup's JSON and expects identical bytes (up to ten entries per object).
func TestCanonicalJSONReencodesCryptsetupsHeaderByteForByte(t *testing.T) {
	requireCryptsetupDeclared(t)

	for _, kdf := range canonicalKDFs() {
		t.Run(kdf.name, func(t *testing.T) {
			// cryptsetup's half of the shared pair. It is the same container
			// the format comparison uses, and a calibrated one.
			original := buildCanonicalPair(t, kdf).theirsJSON

			var metadata header.Metadata
			if err := json.Unmarshal(original, &metadata); err != nil {
				t.Fatalf("this package cannot parse cryptsetup's own metadata: %v\n%s", err, original)
			}

			reencoded, err := header.MarshalCanonicalJSON(&metadata)
			if err != nil {
				t.Fatalf("header.MarshalCanonicalJSON failed: %v", err)
			}

			if !bytes.Equal(original, reencoded) {
				t.Fatalf("this package does not re-encode cryptsetup's %s metadata byte for byte\n"+
					"cryptsetup (%d bytes):\n%s\n\nthis package (%d bytes):\n%s",
					kdf.name, len(original), original, len(reencoded), reencoded)
			}
		})
	}
}

// TestFormattedJSONMatchesCryptsetupByteForByte compares independently formatted JSON, substituting only salts and the digest value.
func TestFormattedJSONMatchesCryptsetupByteForByte(t *testing.T) {
	requireCryptsetupDeclared(t)

	for _, kdf := range canonicalKDFs() {
		t.Run(kdf.name, func(t *testing.T) { formattedJSONMatchesCryptsetup(t, kdf) })
	}
}

func formattedJSONMatchesCryptsetup(t *testing.T, kdf canonicalKDF) {
	t.Helper()

	pair := buildCanonicalPair(t, kdf)

	var ourMetadata header.Metadata
	if err := json.Unmarshal(pair.oursJSON, &ourMetadata); err != nil {
		t.Fatalf("failed to parse this package's own metadata: %v", err)
	}
	var theirMetadata header.Metadata
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

	// The digest iteration count is compared: buildCanonicalPair pinned it to cryptsetup's.
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

	got, err := header.MarshalCanonicalJSON(&ourMetadata)
	if err != nil {
		t.Fatalf("header.MarshalCanonicalJSON failed: %v", err)
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
// Measured, not taken from its documentation -- see digestIterationTargetMs and
// digestCalibrationKeyLen (security.go) for the 14-container measurement.
const (
	cryptsetupDigestTargetMs = 100
	cryptsetupDigestKeyLen   = 64
)

// assertDigestCalibrationTargetIsCryptsetups checks the digest calibration constants match cryptsetup's.
func assertDigestCalibrationTargetIsCryptsetups(t *testing.T) {
	t.Helper()

	if digestIterationTargetMs != cryptsetupDigestTargetMs {
		t.Errorf("digestIterationTargetMs is %d; cryptsetup calibrates its digest to %dms, "+
			"so this package's digest cost has drifted from cryptsetup's",
			digestIterationTargetMs, cryptsetupDigestTargetMs)
	}
	if digestCalibrationKeyLen != cryptsetupDigestKeyLen {
		t.Errorf("digestCalibrationKeyLen is %d; cryptsetup benchmarks a %d-byte derivation whatever the hash, "+
			"so the sha256 digest cost has drifted from cryptsetup's",
			digestCalibrationKeyLen, cryptsetupDigestKeyLen)
	}
	if minPBKDF2Iterations != 1000 {
		t.Errorf("minPBKDF2Iterations is %d; the LUKS2 floor cryptsetup enforces is 1000", minPBKDF2Iterations)
	}
}

// TestFormattedBinaryHeaderMatchesCryptsetup compares the binary headers, excluding the checksum, salt and sequence id.
func TestFormattedBinaryHeaderMatchesCryptsetup(t *testing.T) {
	requireCryptsetupDeclared(t)

	// Run for both header.KDF shapes even though the binary header holds no header.KDF
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
const comparedBinaryHeaderBytes = header.HeaderSize -
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

	if len(got) != header.HeaderSize || len(want) != header.HeaderSize {
		t.Fatalf("the %s binary headers are %d and %d bytes; both must be %d",
			copyName, len(got), len(want), header.HeaderSize)
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

	// The excluded ranges must not be empty.
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

// TestSecondaryHeaderMatchesCryptsetup holds the second copy to the primary's comparison and exclusions.
func TestSecondaryHeaderMatchesCryptsetup(t *testing.T) {
	requireCryptsetupDeclared(t)

	for _, kdf := range canonicalKDFs() {
		t.Run(kdf.name, func(t *testing.T) {
			pair := buildCanonicalPair(t, kdf)
			assertBinaryHeaderMatches(t, "secondary", pair.oursSecondary, pair.theirsSecondary)
		})
	}

	// The comparison must be able to fail: one corrupted byte of cryptsetup's secondary header is named, and only that byte.
	t.Run("detects-one-corrupted-byte", func(t *testing.T) {
		pair := buildCanonicalPair(t, canonicalKDFs()[0])
		for _, offset := range []int{
			0,                     // the secondary magic
			hdrSizeStart + 7,      // hdr_size
			hdrOffsetStart + 6,    // hdr_offset, the field only the secondary sets non-zero
			hdrSaltEnd,            // first UUID byte, just past an excluded range
			hdrChecksumStart - 1,  // last reserved byte before the checksum
			header.HeaderSize - 1, // the final padding byte
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

// TestSequenceIDRecordsTheContainersWriteHistory checks sequence_id increases on update.
func TestSequenceIDRecordsTheContainersWriteHistory(t *testing.T) {
	requireCryptsetupDeclared(t)

	path := canonicalImage(t, "seqid.img")
	formatWithLibraryCheap(t, path)

	primary, _, err := readHeaderForTest(path)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	secondary, _, err := readSecondaryHeaderForTest(path)
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
	if _, err := addKeyForTest(path, []byte(canonicalPassphrase), []byte("a-second-credential"), &addKeyOptionsForTest{
		KDFType:       kdfTypePBKDF2,
		Hash:          "sha512",
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}

	after, _, err := readHeaderForTest(path)
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
