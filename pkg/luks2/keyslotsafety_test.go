// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"context"
	"crypto/fips140"
	"crypto/rand"
	"errors"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/af"
	"github.com/jeremyhahn/go-luks2/internal/areacipher"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// Regression tests for #249 (Lane A, keyslot safety). Where a finding is about
// interoperability, the fixture is written by cryptsetup itself, so what is
// proved is agreement with a third party and not with this package's own
// writer.

const (
	// unboundPassphrase opens the `cryptsetup luksAddKey --unbound` keyslot.
	unboundPassphrase = "unbound-key-passphrase"

	// handPassphrase opens a keyslot this file writes by hand.
	handPassphrase = "hand-written-keyslot-passphrase"

	// rotatedPassphrase is what ChangeKey and AddKey enroll in these tests.
	rotatedPassphrase = "rotated-keyslot-passphrase"
)

// cheapCryptsetupArgs format or enroll at cryptsetup's own PBKDF2 minimum, so a
// fixture costs nothing to open. header.Keyslot cost is not what these tests are about.
// sha512 because ChangeKey raises a preserved count to the floor for its hash,
// and sha512's is a sixth of sha256's in work.
var cheapCryptsetupArgs = []string{"--pbkdf", "pbkdf2", "--hash", "sha512", "--pbkdf-force-iterations", "1000", "--batch-mode"}

// cryptsetupFormat formats a fresh image with cryptsetup luksFormat, the
// passphrase on stdin, and returns its path.
func cryptsetupFormat(t *testing.T, name, passphrase string, extra ...string) string {
	t.Helper()

	requireCryptsetup(t)
	image := newImage(t, name)
	args := append(append([]string{"luksFormat", "--type", "luks2"}, cheapCryptsetupArgs...), extra...)
	if code, out := runCryptsetup(t, passphrase, append(args, image)...); code != 0 {
		t.Fatalf("cryptsetup luksFormat exited %d\n%s", code, out)
	}
	return image
}

// cryptsetupOpensSlot reports whether cryptsetup verifies passphrase against
// the image, optionally against one keyslot only.
func cryptsetupOpensSlot(t *testing.T, image, passphrase string, slot int) bool {
	t.Helper()

	args := []string{"luksOpen", "--test-passphrase", "--batch-mode"}
	if slot >= 0 {
		args = append(args, "--key-slot", strconv.Itoa(slot))
	}
	code, _ := runCryptsetup(t, passphrase, append(args, image)...)
	return code == 0
}

// unboundFixture is a cryptsetup volume whose keyslot 0 holds the volume key
// under conformancePassphrase and whose keyslot 1 holds an UNBOUND key under
// unboundPassphrase -- the header `cryptsetup luksAddKey --unbound` writes.
func unboundFixture(t *testing.T) string {
	t.Helper()

	image := cryptsetupFormat(t, "unbound.img", conformancePassphrase)
	args := append([]string{"luksAddKey", "--unbound", "--key-size", "512"}, cheapCryptsetupArgs...)
	if code, out := runCryptsetup(t, unboundPassphrase, append(args, image)...); code != 0 {
		t.Fatalf("cryptsetup luksAddKey --unbound exited %d\n%s", code, out)
	}

	_, metadata, err := readHeaderForTest(image)
	if err != nil {
		t.Fatalf("ReadHeader on cryptsetup's volume failed: %v", err)
	}
	if !keyslotBoundToDataSegments(metadata, "0") || keyslotBoundToDataSegments(metadata, "1") {
		t.Fatal("the fixture is not a bound keyslot 0 beside an unbound keyslot 1")
	}
	return image
}

// verifyRecoveryKeyForTest reports whether key unlocks device, the way the
// pre-redesign library's VerifyRecoveryKey did before B.6 deleted it in
// favor of (*Volume).Unlock: a failure to verify (ErrWrongKey) is (false,
// nil) rather than an error, so a caller that cares can tell "not this key"
// from "this volume cannot answer the question".
func verifyRecoveryKeyForTest(device string, key *enclave.MemoryEnclave) (bool, error) {
	ctx := context.Background()
	v, err := Open(ctx, device, withTestSys(testVolumeSys()), WithReadOnly())
	if err != nil {
		return false, err
	}
	defer func() { _ = v.Close() }()

	unlocked, err := v.Unlock(ctx, key)
	if err != nil {
		if errors.Is(err, ErrWrongKey) {
			return false, nil
		}
		return false, err
	}
	unlocked.Destroy()
	return true, nil
}

// TestTheRemovalGuardDoesNotCountAnUnboundKeyslot is A1: a keyslot that opens
// only an unbound key is not a survivor, so no removal path may destroy the
// one keyslot holding the volume key beside it.
func TestTheRemovalGuardDoesNotCountAnUnboundKeyslot(t *testing.T) {
	defer parallel(t)()

	golden := goldenBytes(t, unboundFixture(t))
	passphrase := []byte(conformancePassphrase)

	for _, path := range keyslotRemovalPaths {
		t.Run(path.name, func(t *testing.T) {
			device := restoreVolume(t, "unbound-removal.img", golden)
			offset, size := keyslotAreaExtent(t, device, "0")
			before := readAreaBytes(t, device, offset, size)

			err := path.remove(device, passphrase, 0)
			if !errors.Is(err, ErrLastKeyslot) {
				t.Fatalf("removing the only bound keyslot beside an unbound one returned %v, want ErrLastKeyslot", err)
			}
			if !bytes.Equal(before, readAreaBytes(t, device, offset, size)) {
				t.Fatal("the removal was refused AND the volume key's material was destroyed")
			}
			if !cryptsetupOpensSlot(t, device, conformancePassphrase, 0) {
				t.Fatal("cryptsetup no longer opens the volume after the refused removal")
			}
		})
	}

	// The control: a second BOUND keyslot is a survivor, so the same removal
	// is permitted. Without it a guard refusing everything passes the above.
	t.Run("a bound survivor permits it", func(t *testing.T) {
		device := restoreVolume(t, "bound-survivor.img", golden)
		args := append([]string{"luksAddKey"}, cheapCryptsetupArgs...)
		addKey := append(args, device)
		// luksAddKey reads the existing passphrase, then the new one, from stdin.
		if code, out := runCryptsetup(t, conformancePassphrase+"\n"+rotatedPassphrase+"\n", addKey...); code != 0 {
			t.Fatalf("cryptsetup luksAddKey exited %d\n%s", code, out)
		}
		if err := killKeyslotForTest(device, 0); err != nil {
			t.Fatalf("KillKeyslot refused a removal that leaves a bound keyslot: %v", err)
		}
		if !cryptsetupOpensSlot(t, device, rotatedPassphrase, -1) {
			t.Fatal("cryptsetup cannot open the volume through the surviving bound keyslot")
		}
	})
}

// TestAnUnboundCredentialProvesNothingAboutTheVolume is A1's other half: a
// passphrase that opens only an unbound keyslot must not test as opening the
// volume, nor authorize adding or killing a keyslot -- which is what
// cryptsetup holds too.
func TestAnUnboundCredentialProvesNothingAboutTheVolume(t *testing.T) {
	defer parallel(t)()

	device := unboundFixture(t)
	unbound := []byte(unboundPassphrase)
	before := fileDigest(t, device)

	if cryptsetupOpensSlot(t, device, unboundPassphrase, -1) {
		t.Fatal("the fixture is wrong: cryptsetup opens the volume with the unbound passphrase")
	}
	if err := testKeyForTest(device, unbound); !errors.Is(err, ErrWrongKey) {
		t.Errorf("TestKey with the unbound passphrase returned %v, want ErrWrongKey", err)
	}
	if slot, err := addKeyForTest(device, unbound, []byte(rotatedPassphrase), nil); !errors.Is(err, ErrWrongKey) || slot != -1 {
		t.Errorf("AddKey authenticated by the unbound passphrase returned slot %d, %v; want -1, ErrWrongKey", slot, err)
	}
	if err := killSlotForTest(device, unbound, 1); !errors.Is(err, ErrWrongKey) {
		t.Errorf("KillSlot authenticated by the unbound passphrase returned %v, want ErrWrongKey", err)
	}
	ok, err := verifyRecoveryKeyForTest(device, secretOf(t, unbound))
	if ok || err != nil {
		t.Errorf("VerifyRecoveryKey with the unbound passphrase returned %v, %v; want false, nil", ok, err)
	}
	if fileDigest(t, device) != before {
		t.Fatal("an operation refused for an unbound credential changed the device")
	}

	// The volume's own credential still does all of it.
	if err := testKeyForTest(device, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("TestKey with the volume's passphrase failed: %v", err)
	}
	slot, err := addKeyForTest(device, []byte(conformancePassphrase), []byte(rotatedPassphrase), fastAddKeyOptions())
	if err != nil {
		t.Fatalf("AddKey with the volume's passphrase failed: %v", err)
	}
	if !cryptsetupOpensSlot(t, device, rotatedPassphrase, slot) {
		t.Fatalf("cryptsetup cannot open the keyslot %d AddKey wrote", slot)
	}
}

// TestAnUnboundKeyslotSharingThePassphraseDoesNotHijackAddKey: when the same
// passphrase opens the unbound keyslot AND the bound one, AddKey must wrap the
// volume key, so the keyslot it adds opens the volume for cryptsetup.
func TestAnUnboundKeyslotSharingThePassphraseDoesNotHijackAddKey(t *testing.T) {
	defer parallel(t)()

	// The unbound keyslot is slot 0 and the bound one slot 1, so a scan that
	// ignored binding would reach the unbound key FIRST.
	image := newImage(t, "unbound-first.img")
	requireCryptsetup(t)
	args := append([]string{"luksFormat", "--type", "luks2", "--key-slot", "1"}, cheapCryptsetupArgs...)
	if code, out := runCryptsetup(t, conformancePassphrase, append(args, image)...); code != 0 {
		t.Fatalf("cryptsetup luksFormat exited %d\n%s", code, out)
	}
	unboundArgs := append([]string{"luksAddKey", "--unbound", "--key-size", "512", "--key-slot", "0"}, cheapCryptsetupArgs...)
	if code, out := runCryptsetup(t, conformancePassphrase, append(unboundArgs, image)...); code != 0 {
		t.Fatalf("cryptsetup luksAddKey --unbound exited %d\n%s", code, out)
	}

	slot, err := addKeyForTest(image, []byte(conformancePassphrase), []byte(rotatedPassphrase), fastAddKeyOptions())
	if err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
	if !cryptsetupOpensSlot(t, image, rotatedPassphrase, slot) {
		t.Fatalf("the keyslot AddKey wrote (%d) wraps the unbound key, not the volume key", slot)
	}
}

// fastAddKeyOptions asks AddKey for the cheapest keyslot it will calibrate; see
// calibratedCountFloor for what the unit suite makes of that.
func fastAddKeyOptions() *addKeyOptionsForTest {
	return &addKeyOptionsForTest{KDFType: kdfTypePBKDF2, Hash: "sha512", PBKDFIterTime: 1}
}

// confinementFixture formats a container, fills its data segment, and gives it
// a keyslot "1" -- a copy of keyslot 0, key material included -- whose area lies
// at offset `at`, outside keyslot space. It returns the device and the bytes of
// the range that keyslot claims.
func confinementFixture(t *testing.T, at func(dataOffset int64) int64, keyslotType string) (string, int64, int64) {
	t.Helper()

	device := newImage(t, "unconfined.img")
	formatWithLibrary(t, device)
	fillDataArea(t, device)

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	dataOffset, err := parseSize(metadata.Segments["0"].Offset)
	if err != nil {
		t.Fatalf("segment offset: %v", err)
	}
	offset, size := keyslotAreaExtent(t, device, "0")
	target := at(dataOffset)

	sibling := cloneKeyslot(metadata.Keyslots["0"])
	sibling.Type = keyslotType
	sibling.Area.Offset = formatSize(target)
	metadata.Keyslots["1"] = sibling
	digest := metadata.Digests["0"]
	digest.Keyslots = append(digest.Keyslots, "1")

	if keyslotType == "luks2" {
		// Real key material, so the passphrase OPENS the keyslot and a removal
		// gets past its own authentication to the wipe.
		material := readAreaBytes(t, device, offset, size)
		f, err := os.OpenFile(device, os.O_WRONLY, 0)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if _, err := f.WriteAt(material, target); err != nil {
			t.Fatalf("copy the material: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
	if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
		t.Fatalf("failed to write the fixture header: %v", err)
	}
	return device, target, size
}

// TestEveryKeyslotWipeIsConfinedToTheKeyslotsArea is A2: a keyslot whose area
// is declared over the encrypted payload or the header copies is never wiped,
// on any path that destroys a keyslot area.
func TestEveryKeyslotWipeIsConfinedToTheKeyslotsArea(t *testing.T) {
	defer parallel(t)()

	passphrase := []byte(conformancePassphrase)
	cases := []struct {
		name        string
		at          func(int64) int64
		keyslotType string
		paths       []keyslotRemovalPath
	}{
		{"an openable keyslot over the payload", func(data int64) int64 { return data + 4096 }, "luks2", keyslotRemovalPaths},
		{"a reencrypt keyslot over the payload", func(data int64) int64 { return data }, "reencrypt", keyslotRemovalPaths[1:]},
		{"a reencrypt keyslot over the header copies", func(int64) int64 { return 0 }, "reencrypt", keyslotRemovalPaths[1:]},
	}
	for _, tc := range cases {
		for _, path := range tc.paths {
			t.Run(tc.name+"/"+path.name, func(t *testing.T) {
				device, offset, size := confinementFixture(t, tc.at, tc.keyslotType)
				before := readAreaBytes(t, device, offset, size)
				data := dataAreaDigest(t, device)

				err := path.remove(device, passphrase, 1)
				if !errors.Is(err, ErrKeyslotAreaOverlap) {
					t.Fatalf("got %v, want ErrKeyslotAreaOverlap", err)
				}
				if !bytes.Equal(before, readAreaBytes(t, device, offset, size)) || dataAreaDigest(t, device) != data {
					t.Fatal("the wipe was refused AND bytes outside keyslot space were overwritten")
				}
			})
		}
	}

	// ChangeKey wipes the area it relocates OUT of, so it is the fifth path.
	t.Run("ChangeKey", func(t *testing.T) {
		device, offset, size := confinementFixture(t, func(data int64) int64 { return data + 4096 }, "luks2")
		before := fileDigest(t, device)
		err := changeKeyForTest(device, passphrase, []byte(rotatedPassphrase), 1)
		if !errors.Is(err, ErrKeyslotAreaOverlap) {
			t.Fatalf("got %v, want ErrKeyslotAreaOverlap", err)
		}
		if fileDigest(t, device) != before {
			t.Fatalf("ChangeKey refused AND changed the device (area %d+%d)", offset, size)
		}
	})
}

// TestTheUnlockScanRefusesAKeyslotOutsideKeyslotSpace is A2's read-time half:
// a keyslot whose area lies in the payload is not opened, so the payload is
// never read as key material -- as cryptsetup, which refuses the whole header.
func TestTheUnlockScanRefusesAKeyslotOutsideKeyslotSpace(t *testing.T) {
	defer parallel(t)()

	device, _, _ := confinementFixture(t, func(data int64) int64 { return data + 4096 }, "luks2")
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	removeKeyslotFromMetadata(metadata, "0")
	if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
		t.Fatalf("failed to drop keyslot 0: %v", err)
	}

	err = testKeyForTest(device, []byte(conformancePassphrase))
	if !errors.Is(err, ErrKeyslotNotFound) || !errors.Is(err, ErrKeyslotAreaOverlap) {
		t.Fatalf("TestKey opened a keyslot whose area lies in the payload: %v", err)
	}
}

// writeHandKeyslot writes keyslot id by hand: the volume key AF-split into
// `stripes` stripes under passphrase, in an area of areaSize bytes placed after
// every existing one, attested by digest 0. It is the shape no tool this
// package can drive writes: cryptsetup always writes 4000 stripes.
func writeHandKeyslot(t *testing.T, device, id string, passphrase []byte, stripes int, areaSize int64) {
	t.Helper()

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	mk := secretOf(t, volumeKey(t, device, []byte(conformancePassphrase)))
	keySize := mk.Size()

	kdf, err := createKDF(formatOptionsForTest{KDFType: kdfTypePBKDF2, HashAlgo: "sha512", PBKDFIterations: minPBKDF2Iterations},
		keySize, libraryGeneratedCredential, testVolumeSys().fipsMode, testVolumeSys().calibratedCountFloor, testVolumeSys().cryptoRand)
	if err != nil {
		t.Fatalf("createKDF failed: %v", err)
	}
	wrap, err := deriveKeyEnclave(context.Background(), passphrase, kdf, keySize)
	if err != nil {
		t.Fatalf("DeriveKeyEnclave failed: %v", err)
	}
	defer mustDestroy(t, wrap)
	split, err := afCodec(testVolumeSys()).Split(mk, af.Params{Stripes: stripes, Hash: "sha256"})
	if err != nil {
		t.Fatalf("af Split failed: %v", err)
	}
	defer mustDestroy(t, split)
	material, err := areacipher.Default().EncryptEnclave(custody, split, wrap)
	if err != nil {
		t.Fatalf("EncryptEnclave failed: %v", err)
	}
	if int64(len(material)) > areaSize {
		t.Fatalf("%d bytes of material do not fit a %d-byte area", len(material), areaSize)
	}

	start, _, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		t.Fatalf("keyslotsAreaBounds failed: %v", err)
	}
	offset, err := calculateNextKeyslotOffset(metadata, start)
	if err != nil {
		t.Fatalf("calculateNextKeyslotOffset failed: %v", err)
	}
	f, err := os.OpenFile(device, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.WriteAt(material, offset); err != nil {
		t.Fatalf("write the material: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	metadata.Keyslots[id] = &header.Keyslot{
		Type:    "luks2",
		KeySize: keySize,
		Area: &header.KeyslotArea{Type: "raw", KeySize: keySize, Offset: formatSize(offset), Size: formatSize(areaSize),
			Encryption: keyslotAreaEncryption},
		KDF: kdf,
		AF:  &header.AntiForensic{Type: "luks1", Stripes: stripes, Hash: "sha256"},
	}
	metadata.Digests["0"].Keyslots = append(metadata.Digests["0"].Keyslots, id)
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("failed to write the hand-written keyslot: %v", err)
	}
}

// TestChangeKeyRewritesAForeignStripeCount is A3: a keyslot with 2000 stripes
// is rewritten with the 4000 stripes ChangeKey splits into, and DECLARES 4000,
// so the new passphrase opens it -- here and in cryptsetup. Both the area the
// finding describes (large enough for 4000 stripes) and an exactly-sized one
// (which must grow) are covered.
func TestChangeKeyRewritesAForeignStripeCount(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)
	for _, tc := range []struct {
		name string
		area int64
	}{
		{"in an area that holds 4000 stripes", 258048},
		{"in an area sized for its 2000", alignTo(64*2000, keyslotAreaAlignment)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			device := newImage(t, "stripes.img")
			formatWithLibrary(t, device)
			writeHandKeyslot(t, device, "1", []byte(handPassphrase), 2000, tc.area)
			// This package opens it, merging the 2000 stripes it declares.
			// cryptsetup 2.7.0 does NOT: measured, it merges LUKS_STRIPES
			// (4000) whatever af.stripes says, and the digest then fails --
			// so a rewrite that leaves 4000 stripes of material DECLARING 4000
			// is also the one that makes the keyslot cryptsetup's again.
			if err := testKeyForTest(device, []byte(handPassphrase)); err != nil {
				t.Fatalf("the fixture is wrong: the 2000-stripe keyslot does not open here: %v", err)
			}
			offset, size := keyslotAreaExtent(t, device, "1")
			before := readAreaBytes(t, device, offset, size)

			if err := changeKeyForTest(device, []byte(handPassphrase), []byte(rotatedPassphrase), 1); err != nil {
				t.Fatalf("ChangeKey failed: %v", err)
			}

			_, metadata, err := readHeaderForTest(device)
			if err != nil {
				t.Fatalf("ReadHeader failed: %v", err)
			}
			if got := metadata.Keyslots["1"].AF.Stripes; got != header.AFStripes {
				t.Errorf("the rewritten keyslot declares %d stripes, want %d", got, header.AFStripes)
			}
			if !cryptsetupOpensSlot(t, device, rotatedPassphrase, 1) {
				t.Fatal("cryptsetup does not open the rewritten keyslot with the new passphrase")
			}
			if cryptsetupOpensSlot(t, device, handPassphrase, 1) {
				t.Fatal("the old passphrase still opens the rewritten keyslot")
			}
			if bytes.Equal(before, readAreaBytes(t, device, offset, size)) {
				t.Fatal("the old area was not destroyed")
			}
		})
	}
}

// corruptTheNextWrittenArea makes the medium keep something other than the next
// keyslot area written: when that area is synced, 32 KiB of the material just
// written -- it ends where the descriptor's position is -- is overwritten with
// random. The keyslot is written correctly and READ BACK wrong, which is
// exactly the failure the read-back exists to catch.
func corruptTheNextWrittenArea(t *testing.T) volumeSys {
	t.Helper()

	sys := testVolumeSys()
	previous := sys.syncKeyslotArea
	done := false
	sys.syncKeyslotArea = func(f *os.File) error {
		if !done {
			done = true
			end, err := f.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}
			noise := make([]byte, 32<<10)
			if _, err := rand.Read(noise); err != nil {
				return err
			}
			if _, err := f.WriteAt(noise, end-64<<10); err != nil {
				return err
			}
		}
		return previous(f)
	}
	return sys
}

// TestAKeyslotThatDoesNotOpenOnceWrittenIsRolledBack is A3's second half: the
// keyslot ChangeKey or AddKey writes is read back through the committed header
// and must open to the volume key before anything old is destroyed. One that
// does not is rolled back, and the volume still opens as it did.
//
// Not parallel: it substitutes the package's keyslot-area sync seam.
func TestAKeyslotThatDoesNotOpenOnceWrittenIsRolledBack(t *testing.T) {
	passphrase := []byte(conformancePassphrase)
	rotated := []byte(rotatedPassphrase)

	t.Run("ChangeKey", func(t *testing.T) {
		device := newImage(t, "rollback-change.img")
		formatWithLibrary(t, device)
		offset, size := keyslotAreaExtent(t, device, "0")
		before := readAreaBytes(t, device, offset, size)
		sys := corruptTheNextWrittenArea(t)

		err := changeKeyWithSys(device, passphrase, rotated, 0, sys)
		if !errors.Is(err, ErrWrongKey) {
			t.Fatalf("got %v, want ErrWrongKey", err)
		}
		if !bytes.Equal(before, readAreaBytes(t, device, offset, size)) {
			t.Fatal("the old keyslot's material was destroyed although its replacement does not open")
		}
		if _, end := keyslotAreaExtent(t, device, "0"); end != size {
			t.Fatal("the header was not restored to the old keyslot")
		}
		if o, _ := keyslotAreaExtent(t, device, "0"); o != offset {
			t.Fatal("the header still names the rewritten area")
		}
		if err := testKeyForTest(device, passphrase); err != nil {
			t.Fatalf("the old passphrase no longer opens the volume: %v", err)
		}
	})

	t.Run("AddKey", func(t *testing.T) {
		device := newImage(t, "rollback-add.img")
		formatWithLibrary(t, device)
		sys := corruptTheNextWrittenArea(t)

		slot, err := addKeyWithPolicy(context.Background(), device, passphrase, rotated, fastAddKeyOptions(), callerSuppliedCredential, sys)
		if !errors.Is(err, ErrWrongKey) || slot != -1 {
			t.Fatalf("got slot %d, %v; want -1, ErrWrongKey", slot, err)
		}
		_, metadata, err := readHeaderForTest(device)
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		if len(metadata.Keyslots) != 1 || len(metadata.Digests["0"].Keyslots) != 1 {
			t.Fatalf("the unverified keyslot was left in the header: keyslots %v, digest %v",
				len(metadata.Keyslots), metadata.Digests["0"].Keyslots)
		}
		if err := testKeyForTest(device, passphrase); err != nil {
			t.Fatalf("the volume no longer opens: %v", err)
		}
	})
}

// TestRecoveryKeysAreAtLeast256BitsInAKnownFormat is A4.
func TestRecoveryKeysAreAtLeast256BitsInAKnownFormat(t *testing.T) {
	defer parallel(t)()

	for _, tc := range []struct {
		name   string
		length int
		format RecoveryKeyFormat
		want   error
	}{
		{"4 bytes", 4, RecoveryDashed, ErrInvalidArgument},
		{"31 bytes", 31, RecoveryHex, ErrInvalidArgument},
		{"a negative length", -1, RecoveryDashed, ErrInvalidArgument},
		{"a rendering too long to enroll", 257, RecoveryHex, ErrInvalidArgument},
		{"an unknown format", 32, RecoveryKeyFormat(99), ErrInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := NewRecoveryKey(WithRecoveryLength(tc.length), WithRecoveryFormat(tc.format))
			if !errors.Is(err, tc.want) {
				if key != nil {
					key.Destroy()
				}
				t.Fatalf("NewRecoveryKey(%d, %v) = %v, want %v", tc.length, tc.format, err, tc.want)
			}
		})
	}

	for _, format := range []RecoveryKeyFormat{RecoveryHex, RecoveryBase64, RecoveryDashed} {
		key, err := NewRecoveryKey(WithRecoveryLength(DefaultRecoveryKeyLength), WithRecoveryFormat(format))
		if err != nil {
			t.Fatalf("NewRecoveryKey(32, %v) failed: %v", format, err)
		}
		key.Destroy()
	}

	// NewRecoveryKey refuses a too-short length on its own, before there is
	// any rk to hand (*Volume).AddRecoveryKey at all -- the two are
	// deliberately two-phase (DESIGN.md §B.2), unlike the old combined
	// AddRecoveryKey(device, existing, &RecoveryKeyOptions{Length: 4}).
	if _, err := NewRecoveryKey(WithRecoveryLength(4)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("NewRecoveryKey with a 4-byte length returned %v, want ErrInvalidArgument", err)
	}
}

// TestArgon2CreationIsBoundedByWhatTheReaderAccepts is A5: no Argon2 cost the
// read path refuses can be written, whoever supplies it.
func TestArgon2CreationIsBoundedByWhatTheReaderAccepts(t *testing.T) {
	defer parallel(t)()

	for _, tc := range []struct {
		name string
		opts formatOptionsForTest
		want error
	}{
		{"memory over the 4 GiB ceiling", formatOptionsForTest{KDFType: kdfTypeArgon2id, Argon2Memory: maxArgon2Memory + 1}, ErrInvalidArgument},
		{"time over the ceiling", formatOptionsForTest{KDFType: kdfTypeArgon2id, Argon2Time: maxArgon2Time + 1}, ErrInvalidArgument},
		{"parallelism over 255", formatOptionsForTest{KDFType: kdfTypeArgon2i, Argon2Parallel: maxArgon2Parallel + 1}, ErrInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateArgon2CreateCost(tc.opts)
			var costErr *KDFCostError
			if !errors.Is(err, tc.want) || !errors.As(err, &costErr) || costErr.Max == 0 {
				t.Fatalf("validateArgon2CreateCost = %v, want %v carrying the ceiling", err, tc.want)
			}
			if !strings.Contains(err.Error(), "permitted range") {
				t.Errorf("the refusal does not state the range: %v", err)
			}
		})
	}

	// createKDF itself, which every creation path reaches -- ChangeKey's
	// inherited cost included -- refuses what the reader would.
	for _, opts := range []formatOptionsForTest{
		{KDFType: kdfTypeArgon2id, Argon2Memory: maxArgon2Memory + 1, Argon2Time: 4, Argon2Parallel: 4},
		{KDFType: kdfTypeArgon2i, Argon2Memory: 65536, Argon2Time: maxArgon2Time + 1, Argon2Parallel: 4},
	} {
		if kdf, err := createKDF(opts, 64, callerSuppliedCredential, testVolumeSys().fipsMode, testVolumeSys().calibratedCountFloor, testVolumeSys().cryptoRand); err == nil {
			t.Errorf("createKDF wrote %+v, a cost validateKDFCost refuses on read", kdf)
		}
	}

	// And the entry points refuse before touching the device.
	device := newImage(t, "argon2-ceiling.img")
	before := fileDigest(t, device)
	opts := standardFormatOptions(device)
	opts.KDFType, opts.Argon2Memory = kdfTypeArgon2id, maxArgon2Memory+1
	if err := formatForTest(opts); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Format with Argon2 memory over the ceiling returned %v", err)
	}
	if fileDigest(t, device) != before {
		t.Fatal("a refused Format wrote to the device")
	}
}

// TestTheAreaKeySizeIsTheWrappingKeysLength is A6, against a volume cryptsetup
// formatted with --keyslot-key-size 256 under a 512-bit volume key.
func TestTheAreaKeySizeIsTheWrappingKeysLength(t *testing.T) {
	defer parallel(t)()

	device := cryptsetupFormat(t, "keyslot-key-size.img", conformancePassphrase,
		"--key-size", "512", "--keyslot-cipher", "aes-xts-plain64", "--keyslot-key-size", "256")
	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if ks := metadata.Keyslots["0"]; ks.KeySize != 64 || ks.Area.KeySize != 32 {
		t.Fatalf("the fixture keyslot has key_size %d and area.key_size %d, want 64 and 32", ks.KeySize, ks.Area.KeySize)
	}

	if err := testKeyForTest(device, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("TestKey cannot open cryptsetup's --keyslot-key-size volume: %v", err)
	}
	if got := hexOf(volumeKey(t, device, []byte(conformancePassphrase))); got != cryptsetupVolumeKey(t, device) {
		t.Fatal("the volume key recovered here is not the one cryptsetup recovers")
	}

	// A passphrase change keeps the area's key size and stays a keyslot
	// cryptsetup opens.
	if err := changeKeyForTest(device, []byte(conformancePassphrase), []byte(rotatedPassphrase), 0); err != nil {
		t.Fatalf("ChangeKey failed: %v", err)
	}
	if !cryptsetupOpensSlot(t, device, rotatedPassphrase, 0) {
		t.Fatal("cryptsetup does not open the keyslot ChangeKey rewrote")
	}
	_, metadata, err = readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if got := metadata.Keyslots["0"].Area.KeySize; got != 32 {
		t.Errorf("ChangeKey rewrote area.key_size as %d, want 32", got)
	}
}

// TestTheScreenRefusesAnAreaKeySizeXTSCannotUse is A6's refusal half.
func TestTheScreenRefusesAnAreaKeySizeXTSCannotUse(t *testing.T) {
	defer parallel(t)()

	metadata, _ := bindingFixture(t)
	for _, size := range []int{0, 16, 63} {
		keyslot := cloneKeyslot(metadata.Keyslots["0"])
		keyslot.Area.KeySize = size
		if _, err := screenKeyslot("0", keyslot, metadata.Digests, fips.Probe); !errors.Is(err, ErrKeyslotNotFound) {
			t.Errorf("area.key_size %d screened as %v, want ErrInvalidKeyslot", size, err)
		}
	}
}

// hexOf renders key as cryptsetupVolumeKey does.
func hexOf(key []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(key))
	for _, b := range key {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}

// TestExistingCredentialsAreNotHeldToTheNewPassphrasePolicy is A7: a 4 KiB
// cryptsetup key file and a 3-character passphrase both open, rotate and
// authenticate; only nothing at all and more than cryptsetup reads are refused.
func TestExistingCredentialsAreNotHeldToTheNewPassphrasePolicy(t *testing.T) {
	defer parallel(t)()

	keyFile := make([]byte, 4096)
	if _, err := rand.Read(keyFile); err != nil {
		t.Fatalf("rand: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyPath, keyFile, 0o600); err != nil {
		t.Fatalf("write the key file: %v", err)
	}

	t.Run("a 4 KiB key file", func(t *testing.T) {
		device := cryptsetupFormat(t, "keyfile.img", "", "--key-file", keyPath)
		if err := testKeyForTest(device, keyFile); err != nil {
			t.Fatalf("TestKey with cryptsetup's key file failed: %v", err)
		}
		slot, err := addKeyForTest(device, keyFile, []byte(rotatedPassphrase), fastAddKeyOptions())
		if err != nil {
			t.Fatalf("AddKey authenticated by the key file failed: %v", err)
		}
		if err := killSlotForTest(device, keyFile, slot); err != nil {
			t.Fatalf("KillSlot authenticated by the key file failed: %v", err)
		}
		if _, err := addKeyForTest(device, keyFile, []byte(rotatedPassphrase), fastAddKeyOptions()); err != nil {
			t.Fatalf("AddKey failed: %v", err)
		}
		if err := removeKeyForTest(device, keyFile, 0); err != nil {
			t.Fatalf("RemoveKey with the key file failed: %v", err)
		}
		if !cryptsetupOpensSlot(t, device, rotatedPassphrase, -1) {
			t.Fatal("cryptsetup does not open the keyslot AddKey wrote")
		}
	})

	t.Run("a short legacy passphrase", func(t *testing.T) {
		device := cryptsetupFormat(t, "short.img", "abc")
		if err := testKeyForTest(device, []byte("abc")); err != nil {
			t.Fatalf("TestKey with a 3-byte passphrase cryptsetup enrolled failed: %v", err)
		}
		if _, err := addKeyForTest(device, []byte("abc"), []byte(rotatedPassphrase), fastAddKeyOptions()); err != nil {
			t.Fatalf("AddKey authenticated by the short passphrase failed: %v", err)
		}
		if err := removeKeyForTest(device, []byte("abc"), 0); err != nil {
			t.Fatalf("RemoveKey with the short passphrase failed: %v", err)
		}
	})

	t.Run("the bounds that remain", func(t *testing.T) {
		device := newImage(t, "bounds.img")
		formatWithLibrary(t, device)
		if err := testKeyForTest(device, nil); !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("an empty credential returned %v, want ErrInvalidCredential", err)
		}
		if err := testKeyForTest(device, make([]byte, maxCredentialLength+1)); !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("a credential over 8 MiB returned %v, want ErrInvalidCredential", err)
		}
		// A NEW credential is still held to the policy.
		if _, err := addKeyForTest(device, []byte(conformancePassphrase), []byte("abc"), nil); !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("AddKey enrolled a 3-byte NEW passphrase: %v", err)
		}
	})
}

// TestACalibratedCountIsHeldToTheCallerFloor is A8, on the REAL floor: TestMain
// lowers calibratedCountFloor for the keyslots the rest of the suite writes,
// and this test puts it back for itself.
//
// Not parallel: it substitutes a package variable.
func TestACalibratedCountIsHeldToTheCallerFloor(t *testing.T) {
	opts := formatOptionsForTest{KDFType: kdfTypePBKDF2, HashAlgo: "sha256", PBKDFIterTime: 1}
	kdf, err := createKDF(opts, 64, callerSuppliedCredential, defaultVolumeSys().fipsMode, defaultVolumeSys().calibratedCountFloor, defaultVolumeSys().cryptoRand)
	if err != nil {
		t.Fatalf("createKDF failed: %v", err)
	}
	if floor := pbkdf2FloorFor("sha256", callerSuppliedCredential); *kdf.Iterations < floor {
		t.Fatalf("a 1 ms budget calibrated a caller credential to %d iterations, under the %d floor", *kdf.Iterations, floor)
	}

	// The library-generated exemption is unchanged: its floor is LUKS2's own.
	kdf, err = createKDF(opts, 64, libraryGeneratedCredential, defaultVolumeSys().fipsMode, defaultVolumeSys().calibratedCountFloor, defaultVolumeSys().cryptoRand)
	if err != nil {
		t.Fatalf("createKDF failed: %v", err)
	}
	if *kdf.Iterations < minPBKDF2Iterations {
		t.Fatalf("a library-generated credential calibrated to %d iterations, under %d", *kdf.Iterations, minPBKDF2Iterations)
	}
}

// nonCanonicalFixture formats a container and gives it a working keyslot at
// the non-canonical id "01", with its own material and attested by digest 0.
func nonCanonicalFixture(t *testing.T) string {
	t.Helper()

	device := newImage(t, "noncanonical.img")
	formatWithLibrary(t, device)
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	mk := secretOf(t, volumeKey(t, device, []byte(conformancePassphrase)))
	writeKeyslot(t, device, hdr, metadata, "01", metadata.Keyslots["0"], mk, []byte(handPassphrase))
	metadata.Digests["0"].Keyslots = append(metadata.Digests["0"].Keyslots, "01")
	if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
		t.Fatalf("failed to write the fixture header: %v", err)
	}
	return device
}

// TestANonCanonicalKeyslotIDIsNeitherOpenedNorCounted is A9: "01" is not a
// keyslot cryptsetup addresses, so it neither opens the volume nor survives
// for the removal guard.
func TestANonCanonicalKeyslotIDIsNeitherOpenedNorCounted(t *testing.T) {
	defer parallel(t)()

	device := nonCanonicalFixture(t)
	if err := killKeyslotForTest(device, 0); !errors.Is(err, ErrLastKeyslot) {
		t.Fatalf("killKeyslotForTest(0) beside a keyslot at id \"01\" returned %v, want ErrLastKeyslot", err)
	}

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	removeKeyslotFromMetadata(metadata, "0")
	if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
		t.Fatalf("failed to drop keyslot 0: %v", err)
	}
	if err := testKeyForTest(device, []byte(handPassphrase)); err == nil {
		t.Fatal("the unlock scan opened a keyslot at id \"01\", which cryptsetup cannot address")
	}
}

// relinkDuring repoints link at to when the derivation seam first runs: in the
// middle of a keyslot operation, after it has locked and read the device.
func relinkDuring(t *testing.T, link, to string) volumeSys {
	t.Helper()

	sys := testVolumeSys()
	real := sys.passphraseKDF
	moved := false
	sys.passphraseKDF = func(ctx context.Context, p []byte, kdf *rawKDF, keySize int) (*enclave.MemoryEnclave, error) {
		if !moved {
			moved = true
			if err := os.Remove(link); err != nil {
				return nil, err
			}
			if err := os.Symlink(to, link); err != nil {
				return nil, err
			}
		}
		return real(ctx, p, kdf, keySize)
	}
	return sys
}

// TestAKeyslotOperationStaysOnTheDeviceItLocked is A10: the path is resolved
// ONCE. A link re-pointed mid-operation must not receive a single byte.
//
// Not parallel: it substitutes the package's derivation seam.
func TestAKeyslotOperationStaysOnTheDeviceItLocked(t *testing.T) {
	passphrase := []byte(conformancePassphrase)
	rotated := []byte(rotatedPassphrase)

	for _, op := range []struct {
		name string
		run  func(device string, sys volumeSys) error
	}{
		{"ChangeKey", func(device string, sys volumeSys) error { return changeKeyWithSys(device, passphrase, rotated, 0, sys) }},
		{"AddKey", func(device string, sys volumeSys) error {
			_, err := addKeyWithPolicy(context.Background(), device, passphrase, rotated, fastAddKeyOptions(), callerSuppliedCredential, sys)
			return err
		}},
	} {
		t.Run(op.name, func(t *testing.T) {
			locked := newImage(t, "locked.img")
			formatWithLibrary(t, locked)
			other := newImage(t, "other.img")
			formatWithLibrary(t, other)
			otherBefore := fileDigest(t, other)

			link := filepath.Join(t.TempDir(), "device")
			if err := os.Symlink(locked, link); err != nil {
				t.Fatalf("symlink: %v", err)
			}
			sys := relinkDuring(t, link, other)

			if err := op.run(link, sys); err != nil {
				t.Fatalf("%s failed: %v", op.name, err)
			}
			if fileDigest(t, other) != otherBefore {
				t.Fatal("the device the path was re-pointed at was written to; the operation did not stay on the device it locked")
			}
			if err := testKeyForTest(locked, rotated); err != nil {
				t.Fatalf("the locked device does not open with the new passphrase: %v", err)
			}
		})
	}
}

// TestADevicePathMayContainTwoDots is A10's path half: ".." as a path ELEMENT
// is resolved by Clean, and two dots inside a name are just a name.
func TestADevicePathMayContainTwoDots(t *testing.T) {
	defer parallel(t)()

	device := filepath.Join(t.TempDir(), "a..b")
	if err := os.WriteFile(device, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := validateDevicePath(device); err != nil {
		t.Fatalf("ValidateDevicePath refused %q: %v", device, err)
	}
	if err := validateDevicePath("../" + filepath.Base(device)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("a relative path was accepted: %v", err)
	}
}

// TestTheLockedDescriptorMustBeAFileOrABlockDevice: what is checked is what was
// OPENED, not what the path named when it was validated.
func TestTheLockedDescriptorMustBeAFileOrABlockDevice(t *testing.T) {
	defer parallel(t)()

	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	lock, err := acquireDeviceLock(fifo)
	if err != nil {
		t.Fatalf("acquireDeviceLock: %v", err)
	}
	defer func() { _ = lock.Release() }()

	if _, err := pinnedKeyslotDevice(lock, fifo, testVolumeSys()); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("a FIFO was accepted as a keyslot device: %v", err)
	}
}

// TestANewKeyslotJoinsTheDigestBindingEverySegment: when the volume key matches
// a digest binding only some data segments AND one binding all of them, the
// keyslot AddKey writes joins the latter, whichever sorts first (Codex round 1
// on #249).
func TestANewKeyslotJoinsTheDigestBindingEverySegment(t *testing.T) {
	defer parallel(t)()

	metadata, key := bindingFixture(t)
	mk := secretOf(t, key)
	twoSegments := *metadata
	twoSegments.Segments = map[string]*header.Segment{"0": metadata.Segments["0"], "1": metadata.Segments["0"]}
	twoSegments.Digests = map[string]*rawDigest{
		"0": digestVariant(metadata.Digests["0"], []string{"0"}, []string{"0"}),
		"1": digestVariant(metadata.Digests["0"], []string{"0"}, []string{"0", "1"}),
	}
	if id, err := digestAttestingKey(&twoSegments, mk); err != nil || id != "1" {
		t.Fatalf("digestAttestingKey = %q, %v; want the digest binding every segment, 1", id, err)
	}
}

// TestMigrateToFIPSHoldsItsSourceToTheStrictBinding: a keyslot attested by a
// bound digest AND an unbound one is not a volume-key keyslot by the strict
// predicate, so the import refuses it as a source rather than carrying it
// across (Codex round 1 on #249).
func TestMigrateToFIPSHoldsItsSourceToTheStrictBinding(t *testing.T) {
	if fips140.Enabled() {
		assertMigrationRefusedUnderFIPS(t)
		return
	}
	device := newImage(t, "strict-source.img")
	formatWithLibrary(t, device)
	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Digests["1"] = digestVariant(metadata.Digests["0"], []string{"0"}, []string{})
	if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
		t.Fatalf("write the fixture: %v", err)
	}
	before := fileDigest(t, device)

	if _, err := migrateToFIPSForTest(device, migrationPassphrase, cheapMigration()); !errors.Is(err, errFIPSMigrationUnboundKey) {
		t.Fatalf("MigrateToFIPS from a keyslot with a bound and an unbound digest returned %v, want ErrFIPSMigrationUnboundKey", err)
	}
	if fileDigest(t, device) != before {
		t.Fatal("the refused import changed the device")
	}
}
