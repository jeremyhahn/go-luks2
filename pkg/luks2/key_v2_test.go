// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/volkey"
)

const testPassphraseText = "correct horse battery staple"

func newTestPassphrase(t *testing.T) *enclave.MemoryEnclave {
	t.Helper()
	e, err := enclave.NewMemoryEnclaveCopy([]byte(testPassphraseText))
	if err != nil {
		t.Fatalf("could not build a test passphrase enclave: %v", err)
	}
	return e
}

func TestVolumeUnlockRecoversTheVolumeKey(t *testing.T) {
	path := formattedVolumeImage(t, "unlock.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	if got := key.Keyslot(); got != 0 {
		t.Errorf("header.Keyslot() = %d, want 0", got)
	}
	if got := key.Size(); got != 512/8 {
		t.Errorf("Size() = %d, want %d", got, 512/8)
	}
}

func TestVolumeUnlockWithTheWrongPassphraseFails(t *testing.T) {
	path := formattedVolumeImage(t, "unlock-wrong.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	wrong, err := enclave.NewMemoryEnclaveCopy([]byte("the wrong passphrase entirely"))
	if err != nil {
		t.Fatalf("could not build the wrong-passphrase enclave: %v", err)
	}
	defer func() { _ = wrong.Destroy() }()

	if _, err := v.Unlock(context.Background(), wrong); !errors.Is(err, ErrWrongKey) {
		t.Errorf("Unlock with the wrong passphrase = %v, want ErrWrongKey", err)
	}
}

func TestVolumeUnlockKeyslotRecoversFromTheGivenSlot(t *testing.T) {
	path := formattedVolumeImage(t, "unlockkeyslot.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	key, err := v.UnlockKeyslot(context.Background(), 0, pass)
	if err != nil {
		t.Fatalf("UnlockKeyslot failed: %v", err)
	}
	defer key.Destroy()

	if got := key.Keyslot(); got != 0 {
		t.Errorf("header.Keyslot() = %d, want 0", got)
	}
}

func TestVolumeUnlockKeyslotRefusesAKeyslotThatDoesNotExist(t *testing.T) {
	path := formattedVolumeImage(t, "unlockkeyslot-missing.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	if _, err := v.UnlockKeyslot(context.Background(), 7, pass); !errors.Is(err, ErrKeyslotNotFound) {
		t.Errorf("UnlockKeyslot on an unused slot = %v, want ErrInvalidKeyslot", err)
	}
}

func TestVolumeUnlockWithVolumeKeyAcceptsTheRecoveredKey(t *testing.T) {
	path := formattedVolumeImage(t, "unlockwithvolumekey.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	recovered, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer recovered.Destroy()

	// Borrow is legitimate here only because this test lives inside the
	// module; an outside consumer has no route to these bytes at all.
	var vk *enclave.MemoryEnclave
	if err := volkey.Borrow("test setup", recovered, func(b []byte) error {
		var berr error
		vk, berr = enclave.NewMemoryEnclaveCopy(b)
		return berr
	}); err != nil {
		t.Fatalf("could not borrow the recovered key: %v", err)
	}
	defer func() { _ = vk.Destroy() }()

	key, err := v.UnlockWithVolumeKey(context.Background(), vk)
	if err != nil {
		t.Fatalf("UnlockWithVolumeKey failed: %v", err)
	}
	defer key.Destroy()

	if got := key.Keyslot(); got != -1 {
		t.Errorf("header.Keyslot() = %d, want -1 for a supplied key", got)
	}
	if got, want := key.Size(), recovered.Size(); got != want {
		t.Errorf("Size() = %d, want %d", got, want)
	}

	// vk must still be usable: UnlockWithVolumeKey must not have taken
	// ownership of the caller's enclave.
	if !vk.IsAlive() {
		t.Error("UnlockWithVolumeKey destroyed the caller's own enclave")
	}
}

func TestVolumeUnlockWithVolumeKeyRefusesAWrongSizeKey(t *testing.T) {
	path := formattedVolumeImage(t, "unlockwithvolumekey-wrongsize.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	vk, err := enclave.NewMemoryEnclaveCopy(make([]byte, 16))
	if err != nil {
		t.Fatalf("could not build the wrong-size enclave: %v", err)
	}
	defer func() { _ = vk.Destroy() }()

	if _, err := v.UnlockWithVolumeKey(context.Background(), vk); err == nil {
		t.Fatal("UnlockWithVolumeKey with a wrong-size key succeeded, want an error")
	}
}

func TestVolumeTargetReportsTheSegmentGeometry(t *testing.T) {
	// Target reports the backing device's major:minor, which only a real
	// block device has; blockDeviceOf is substituted here exactly as the
	// old unlock tests already substitute it for a regular temp file.
	const fakeBackingDevNo = 0xabcd

	path := formattedVolumeImage(t, "target.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()
	v.sys.blockDeviceOf = func(*os.File) (uint64, error) { return fakeBackingDevNo, nil }

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	target, err := v.Target(context.Background(), key)
	if err != nil {
		t.Fatalf("Target failed: %v", err)
	}

	if target.Cipher != "aes-xts-plain64" {
		t.Errorf("Cipher = %q, want %q", target.Cipher, "aes-xts-plain64")
	}
	if target.KeySize != 512 {
		t.Errorf("KeySize = %d, want 512", target.KeySize)
	}
	if target.SectorSize != 512 {
		t.Errorf("SectorSize = %d, want 512", target.SectorSize)
	}
	if target.Length == 0 {
		t.Error("Length = 0, want the data segment's length")
	}
}

// TestVolumeTargetRefusesAnythingButABlockDevice is Target's half of C6
// (#250): dm-crypt maps a block device, and a regular file -- all an
// unprivileged test can format -- is refused rather than silently treated
// as one. pkg/dmcrypt.Activate relies on this to fail before any
// device-mapper state exists.
func TestVolumeTargetRefusesAnythingButABlockDevice(t *testing.T) {
	path := formattedVolumeImage(t, "target-not-block.img", "", "")

	v, err := Open(context.Background(), path, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	if _, err := v.Target(context.Background(), key); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Target = %v, want ErrInvalidArgument for a regular file", err)
	}
}

// --- C1 (#250): the key handed to a mapping must be bound to the mapped
// segment. These used to be driven through the old free Unlock/dm pair;
// the dm half moved to pkg/dmcrypt (#268), and what is pinned here is the
// key-recovery half, which (*Volume).Unlock still performs. ---

// TestVolumeUnlockRefusesAPassphraseThatOpensOnlyAnUnboundKey is C1. The
// passphrase opens keyslot 1, whose digest binds NO segment: a LUKS2
// unbound key. getMasterKey only reordered such keyslots, so the scan
// reached keyslot 1, the key verified against its own digest, and the old
// Unlock handed it to dm-crypt. cryptsetup refuses the same passphrase
// with "No usable keyslot".
func TestVolumeUnlockRefusesAPassphraseThatOpensOnlyAnUnboundKey(t *testing.T) {
	device, _ := unlockableVolume(t)
	unboundKeyslot(t, device, otherPassphrase)

	v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	wrong, err := enclave.NewMemoryEnclaveCopy(otherPassphrase)
	if err != nil {
		t.Fatalf("could not build the test passphrase enclave: %v", err)
	}
	defer func() { _ = wrong.Destroy() }()

	if _, err := v.Unlock(context.Background(), wrong); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("Unlock = %v, want ErrWrongKey for a key no digest binds to the data segment", err)
	}
}

// TestVolumeUnlockStillOpensWithTheBoundPassphrase is the control: the
// same header, the volume's own passphrase, still opens.
func TestVolumeUnlockStillOpensWithTheBoundPassphrase(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	unboundKeyslot(t, device, otherPassphrase)

	v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		t.Fatalf("could not build the test passphrase enclave: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock with the bound passphrase failed: %v", err)
	}
	key.Destroy()
}

// TestVolumeUnlockVerifiesTheKeyAgainstTheSegmentsDigest pins the second
// half of C1: a keyslot that a segment digest names is not enough when the
// key it holds verifies only against ANOTHER digest. header.Keyslot 1 holds an
// unbound key and is named both by its own unbound digest and by the data
// segment's digest; verifyMasterKey accepts it on the unbound digest, and
// only the segment check refuses it.
func TestVolumeUnlockVerifiesTheKeyAgainstTheSegmentsDigest(t *testing.T) {
	device, _ := unlockableVolume(t)
	unboundKeyslot(t, device, otherPassphrase)

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Digests["0"].Keyslots = append(metadata.Digests["0"].Keyslots, "1")
	hdr.SequenceID++
	if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}

	v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	wrong, err := enclave.NewMemoryEnclaveCopy(otherPassphrase)
	if err != nil {
		t.Fatalf("could not build the test passphrase enclave: %v", err)
	}
	defer func() { _ = wrong.Destroy() }()

	if _, err := v.Unlock(context.Background(), wrong); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("Unlock = %v, want ErrWrongKey for a key the segment's digest does not attest", err)
	}
}

// --- C2 (#250): requirements and multi-segment headers are refused for
// activation. unlockHeader -- shared by Unlock, UnlockKeyslot,
// UnlockWithVolumeKey and Target -- runs this check now. ---

// writeRequirement stamps config.requirements onto device, going around
// the write path's own guard (which correctly refuses a requirement it
// does not implement) the way a header this package did not write would
// have to be modeled anyway.
func writeRequirement(t *testing.T, device, requirement string) {
	t.Helper()

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Config.Requirements = &header.Requirements{Mandatory: []string{requirement}}
	// An online reencryption carries its backup-previous and backup-final
	// segments, attested by the digest, as cryptsetup writes them; without
	// them the header is one cryptsetup and this package's reader refuse
	// before activation is ever asked (#248).
	if slices.Contains(header.OnlineReencryptRequirements, requirement) {
		for id, flag := range map[string]string{"1": "backup-previous", "2": "backup-final"} {
			backup := *metadata.Segments["0"]
			backup.ClearUnknownMembers()
			backup.SetUnknownMember("flags", json.RawMessage(`["`+flag+`"]`))
			metadata.Segments[id] = &backup
		}
		metadata.Digests["0"].Segments = []string{"0", "1", "2"}
	}
	hdr.SequenceID++

	if err := writeHeaderIgnoringRequirements(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}
}

// TestVolumeUnlockRefusesAContainerMidReencryption is C2:
// online-reencrypt-v2 is what an interrupted `cryptsetup reencrypt`
// leaves, and activation must not ignore it. The devcontainer suite drives
// a real interrupted reencryption; this pins the refusal on its own.
func TestVolumeUnlockRefusesAContainerMidReencryption(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	writeRequirement(t, device, "online-reencrypt-v2")

	v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		t.Fatalf("could not build the test passphrase enclave: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	kdfCalls := 0
	real := v.sys.passphraseKDF
	v.sys.passphraseKDFOverride = func(ctx context.Context, p []byte, kdf *header.KDF, keySize int) (*enclave.MemoryEnclave, error) {
		kdfCalls++
		return real(ctx, p, kdf, keySize)
	}

	_, err = v.Unlock(context.Background(), pass)
	if !errors.Is(err, ErrUnsupportedRequirement) {
		t.Fatalf("Unlock = %v, want ErrUnsupportedRequirement", err)
	}
	var reqErr *header.UnsupportedRequirementError
	if !errors.As(err, &reqErr) || reqErr.Requirement != "online-reencrypt-v2" {
		t.Fatalf("Unlock = %v, want the requirement named", err)
	}
	if kdfCalls != 0 {
		t.Fatalf("the keyslot KDF ran %d time(s) for a container that cannot be activated", kdfCalls)
	}

	// UnlockWithVolumeKey shares the path and the refusal.
	volumeKey := masterKeyOf(t, device, passphrase)
	vk, err := enclave.NewMemoryEnclaveCopy(volumeKey)
	if err != nil {
		t.Fatalf("could not build the volume key enclave: %v", err)
	}
	defer func() { _ = vk.Destroy() }()
	if _, err := v.UnlockWithVolumeKey(context.Background(), vk); !errors.Is(err, ErrUnsupportedRequirement) {
		t.Fatalf("UnlockWithVolumeKey = %v, want ErrUnsupportedRequirement", err)
	}
}

// TestVolumeUnlockRefusesAHeaderWithMoreThanOneSegment is C2's other half:
// a header that declares several segments without a requirement flag is
// not mapped by guessing which one is the volume.
func TestVolumeUnlockRefusesAHeaderWithMoreThanOneSegment(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	// Two regular segments in a layout cryptsetup accepts: the first a
	// fixed 1 MiB, the second dynamic after it, both attested (#248).
	second := *metadata.Segments["0"]
	metadata.Segments["0"].Size = "1048576"
	second.Offset = "17825792"
	metadata.Segments["1"] = &second
	metadata.Digests["0"].Segments = []string{"0", "1"}
	hdr.SequenceID++
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}

	v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		t.Fatalf("could not build the test passphrase enclave: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	if _, err := v.Unlock(context.Background(), pass); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Unlock = %v, want ErrUnsupported", err)
	}
}

// TestVolumeUnlockRefusesAnIntegritySegment: a cryptsetup --integrity
// container's data sits on dm-integrity, and dm-crypt mapped straight over
// the device reads garbage and destroys the integrity tags on every write.
// Its keyslots can be opened -- with an XTS-sized volume key
// (--key-size 256 with hmac-sha256) they pass every keyslot check -- so
// the refusal has to come from the segment, before any key is derived.
func TestVolumeUnlockRefusesAnIntegritySegment(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Segments["0"].SetUnknownMember("integrity", json.RawMessage(`{"type":"hmac(sha256)","journal_encryption":"none","journal_integrity":"none"}`))
	hdr.SequenceID++
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}

	v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		t.Fatalf("could not build the test passphrase enclave: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	kdfCalls := 0
	real := v.sys.passphraseKDF
	v.sys.passphraseKDFOverride = func(ctx context.Context, p []byte, kdf *header.KDF, keySize int) (*enclave.MemoryEnclave, error) {
		kdfCalls++
		return real(ctx, p, kdf, keySize)
	}

	if _, err := v.Unlock(context.Background(), pass); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Unlock = %v, want ErrUnsupported", err)
	}
	if kdfCalls != 0 {
		t.Fatalf("the KDF ran %d time(s) for a container that cannot be activated", kdfCalls)
	}
	if err := testKeyForTest(device, passphrase); err != nil {
		t.Fatalf("the keyslots of an integrity container are no longer usable: %v", err)
	}
}

// TestVolumeTargetPassesThePersistentPerformanceFlags: `cryptsetup open
// --perf-* --persistent` stores flags in config.flags, and every later
// activation puts them in the dm-crypt table; Target does too, in
// cryptsetup's order. allow-discards is stored the same way and is NOT
// passed (see persistentCryptFlags), and a flag nothing knows is ignored,
// as cryptsetup ignores it.
func TestVolumeTargetPassesThePersistentPerformanceFlags(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	hdr, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Config.Flags = []string{"no-write-workqueue", "allow-discards", "x-unknown-flag",
		"no-read-workqueue", "submit-from-crypt-cpus", "same-cpu-crypt"}
	hdr.SequenceID++
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}

	v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()
	v.sys.blockDeviceOf = func(*os.File) (uint64, error) { return 0x0703, nil }

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		t.Fatalf("could not build the test passphrase enclave: %v", err)
	}
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer key.Destroy()

	target, err := v.Target(context.Background(), key)
	if err != nil {
		t.Fatalf("Target failed: %v", err)
	}
	want := []string{"same_cpu_crypt", "submit_from_crypt_cpus", "no_read_workqueue", "no_write_workqueue"}
	if !slices.Equal(target.Flags, want) {
		t.Fatalf("Target flags %q, want %q", target.Flags, want)
	}
}

// --- C6 (#250): one open; the table names the device by number ---

// TestVolumeUnlockReadsTheKeyslotsThroughThePinnedDescriptor is C6 end to
// end. The caller's path is a symlink, and it is re-pointed at a
// DIFFERENT container after the header has been read and before the
// keyslot area is: the moment passphraseKDF runs. Reading the keyslot by
// path then reads the other container's keyslot, and the key does not
// verify; reading it through the descriptor whose header was read opens
// the volume.
func TestVolumeUnlockReadsTheKeyslotsThroughThePinnedDescriptor(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	// The other container: the same bytes with its keyslot area destroyed.
	other := filepath.Join(t.TempDir(), "other.img")
	data, err := os.ReadFile(device) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatalf("reading the fixture failed: %v", err)
	}
	_, metadata, err := readHeaderForTest(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	area := metadata.Keyslots["0"].Area
	offset, _ := parseSize(area.Offset)
	size, _ := parseSize(area.Size)
	garbage, err := randomBytes(int(size), testVolumeSys().cryptoRand)
	if err != nil {
		t.Fatalf("randomBytes failed: %v", err)
	}
	copy(data[offset:offset+size], garbage)
	if err := os.WriteFile(other, data, 0o600); err != nil {
		t.Fatalf("writing the other container failed: %v", err)
	}

	link := filepath.Join(t.TempDir(), "volume")
	if err := os.Symlink(device, link); err != nil {
		t.Fatalf("symlink failed: %v", err)
	}

	v, err := Open(context.Background(), link, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	real := v.sys.passphraseKDF
	v.sys.passphraseKDFOverride = func(ctx context.Context, p []byte, kdf *header.KDF, keySize int) (*enclave.MemoryEnclave, error) {
		_ = os.Remove(link)
		if err := os.Symlink(other, link); err != nil {
			t.Errorf("re-pointing the symlink failed: %v", err)
		}
		return real(ctx, p, kdf, keySize)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		t.Fatalf("could not build the test passphrase enclave: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock = %v; the keyslot was read from whatever the path named by then, not from the device whose header was read", err)
	}
	key.Destroy()
}

// mappingNameTraversalCases is shared by the entries that must refuse a
// path-traversal mapping name before anything is resolved, run or removed
// (#250, C3).
// TestMappingNameEntriesRefuseTraversal is C3. "/dev/mapper/../sdb" is
// /dev/sdb: every entry that builds that path from a caller's name must
// refuse the name before anything is resolved, run or removed.
//
// MakeFilesystem, Mount and IsMappingMounted still live here; Lock's half
// of this guard is dmcrypt.ValidateName's own test now, and so is
// IsUnlocked's and GetMappedDevicePath's -- both moved to dmcrypt.Lookup
// (#268). MakeFilesystem's own "nothing ran" half is pkg/filesystem's test
// now (fakeTools moved there with it); this only pins the refusal itself.
