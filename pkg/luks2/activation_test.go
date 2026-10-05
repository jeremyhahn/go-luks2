// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anatol/devmapper.go"
	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/sys/unix"
)

// Activation and the device layer (#250). Each test names the finding it pins.
// The ones that drive Unlock install the fake device mapper, which is package
// state, so they are sequential; the rest run in parallel.

// --- C1: the key handed to dm-crypt must be bound to the mapped segment ---

// TestUnlockRefusesAPassphraseThatOpensOnlyAnUnboundKey is C1. The passphrase
// opens keyslot 1, whose digest binds NO segment: a LUKS2 unbound key.
// getMasterKey only reordered such keyslots, so the scan reached keyslot 1,
// the key verified against its own digest, and Unlock handed it to dm-crypt.
// cryptsetup refuses the same passphrase with "No usable keyslot".
func TestUnlockRefusesAPassphraseThatOpensOnlyAnUnboundKey(t *testing.T) {
	device, _ := unlockableVolume(t)
	unboundKeyslot(t, device, otherPassphrase)

	fake := newFakeDeviceMapper()
	fake.install(t)

	err := Unlock(device, otherPassphrase, "unbound")
	if err == nil {
		t.Fatal("Unlock mapped a key that no digest binds to the data segment")
	}
	if !errors.Is(err, ErrMasterKeyVerification) {
		t.Fatalf("Unlock = %v, want ErrMasterKeyVerification", err)
	}
	if len(fake.created) != 0 || len(fake.loaded) != 0 {
		t.Fatalf("device-mapper was reached with an unbound key: created %v", fake.created)
	}
}

// TestUnlockStillOpensWithTheBoundPassphrase is the control: the same header,
// the volume's own passphrase, maps.
func TestUnlockStillOpensWithTheBoundPassphrase(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	unboundKeyslot(t, device, otherPassphrase)

	fake := newFakeDeviceMapper()
	fake.install(t)

	if err := Unlock(device, passphrase, "bound"); err != nil {
		t.Fatalf("Unlock with the bound passphrase failed: %v", err)
	}
}

// TestUnlockVerifiesTheKeyAgainstTheSegmentsDigest pins the second half of
// C1: a keyslot that a segment digest names is not enough when the key it
// holds verifies only against ANOTHER digest. Keyslot 1 holds an unbound key
// and is named both by its own unbound digest and by the data segment's
// digest; verifyMasterKey accepts it on the unbound digest, and only the
// segment check refuses it.
func TestUnlockVerifiesTheKeyAgainstTheSegmentsDigest(t *testing.T) {
	device, _ := unlockableVolume(t)
	unboundKeyslot(t, device, otherPassphrase)

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Digests["0"].Keyslots = append(metadata.Digests["0"].Keyslots, "1")
	hdr.SequenceID++
	if err := writeHeaderUnvalidated(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}

	fake := newFakeDeviceMapper()
	fake.install(t)

	err = Unlock(device, otherPassphrase, "doubly-named")
	if !errors.Is(err, ErrMasterKeyVerification) {
		t.Fatalf("Unlock = %v, want ErrMasterKeyVerification for a key the segment's digest does not attest", err)
	}
	if len(fake.created) != 0 {
		t.Fatalf("device-mapper was reached: %v", fake.created)
	}
}

// TestAddKeyRefusesAnExistingPassphraseThatOpensOnlyAnUnboundKey is C1 on
// AddKey. It used to wrap the unbound key under the new passphrase and report
// success: a credential that never opens the volume.
func TestAddKeyRefusesAnExistingPassphraseThatOpensOnlyAnUnboundKey(t *testing.T) {
	defer parallel(t)()

	device, _ := unlockableVolume(t)
	unboundKeyslot(t, device, otherPassphrase)
	before := fileDigest(t, device)

	slot, err := AddKey(device, otherPassphrase, []byte("a-brand-new-passphrase"), &AddKeyOptions{PBKDFIterTime: 1})
	if !errors.Is(err, ErrMasterKeyVerification) {
		t.Fatalf("AddKey = %d, %v; want ErrMasterKeyVerification", slot, err)
	}
	if fileDigest(t, device) != before {
		t.Fatal("the refused AddKey changed the device")
	}
}

// --- C2: requirements and multi-segment headers are refused for activation ---

// writeRequirement stamps config.requirements onto device. The writer refuses
// a requirement it does not implement -- correctly -- so the fixture marks it
// implemented for the one write that creates it.
func writeRequirement(t *testing.T, device, requirement string) {
	t.Helper()

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	metadata.Config.Requirements = &Requirements{Mandatory: []string{requirement}}
	// An online reencryption carries its backup-previous and backup-final
	// segments, attested by the digest, as cryptsetup writes them; without
	// them the header is one cryptsetup and this package's reader refuse
	// before activation is ever asked (#248).
	if slices.Contains(onlineReencryptRequirements, requirement) {
		for id, flag := range map[string]string{"1": "backup-previous", "2": "backup-final"} {
			backup := *metadata.Segments["0"]
			backup.unknown = nil
			withUnknown(&backup, "flags", `["`+flag+`"]`)
			metadata.Segments[id] = &backup
		}
		metadata.Digests["0"].Segments = []string{"0", "1", "2"}
	}
	hdr.SequenceID++

	implementedRequirements[requirement] = true
	err = writeHeaderUnvalidated(device, hdr, metadata)
	delete(implementedRequirements, requirement)
	if err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}
}

// TestUnlockRefusesAContainerMidReencryption is C2: online-reencrypt-v2 is
// what an interrupted `cryptsetup reencrypt` leaves, and Unlock ignored it.
// The devcontainer suite drives a real interrupted reencryption; this pins the
// refusal on its own.
func TestUnlockRefusesAContainerMidReencryption(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	writeRequirement(t, device, "online-reencrypt-v2")

	fake := newFakeDeviceMapper()
	fake.install(t)
	kdfCalls := 0
	previous := passphraseKDF
	t.Cleanup(func() { passphraseKDF = previous })
	passphraseKDF = func(p []byte, kdf *KDF, keySize int) (*enclave.MemoryEnclave, error) {
		kdfCalls++
		return previous(p, kdf, keySize)
	}

	err := Unlock(device, passphrase, "mid-reencrypt")
	if !errors.Is(err, ErrUnsupportedRequirement) {
		t.Fatalf("Unlock = %v, want ErrUnsupportedRequirement", err)
	}
	var reqErr *UnsupportedRequirementError
	if !errors.As(err, &reqErr) || reqErr.Requirement != "online-reencrypt-v2" {
		t.Fatalf("Unlock = %v, want the requirement named", err)
	}
	if len(fake.created) != 0 {
		t.Fatalf("device-mapper was reached: %v", fake.created)
	}
	if kdfCalls != 0 {
		t.Fatalf("the keyslot KDF ran %d time(s) for a container that cannot be activated", kdfCalls)
	}

	// UnlockWithVolumeKey shares the path and the refusal.
	key := volumeKeyEnclave(t, volumeKey(t, device, passphrase))
	if err := UnlockWithVolumeKey(device, key, "mid-reencrypt"); !errors.Is(err, ErrUnsupportedRequirement) {
		t.Fatalf("UnlockWithVolumeKey = %v, want ErrUnsupportedRequirement", err)
	}
}

// TestUnlockRefusesAHeaderWithMoreThanOneSegment is C2's other half: a header
// that declares several segments without a requirement flag is not mapped by
// guessing which one is the volume.
func TestUnlockRefusesAHeaderWithMoreThanOneSegment(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	// Two regular segments in a layout cryptsetup accepts: the first a fixed
	// 1 MiB, the second dynamic after it, both attested (#248).
	second := *metadata.Segments["0"]
	metadata.Segments["0"].Size = "1048576"
	second.Offset = "17825792"
	metadata.Segments["1"] = &second
	metadata.Digests["0"].Segments = []string{"0", "1"}
	hdr.SequenceID++
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}

	fake := newFakeDeviceMapper()
	fake.install(t)

	err = Unlock(device, passphrase, "two-segments")
	if !errors.Is(err, ErrUnsupportedSegmentLayout) {
		t.Fatalf("Unlock = %v, want ErrUnsupportedSegmentLayout", err)
	}
	if len(fake.created) != 0 {
		t.Fatalf("device-mapper was reached: %v", fake.created)
	}
}

// --- C3: mapping names are validated at every public entry ---

// TestMappingNameEntriesRefuseTraversal is C3. "/dev/mapper/../sdb" is
// /dev/sdb: every entry that builds that path from a caller's name must refuse
// the name before anything is resolved, run or removed.
func TestMappingNameEntriesRefuseTraversal(t *testing.T) {
	dir := t.TempDir()
	withDevDir(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, "mapper"), 0o755); err != nil {
		t.Fatalf("building the fake /dev failed: %v", err)
	}
	// The raw "disk" the traversal lands on.
	writeFakeNode(t, filepath.Join(dir, "sdb"))

	fake := newFakeDeviceMapper()
	fake.install(t)
	record := fakeTools(t, map[string]fakeTool{"mkfs.ext4": {}})
	recordRetryWaits(t)

	for _, name := range []string{"../sdb", "/dev/sdb", "..", "a/../../sdb"} {
		if IsUnlocked(name) {
			t.Errorf("IsUnlocked(%q) = true", name)
		}
		if path, err := GetMappedDevicePath(name); !errors.Is(err, ErrInvalidMappingName) {
			t.Errorf("GetMappedDevicePath(%q) = %q, %v; want ErrInvalidMappingName", name, path, err)
		}
		if err := MakeFilesystem(name, "ext4", ""); !errors.Is(err, ErrInvalidMappingName) {
			t.Errorf("MakeFilesystem(%q) = %v, want ErrInvalidMappingName", name, err)
		}
		if err := Mount(MountOptions{Device: name, MountPoint: t.TempDir(), FSType: "ext4"}); !errors.Is(err, ErrInvalidMappingName) {
			t.Errorf("Mount(%q) = %v, want ErrInvalidMappingName", name, err)
		}
		if err := Lock(name); !errors.Is(err, ErrInvalidMappingName) {
			t.Errorf("Lock(%q) = %v, want ErrInvalidMappingName", name, err)
		}
		if _, err := IsMappingMounted(name); !errors.Is(err, ErrInvalidMappingName) {
			t.Errorf("IsMappingMounted(%q) = %v, want ErrInvalidMappingName", name, err)
		}
	}
	if got := record("mkfs.ext4"); got != nil {
		t.Fatalf("mkfs.ext4 ran with %q for a traversal name", got)
	}
	if fake.inspects != 0 || len(fake.removed) != 0 {
		t.Fatalf("device-mapper was consulted (%d inspections, removals %v) for names that should never reach it", fake.inspects, fake.removed)
	}
}

// --- C4: a losing concurrent Unlock leaves the winner's mapping alone ---

// TestALosingUnlockDoesNotRollBackTheWinnersMapping is C4. Both unlocks see
// the name free; the other one creates first. The loser's create fails with
// EBUSY, and it must not run a rollback at all: the dm UUID is a function of
// the volume and the name, so the winner's target carries exactly the UUID the
// loser would have used, and the old rollback removed it.
func TestALosingUnlockDoesNotRollBackTheWinnersMapping(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	const name = "contended"

	fake := newFakeDeviceMapper()
	fake.install(t)

	// The winner's target appears between the loser's availability check and
	// its create, with the UUID the loser computes for itself.
	var winnerUUID string
	inner := dm.create
	dm.create = func(n, uuid string) (uint64, error) {
		winnerUUID = uuid
		fake.targets[n] = uuid
		fake.devNos[n] = 0xfe42
		// From here on, any inspection or removal is the loser rolling back.
		fake.inspects = 0
		return inner(n, uuid)
	}

	err := Unlock(device, passphrase, name)
	if !errors.Is(err, ErrVolumeAlreadyUnlocked) {
		t.Fatalf("Unlock = %v, want ErrVolumeAlreadyUnlocked for a name another activation took", err)
	}
	if errors.Is(err, ErrMappingStillLive) {
		t.Fatalf("the loser reported a mapping of its own: %v", err)
	}
	if uuid, live := fake.targets[name]; !live || uuid != winnerUUID {
		t.Fatalf("the winner's mapping is gone or replaced: targets[%q] = %q, live=%v", name, uuid, live)
	}
	if len(fake.removed) != 0 || fake.inspects != 0 {
		t.Fatalf("the loser ran a rollback (%d inspections, removals %v) for a target it never created", fake.inspects, fake.removed)
	}
}

// TestRollbackIsPinnedToTheCreatedDeviceNumber is C4's second layer: the
// rollback removes only the activation whose device number its own create
// returned, so a target of the same volume under the same name -- same UUID --
// is left alone.
func TestRollbackIsPinnedToTheCreatedDeviceNumber(t *testing.T) {
	const name = "pinned"
	const uuid = "CRYPT-LUKS2-same-volume-pinned"

	fake := newFakeDeviceMapper()
	fake.targets[name] = uuid
	fake.devNos[name] = 0xfe42 // someone else's activation
	fake.install(t)
	recordRetryWaits(t)

	if err := removeCreatedMapping(name, uuid, 0xfe43); err != nil {
		t.Fatalf("removeCreatedMapping = %v; another activation is nothing to roll back", err)
	}
	if _, live := fake.targets[name]; !live || len(fake.removed) != 0 {
		t.Fatalf("the rollback removed an activation it did not create: removals %v", fake.removed)
	}
}

// TestUnlockUnderTheLongestValidName: the dm UUID is cut to the 128 bytes the
// kernel stores, so the identity checks compare what the kernel holds. A
// 127-byte name used to fail the unlock and leave its target behind, because
// the rollback compared the uncut UUID and decided the target was not its own.
func TestUnlockUnderTheLongestValidName(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	name := strings.Repeat("n", MaxMappingNameLength)

	fake := newFakeDeviceMapper()
	fake.install(t)
	if err := Unlock(device, passphrase, name); err != nil {
		t.Fatalf("Unlock under a valid %d-byte name failed: %v", len(name), err)
	}
	if uuid := fake.targets[name]; len(uuid) != dmUUIDMaxLength || !strings.HasPrefix(uuid, "CRYPT-LUKS2-") {
		t.Fatalf("the dm UUID is %q (%d bytes), want the cryptsetup form cut to %d", uuid, len(uuid), dmUUIDMaxLength)
	}

	// And a failed unlock under that name rolls its own target back.
	fake = newFakeDeviceMapper()
	fake.readyErr = errors.New("udev never created the node")
	fake.install(t)
	if err := Unlock(device, passphrase, name); err == nil {
		t.Fatal("Unlock reported success with readiness failing")
	} else if errors.Is(err, ErrMappingStillLive) {
		t.Fatalf("the rollback did not recognize its own target: %v", err)
	}
	if live := fake.live(); len(live) != 0 {
		t.Fatalf("a failed unlock under a long name left %v live", live)
	}
}

// TestMappingUUIDReadsTheHeaderUUIDAsTheKernelWould: the header UUID is a
// C string to the kernel, so it ends at its first NUL here too.
func TestMappingUUIDReadsTheHeaderUUIDAsTheKernelWould(t *testing.T) {
	defer parallel(t)()

	var hdr LUKS2BinaryHeader
	copy(hdr.UUID[:], "1234-5678\x00trailing-garbage")
	if got := mappingUUID(&hdr, "vol"); got != "CRYPT-LUKS2-12345678-vol" {
		t.Fatalf("mappingUUID = %q", got)
	}
	if _, err := createTarget(strings.Repeat("n", 128), "u"); !errors.Is(err, ErrInvalidMappingName) {
		t.Fatalf("createTarget accepted a name the ioctl would cut: %v", err)
	}
	if _, err := createTarget("n", strings.Repeat("u", 129)); !errors.Is(err, ErrInvalidMappingName) {
		t.Fatalf("createTarget accepted a UUID the ioctl would cut: %v", err)
	}
}

// --- C5: device-mapper is authoritative; a stale node is never trusted ---

// staleMapperNode makes devDir/mapper/<name> a symlink to /dev/null -- a real
// device node an unprivileged test can point at, and not the mapping's.
func staleMapperNode(t *testing.T, name string) string {
	t.Helper()

	dir := t.TempDir()
	withDevDir(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, "mapper"), 0o755); err != nil {
		t.Fatalf("building the fake /dev failed: %v", err)
	}
	stale := filepath.Join(dir, "mapper", name)
	if err := os.Symlink("/dev/null", stale); err != nil {
		t.Fatalf("planting the stale node failed: %v", err)
	}
	return stale
}

// TestIsUnlockedDoesNotTrustAStaleNode is C5: no dm target, a device node at
// /dev/mapper/<name>. IsUnlocked used to answer true from the node.
func TestIsUnlockedDoesNotTrustAStaleNode(t *testing.T) {
	staleMapperNode(t, "stale")
	newFakeDeviceMapper().install(t)

	if IsUnlocked("stale") {
		t.Fatal("IsUnlocked trusted a /dev/mapper node device-mapper knows nothing about")
	}
}

// TestGetMappedDevicePathRefusesANodeThatIsNotTheMapping is C5 with a live
// mapping: /dev/mapper/<name> exists but names another device. The path used
// to be returned because it stat'd.
func TestGetMappedDevicePathRefusesANodeThatIsNotTheMapping(t *testing.T) {
	staleMapperNode(t, "replaced")
	fake := newFakeDeviceMapper()
	fake.targets["replaced"] = "CRYPT-LUKS2-replaced"
	fake.install(t)
	waits := recordRetryWaits(t)

	path, err := GetMappedDevicePath("replaced")
	if !errors.Is(err, ErrDeviceNodeUnverified) {
		t.Fatalf("GetMappedDevicePath = %q, %v; want ErrDeviceNodeUnverified", path, err)
	}
	if want := int(mappedNodeTimeout / deviceReadyPollInterval); len(*waits) != want {
		t.Fatalf("waited %d times for a verified node, want the %d-poll budget", len(*waits), want)
	}
}

// fakeNodes stands in for mknod and stat(2) on device nodes. A node "made" by
// makeBlockNode is a plain file, and its device number is remembered by INODE,
// so it survives the rename placeNode does; blockNodeRdev follows symlinks and
// looks the inode up. register gives an existing file a device number.
func fakeNodes(t *testing.T) (register func(path string, rdev uint64)) {
	t.Helper()

	byInode := map[uint64]uint64{}
	inodeOf := func(path string) (uint64, error) {
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			return 0, err
		}
		return st.Ino, nil
	}
	register = func(path string, rdev uint64) {
		ino, err := inodeOf(path)
		if err != nil {
			t.Fatalf("registering %s failed: %v", path, err)
		}
		byInode[ino] = rdev
	}

	previousMake, previousRdev := makeBlockNode, blockNodeRdev
	t.Cleanup(func() { makeBlockNode, blockNodeRdev = previousMake, previousRdev })
	makeBlockNode = func(path string, devNo uint64) error {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return err
		}
		major, minor := decodeDevNo(devNo)
		register(path, unix.Mkdev(major, minor))
		return nil
	}
	blockNodeRdev = func(path string) (uint64, error) {
		ino, err := inodeOf(path)
		if err != nil {
			return 0, err
		}
		if rdev, ok := byInode[ino]; ok {
			return rdev, nil
		}
		return 0, ErrNotBlockDevice
	}
	return register
}

// TestWaitForDeviceReadyReplacesAStaleMapperEntry is C5 at the unlock: a stale
// /dev/mapper/<name> used to satisfy the readiness check at once, so the
// caller's next step -- mount, mkfs -- went to whatever it pointed at. It must
// be replaced by an entry that resolves to the new mapping.
func TestWaitForDeviceReadyReplacesAStaleMapperEntry(t *testing.T) {
	stale := staleMapperNode(t, "fresh")
	fakeNodes(t)
	waits := recordRetryWaits(t)

	info := &devmapper.DeviceInfo{Name: "fresh", DevNo: unix.Mkdev(253, 7)}
	if err := waitForDeviceReady("fresh", info); err != nil {
		t.Fatalf("waitForDeviceReady = %v", err)
	}
	if want := int(deviceReadyTimeout / deviceReadyPollInterval); len(*waits) != want {
		t.Fatalf("waited %d times for udev, want the %d-poll budget before acting", len(*waits), want)
	}
	target, err := os.Readlink(stale)
	if err != nil {
		t.Fatalf("the mapper entry is not a symlink: %v", err)
	}
	if target != dmNodePath(7) {
		t.Fatalf("the mapper entry points at %q, want the verified %q", target, dmNodePath(7))
	}
	if !isOurNode(stale, info) {
		t.Fatal("the mapper entry does not resolve to the mapping")
	}
}

// TestEnsureDeviceNodeReplacesARecycledDMNode is C5 for /dev/dm-N: a node at
// the right path carrying another device's number -- a recycled minor -- used
// to count as present.
func TestEnsureDeviceNodeReplacesARecycledDMNode(t *testing.T) {
	dir := t.TempDir()
	withDevDir(t, dir)
	register := fakeNodes(t)
	// A fake node cannot be a block device unprivileged, so the recycled
	// node is a symlink to a file standing in for another device's node.
	other := filepath.Join(t.TempDir(), "other-device")
	writeFakeNode(t, other)
	register(other, unix.Mkdev(9, 7))
	recycled := filepath.Join(dir, "dm-7")
	if err := os.Symlink(other, recycled); err != nil {
		t.Fatalf("symlink failed: %v", err)
	}

	info := &devmapper.DeviceInfo{Name: "vol", DevNo: unix.Mkdev(253, 7)}
	if err := ensureDeviceNode("vol", info); err != nil {
		t.Fatalf("ensureDeviceNode = %v", err)
	}
	if !isOurNode(recycled, info) {
		t.Fatal("/dev/dm-7 still names another device")
	}
}

// TestNodeRepairNeverReplacesTheControlNode: "control" is not a mapping name,
// and the node repair refuses to rename over anything that cannot be a stale
// dm node -- a character device such as /dev/mapper/control, a directory, a
// regular file.
func TestNodeRepairNeverReplacesTheControlNode(t *testing.T) {
	if err := ValidateMappingName("control"); !errors.Is(err, ErrInvalidMappingName) {
		t.Fatalf("ValidateMappingName(control) = %v, want ErrInvalidMappingName", err)
	}
	fake := newFakeDeviceMapper()
	fake.install(t)
	device, passphrase := unlockableVolume(t)
	if err := Unlock(device, passphrase, "control"); !errors.Is(err, ErrInvalidMappingName) {
		t.Fatalf("Unlock(control) = %v, want ErrInvalidMappingName", err)
	}
	if len(fake.created) != 0 {
		t.Fatalf("device-mapper was reached: %v", fake.created)
	}

	// /dev/null stands in for the control node: a character device. placeNode
	// refuses before creating anything, so /dev/null is never touched.
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	writeFakeNode(t, plain)
	for _, target := range []string{"/dev/null", dir, plain} {
		created := false
		err := placeNode(target, func(string) error { created = true; return nil })
		if !errors.Is(err, ErrDeviceNodeUnverified) || created {
			t.Errorf("placeNode(%s) = %v (created=%v), want a refusal before anything is made", target, err, created)
		}
	}
}

// --- C6: one open; the table names the device by number ---

// TestUnlockGivesDeviceMapperTheDeviceNumber is C6: the dm-crypt table names
// the backing device as major:minor from fstat of the descriptor whose header
// was read, never as a path.
func TestUnlockGivesDeviceMapperTheDeviceNumber(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	fake := newFakeDeviceMapper()
	fake.install(t)

	if err := Unlock(device, passphrase, "by-number"); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	if got := fake.cryptTable(t).BackendDevice; got != "7:3" {
		t.Fatalf("the table names the backing device as %q, want 7:3 from the pinned descriptor", got)
	}
	if fake.readyInfo == nil || fake.readyInfo.DevNo != fake.devNos["by-number"] {
		t.Fatalf("readiness was checked against %+v, not the device number the create returned", fake.readyInfo)
	}
}

// TestUnlockRefusesAnythingButABlockDevice is C6's refusal: dm-crypt maps a
// block device, and a regular file is refused before anything is read.
func TestUnlockRefusesAnythingButABlockDevice(t *testing.T) {
	device, passphrase := unlockableVolume(t)
	live := blockDeviceOf
	fake := newFakeDeviceMapper()
	fake.install(t)
	// The fake device mapper stands the image in for a block device; this test
	// is about the live check, so it puts that back.
	blockDeviceOf = live

	if err := Unlock(device, passphrase, "a-file"); !errors.Is(err, ErrNotBlockDevice) {
		t.Fatalf("Unlock = %v, want ErrNotBlockDevice for a regular file", err)
	}
	if len(fake.created) != 0 {
		t.Fatalf("device-mapper was reached: %v", fake.created)
	}
}

// TestUnlockReadsTheKeyslotsThroughThePinnedDescriptor is C6 end to end. The
// caller's path is a symlink, and it is re-pointed at a DIFFERENT container
// after the header has been read and before the keyslot area is: the moment
// passphraseKDF runs. Reading the keyslot by path then reads the other
// container's keyslot, and the key does not verify; reading it through the
// descriptor whose header was read opens the volume.
func TestUnlockReadsTheKeyslotsThroughThePinnedDescriptor(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	// The other container: the same bytes with its keyslot area destroyed.
	other := filepath.Join(t.TempDir(), "other.img")
	data, err := os.ReadFile(device) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatalf("reading the fixture failed: %v", err)
	}
	_, metadata, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	area := metadata.Keyslots["0"].Area
	offset, _ := parseSize(area.Offset)
	size, _ := parseSize(area.Size)
	garbage, err := randomBytes(int(size))
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

	fake := newFakeDeviceMapper()
	fake.install(t)
	previous := passphraseKDF
	t.Cleanup(func() { passphraseKDF = previous })
	passphraseKDF = func(p []byte, kdf *KDF, keySize int) (*enclave.MemoryEnclave, error) {
		_ = os.Remove(link)
		if err := os.Symlink(other, link); err != nil {
			t.Errorf("re-pointing the symlink failed: %v", err)
		}
		return previous(p, kdf, keySize)
	}

	if err := Unlock(link, passphrase, "pinned-descriptor"); err != nil {
		t.Fatalf("Unlock = %v; the keyslot was read from whatever the path named by then, not from the device whose header was read", err)
	}
}

// --- C7: filesystem tools come from fixed directories, not PATH ---

// TestFilesystemToolsAreNotResolvedThroughPATH is C7. A program first on the
// caller's PATH used to be the one run as root against the device.
func TestFilesystemToolsAreNotResolvedThroughPATH(t *testing.T) {
	record := fakeTools(t, map[string]fakeTool{"mkfs.ext4": {}})

	decoy := t.TempDir()
	marker := filepath.Join(t.TempDir(), "decoy-ran")
	script := "#!/bin/sh\ntouch " + shellQuote(marker) + "\n"
	if err := os.WriteFile(filepath.Join(decoy, "mkfs.ext4"), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("writing the decoy failed: %v", err)
	}
	t.Setenv("PATH", decoy)
	t.Setenv("LUKS2_TEST_INHERITED", "must-not-reach-the-tool")

	if err := makeExt4("/dev/mapper/vol", &FilesystemOptions{}); err != nil {
		t.Fatalf("makeExt4 = %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the mkfs.ext4 on PATH ran")
	}
	if record("mkfs.ext4") == nil {
		t.Fatal("the mkfs.ext4 in the trusted directory did not run")
	}
}

// TestFilesystemToolsRunWithAMinimalEnvironment is C7's environment half.
func TestFilesystemToolsRunWithAMinimalEnvironment(t *testing.T) {
	bin := t.TempDir()
	if err := os.Chmod(bin, 0o700); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	envFile := filepath.Join(t.TempDir(), "env")
	script := "#!/bin/sh\nenv > " + shellQuote(envFile) + "\n"
	if err := os.WriteFile(filepath.Join(bin, "blkid"), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("writing the fake failed: %v", err)
	}
	previous := toolDirs
	t.Cleanup(func() { toolDirs = previous })
	toolDirs = []string{bin}
	t.Setenv("LD_PRELOAD", "/nonexistent/evil.so")
	t.Setenv("LUKS2_TEST_INHERITED", "must-not-reach-the-tool")

	_, _ = GetFilesystemInfo("/dev/mapper/vol")
	env, err := os.ReadFile(envFile) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatalf("the fake blkid did not run: %v", err)
	}
	for _, leaked := range []string{"LD_PRELOAD", "LUKS2_TEST_INHERITED"} {
		if strings.Contains(string(env), leaked+"=") {
			t.Errorf("%s reached the tool's environment:\n%s", leaked, env)
		}
	}
	if !strings.Contains(string(env), "LC_ALL=C") {
		t.Errorf("the tool ran without LC_ALL=C:\n%s", env)
	}
}

// TestUntrustedToolsAreRefused is C7: a program another user could replace
// is not run.
func TestUntrustedToolsAreRefused(t *testing.T) {
	record := fakeTools(t, map[string]fakeTool{"mkfs.ext4": {}})
	if err := os.Chmod(toolDirs[0], 0o777); err != nil { // #nosec G302 -- deliberately unsafe, to be refused
		t.Fatalf("chmod failed: %v", err)
	}

	err := makeExt4("/dev/mapper/vol", &FilesystemOptions{})
	if !errors.Is(err, ErrFilesystemTool) {
		t.Fatalf("makeExt4 = %v, want ErrFilesystemTool for a world-writable tool directory", err)
	}
	if record("mkfs.ext4") != nil {
		t.Fatal("a tool from a world-writable directory ran")
	}
}

// TestZFSNamesCannotBeOptions is C7: a pool or dataset name that zpool or zfs
// would read as an option is refused before either runs.
func TestZFSNamesCannotBeOptions(t *testing.T) {
	record := fakeTools(t, map[string]fakeTool{"zpool": {}, "zfs": {}})

	for _, zfs := range []ZFSOptions{
		{PoolName: "-f"},
		{PoolName: "--help"},
		{PoolName: "1tank"},
		{PoolName: "mirror0"},
		{PoolName: "c0t0"},
		{PoolName: "log"},
		{PoolName: "tank pool"},
		{PoolName: "tank", DatasetName: "-o"},
		{PoolName: "tank", DatasetName: "a/../b"},
		{PoolName: "tank", DatasetName: "a//b"},
		{PoolName: "tank", Features: []string{"-x"}},
		{PoolName: "tank", Features: []string{"a=b"}},
		{PoolName: "tank", Properties: map[string]string{"-o": "x"}},
		{PoolName: "tank", Properties: map[string]string{"comment": "a\nb"}},
		{PoolName: "tank", Compression: "-V"},
		{PoolName: "tank", RecordSize: "1M x"},
		{PoolName: "tank", MountPoint: "-m"},
		{PoolName: "tank", Ashift: 40},
	} {
		err := makeZFS("/dev/mapper/vol", &FilesystemOptions{ZFSOptions: &zfs})
		if !errors.Is(err, ErrInvalidFilesystemOption) {
			t.Errorf("makeZFS(%+v) = %v, want ErrInvalidFilesystemOption", zfs, err)
		}
	}
	if got := record("zpool"); got != nil {
		t.Fatalf("zpool ran with %q", got)
	}

	r := &scriptedRunner{}
	if _, err := checkZFS(r.run, "-x", false); !errors.Is(err, ErrInvalidFilesystemOption) || len(r.calls) != 0 {
		t.Fatalf("checkZFS(-x) = %v after running %v, want a refusal before anything ran", err, r.calls)
	}
}

// TestZFSAcceptsOrdinaryNames is the control on the validator.
func TestZFSAcceptsOrdinaryNames(t *testing.T) {
	defer parallel(t)()

	for _, name := range []string{"tank", "Tank_1", "data-pool.v2", "a:b"} {
		if err := validateZFSPoolName(name); err != nil {
			t.Errorf("validateZFSPoolName(%q) = %v", name, err)
		}
	}
	for _, name := range []string{"data", "data/home", "a.b/c_d/e-f:g"} {
		if err := validateZFSDatasetName(name); err != nil {
			t.Errorf("validateZFSDatasetName(%q) = %v", name, err)
		}
	}
}

// TestResolveToolRefusesWhatItCannotTrust covers the resolver's refusals on
// their own: a non-bare name, a missing program, and a file that is not an
// executable.
func TestResolveToolRefusesWhatItCannotTrust(t *testing.T) {
	bin := t.TempDir()
	if err := os.Chmod(bin, 0o700); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bin, "not-exec"), nil, 0o600); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}
	previous := toolDirs
	t.Cleanup(func() { toolDirs = previous })
	toolDirs = []string{bin}

	for _, name := range []string{"", "../bin/sh", "/bin/sh", "absent", "not-exec"} {
		if path, _, err := resolveTool(name); !errors.Is(err, ErrFilesystemTool) {
			t.Errorf("resolveTool(%q) = %q, %v; want ErrFilesystemTool", name, path, err)
		}
	}
}

// TestToolSymlinksAreFollowedOnlyIntoTrustedDirectories: a trusted directory
// entry that is a symlink is judged by what it resolves to. Into a directory
// others can write, it is refused; into a trusted one, the resolved file runs
// with argv[0] kept as the name it was found under.
func TestToolSymlinksAreFollowedOnlyIntoTrustedDirectories(t *testing.T) {
	bin := t.TempDir()
	if err := os.Chmod(bin, 0o700); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	previous := toolDirs
	t.Cleanup(func() { toolDirs = previous })
	toolDirs = []string{bin}

	shared := t.TempDir()
	if err := os.Chmod(shared, 0o777); err != nil { // #nosec G302 -- deliberately unsafe, to be refused
		t.Fatalf("chmod failed: %v", err)
	}
	ran := filepath.Join(t.TempDir(), "ran")
	script := "#!/bin/sh\ntouch " + shellQuote(ran) + "\n"
	for _, dir := range []string{shared} {
		if err := os.WriteFile(filepath.Join(dir, "mke2fs"), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
			t.Fatalf("writing the fixture failed: %v", err)
		}
	}
	if err := os.Symlink(filepath.Join(shared, "mke2fs"), filepath.Join(bin, "mkfs.ext4")); err != nil {
		t.Fatalf("symlink failed: %v", err)
	}
	if err := makeExt4("/dev/mapper/vol", &FilesystemOptions{}); !errors.Is(err, ErrFilesystemTool) {
		t.Fatalf("makeExt4 = %v, want ErrFilesystemTool for a symlink into a world-writable directory", err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("the program behind the symlink ran")
	}

	// The same link into a trusted directory runs, as mkfs.ext4.
	trusted := t.TempDir()
	if err := os.Chmod(trusted, 0o700); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(trusted, "mke2fs"), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test fixture under t.TempDir()
		t.Fatalf("writing the fixture failed: %v", err)
	}
	if err := os.Remove(filepath.Join(bin, "mkfs.ext4")); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if err := os.Symlink(filepath.Join(trusted, "mke2fs"), filepath.Join(bin, "mkfs.ext4")); err != nil {
		t.Fatalf("symlink failed: %v", err)
	}
	if err := makeExt4("/dev/mapper/vol", &FilesystemOptions{}); err != nil {
		t.Fatalf("makeExt4 through a trusted symlink = %v", err)
	}
	if _, err := os.Stat(ran); err != nil {
		t.Fatalf("the program did not run: %v", err)
	}

	// A shell script cannot see argv[0] (the kernel hands it its own path), so
	// the command is inspected: the resolved file is executed, under the name
	// it was found by.
	cmd, err := toolCommand("mkfs.ext4")
	if err != nil {
		t.Fatalf("toolCommand = %v", err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(trusted, "mke2fs"))
	if err != nil {
		t.Fatalf("EvalSymlinks failed: %v", err)
	}
	if cmd.Path != resolved || cmd.Args[0] != filepath.Join(bin, "mkfs.ext4") {
		t.Fatalf("runs %q as argv[0] %q, want %q as %q so mke2fs makes ext4", cmd.Path, cmd.Args[0], resolved, filepath.Join(bin, "mkfs.ext4"))
	}
}

// --- C8: loop devices are matched by device and inode ---

// fakeLoopSysfs builds a sysfs root with one bound loop device whose
// backing_file reads backing.
func fakeLoopSysfs(t *testing.T, backing string) string {
	t.Helper()

	root := t.TempDir()
	dir := filepath.Join(root, "loop5", "loop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("building the fake sysfs failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backing_file"), []byte(backing+"\n"), 0o600); err != nil {
		t.Fatalf("building the fake sysfs failed: %v", err)
	}
	return root
}

// withLoopIdentity makes loopBackingIdentity report dev and ino for every
// device.
func withLoopIdentity(t *testing.T, dev, ino uint64) {
	t.Helper()

	previous := loopBackingIdentity
	t.Cleanup(func() { loopBackingIdentity = previous })
	loopBackingIdentity = func(string) (uint64, uint64, error) { return dev, ino, nil }
}

func statIdentity(t *testing.T, path string) (dev, ino uint64) {
	t.Helper()

	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	return uint64(st.Dev), st.Ino //nolint:unconvert // Dev is not uint64 on every GOARCH
}

// TestFindLoopDeviceMatchesTheFileNotItsPath is C8: the loop driver recorded
// the file under another path (here, the target of the symlink the caller
// names). The path comparison reported it unattached.
func TestFindLoopDeviceMatchesTheFileNotItsPath(t *testing.T) {
	file := filepath.Join(t.TempDir(), "backing.img")
	writeFakeNode(t, file)
	link := filepath.Join(t.TempDir(), "alias.img")
	if err := os.Symlink(file, link); err != nil {
		t.Fatalf("symlink failed: %v", err)
	}
	root := fakeLoopSysfs(t, file)
	dev, ino := statIdentity(t, file)
	withLoopIdentity(t, dev, ino)

	got, err := findLoopDeviceIn(root, link)
	if err != nil || got != "/dev/loop5" {
		t.Fatalf("findLoopDeviceIn(%s) = %q, %v; want /dev/loop5", link, got, err)
	}
}

// TestFindLoopDeviceDoesNotMatchAReplacedFile is C8's other direction: the
// path sysfs prints is the caller's path, but the file there now is a
// different one than the loop device is backed by.
func TestFindLoopDeviceDoesNotMatchAReplacedFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "backing.img")
	writeFakeNode(t, file)
	root := fakeLoopSysfs(t, file)
	dev, ino := statIdentity(t, file)
	withLoopIdentity(t, dev, ino+1)

	if got, err := findLoopDeviceIn(root, file); err == nil {
		t.Fatalf("findLoopDeviceIn = %q; a loop device backed by another inode was reported as this file's", got)
	}
}

// TestFindLoopDeviceCountsAnUnidentifiableDevice: a bound device whose backing
// file cannot be identified is not evidence of absence.
func TestFindLoopDeviceCountsAnUnidentifiableDevice(t *testing.T) {
	file := filepath.Join(t.TempDir(), "backing.img")
	writeFakeNode(t, file)
	root := fakeLoopSysfs(t, file)
	previous := loopBackingIdentity
	t.Cleanup(func() { loopBackingIdentity = previous })
	loopBackingIdentity = func(string) (uint64, uint64, error) { return 0, 0, unix.EACCES }

	_, err := findLoopDeviceIn(root, file)
	var de *DeviceError
	if !errors.As(err, &de) || !errors.Is(err, unix.EACCES) {
		t.Fatalf("findLoopDeviceIn = %v, want a DeviceError carrying the cause", err)
	}

	// A device released between the sysfs read and the ioctl is unbound.
	loopBackingIdentity = func(string) (uint64, uint64, error) { return 0, 0, unix.ENXIO }
	if _, err := findLoopDeviceIn(root, file); err == nil || errors.As(err, &de) {
		t.Fatalf("findLoopDeviceIn = %v, want plain not-found for a released device", err)
	}
}

// --- C9: the keyring thread is discarded ---

// TestTheKeyringThreadIsDiscarded is C9. The work runs on a locked thread
// that must EXIT when it is done rather than return to the scheduler with
// whatever credentials the keyring calls gave it.
func TestTheKeyringThreadIsDiscarded(t *testing.T) {
	defer parallel(t)()

	var tid int
	if err := runOnDiscardedThread(func() error {
		tid = unix.Gettid()
		return nil
	}); err != nil {
		t.Fatalf("runOnDiscardedThread = %v", err)
	}

	// The runtime exits the thread after the goroutine returns, which is after
	// the result was sent: poll for it. The bound is a hang guard, not a
	// timing claim -- a thread returned to the scheduler never goes away.
	task := filepath.Join("/proc/self/task", strconv.Itoa(tid))
	for range 1000 {
		if _, err := os.Stat(task); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("thread %d is still alive: it was handed back to the scheduler", tid)
}

// TestRunOnDiscardedThreadCarriesErrorsAndPanics: the caller sees fn's error,
// and a panic is re-raised on the caller's goroutine rather than killing the
// process.
func TestRunOnDiscardedThreadCarriesErrorsAndPanics(t *testing.T) {
	defer parallel(t)()

	sentinel := errors.New("from the discarded thread")
	if err := runOnDiscardedThread(func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("runOnDiscardedThread = %v, want the function's error", err)
	}

	defer func() {
		if r := recover(); r != "boom" {
			t.Fatalf("recovered %v, want the function's panic", r)
		}
	}()
	_ = runOnDiscardedThread(func() error { panic("boom") })
	t.Fatal("the panic was swallowed")
}

// --- C10: whether a MAPPING is mounted is answered by device number ---

func withMountInfo(t *testing.T, table string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(path, []byte(table), 0o600); err != nil {
		t.Fatalf("writing the fake mountinfo failed: %v", err)
	}
	previous := mountInfoPath
	t.Cleanup(func() { mountInfoPath = previous })
	mountInfoPath = path
}

// TestIsMappingMountedMatchesTheDeviceNumber is C10. The mount was made
// through /dev/dm-7, so no path names the mapping; the device number does.
func TestIsMappingMountedMatchesTheDeviceNumber(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["vol"] = "CRYPT-LUKS2-vol"
	fake.devNos["vol"] = unix.Mkdev(253, 7)
	fake.install(t)
	withMountInfo(t, "36 35 98:0 / /mnt1 rw,noatime master:1 - ext3 /dev/root rw\n"+
		"40 35 253:7 / /srv/data rw,relatime shared:5 - ext4 /dev/dm-7 rw\n")

	mounted, err := IsMappingMounted("vol")
	if err != nil || !mounted {
		t.Fatalf("IsMappingMounted = %v, %v; want true for the mount of 253:7", mounted, err)
	}

	withMountInfo(t, "40 35 253:70 / /srv/data rw - ext4 /dev/dm-70 rw\n")
	if mounted, err := IsMappingMounted("vol"); err != nil || mounted {
		t.Fatalf("IsMappingMounted = %v, %v; want false when only 253:70 is mounted", mounted, err)
	}

	if mounted, err := IsMappingMounted("absent"); err != nil || mounted {
		t.Fatalf("IsMappingMounted(absent) = %v, %v; want false, nil", mounted, err)
	}

	mountInfoPath = filepath.Join(t.TempDir(), "missing")
	if _, err := IsMappingMounted("vol"); err == nil {
		t.Fatal("an unreadable mount table was read as not mounted")
	}

	fake.infoErr = os.NewSyscallError("dm ioctl", unix.EACCES)
	if _, err := IsMappingMounted("vol"); !errors.Is(err, unix.EACCES) {
		t.Fatalf("IsMappingMounted = %v, want the inspection failure", err)
	}
}

// TestMountInfoParsingIgnoresOtherFields: only the device field matches.
func TestMountInfoParsingIgnoresOtherFields(t *testing.T) {
	defer parallel(t)()

	table := "40 35 8:1 /253:7 /253:7 rw - ext4 /dev/253:7 rw\nshort line\n"
	got, err := deviceListedInMountInfo(strings.NewReader(table), 253, 7)
	if err != nil || got {
		t.Fatalf("deviceListedInMountInfo = %v, %v; a path that spells 253:7 is not the device", got, err)
	}
	if !slices.Contains(strings.Fields("40 35 253:7 / /x"), "253:7") {
		t.Fatal("fixture sanity")
	}
	if got, _ := deviceListedInMountInfo(bytes.NewReader([]byte("40 35 253:7 / /x rw - ext4 /dev/dm-7 rw\n")), 253, 7); !got {
		t.Fatal("the device field was not matched")
	}
}
