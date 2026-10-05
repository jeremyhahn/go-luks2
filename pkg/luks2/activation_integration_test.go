// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Activation and the device layer against the real kernel and cryptsetup
// (#250). Each test names the finding it proves.

// activationImage creates a fresh image of sizeMiB, beginning with fill when
// fill is non-nil.
func activationImage(t *testing.T, name string, sizeMiB int, fill []byte) string {
	t.Helper()

	image := filepath.Join(t.TempDir(), name)
	f, err := os.Create(image) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatalf("creating %s failed: %v", image, err)
	}
	if err := f.Truncate(int64(sizeMiB) << 20); err != nil {
		t.Fatalf("sizing %s failed: %v", image, err)
	}
	if fill != nil {
		if _, err := f.WriteAt(fill, 0); err != nil {
			t.Fatalf("filling %s failed: %v", image, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing %s failed: %v", image, err)
	}
	return image
}

// attachLoop attaches a loop device to image and registers the detach.
func attachLoop(t *testing.T, image string) string {
	t.Helper()

	loopDev, err := SetupLoopDevice(image)
	if err != nil {
		t.Fatalf("attaching %s failed: %v", image, err)
	}
	t.Cleanup(func() { _ = DetachLoopDevice(loopDev) })
	return loopDev
}

// activationLoop is a fresh image attached to a loop device.
func activationLoop(t *testing.T, name string, sizeMiB int, fill []byte) (loopDev, image string) {
	t.Helper()

	image = activationImage(t, name, sizeMiB, fill)
	return attachLoop(t, image), image
}

// libraryVolumeLoop is a container this package formatted, attached to a loop
// device. Its passphrase is canonicalPassphrase.
func libraryVolumeLoop(t *testing.T, name string) string {
	t.Helper()

	image := activationImage(t, name, 64, nil)
	formatWithLibraryCheap(t, image)
	return attachLoop(t, image)
}

// deviceDigest hashes the first n bytes of a device.
func deviceDigest(t *testing.T, device string, n int64) [32]byte {
	t.Helper()

	f, err := os.Open(device) // #nosec G304 -- a loop device this test attached
	if err != nil {
		t.Fatalf("opening %s failed: %v", device, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.CopyN(h, f, n); err != nil {
		t.Fatalf("reading %s failed: %v", device, err)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// --- C3 ---

// TestMappingNameTraversalIsRefusedOnTheRealKernel is C3 on a real device.
// /dev/mapper/../loopN is /dev/loopN, and MakeFilesystem("../loopN") used to
// find a block device there and run mkfs on it. Every entry must refuse the
// name, and the device must be byte-for-byte untouched.
func TestMappingNameTraversalIsRefusedOnTheRealKernel(t *testing.T) {
	requireRoot(t)

	pattern := bytes.Repeat([]byte("raw-disk-must-survive "), 1<<14)
	loopDev, _ := activationLoop(t, "traversal-victim.img", 16, pattern)
	before := deviceDigest(t, loopDev, 16<<20)

	name := "../" + filepath.Base(loopDev)
	if fi, err := os.Stat(filepath.Join("/dev/mapper", name)); err != nil || fi.Mode()&os.ModeDevice == 0 {
		t.Fatalf("fixture: /dev/mapper/%s does not reach the raw device (%v), so this test proves nothing", name, err)
	}

	if IsUnlocked(name) {
		t.Errorf("IsUnlocked(%q) = true", name)
	}
	if path, err := GetMappedDevicePath(name); !errors.Is(err, ErrInvalidMappingName) {
		t.Errorf("GetMappedDevicePath(%q) = %q, %v; want ErrInvalidMappingName", name, path, err)
	}
	if err := MakeFilesystem(name, "ext4", "pwned"); !errors.Is(err, ErrInvalidMappingName) {
		t.Errorf("MakeFilesystem(%q) = %v; want ErrInvalidMappingName", name, err)
	}
	mountPoint := t.TempDir()
	if err := Mount(MountOptions{Device: name, MountPoint: mountPoint, FSType: "ext4"}); !errors.Is(err, ErrInvalidMappingName) {
		_ = Unmount(mountPoint, 0)
		t.Errorf("Mount(%q) = %v; want ErrInvalidMappingName", name, err)
	}
	// Lock is not driven here: TestEveryMappingNameIsRunScoped admits only
	// run-scoped names to it, and its refusal of this one is unit-tested
	// (TestMappingNameEntriesRefuseTraversal).
	if _, err := IsMappingMounted(name); !errors.Is(err, ErrInvalidMappingName) {
		t.Errorf("IsMappingMounted(%q) = %v; want ErrInvalidMappingName", name, err)
	}

	if deviceDigest(t, loopDev, 16<<20) != before {
		t.Fatal("the raw device behind /dev/mapper/" + name + " was modified")
	}
}

// --- C4 ---

// TestConcurrentUnlocksLeaveTheWinnersMappingIntact is C4 on the real
// kernel: two Unlocks of the same volume under the same name, released
// together, many times. Exactly one wins; the loser fails with a typed
// refusal; and the winner's mapping is live and decrypts the volume. The old
// rollback removed the WINNER's mapping, because its dm UUID is the loser's
// too.
func TestConcurrentUnlocksLeaveTheWinnersMappingIntact(t *testing.T) {
	requireRoot(t)

	loopDev := libraryVolumeLoop(t, "race.img")

	passphrase := []byte(canonicalPassphrase)
	name := runVolume(t, "race")
	defer releaseVolume(t, name)

	// Write a marker through the mapping once, so each round can check that
	// what survives decrypts the volume.
	marker := []byte("written-through-the-winners-mapping")
	if err := Unlock(loopDev, passphrase, name); err != nil {
		t.Fatalf("the setup unlock failed: %v", err)
	}
	writeThroughMapping(t, name, marker)
	if err := releaseVolumeErr(name); err != nil {
		t.Fatal(err)
	}

	const rounds = 15
	for round := range rounds {
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, 2)
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = Unlock(loopDev, passphrase, name)
			}()
		}
		close(start)
		wg.Wait()

		winners := 0
		for _, err := range errs {
			switch {
			case err == nil:
				winners++
			case errors.Is(err, ErrVolumeAlreadyUnlocked), errors.Is(err, ErrKeyringEntryExists):
				// The typed refusals a loser may see, depending on where it lost.
			default:
				t.Fatalf("round %d: a loser failed with an untyped or wrong error: %v", round, err)
			}
			if errors.Is(err, ErrMappingStillLive) {
				t.Fatalf("round %d: a loser claims a mapping of its own: %v", round, err)
			}
		}
		if winners != 1 {
			t.Fatalf("round %d: %d unlocks succeeded, want exactly 1 (errors %v)", round, winners, errs)
		}
		if !IsUnlocked(name) {
			t.Fatalf("round %d: the winner's mapping is gone after the loser returned", round)
		}
		if got := readThroughMapping(t, name, len(marker)); !bytes.Equal(got, marker) {
			t.Fatalf("round %d: the surviving mapping does not decrypt the volume: read %q", round, got)
		}
		if err := releaseVolumeErr(name); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
}

func writeThroughMapping(t *testing.T, name string, data []byte) {
	t.Helper()

	path, err := GetMappedDevicePath(name)
	if err != nil {
		t.Fatalf("GetMappedDevicePath failed: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- the mapping this test opened
	if err != nil {
		t.Fatalf("opening %s failed: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteAt(data, 0); err != nil {
		t.Fatalf("writing through %s failed: %v", path, err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("syncing %s failed: %v", path, err)
	}
}

func readThroughMapping(t *testing.T, name string, n int) []byte {
	t.Helper()

	path, err := GetMappedDevicePath(name)
	if err != nil {
		t.Fatalf("GetMappedDevicePath failed: %v", err)
	}
	f, err := os.Open(path) // #nosec G304 -- the mapping this test opened
	if err != nil {
		t.Fatalf("opening %s failed: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, 0); err != nil {
		t.Fatalf("reading through %s failed: %v", path, err)
	}
	return buf
}

// TestUnlockUnderTheLongestValidNameOnTheRealKernel: with a 127-byte name the
// dm UUID is longer than the 128 bytes the kernel stores. It used to be cut by
// the ioctl and compared uncut afterwards, so the unlock failed and left its
// target behind. It is cut once, before the create, now.
func TestUnlockUnderTheLongestValidNameOnTheRealKernel(t *testing.T) {
	requireRoot(t)

	overhead := len(runVolume(t, "x")) - 1
	name := runVolume(t, strings.Repeat("l", MaxMappingNameLength-overhead))
	if len(name) != MaxMappingNameLength {
		t.Fatalf("fixture: the name is %d bytes, want %d", len(name), MaxMappingNameLength)
	}
	loopDev := libraryVolumeLoop(t, "long-name.img")

	defer releaseVolume(t, name)
	if err := Unlock(loopDev, []byte(canonicalPassphrase), name); err != nil {
		t.Fatalf("Unlock under a valid %d-byte name failed: %v", len(name), err)
	}
	info, err := dm.infoByName(name)
	if err != nil {
		t.Fatalf("dm lookup failed: %v", err)
	}
	if len(info.UUID) != dmUUIDMaxLength {
		t.Fatalf("the kernel holds a %d-byte UUID %q, want %d", len(info.UUID), info.UUID, dmUUIDMaxLength)
	}
	if err := Lock(name); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}
	if IsUnlocked(name) {
		t.Fatal("the mapping is still there after Lock")
	}
}

// --- C5 ---

// TestAStaleMapperNodeIsNotTrusted is C5 on the real kernel.
// /dev/mapper/<name> is left pointing at a raw loop device, with no dm target
// of that name. The old code answered "unlocked" from the node, refused a
// real Unlock of that name as already unlocked, returned the stale path, and
// ran mkfs on the raw device.
func TestAStaleMapperNodeIsNotTrusted(t *testing.T) {
	requireRoot(t)

	pattern := bytes.Repeat([]byte("stale-node-victim "), 1<<14)
	victim, _ := activationLoop(t, "stale-victim.img", 16, pattern)
	before := deviceDigest(t, victim, 16<<20)

	name := runVolume(t, "stale")
	defer releaseVolume(t, name)
	stale := mapperNodePath(name)
	if err := os.MkdirAll(mapperDir(), 0o750); err != nil {
		t.Fatalf("creating %s failed: %v", mapperDir(), err)
	}
	if err := os.Symlink(victim, stale); err != nil {
		t.Fatalf("planting the stale node failed: %v", err)
	}
	// Deferred after releaseVolume, so it runs first: the teardown check
	// counts a device node at /dev/mapper/<name> as a live mapping.
	defer func() {
		if target, err := os.Readlink(stale); err == nil && target == victim {
			_ = os.Remove(stale)
		}
	}()

	if IsUnlocked(name) {
		t.Error("IsUnlocked trusted the stale node")
	}
	if path, err := GetMappedDevicePath(name); !errors.Is(err, ErrVolumeNotUnlocked) {
		t.Errorf("GetMappedDevicePath = %q, %v; want ErrVolumeNotUnlocked", path, err)
	}
	if err := MakeFilesystem(name, "ext4", "pwned"); !errors.Is(err, ErrVolumeNotUnlocked) {
		t.Errorf("MakeFilesystem = %v; want ErrVolumeNotUnlocked", err)
	}
	if deviceDigest(t, victim, 16<<20) != before {
		t.Fatal("the device behind the stale node was modified")
	}

	// A real unlock under that name succeeds, and the entry it leaves names
	// the new mapping and not the device the stale node pointed at.
	loopDev := libraryVolumeLoop(t, "stale-volume.img")

	if err := Unlock(loopDev, []byte(canonicalPassphrase), name); err != nil {
		t.Fatalf("Unlock under a name with a stale node failed: %v", err)
	}
	info, err := dm.infoByName(name)
	if err != nil {
		t.Fatalf("dm lookup failed: %v", err)
	}
	path, err := GetMappedDevicePath(name)
	if err != nil {
		t.Fatalf("GetMappedDevicePath after the unlock failed: %v", err)
	}
	if !isOurNode(path, info) || !isOurNode(stale, info) {
		t.Fatalf("after the unlock, %s / %s do not name the mapping", path, stale)
	}
	if deviceDigest(t, victim, 16<<20) != before {
		t.Fatal("the device behind the stale node was modified")
	}
}

// --- C2 ---

// TestAnInterruptedCryptsetupReencryptIsRefusedForActivation is C2 against a
// real cryptsetup reencryption, killed part-way. The container then declares
// online-reencrypt-v2 and splits the data across several segments under two
// keys; mapping any one of them with any one key returns garbage.
func TestAnInterruptedCryptsetupReencryptIsRefusedForActivation(t *testing.T) {
	requireRoot(t)
	requireCryptsetupDeclared(t)

	const passphrase = "reencrypt-interrupted"
	loopDev, _ := activationLoop(t, "reencrypt.img", 96, nil)
	cryptsetupRun(t, passphrase, "luksFormat", "--type", "luks2", "--batch-mode",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", "-", loopDev)

	// A journaled reencryption in 64 KiB hotzones, so it is still running
	// when it is killed.
	cmd := exec.Command("cryptsetup", "reencrypt", "--batch-mode", // #nosec G204 -- test constants and a test-owned loop device
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
		"--resilience", "journal", "--hotzone-size", "64k", "--key-file", "-", loopDev)
	cmd.Stdin = strings.NewReader(passphrase)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting cryptsetup reencrypt failed: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	// Kill it once the header shows the reencryption under way: the
	// requirement set and the data split across more than one segment. The
	// header is polled rather than slept on; the bound is a hang guard.
	var midway bool
	for range 2000 {
		if _, metadata, err := ReadHeader(loopDev); err == nil &&
			metadata.Config.Requirements != nil && len(metadata.Segments) > 1 {
			midway = true
			break
		}
		select {
		case err := <-exited:
			t.Fatalf("cryptsetup reencrypt finished (%v) before it could be interrupted:\n%s", err, output.String())
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := cmd.Process.Signal(unix.SIGKILL); err != nil {
		t.Fatalf("killing cryptsetup failed: %v", err)
	}
	<-exited
	if !midway {
		t.Fatalf("the header never showed the reencryption under way:\n%s", output.String())
	}

	_, metadata, err := ReadHeader(loopDev)
	if err != nil {
		t.Fatalf("ReadHeader after the interruption failed: %v", err)
	}
	if metadata.Config.Requirements == nil || len(metadata.Config.Requirements.Mandatory) == 0 ||
		metadata.Config.Requirements.Mandatory[0] != "online-reencrypt-v2" {
		t.Fatalf("the interrupted container declares %+v, want online-reencrypt-v2", metadata.Config.Requirements)
	}
	if len(metadata.Segments) < 2 {
		t.Fatalf("the interrupted container has %d segment(s); it is not mid-reencryption", len(metadata.Segments))
	}

	name := runVolume(t, "reencrypt")
	defer releaseVolume(t, name)
	err = Unlock(loopDev, []byte(passphrase), name)
	if !errors.Is(err, ErrUnsupportedRequirement) {
		t.Fatalf("Unlock = %v, want ErrUnsupportedRequirement for a container mid-reencryption", err)
	}
	if IsUnlocked(name) {
		t.Fatal("a mapping exists after the refused activation")
	}
}

// --- C1 ---

// TestAnUnboundCryptsetupKeyslotDoesNotActivate is C1 against cryptsetup's
// own unbound keyslot (luksAddKey --unbound). cryptsetup refuses that
// passphrase for activation; so must this package.
func TestAnUnboundCryptsetupKeyslotDoesNotActivate(t *testing.T) {
	requireRoot(t)
	requireCryptsetupDeclared(t)

	const passphrase = "bound-passphrase-1"
	const unbound = "unbound-passphrase-1"
	loopDev, _ := activationLoop(t, "unbound.img", 32, nil)
	cryptsetupRun(t, passphrase, "luksFormat", "--type", "luks2", "--batch-mode",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", "-", loopDev)
	keyFile := filepath.Join(t.TempDir(), "unbound.key")
	if err := os.WriteFile(keyFile, []byte(unbound), 0o600); err != nil {
		t.Fatalf("writing the key file failed: %v", err)
	}
	cryptsetupRun(t, "", "luksAddKey", "--batch-mode", "--unbound", "--key-size", "512",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", loopDev, keyFile)

	name := runVolume(t, "unbound")
	defer releaseVolume(t, name)
	if err := Unlock(loopDev, []byte(unbound), name); !errors.Is(err, ErrMasterKeyVerification) {
		t.Fatalf("Unlock with the unbound keyslot's passphrase = %v, want ErrMasterKeyVerification", err)
	}
	if IsUnlocked(name) {
		t.Fatal("the unbound key was mapped")
	}
	if err := Unlock(loopDev, []byte(passphrase), name); err != nil {
		t.Fatalf("Unlock with the bound passphrase failed: %v", err)
	}
}

// --- C8 ---

// TestFindLoopDeviceFindsAFileNamedThroughASymlink is C8 on the real loop
// driver, which records the backing file by its resolved path: the caller's
// symlink spelling never matched it.
func TestFindLoopDeviceFindsAFileNamedThroughASymlink(t *testing.T) {
	requireRoot(t)

	loopDev, image := activationLoop(t, "symlinked.img", 4, nil)
	link := filepath.Join(t.TempDir(), "alias.img")
	if err := os.Symlink(image, link); err != nil {
		t.Fatalf("symlink failed: %v", err)
	}

	got, err := FindLoopDevice(link)
	if err != nil || got != loopDev {
		t.Fatalf("FindLoopDevice(%s) = %q, %v; want %s", link, got, err, loopDev)
	}
}

// --- C10 ---

// TestIsMappingMountedSeesAMountedMapping is C10 on the real kernel: the CLI's
// close asked IsMounted("/dev/mapper/<name>"), which is false for a mounted
// volume because that path is never a mount point.
func TestIsMappingMountedSeesAMountedMapping(t *testing.T) {
	requireRoot(t)

	loopDev := libraryVolumeLoop(t, "mounted.img")

	name := runVolume(t, "mounted")
	defer releaseVolume(t, name)
	if err := Unlock(loopDev, []byte(canonicalPassphrase), name); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	if err := MakeFilesystem(name, "ext4", ""); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}
	mountPoint := t.TempDir()
	if err := Mount(MountOptions{Device: name, MountPoint: mountPoint, FSType: "ext4"}); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}
	t.Cleanup(func() { _ = Unmount(mountPoint, 0) })

	if mounted, err := IsMappingMounted(name); err != nil || !mounted {
		t.Fatalf("IsMappingMounted = %v, %v; want true while mounted at %s", mounted, err, mountPoint)
	}
	// The question close used to ask, answered wrongly, for the record.
	if mounted, err := IsMounted(mapperNodePath(name)); err != nil || mounted {
		t.Fatalf("IsMounted(%s) = %v, %v; the fixture no longer shows the old defect", mapperNodePath(name), mounted, err)
	}

	if err := Unmount(mountPoint, 0); err != nil {
		t.Fatalf("Unmount failed: %v", err)
	}
	if mounted, err := IsMappingMounted(name); err != nil || mounted {
		t.Fatalf("IsMappingMounted = %v, %v after the unmount; want false", mounted, err)
	}
}
