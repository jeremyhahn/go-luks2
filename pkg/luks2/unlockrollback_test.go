// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"
)

// Unlock must be TRANSACTIONAL with respect to the dm-crypt target it creates.
//
// The defect these tests pin (#76) is not untidiness. If CreateAndLoad succeeds
// and the readiness check then fails -- missing or delayed udev, a device node
// that could not be made -- the target stays live while Unlock returns an
// error. The mapping is DECRYPTED DATA. A caller told "unlock failed" is
// entitled to assume no plaintext device exists, so nothing in its error path
// removes one, and the plaintext mapping outlives the operation with no owner.
//
// It cascades, too: in go-blockstore the rollback then tries to deactivate the
// backing LV and fails because the mapping still holds it open, so the operator
// gets a failed attach, a live plaintext mapping AND an activated LV -- the
// opposite of what the error reported.
//
// # Why these tests inject at the seam
//
// Producing this state for real needs root and a real kernel: dm activation is
// privileged, and the test account here is uid 1000. A failure that can only be
// reproduced in a privileged integration environment is a failure nothing
// checks on the way in. So the tests replace the deviceMapper value with a fake
// that records what was asked of it, and drive the exact sequence the kernel
// and udev produce.

// fakeDeviceMapper records dm operations and can be told to fail any of them.
type fakeDeviceMapper struct {
	// targets is the live dm state: name -> uuid.
	targets map[string]string

	// devNos is each target's device number, set by create. A target a test
	// put in targets directly has fakeDefaultDevNo.
	devNos  map[string]uint64
	nextDev uint64

	createErr error
	loadErr   error
	resumeErr error
	nodeErr   error
	readyErr  error
	removeErr error

	// infoErr, when set, is returned by infoByName INSTEAD of consulting
	// targets, so a test can model an inspection that fails for a reason other
	// than the target being absent.
	infoErr error

	created  []string
	removed  []string
	inspects int

	// loaded records the tables handed to load, so a test can assert on WHAT
	// device-mapper was given and not merely that it was called. The dm-crypt
	// table is where the volume key used to travel; see unlockkeyring_test.go.
	loaded []devmapper.Table

	// onLoad, when set, runs inside load -- at the moment the kernel would be
	// resolving the table -- so a test can observe state that exists only for
	// the duration of the activation call.
	onLoad func(name, uuid string, tables []devmapper.Table)

	// readyInfo records the identity waitReady was asked to wait for.
	readyInfo *devmapper.DeviceInfo
}

// fakeDefaultDevNo is the device number of a target a test placed directly.
const fakeDefaultDevNo = 0xfe00

func newFakeDeviceMapper() *fakeDeviceMapper {
	return &fakeDeviceMapper{targets: map[string]string{}, devNos: map[string]uint64{}, nextDev: 0xfe10}
}

func (f *fakeDeviceMapper) devNoOf(name string) uint64 {
	if devNo, ok := f.devNos[name]; ok {
		return devNo
	}
	return fakeDefaultDevNo
}

func (f *fakeDeviceMapper) install(t *testing.T) {
	t.Helper()

	previous := dm
	t.Cleanup(func() { dm = previous })

	// A fake device mapper maps the regular-file images the unit tests use.
	withImageAsBlockDevice(t)

	dm = deviceMapper{
		create: func(name, uuid string) (uint64, error) {
			if f.createErr != nil {
				return 0, f.createErr
			}
			if _, exists := f.targets[name]; exists {
				// What the kernel does: a create against a name in use fails.
				return 0, os.NewSyscallError("dm ioctl DM_DEV_CREATE", unix.EBUSY)
			}
			// What the kernel stores: a C string of at most 128 bytes.
			if i := strings.IndexByte(uuid, 0); i >= 0 {
				uuid = uuid[:i]
			}
			if len(uuid) > dmUUIDMaxLength {
				uuid = uuid[:dmUUIDMaxLength]
			}
			f.targets[name] = uuid
			f.devNos[name] = f.nextDev
			f.nextDev++
			f.created = append(f.created, name)
			return f.devNos[name], nil
		},
		load: func(name string, table devmapper.Table) error {
			f.loaded = append(f.loaded, snapshotTable(table))
			if f.onLoad != nil {
				f.onLoad(name, f.targets[name], []devmapper.Table{table})
			}
			return f.loadErr
		},
		resume: func(string) error { return f.resumeErr },
		infoByName: func(name string) (*devmapper.DeviceInfo, error) {
			f.inspects++
			if f.infoErr != nil {
				return nil, f.infoErr
			}
			uuid, exists := f.targets[name]
			if !exists {
				return nil, os.NewSyscallError("dm ioctl", unix.ENXIO)
			}
			return &devmapper.DeviceInfo{Name: name, UUID: uuid, DevNo: f.devNoOf(name)}, nil
		},
		remove: func(name string) error {
			f.removed = append(f.removed, name)
			if f.removeErr != nil {
				return f.removeErr
			}
			delete(f.targets, name)
			delete(f.devNos, name)
			return nil
		},
		ensureNode: func(string, *devmapper.DeviceInfo) error { return f.nodeErr },
		waitReady: func(_ string, info *devmapper.DeviceInfo) error {
			f.readyInfo = info
			return f.readyErr
		},
	}
}

// snapshotTable copies a table for later inspection, taking its own copy of any
// key bytes.
//
// The copy is not tidiness. On the in-table fallback path CryptTable.Key is the
// slice BORROWED from the enclave, and go-enclave unmaps those pages when the
// borrow window closes -- so a test that kept the table verbatim and read Key
// after Unlock returned would fault on unmapped memory. That the recorded table
// has to be copied at all is itself evidence the borrow is real: the real
// device-mapper consumes the table inside the window and keeps nothing.
func snapshotTable(table devmapper.Table) devmapper.Table {
	crypt, ok := table.(devmapper.CryptTable)
	if !ok {
		return table
	}
	crypt.Key = append([]byte(nil), crypt.Key...)
	return crypt
}

// cryptTable returns the single dm-crypt table that was loaded, failing the
// test if the count is anything other than one.
func (f *fakeDeviceMapper) cryptTable(t *testing.T) devmapper.CryptTable {
	t.Helper()

	if len(f.loaded) != 1 {
		t.Fatalf("expected exactly one table to be loaded, got %d", len(f.loaded))
	}
	table, ok := f.loaded[0].(devmapper.CryptTable)
	if !ok {
		t.Fatalf("the loaded table is a %T, not a devmapper.CryptTable", f.loaded[0])
	}
	return table
}

// live reports whether any dm target is still present.
func (f *fakeDeviceMapper) live() []string {
	names := make([]string, 0, len(f.targets))
	for name := range f.targets {
		names = append(names, name)
	}
	return names
}

// unlockableVolume returns a formatted container and the passphrase that opens
// it, so the tests below exercise the REAL unlock path down to the dm call
// rather than a stub of it. Everything before the mapping -- header parsing,
// keyslot scan, key derivation, digest verification -- runs for real.
func unlockableVolume(t *testing.T) (string, []byte) {
	t.Helper()

	path := newImage(t, "rollback.img")
	formatWithLibrary(t, path)
	return path, []byte(conformancePassphrase)
}

// fakeBackingDevNo is the device number a regular-file image is given when a
// test maps it through the fake device mapper.
const fakeBackingDevNo = 0x0703 // 7:3, a loop device

// withImageAsBlockDevice lets Unlock map a regular-file image: the unit tests
// cannot create block devices, and Unlock refuses anything else (C6). The
// fstat seam reports the image as loop device 7:3, and cryptsetup's lock
// directory is one of the test's own, so the read lock Unlock takes for 7:3
// never touches the host's /run/cryptsetup.
func withImageAsBlockDevice(t *testing.T) {
	t.Helper()

	previous := blockDeviceOf
	previousDir := cryptsetupLockDir
	t.Cleanup(func() { blockDeviceOf, cryptsetupLockDir = previous, previousDir })
	blockDeviceOf = func(*os.File) (uint64, error) { return fakeBackingDevNo, nil }
	cryptsetupLockDir = filepath.Join(t.TempDir(), "cryptsetup")
}

// TestUnlockRemovesTheMappingWhenReadinessFails is the regression test for #76.
//
// Before the fix this failed on the final assertion: Unlock reported "device not
// ready after unlock" and left "rollback-target" live.
func TestUnlockRemovesTheMappingWhenReadinessFails(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	fake.readyErr = errors.New("udev never created the node")
	fake.install(t)

	err := Unlock(device, passphrase, "rollback-target")
	if err == nil {
		t.Fatal("Unlock reported success even though the device never became ready")
	}
	if !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("the reported failure is not the readiness one: %v", err)
	}

	// The whole point: the caller was told the unlock failed, so no plaintext
	// device may be left behind for it to not know about.
	if live := fake.live(); len(live) != 0 {
		t.Fatalf("Unlock failed but left live device-mapper targets: %v", live)
	}
	if len(fake.created) != 1 {
		t.Fatalf("expected exactly one target to be created, got %v", fake.created)
	}
	if len(fake.removed) != 1 || fake.removed[0] != "rollback-target" {
		t.Fatalf("the created target was not removed; removals were %v", fake.removed)
	}
}

// TestUnlockRemovesTheMappingWhenTheLoadItselfFailsPartway covers the other
// half of the same transaction.
//
// The activation is create-then-load-then-resume, and a failure after the
// create leaves a target behind whichever step it was. The rollback has to run
// on that path too, not only after the readiness check.
func TestUnlockRemovesTheMappingWhenTheLoadItselfFailsPartway(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	// Model a failed resume: the target exists and has its table, and the
	// activation still reports failure.
	fake.resumeErr = errors.New("device-mapper resume failed")
	fake.install(t)

	err := Unlock(device, passphrase, "half-created")
	if err == nil {
		t.Fatal("Unlock reported success even though the table load failed")
	}

	if live := fake.live(); len(live) != 0 {
		t.Fatalf("a half-created target was left live: %v", live)
	}
}

// TestUnlockRefusesToRemoveAMappingItDidNotCreate is the safety half, and it
// matters as much as the cleanup.
//
// A rollback that removes by NAME would, in the window between this unlock's
// create and its readiness failure, happily take down a mapping some other
// process created under the same name -- turning a cleanup path into a denial
// of service on a volume this call never touched, on an error path where nobody
// would think to look.
func TestUnlockRefusesToRemoveAMappingItDidNotCreate(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	fake.readyErr = errors.New("udev never created the node")
	fake.install(t)

	// Between the create and the readiness check, somebody else's mapping takes
	// over the name.
	previous := dm.waitReady
	dm.waitReady = func(name string, info *devmapper.DeviceInfo) error {
		fake.targets[name] = "CRYPT-LUKS2-somebodyelse-" + name
		return previous(name, info)
	}

	if err := Unlock(device, passphrase, "contended"); err == nil {
		t.Fatal("Unlock reported success even though the device never became ready")
	}

	if _, exists := fake.targets["contended"]; !exists {
		t.Fatal("the rollback removed a device-mapper target this unlock did not create")
	}
	if len(fake.removed) != 0 {
		t.Fatalf("the rollback issued removals for a foreign target: %v", fake.removed)
	}
}

// TestUnlockReportsAMappingItCouldNotRemove covers the case where the rollback
// itself fails.
//
// Silence here would be the worst outcome of all: the caller would read an
// ordinary readiness failure and have no way to learn that a decrypted device
// is sitting there. The error must say so, and must be matchable so a caller
// can branch on it rather than parse text.
func TestUnlockReportsAMappingItCouldNotRemove(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	fake.readyErr = errors.New("udev never created the node")
	fake.removeErr = os.NewSyscallError("dm ioctl", unix.EBUSY)
	fake.install(t)

	err := Unlock(device, passphrase, "stuck")
	if err == nil {
		t.Fatal("Unlock reported success")
	}
	if !errors.Is(err, ErrMappingStillLive) {
		t.Fatalf("a mapping that could not be removed was not reported as still live: %v", err)
	}
	// The original cause is still there: an operator needs both facts, not
	// whichever one the error path happened to keep.
	if !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("the readiness failure was lost behind the rollback failure: %v", err)
	}
	if !strings.Contains(err.Error(), "luks2 close stuck") {
		t.Fatalf("the error does not tell an operator how to clean up: %v", err)
	}
}

// TestUnlockReportsAMappingItCouldNotInspect pins the conservative direction.
//
// If the target cannot be inspected for a reason other than its absence -- a
// permission failure, an interrupted syscall -- then whether a plaintext
// mapping is live is UNKNOWN. Unknown must be reported as possibly-live, not
// assumed gone: the cost of a false alarm is an operator checking dmsetup, and
// the cost of a false all-clear is an unowned decrypted device.
func TestUnlockReportsAMappingItCouldNotInspect(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	fake.readyErr = errors.New("udev never created the node")
	fake.infoErr = os.NewSyscallError("dm ioctl", unix.EACCES)
	fake.install(t)

	err := Unlock(device, passphrase, "unknowable")
	if !errors.Is(err, ErrMappingStillLive) {
		t.Fatalf("an uninspectable target was not reported as possibly live: %v", err)
	}
	if len(fake.removed) != 0 {
		t.Fatalf("a target that could not be identified was removed anyway: %v", fake.removed)
	}
}

// TestUnlockTreatsAnAbsentTargetAsNothingToClean is the control on the test
// above: ENXIO really is the kernel saying the target is gone, and it must NOT
// raise a false alarm. Without this, reporting every inspection failure as a
// live mapping would pass the previous test while making the common,
// already-cleaned-up case look like a leak.
func TestUnlockTreatsAnAbsentTargetAsNothingToClean(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	fake.readyErr = errors.New("udev never created the node")
	fake.install(t)

	// Model devmapper's own cleanup having already removed the target.
	previous := dm.waitReady
	dm.waitReady = func(name string, info *devmapper.DeviceInfo) error {
		delete(fake.targets, name)
		return previous(name, info)
	}

	err := Unlock(device, passphrase, "already-gone")
	if err == nil {
		t.Fatal("Unlock reported success")
	}
	if errors.Is(err, ErrMappingStillLive) {
		t.Fatalf("an already-removed target was reported as still live: %v", err)
	}
	if len(fake.removed) != 0 {
		t.Fatalf("a removal was issued for a target that was already gone: %v", fake.removed)
	}
}

// TestUnlockSurfacesAFailedDeviceNodeCreation covers the ignored error at the
// ensureDeviceNode call.
//
// Keeping it non-fatal is right -- the device may still be reachable through
// /dev/mapper -- but it must not be SILENT when the readiness check then fails,
// because the two are almost always the same story and an operator reading only
// "device not ready" has no reason to look at mknod.
func TestUnlockSurfacesAFailedDeviceNodeCreation(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	fake.nodeErr = errors.New("mknod: operation not permitted")
	fake.readyErr = errors.New("udev never created the node")
	fake.install(t)

	err := Unlock(device, passphrase, "no-node")
	if err == nil {
		t.Fatal("Unlock reported success")
	}
	if !strings.Contains(err.Error(), "mknod") {
		t.Fatalf("the device-node failure was swallowed: %v", err)
	}
	if live := fake.live(); len(live) != 0 {
		t.Fatalf("Unlock failed but left live device-mapper targets: %v", live)
	}
}

// TestUnlockKeepsTheMappingWhenItSucceeds is the control that stops every
// assertion above from being satisfiable by a function that always rolls back.
func TestUnlockKeepsTheMappingWhenItSucceeds(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	fake := newFakeDeviceMapper()
	fake.install(t)

	if err := Unlock(device, passphrase, "good"); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	if len(fake.removed) != 0 {
		t.Fatalf("a successful unlock removed its own mapping: %v", fake.removed)
	}
	if uuid, exists := fake.targets["good"]; !exists {
		t.Fatal("a successful unlock left no mapping")
	} else if !strings.HasPrefix(uuid, "CRYPT-LUKS2-") {
		t.Fatalf("the mapping carries an unexpected dm UUID: %q", uuid)
	}
}

// TestRemoveCreatedMappingMatchesOnTheUUIDNotTheName exercises the identity
// check directly, at the boundary where a name collision is decided.
func TestRemoveCreatedMappingMatchesOnTheUUIDNotTheName(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)

	const name = "shared-name"
	fake.targets[name] = "CRYPT-LUKS2-theirs-" + name

	if err := removeCreatedMapping(name, "CRYPT-LUKS2-ours-"+name, fakeDefaultDevNo); err != nil {
		t.Fatalf("removeCreatedMapping reported a failure for a foreign target: %v", err)
	}
	if len(fake.removed) != 0 {
		t.Fatalf("a foreign target was removed: %v", fake.removed)
	}

	// The same name, now genuinely ours, must be removed.
	fake.targets[name] = "CRYPT-LUKS2-ours-" + name
	if err := removeCreatedMapping(name, "CRYPT-LUKS2-ours-"+name, fakeDefaultDevNo); err != nil {
		t.Fatalf("removeCreatedMapping failed on its own target: %v", err)
	}
	if _, exists := fake.targets[name]; exists {
		t.Fatal("removeCreatedMapping left its own target live")
	}
}

func TestIsNoSuchDeviceDistinguishesAbsenceFromIgnorance(t *testing.T) {
	absent := []error{
		os.NewSyscallError("dm ioctl", unix.ENXIO),
		os.NewSyscallError("dm ioctl", unix.ENODEV),
		fmt.Errorf("wrapped: %w", os.NewSyscallError("dm ioctl", unix.ENXIO)),
	}
	for _, err := range absent {
		if !isNoSuchDevice(err) {
			t.Errorf("isNoSuchDevice(%v) = false, want true", err)
		}
	}

	// ENOENT is the interesting one: it comes from opening /dev/mapper/control,
	// so it says dm cannot be queried, not that the target is gone.
	unknown := []error{
		os.NewSyscallError("dm ioctl", unix.EACCES),
		os.NewSyscallError("dm ioctl", unix.EINTR),
		&os.PathError{Op: "open", Path: "/dev/mapper/control", Err: unix.ENOENT},
		errors.New("something else entirely"),
	}
	for _, err := range unknown {
		if isNoSuchDevice(err) {
			t.Errorf("isNoSuchDevice(%v) = true, want false", err)
		}
	}
}
