// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package dmcrypt

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anatol/devmapper.go"
	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	keyringpkg "github.com/jeremyhahn/go-luks2/internal/keyring"
	"github.com/jeremyhahn/go-luks2/internal/volkey"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// formattedVolume formats a real (regular-file) LUKS2 container through
// pkg/luks2's own public API and unlocks it, so Activate can be driven
// against a genuine *luks2.Volume and *luks2.Key rather than a hand-built
// approximation. The volume key never leaves protected memory on the way
// here: Unlock is the same call a real caller makes.
func formattedVolume(t *testing.T) (*luks2.Volume, *luks2.Key) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "volume.img")
	f, err := os.Create(path) //nolint:gosec // path is under t.TempDir()
	if err != nil {
		t.Fatalf("creating the test image failed: %v", err)
	}
	if err := f.Truncate(32 << 20); err != nil {
		t.Fatalf("sizing the test image failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing the test image failed: %v", err)
	}

	passphrase := []byte("dmcrypt-test-passphrase")
	passEnclave, err := enclave.NewMemoryEnclaveCopy(passphrase)
	if err != nil {
		t.Fatalf("could not hold the test passphrase in protected memory: %v", err)
	}
	defer func() { _ = passEnclave.Destroy() }()

	v, err := luks2.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })

	if err := v.Format(context.Background(), passEnclave, luks2.FormatParams{
		KDF: luks2.KDFParams{Type: luks2.KDFPBKDF2, IterTime: time.Millisecond},
	}); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	key, err := v.Unlock(context.Background(), passEnclave)
	if err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	t.Cleanup(key.Destroy)

	return v, key
}

// TestActivateReachesTargetThenFailsOnARegularFile pins the boundary this
// package's own tests cannot cross without root: dm-crypt maps a block
// device, and a regular-file-backed volume -- which is all an unprivileged
// test can format -- must be refused by (*luks2.Volume).Target before any
// dm-crypt state is created. The refusal reaching Activate's caller intact
// proves this package's wiring to the real Volume API, not merely to its
// own fakes.
func TestActivateReachesTargetThenFailsOnARegularFile(t *testing.T) {
	newFakeDeviceMapper().install(t)
	v, key := formattedVolume(t)

	_, err := Activate(context.Background(), v, key, "regular-file-target")
	if !errors.Is(err, luks2.ErrInvalidArgument) {
		t.Fatalf("Activate = %v, want ErrNotBlockDevice", err)
	}
}

// testKey returns a *luks2.Key over key, the way a real recovery or
// UnlockWithVolumeKey would hand one to Activate -- held in protected
// memory, never a plain slice by the time Activate sees it.
func testKey(t *testing.T, key []byte) *luks2.Key {
	t.Helper()

	e, err := enclave.NewMemoryEnclaveCopy(key)
	if err != nil {
		t.Fatalf("could not hold the test key in protected memory: %v", err)
	}
	return volkey.New(e, 0)
}

// recordRetryWaits runs this package's waits on a fake clock that records
// every sleep it is asked for and returns at once.
func recordRetryWaits(t *testing.T) *clock.Fake {
	t.Helper()

	clk := clock.NewFake(t)
	previous := sys.clock
	t.Cleanup(func() { sys.clock = previous })
	sys.clock = clk
	return clk
}

// --- mappingUUID ---

func TestMappingUUIDReadsTheHeaderUUIDAsTheKernelWould(t *testing.T) {
	if got, want := mappingUUID("1234-5678", "vol"), "CRYPT-LUKS2-12345678-vol"; got != want {
		t.Fatalf("mappingUUID = %q, want %q", got, want)
	}
}

func TestMappingUUIDIsCutToWhatTheKernelStores(t *testing.T) {
	name := strings.Repeat("n", MaxNameLength)
	uuid := mappingUUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", name)
	if len(uuid) != dmUUIDMaxLength {
		t.Fatalf("mappingUUID produced %d bytes, want the cut length %d", len(uuid), dmUUIDMaxLength)
	}
	if !strings.HasPrefix(uuid, "CRYPT-LUKS2-") {
		t.Fatalf("mappingUUID = %q, want the cryptsetup form", uuid)
	}
}

// --- activateTable / activateCreated / confirmCreated ---

func testTarget() *luks2.Target {
	return &luks2.Target{
		Major: 7, Minor: 3,
		Offset: 16384, Length: 1048576,
		Cipher: "aes-xts-plain64", KeySize: 512,
		SectorSize: 512,
	}
}

func TestActivateTableCarriesNoKeyOnlyAKeyringReference(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)

	key := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd")
	devNo, created, err := activateTable(context.Background(), "by-reference", "CRYPT-LUKS2-abc-by-reference", "7:3", testTarget(), testKey(t, key))
	if err != nil {
		t.Fatalf("activateTable failed: %v", err)
	}
	if !created {
		t.Fatal("activateTable reported created=false after a successful create")
	}
	if devNo == 0 {
		t.Fatal("activateTable reported devNo=0")
	}

	table := fake.cryptTable(t)
	if len(table.Key) != 0 {
		t.Fatalf("the volume key was placed in the device-mapper table (%d bytes)", len(table.Key))
	}
	if table.KeyID == "" {
		t.Fatal("the table carries no kernel-keyring reference")
	}
	if strings.Contains(table.KeyID, hex.EncodeToString(key)) || strings.Contains(table.KeyID, string(key)) {
		t.Fatalf("the keyring reference carries the volume key: %q", table.KeyID)
	}
	want := ":" + strconv.Itoa(len(key)) + ":logon:"
	if !strings.HasPrefix(table.KeyID, want) {
		t.Errorf("the reference %q does not describe a %d-byte logon key", table.KeyID, len(key))
	}
}

// TestActivateTableRoundsTheLengthDownToTheSectorSize is S11: a dynamic
// segment's length is the device size minus the offset, which need not be a
// multiple of the segment's sector size, and dm-crypt refuses a target whose
// length is not.
func TestActivateTableRoundsTheLengthDownToTheSectorSize(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)

	target := testTarget()
	target.SectorSize = 4096
	target.Length = 1048576 + 512 // a 512-byte-multiple tail, not a 4096 one

	if _, _, err := activateTable(context.Background(), "rounded", "CRYPT-LUKS2-abc-rounded", "7:3", target,
		testKey(t, make([]byte, 32))); err != nil {
		t.Fatalf("activateTable failed: %v", err)
	}
	if got := fake.cryptTable(t).Length; got != 1048576 {
		t.Fatalf("table Length = %d, want %d: rounded down to the 4096 sector size", got, 1048576)
	}
}

func TestActivateTableFailsClosedWhenTheKeyringIsUnavailable(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)
	(&fakeKeyring{addErr: unix.EPERM}).install(t)

	_, created, err := activateTable(context.Background(), "no-keyring", "CRYPT-LUKS2-abc-no-keyring", "7:3", testTarget(),
		testKey(t, make([]byte, 32)))
	if err == nil {
		t.Fatal("activateTable succeeded with the kernel keyring unavailable")
	}
	if !created {
		t.Fatal("activateTable reported created=false; the create ioctl ran before the keyring step and did succeed")
	}
	var kerr *KeyringError
	if !errors.As(err, &kerr) {
		t.Fatalf("the refusal is not a *KeyringError: %T %v", err, err)
	}
	if !errors.Is(err, ErrKeyringBlocked) || !errors.Is(err, ErrKeyringUnavailable) || !errors.Is(err, ErrKeyring) {
		t.Fatalf("the refusal does not match the keyring sentinel family: %v", err)
	}
	if len(fake.loaded) != 0 {
		t.Fatalf("a table was handed to device-mapper despite the keyring refusal: %+v", fake.loaded)
	}
}

func TestActivateTableRefusesWhenAKeyringEntryAlreadyExists(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)
	fk := &fakeKeyring{}
	fk.install(t)

	// Occupy the description THIS activation's AddVolumeKey will compute,
	// exactly as a leftover from a crashed process would.
	uuid := "CRYPT-LUKS2-abc-occupied"
	description := keyringpkg.Description(uuid)
	ring, err := fk.sessionRing()
	if err != nil {
		t.Fatalf("could not resolve the fake session ring: %v", err)
	}
	if _, err := fk.add(keyringpkg.KeyType, description, []byte{1, 2, 3, 4}, ring); err != nil {
		t.Fatalf("could not plant a pre-existing entry: %v", err)
	}

	_, created, err := activateTable(context.Background(), "occupied", uuid, "7:3", testTarget(), testKey(t, make([]byte, 32)))
	if err == nil {
		t.Fatal("activateTable proceeded over a pre-existing keyring entry")
	}
	if !created {
		t.Fatal("activateTable reported created=false; the create ioctl ran before the keyring step and did succeed")
	}
	if !errors.Is(err, ErrKeyringEntryExists) {
		t.Fatalf("the refusal is not matchable as ErrKeyringEntryExists: %v", err)
	}
	if len(fake.loaded) != 0 {
		t.Fatalf("a table was handed to device-mapper anyway: %+v", fake.loaded)
	}
}

func TestActivateTableReleasesTheKeyringEntryWhenTheLoadFails(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.loadErr = errors.New("device-mapper table load failed")
	var reference string
	fake.onLoad = func(_, _ string, tables []devmapper.Table) {
		reference = tables[0].(devmapper.CryptTable).KeyID
	}
	fake.install(t)
	fk := &fakeKeyring{}
	fk.install(t)

	_, created, err := activateTable(context.Background(), "failed-load", "CRYPT-LUKS2-abc-failed-load", "7:3", testTarget(),
		testKey(t, make([]byte, 32)))
	if err == nil {
		t.Fatal("activateTable reported success even though the table load failed")
	}
	if !created {
		t.Fatal("activateTable reported created=false; the create ioctl did succeed")
	}
	if reference == "" {
		t.Fatal("no keyring reference was ever put in the table")
	}
	if fk.linkedKeys(memorySessionRing) != 0 {
		t.Fatal("a failed activation left the volume key in the kernel keyring")
	}
}

func TestActivateTableReportsAKeyringEntryItCouldNotRelease(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)
	stuck := &fakeKeyring{unlinkErr: unix.EACCES}
	stuck.install(t)

	_, created, err := activateTable(context.Background(), "unreleased", "CRYPT-LUKS2-abc-unreleased", "7:3", testTarget(),
		testKey(t, make([]byte, 32)))
	if err == nil {
		t.Fatal("an activation that left the volume key in the kernel keyring reported success")
	}
	if !created {
		t.Fatal("activateTable reported created=false; the create and load did succeed")
	}
	if !errors.Is(err, ErrKeyringKeyNotReleased) {
		t.Fatalf("the failure is not matchable as ErrKeyringKeyNotReleased: %v", err)
	}
	if stuck.linkedKeys(memorySessionRing) != 1 {
		t.Errorf("the activation reported an unreleasable entry but the ring does not hold one")
	}
}

func TestConfirmCreatedReportsAnInspectionFailure(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.infoErr = unix.EACCES
	fake.install(t)

	if err := confirmCreated("vol", "uuid", 1); err == nil {
		t.Fatal("confirmCreated succeeded despite an inspection failure")
	}
}

func TestConfirmCreatedRefusesAReplacedTarget(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["vol"] = "CRYPT-LUKS2-someone-elses"
	fake.devNos["vol"] = 0xfe99
	fake.install(t)

	if err := confirmCreated("vol", "CRYPT-LUKS2-ours", fakeDefaultDevNo); err == nil {
		t.Fatal("confirmCreated accepted a target with a different UUID and device number")
	}
}

func TestActivateCreatedRefusesWhenTheTargetWasReplacedBeforeLoad(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["vol"] = "CRYPT-LUKS2-someone-elses"
	fake.install(t)

	err := activateCreated("vol", "CRYPT-LUKS2-ours", fakeDefaultDevNo, devmapper.CryptTable{})
	if err == nil {
		t.Fatal("activateCreated loaded a table into a target it did not create")
	}
	if len(fake.loaded) != 0 {
		t.Fatalf("a table was loaded despite the identity mismatch: %+v", fake.loaded)
	}
}

func TestActivateCreatedRefusesWhenTheTargetWasReplacedBeforeResume(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["vol"] = "CRYPT-LUKS2-ours"
	fake.install(t)

	calls := 0
	previous := sys.infoByName
	sys.infoByName = func(n string) (*devmapper.DeviceInfo, error) {
		calls++
		if calls == 2 {
			// Replaced between the load and the resume.
			return &devmapper.DeviceInfo{Name: n, UUID: "CRYPT-LUKS2-someone-elses", DevNo: fake.devNoOf(n)}, nil
		}
		return previous(n)
	}
	t.Cleanup(func() { sys.infoByName = previous })

	if err := activateCreated("vol", "CRYPT-LUKS2-ours", fakeDefaultDevNo, devmapper.CryptTable{}); err == nil {
		t.Fatal("activateCreated resumed a target that was replaced after the load")
	}
}

func TestActivateTableRefusesANameAlreadyTaken(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["taken"] = "CRYPT-LUKS2-someone-elses-volume"
	fake.install(t)

	_, created, err := activateTable(context.Background(), "taken", "CRYPT-LUKS2-abc-taken", "7:3", testTarget(), testKey(t, make([]byte, 32)))
	if !errors.Is(err, ErrActive) {
		t.Fatalf("activateTable = %v, want ErrActive for a name another activation took", err)
	}
	if created {
		t.Fatal("activateTable reported created=true for a create the kernel refused")
	}
}

// --- rollback ---

func TestRollbackDoesNothingWhenTheTargetIsAlreadyGone(t *testing.T) {
	newFakeDeviceMapper().install(t)

	if err := rollback(context.Background(), "gone", "CRYPT-LUKS2-gone", fakeDefaultDevNo); err != nil {
		t.Fatalf("rollback = %v; a target that was never created is nothing to roll back", err)
	}
}

func TestRollbackMatchesOnTheUUIDNotTheName(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)

	const name = "shared-name"
	fake.targets[name] = "CRYPT-LUKS2-theirs-" + name

	if err := rollback(context.Background(), name, "CRYPT-LUKS2-ours-"+name, fakeDefaultDevNo); err != nil {
		t.Fatalf("rollback reported a failure for a foreign target: %v", err)
	}
	if len(fake.removed) != 0 {
		t.Fatalf("a foreign target was removed: %v", fake.removed)
	}

	fake.targets[name] = "CRYPT-LUKS2-ours-" + name
	if err := rollback(context.Background(), name, "CRYPT-LUKS2-ours-"+name, fakeDefaultDevNo); err != nil {
		t.Fatalf("rollback failed on its own target: %v", err)
	}
	if _, exists := fake.targets[name]; exists {
		t.Fatal("rollback left its own target live")
	}
}

func TestRollbackIsPinnedToTheCreatedDeviceNumber(t *testing.T) {
	const name = "pinned"
	const uuid = "CRYPT-LUKS2-same-volume-pinned"

	fake := newFakeDeviceMapper()
	fake.targets[name] = uuid
	fake.devNos[name] = 0xfe42 // someone else's activation
	fake.install(t)
	recordRetryWaits(t)

	if err := rollback(context.Background(), name, uuid, 0xfe43); err != nil {
		t.Fatalf("rollback = %v; another activation is nothing to roll back", err)
	}
	if _, live := fake.targets[name]; !live || len(fake.removed) != 0 {
		t.Fatalf("the rollback removed an activation it did not create: removals %v", fake.removed)
	}
}

func TestRollbackStillFailsClosedWhenTheDeviceIsNeverReleased(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["held"] = "CRYPT-LUKS2-held"
	fake.install(t)
	fake.removeErr = os.NewSyscallError("dm ioctl", unix.EBUSY)
	recordRetryWaits(t)

	err := rollback(context.Background(), "held", "CRYPT-LUKS2-held", fakeDefaultDevNo)
	if err == nil {
		t.Fatal("rollback reported success for a target it could not remove")
	}
	if !errors.Is(err, ErrStillLive) {
		t.Fatalf("rollback = %v, want ErrStillLive", err)
	}
}

func TestRollbackRidesOutATransientBusy(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["transient"] = "CRYPT-LUKS2-transient"
	fake.install(t)
	recordRetryWaits(t)

	calls := 0
	previous := sys.remove
	t.Cleanup(func() { sys.remove = previous })
	sys.remove = func(name string) error {
		calls++
		if calls <= 2 {
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return previous(name)
	}

	if err := rollback(context.Background(), "transient", "CRYPT-LUKS2-transient", fakeDefaultDevNo); err != nil {
		t.Fatalf("rollback raised %v for a hold that cleared", err)
	}
	if calls != 3 {
		t.Fatalf("remove was called %d times, want 3", calls)
	}
}

func TestRollbackClearsAStaleInspectionError(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["stale"] = "CRYPT-LUKS2-stale"
	fake.install(t)

	inspects := 0
	previous := sys.infoByName
	sys.infoByName = func(n string) (*devmapper.DeviceInfo, error) {
		inspects++
		if inspects == 1 {
			return nil, os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return previous(n)
	}
	t.Cleanup(func() { sys.infoByName = previous })
	recordRetryWaits(t)

	if err := rollback(context.Background(), "stale", "CRYPT-LUKS2-stale", fakeDefaultDevNo); err != nil {
		t.Fatalf("rollback = %v, want success: the second attempt inspected and removed the target", err)
	}
	if inspects < 2 {
		t.Fatalf("the transient inspection error was not retried (%d inspections)", inspects)
	}
}

func TestRollbackStopsWhenTheTargetDisappearsMidRetry(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["vanishes"] = "CRYPT-LUKS2-vanishes"
	fake.install(t)
	recordRetryWaits(t)

	removeCalls := 0
	previous := sys.remove
	t.Cleanup(func() { sys.remove = previous })
	sys.remove = func(n string) error {
		removeCalls++
		if removeCalls == 1 {
			delete(fake.targets, n)
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return previous(n)
	}

	if err := rollback(context.Background(), "vanishes", "CRYPT-LUKS2-vanishes", fakeDefaultDevNo); err != nil {
		t.Fatalf("rollback = %v; a target that is already gone is the success case", err)
	}
	if removeCalls != 1 {
		t.Fatalf("remove was issued %d times against a target that had vanished", removeCalls)
	}
}

// --- Activate: branches reachable without a real Volume/Target ---

func TestActivateRefusesAnInvalidName(t *testing.T) {
	newFakeDeviceMapper().install(t)

	if _, err := Activate(context.Background(), nil, nil, "../escape"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Activate(../escape) = %v, want ErrInvalidName", err)
	}
}

func TestActivateRefusesAnAlreadyActiveName(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["taken"] = "CRYPT-LUKS2-someone-elses-volume"
	fake.install(t)

	// v and key are never touched on this path: the name collision is
	// refused before either is read.
	if _, err := Activate(context.Background(), nil, nil, "taken"); !errors.Is(err, ErrActive) {
		t.Fatalf("Activate(taken) = %v, want ErrActive", err)
	}
}

func TestActivateHonoursACanceledContext(t *testing.T) {
	newFakeDeviceMapper().install(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Activate(ctx, nil, nil, "vol"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Activate with a canceled context = %v, want context.Canceled", err)
	}
}

func TestDeactivateHonoursACanceledContext(t *testing.T) {
	newFakeDeviceMapper().install(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Deactivate(ctx, "vol"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Deactivate with a canceled context = %v, want context.Canceled", err)
	}
}

func TestCheckKeyringHonoursACanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CheckKeyring(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("CheckKeyring with a canceled context = %v, want context.Canceled", err)
	}
}

// --- Deactivate ---

func TestDeactivateClosesAMappingThatIsOpen(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["open-mapping"] = "CRYPT-LUKS2-open"
	fake.install(t)

	if err := Deactivate(context.Background(), "open-mapping"); err != nil {
		t.Fatalf("Deactivate refused a mapping that is open: %v", err)
	}
	if len(fake.removed) != 1 || fake.removed[0] != "open-mapping" {
		t.Fatalf("the open mapping was not removed; removals were %v", fake.removed)
	}
}

func TestDeactivateRefusesANameNothingHasOpened(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)

	err := Deactivate(context.Background(), "no-such-mapping")
	if !errors.Is(err, ErrNotActive) {
		t.Fatalf("Deactivate = %v, want ErrNotActive", err)
	}
	if len(fake.removed) != 0 {
		t.Fatalf("Deactivate asked device-mapper to remove %v despite there being nothing to close", fake.removed)
	}
}

func TestDeactivateRetriesATransientBusyAndSucceeds(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["busy-then-free"] = "CRYPT-LUKS2-transient"
	fake.install(t)
	recordRetryWaits(t)

	calls := 0
	previous := sys.remove
	t.Cleanup(func() { sys.remove = previous })
	sys.remove = func(name string) error {
		calls++
		if calls <= 2 {
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return previous(name)
	}

	if err := Deactivate(context.Background(), "busy-then-free"); err != nil {
		t.Fatalf("Deactivate = %v, want success once the transient hold clears", err)
	}
	if calls != 3 {
		t.Fatalf("device-mapper remove was called %d times, want 3", calls)
	}
}

func TestDeactivateGivesUpBoundedWhenSomethingGenuinelyHoldsTheDevice(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["genuinely-held"] = "CRYPT-LUKS2-held"
	fake.removeErr = os.NewSyscallError("dm ioctl", unix.EBUSY)
	fake.install(t)
	waits := recordRetryWaits(t)

	err := Deactivate(context.Background(), "genuinely-held")
	if err == nil {
		t.Fatal("Deactivate reported success against a device that is never released")
	}
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("Deactivate = %v, want ErrBusy", err)
	}
	if !errors.Is(err, unix.EBUSY) {
		t.Fatalf("the underlying EBUSY is no longer reachable: %v", err)
	}
	if len(waits.Waits()) == 0 {
		t.Fatal("no backoff was recorded, so nothing was actually retried")
	}
}

func TestDeactivateWillNotRemoveAMappingThatChangedIdentityMidRetry(t *testing.T) {
	fake := newFakeDeviceMapper()
	const name = "recycled-on-close"
	fake.targets[name] = "CRYPT-LUKS2-ours"
	fake.install(t)
	recordRetryWaits(t)

	removeCalls := 0
	previousRemove := sys.remove
	t.Cleanup(func() { sys.remove = previousRemove })
	sys.remove = func(n string) error {
		removeCalls++
		if removeCalls == 1 {
			fake.targets[name] = "CRYPT-LUKS2-SOMEONE-ELSES"
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return previousRemove(n)
	}

	if err := Deactivate(context.Background(), name); err != nil {
		t.Fatalf("Deactivate = %v; the mapping it was asked to close is gone, which is the goal", err)
	}
	if uuid, live := fake.targets[name]; !live || uuid != "CRYPT-LUKS2-SOMEONE-ELSES" {
		t.Fatalf("Deactivate removed a mapping that was not the one it inspected: targets[%q] = %q, live=%v", name, uuid, live)
	}
	if removeCalls != 1 {
		t.Fatalf("remove was issued %d times; the second attempt must be refused by the identity re-check", removeCalls)
	}
}

func TestDeactivateRefusesToRemoveWhenIdentityCannotBeEstablished(t *testing.T) {
	fake := newFakeDeviceMapper()
	const name = "identity-unknown"
	fake.targets[name] = "CRYPT-LUKS2-identity-unknown"
	fake.install(t)

	inspects := 0
	sys.infoByName = func(n string) (*devmapper.DeviceInfo, error) {
		inspects++
		if inspects == 1 {
			return &devmapper.DeviceInfo{Name: n, UUID: fake.targets[n], DevNo: 0xfe00}, nil
		}
		return nil, os.NewSyscallError("dm ioctl", unix.EPERM)
	}
	removes := 0
	sys.remove = func(string) error { removes++; return nil }
	recordRetryWaits(t)

	err := Deactivate(context.Background(), name)
	if err == nil {
		t.Fatal("Deactivate reported success without ever establishing the mapping identity")
	}
	if removes != 0 {
		t.Fatalf("remove was called %d times with an unknown identity", removes)
	}
	if errors.Is(err, ErrNotActive) {
		t.Fatalf("Deactivate = %v, want an inspection failure, not ErrNotActive", err)
	}
}

func TestDeactivateRidesOutATransientIdentityLookupFailure(t *testing.T) {
	fake := newFakeDeviceMapper()
	const name = "transient-identity"
	const uuid = "CRYPT-LUKS2-transient-identity"
	fake.targets[name] = uuid
	fake.install(t)

	inspects := 0
	sys.infoByName = func(n string) (*devmapper.DeviceInfo, error) {
		inspects++
		if inspects == 2 {
			return nil, os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		u, live := fake.targets[n]
		if !live {
			return nil, os.NewSyscallError("dm ioctl", unix.ENXIO)
		}
		return &devmapper.DeviceInfo{Name: n, UUID: u, DevNo: 0xfe00}, nil
	}
	recordRetryWaits(t)

	if err := Deactivate(context.Background(), name); err != nil {
		t.Fatalf("Deactivate = %v, want success: a transient EBUSY from the identity lookup is absorbed", err)
	}
	if inspects < 3 {
		t.Fatalf("the transient lookup failure was not retried (%d inspections)", inspects)
	}
	if _, live := fake.targets[name]; live {
		t.Fatalf("Deactivate returned success but %q is still live", name)
	}
}

// node placement, exercised directly: internal/dm's own suite proves the
// identity-checked mechanics (IsOurNode, PlaceNode, RemoveMappingNodes);
// these pin this package's wiring of devDir/blockNodeRdev/clock into it.

func TestWaitForDeviceReadyReplacesAStaleMapperEntry(t *testing.T) {
	dir := t.TempDir()
	previousDir := sys.devDir
	t.Cleanup(func() { sys.devDir = previousDir })
	sys.devDir = dir
	if err := os.MkdirAll(dir+"/mapper", 0o755); err != nil {
		t.Fatalf("building the fake /dev failed: %v", err)
	}
	stale := dir + "/mapper/fresh"
	if err := os.Symlink("/dev/null", stale); err != nil {
		t.Fatalf("planting the stale node failed: %v", err)
	}

	byInode := map[uint64]uint64{}
	inodeOf := func(path string) (uint64, error) {
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			return 0, err
		}
		return st.Ino, nil
	}
	previousMake, previousRdev := sys.makeBlockNode, sys.blockNodeRdev
	t.Cleanup(func() { sys.makeBlockNode, sys.blockNodeRdev = previousMake, previousRdev })
	sys.makeBlockNode = func(path string, devNo uint64) error {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return err
		}
		ino, err := inodeOf(path)
		if err != nil {
			return err
		}
		major, minor := unix.Major(devNo), unix.Minor(devNo)
		byInode[ino] = unix.Mkdev(major, minor)
		return nil
	}
	sys.blockNodeRdev = func(path string) (uint64, error) {
		ino, err := inodeOf(path)
		if err != nil {
			return 0, err
		}
		if rdev, ok := byInode[ino]; ok {
			return rdev, nil
		}
		return 0, &os.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
	}
	recordRetryWaits(t)

	info := &devmapper.DeviceInfo{Name: "fresh", DevNo: unix.Mkdev(253, 7)}
	if err := waitForDeviceReady(context.Background(), "fresh", info); err != nil {
		t.Fatalf("waitForDeviceReady = %v", err)
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

// withFakeNodes installs a devDir plus a blockNodeRdev that tracks device
// numbers by inode rather than by path, so a node "made" by sys.makeBlockNode
// survives the rename placeNode performs.
func withFakeNodes(t *testing.T) (register func(path string, rdev uint64)) {
	t.Helper()

	dir := t.TempDir()
	previousDir := sys.devDir
	t.Cleanup(func() { sys.devDir = previousDir })
	sys.devDir = dir
	if err := os.MkdirAll(dir+"/mapper", 0o755); err != nil {
		t.Fatalf("building the fake /dev failed: %v", err)
	}

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

	previousMake, previousRdev := sys.makeBlockNode, sys.blockNodeRdev
	t.Cleanup(func() { sys.makeBlockNode, sys.blockNodeRdev = previousMake, previousRdev })
	sys.makeBlockNode = func(path string, devNo uint64) error {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return err
		}
		major, minor := unix.Major(devNo), unix.Minor(devNo)
		register(path, unix.Mkdev(major, minor))
		return nil
	}
	sys.blockNodeRdev = func(path string) (uint64, error) {
		ino, err := inodeOf(path)
		if err != nil {
			return 0, err
		}
		if rdev, ok := byInode[ino]; ok {
			return rdev, nil
		}
		return 0, &os.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
	}
	return register
}

func TestEnsureDeviceNodeSkipsWhenAlreadyCorrect(t *testing.T) {
	register := withFakeNodes(t)
	recordRetryWaits(t)

	info := &devmapper.DeviceInfo{Name: "vol", DevNo: unix.Mkdev(253, 9)}
	dmPath := dmNodePath(9)
	if err := os.WriteFile(dmPath, nil, 0o600); err != nil {
		t.Fatalf("writing the fixture node failed: %v", err)
	}
	register(dmPath, info.DevNo)

	placeCalled := false
	previous := sys.makeBlockNode
	t.Cleanup(func() { sys.makeBlockNode = previous })
	sys.makeBlockNode = func(string, uint64) error { placeCalled = true; return previous("", 0) }

	if err := ensureDeviceNode(context.Background(), "vol", info); err != nil {
		t.Fatalf("ensureDeviceNode = %v", err)
	}
	if placeCalled {
		t.Fatal("ensureDeviceNode replaced a node that already carried the right device number")
	}
}

func TestWaitForDeviceReadyReturnsImmediatelyWhenAlreadyReady(t *testing.T) {
	register := withFakeNodes(t)
	recordRetryWaits(t)

	info := &devmapper.DeviceInfo{Name: "vol", DevNo: unix.Mkdev(253, 11)}
	mapperPath := mapperNodePath("vol")
	if err := os.WriteFile(mapperPath, nil, 0o600); err != nil {
		t.Fatalf("writing the fixture node failed: %v", err)
	}
	register(mapperPath, info.DevNo)

	if err := waitForDeviceReady(context.Background(), "vol", info); err != nil {
		t.Fatalf("waitForDeviceReady = %v", err)
	}
}

// TestWaitForDeviceReadyReportsErrNodeUnverifiedWhenNothingEverVerifies is
// the case pkg/luks2's devicemapper.go used to cover before activation
// moved to this package: when blockNodeRdev never reports the mapping's device
// number -- for the mapper symlink, the dm-N node, or the one this repairs
// into place -- waitForDeviceReady gives up with ErrNodeUnverified rather
// than succeeding on an unverifiable node.
func TestWaitForDeviceReadyReportsErrNodeUnverifiedWhenNothingEverVerifies(t *testing.T) {
	dir := t.TempDir()
	previousDir := sys.devDir
	t.Cleanup(func() { sys.devDir = previousDir })
	sys.devDir = dir
	if err := os.MkdirAll(dir+"/mapper", 0o755); err != nil {
		t.Fatalf("building the fake /dev failed: %v", err)
	}
	recordRetryWaits(t)

	previousRdev := sys.blockNodeRdev
	t.Cleanup(func() { sys.blockNodeRdev = previousRdev })
	sys.blockNodeRdev = func(string) (uint64, error) { return 0, errors.New("no such node") }

	previousMake := sys.makeBlockNode
	t.Cleanup(func() { sys.makeBlockNode = previousMake })
	sys.makeBlockNode = func(path string, _ uint64) error { return os.WriteFile(path, nil, 0o600) }

	info := &devmapper.DeviceInfo{Name: "vol", DevNo: unix.Mkdev(253, 13)}
	err := waitForDeviceReady(context.Background(), "vol", info)
	if !errors.Is(err, ErrNodeUnverified) {
		t.Fatalf("waitForDeviceReady = %v, want ErrNodeUnverified", err)
	}
}

func TestPlaceNodePropagatesAnOrdinaryCreateFailure(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/node"
	sentinel := errors.New("create failed")

	if err := placeNode(context.Background(), path, func(string) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("placeNode = %v, want the create failure reachable unchanged", err)
	}
}

func TestCreateTargetRefusesANameTheIoctlWouldCut(t *testing.T) {
	if _, err := createTarget(context.Background(), strings.Repeat("n", 128), "u"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("createTarget accepted a name the ioctl would cut: %v", err)
	}
	if _, err := createTarget(context.Background(), "n", strings.Repeat("u", 129)); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("createTarget accepted a UUID the ioctl would cut: %v", err)
	}
}

func TestStatBlockRdevRefusesANonBlockDevice(t *testing.T) {
	path := t.TempDir() + "/plain"
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}
	if _, err := statBlockRdev(path); err == nil {
		t.Fatal("statBlockRdev accepted a regular file as a block device")
	}
	if _, err := statBlockRdev(t.TempDir() + "/missing"); err == nil {
		t.Fatal("statBlockRdev succeeded on a path that does not exist")
	}
}

func TestNodeRepairNeverReplacesTheControlNode(t *testing.T) {
	dir := t.TempDir()
	plain := dir + "/plain"
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatalf("writing the fixture failed: %v", err)
	}
	for _, target := range []string{"/dev/null", dir, plain} {
		created := false
		err := placeNode(context.Background(), target, func(string) error { created = true; return nil })
		if !errors.Is(err, ErrNodeUnverified) || created {
			t.Errorf("placeNode(%s) = %v (created=%v), want a refusal before anything is made", target, err, created)
		}
	}
}

// ensure the fake clock type is actually exercised in these tests, so a
// change that stopped reading sys.clock would be caught by a timeout
// instead of silently passing.
func TestRecordRetryWaitsActuallyRoutesThroughTheClockSeam(t *testing.T) {
	clk := recordRetryWaits(t)
	clk.OnWait(func(time.Time) {})
	_, _ = retryWhileBusy(context.Background(), func() error { return os.NewSyscallError("dm ioctl", unix.EBUSY) })
	if len(clk.Waits()) == 0 {
		t.Fatal("retryWhileBusy never consulted the fake clock")
	}
}
