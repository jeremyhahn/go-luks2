// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package dmcrypt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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
	dmpkg "github.com/jeremyhahn/go-luks2/internal/dm"
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
	passEnclave, err := enclave.NewMemoryCopy(passphrase)
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

	e, err := enclave.NewMemoryCopy(key)
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

	key := randomKey(t, 62)
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

func randomKey(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to generate %d random bytes: %v", n, err)
	}
	return b
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

// TestActivateTableRefusesAZeroOrNegativeSectorSize is the SPEC row of
// docs/dm-crypt-activation/architecture.md: a table whose sector size is zero
// or negative is refused, and no table reaches device-mapper.
func TestActivateTableRefusesAZeroOrNegativeSectorSize(t *testing.T) {
	for _, size := range []int{0, -512} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			fake := newFakeDeviceMapper()
			fake.install(t)

			target := testTarget()
			target.SectorSize = size

			_, _, err := activateTable(context.Background(), "bad-sector", "CRYPT-LUKS2-abc-bad-sector", "7:3", target,
				testKey(t, make([]byte, 32)))
			if !errors.Is(err, luks2.ErrInvalidArgument) {
				t.Fatalf("activateTable(sector size %d) = %v, want ErrInvalidArgument", size, err)
			}
			if len(fake.loaded) != 0 {
				t.Fatalf("a table with sector size %d was handed to device-mapper: %+v", size, fake.loaded)
			}
		})
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

// TestRollbackStillLiveMessagesNameTheTargetAndRemedy pins the detail text of
// both fail-closed rollback outcomes: a target held past the budget and a
// target that cannot be inspected. Each names the target and what to run.
func TestRollbackStillLiveMessagesNameTheTargetAndRemedy(t *testing.T) {
	t.Run("held", func(t *testing.T) {
		fake := newFakeDeviceMapper()
		fake.targets["held-msg"] = "CRYPT-LUKS2-held-msg"
		fake.install(t)
		fake.removeErr = os.NewSyscallError("dm ioctl", unix.EBUSY)
		recordRetryWaits(t)

		err := rollback(context.Background(), "held-msg", "CRYPT-LUKS2-held-msg", fakeDefaultDevNo)
		if !errors.Is(err, ErrStillLive) {
			t.Fatalf("rollback = %v, want ErrStillLive", err)
		}
		for _, want := range []string{
			`"held-msg"`, "STILL LIVE", "over " + dmpkg.RemoveRetryBudget.String(),
			`dmcrypt.Deactivate(ctx, "held-msg")`,
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("message lacks %q:\n%v", want, err)
			}
		}
	})
	t.Run("uninspectable", func(t *testing.T) {
		fake := newFakeDeviceMapper()
		fake.targets["blind-msg"] = "CRYPT-LUKS2-blind-msg"
		fake.install(t)
		previous := sys.infoByName
		t.Cleanup(func() { sys.infoByName = previous })
		sys.infoByName = func(string) (*devmapper.DeviceInfo, error) {
			return nil, os.NewSyscallError("dm ioctl", unix.EIO)
		}
		recordRetryWaits(t)

		err := rollback(context.Background(), "blind-msg", "CRYPT-LUKS2-blind-msg", fakeDefaultDevNo)
		if !errors.Is(err, ErrStillLive) {
			t.Fatalf("rollback = %v, want ErrStillLive", err)
		}
		for _, want := range []string{`"blind-msg"`, "cannot be confirmed removed", "dmsetup info blind-msg"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("message lacks %q:\n%v", want, err)
			}
		}
	})
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

// holdFirstRemove makes the first removal attempt fail as briefly held (a
// udev rule), so a rollback has to retry, and a retry bound to a canceled
// caller's context would give up and leave the plaintext target live. Call
// it after the fake device-mapper is installed.
func holdFirstRemove(t *testing.T) {
	t.Helper()
	remove := sys.remove
	held := true
	sys.remove = func(name string) error {
		if held {
			held = false
			return os.NewSyscallError("dm ioctl", unix.EBUSY)
		}
		return remove(name)
	}
}

// assertRolledBack fails the test unless the target this activation created
// under name was removed and nothing is left live under the name.
func assertRolledBack(t *testing.T, fake *fakeDeviceMapper, name string, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("activateTarget reported success for an activation that failed after its create")
	}
	if errors.Is(err, ErrStillLive) {
		t.Fatalf("the rollback did not confirm the removal: %v", err)
	}
	if len(fake.created) != 1 || fake.created[0] != name {
		t.Fatalf("created = %v, want exactly [%s]", fake.created, name)
	}
	if _, live := fake.targets[name]; live {
		t.Fatalf("the target %q this activation created is still live after its failure", name)
	}
}

func TestActivateTargetReturnsTheVerifiedMapping(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)
	ring := &fakeKeyring{}
	ring.install(t)

	const name, uuid = "fresh", "CRYPT-LUKS2-abc-fresh"
	m, err := activateTarget(context.Background(), name, uuid, testTarget(), testKey(t, make([]byte, 32)))
	if err != nil {
		t.Fatalf("activateTarget = %v", err)
	}
	devNo := fake.devNos[name]
	if m.Name != name || m.UUID != uuid || m.Major != unix.Major(devNo) || m.Minor != unix.Minor(devNo) {
		t.Fatalf("mapping = %+v, want %s %s %d:%d", m, name, uuid, unix.Major(devNo), unix.Minor(devNo))
	}
	if fake.readyInfo == nil || fake.readyInfo.UUID != uuid || fake.readyInfo.DevNo != devNo {
		t.Fatalf("waitReady waited for %+v, not the created target", fake.readyInfo)
	}
	if n := ring.linkedKeys(memorySessionRing); n != 0 {
		t.Fatalf("the session ring holds %d entries after a successful activation, want 0", n)
	}
	if len(fake.removed) != 0 {
		t.Fatalf("a successful activation removed %v", fake.removed)
	}
}

func TestActivateTargetRollsBackAFailureAfterCreateEvenWhenTheCallerCanceled(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)
	fake.loadErr = os.NewSyscallError("dm ioctl DM_TABLE_LOAD", unix.EINVAL)
	recordRetryWaits(t)

	holdFirstRemove(t)

	ctx, cancel := context.WithCancel(context.Background())
	fake.onLoad = func(string, string, []devmapper.Table) { cancel() }

	ring := &fakeKeyring{}
	ring.install(t)

	_, err := activateTarget(ctx, "canceled", "CRYPT-LUKS2-abc-canceled", testTarget(), testKey(t, make([]byte, 32)))
	assertRolledBack(t, fake, "canceled", err)
	if n := ring.linkedKeys(memorySessionRing); n != 0 {
		t.Fatalf("the caller's cancellation left %d keyring entries; the release must complete regardless", n)
	}
}

func TestActivateTargetRollsBackWhenTheKeyringCannotHoldTheKey(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)
	(&fakeKeyring{addErr: unix.EPERM}).install(t)

	_, err := activateTarget(context.Background(), "blocked", "CRYPT-LUKS2-abc-blocked", testTarget(), testKey(t, make([]byte, 32)))
	assertRolledBack(t, fake, "blocked", err)
	if !errors.Is(err, ErrKeyringBlocked) || !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("activateTarget = %v, want ErrKeyringBlocked under ErrKeyringUnavailable", err)
	}
	if len(fake.loaded) != 0 {
		t.Fatalf("a table was loaded although the keyring could not hold the key: %d table(s)", len(fake.loaded))
	}
}

func TestActivateTableReleasesTheKeyringEntryOnAPanic(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)
	ring := &fakeKeyring{}
	ring.install(t)
	fake.onLoad = func(string, string, []devmapper.Table) { panic("load blew up") }

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the panic inside the activation was swallowed, not re-raised")
			}
		}()
		_, _, _ = activateTable(context.Background(), "panicked", "CRYPT-LUKS2-abc-panicked", "7:3", testTarget(), testKey(t, make([]byte, 32)))
	}()
	if len(ring.added) != 1 {
		t.Fatalf("keyring adds = %v, want one", ring.added)
	}
	if n := ring.linkedKeys(memorySessionRing); n != 0 {
		t.Fatalf("a panic during the load left %d keyring entries holding the volume key", n)
	}
}

func TestActivateTargetRollsBackWhenTheKeyringEntryIsNotReleased(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)
	stuck := &fakeKeyring{unlinkErr: unix.EACCES}
	stuck.install(t)

	_, err := activateTarget(context.Background(), "unreleased", "CRYPT-LUKS2-abc-unreleased", testTarget(), testKey(t, make([]byte, 32)))
	assertRolledBack(t, fake, "unreleased", err)
	if !errors.Is(err, ErrKeyringKeyNotReleased) {
		t.Fatalf("activateTarget = %v, want ErrKeyringKeyNotReleased", err)
	}
}

func TestActivateTargetRollsBackWhenTheNodeNeverVerifies(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)
	fake.nodeErr = errors.New("mknod refused")
	fake.readyErr = &Error{Kind: ErrNodeUnverified, Detail: "no node verified"}
	recordRetryWaits(t)
	holdFirstRemove(t)

	// The caller gives up while the node is awaited; the rollback still runs.
	ctx, cancel := context.WithCancel(context.Background())
	waitReady := sys.waitReady
	sys.waitReady = func(ctx context.Context, name string, info *devmapper.DeviceInfo) error {
		cancel()
		return waitReady(ctx, name, info)
	}

	_, err := activateTarget(ctx, "unverified", "CRYPT-LUKS2-abc-unverified", testTarget(), testKey(t, make([]byte, 32)))
	assertRolledBack(t, fake, "unverified", err)
	if !errors.Is(err, ErrNodeUnverified) {
		t.Fatalf("activateTarget = %v, want ErrNodeUnverified", err)
	}
	if !strings.Contains(err.Error(), "mknod refused") {
		t.Errorf("the node failure that explains the readiness failure is not reported: %v", err)
	}
}

func TestActivateTargetJoinsTheCauseWithAFailedRollback(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.install(t)
	(&fakeKeyring{addErr: unix.EDQUOT}).install(t)
	fake.removeErr = os.NewSyscallError("dm ioctl", unix.EBUSY)
	recordRetryWaits(t)

	_, err := activateTarget(context.Background(), "stuck", "CRYPT-LUKS2-abc-stuck", testTarget(), testKey(t, make([]byte, 32)))
	if !errors.Is(err, ErrStillLive) {
		t.Fatalf("activateTarget = %v, want ErrStillLive for a rollback that could not remove the target", err)
	}
	if !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("activateTarget = %v, the keyring cause is lost from the joined error", err)
	}
	if !strings.Contains(err.Error(), "Deactivate") {
		t.Errorf("ErrStillLive does not name the Deactivate call that closes the target: %v", err)
	}
}

func TestActivateTargetLoserOfTheCreateRaceRemovesNothing(t *testing.T) {
	fake := newFakeDeviceMapper()
	const theirs = "CRYPT-LUKS2-winner-raced"
	fake.targets["raced"] = theirs
	fake.install(t)

	_, err := activateTarget(context.Background(), "raced", "CRYPT-LUKS2-loser-raced", testTarget(), testKey(t, make([]byte, 32)))
	if !errors.Is(err, ErrActive) {
		t.Fatalf("activateTarget = %v, want ErrActive for the loser of the create race", err)
	}
	if len(fake.removed) != 0 || fake.targets["raced"] != theirs {
		t.Fatalf("the loser of the create race touched the winner's target: removed=%v targets=%v", fake.removed, fake.targets)
	}
}

// TestActivatePrivilegeRefusalsAreErrPermissionDenied: every device-mapper
// and /dev node step of an activation that the kernel refuses for lack of
// privilege is ErrPermissionDenied (engineering.md, error table), with the
// errno still reachable: the name check, the create, the table load and the
// node.
func TestActivatePrivilegeRefusalsAreErrPermissionDenied(t *testing.T) {
	want := func(t *testing.T, step string, err error, errno unix.Errno) {
		t.Helper()
		if !errors.Is(err, ErrPermissionDenied) || !errors.Is(err, errno) {
			t.Errorf("%s refused with %v = %v, want ErrPermissionDenied wrapping the errno", step, errno, err)
		}
	}
	t.Run("name check", func(t *testing.T) {
		fake := newFakeDeviceMapper()
		fake.infoErr = os.NewSyscallError("dm ioctl", unix.EACCES)
		fake.install(t)
		// The refusal comes before the volume is read: a zero one will do.
		_, err := Activate(context.Background(), &luks2.Volume{}, testKey(t, make([]byte, 32)), "denied")
		want(t, "the name check", err, unix.EACCES)
	})
	t.Run("create", func(t *testing.T) {
		fake := newFakeDeviceMapper()
		fake.createErr = os.NewSyscallError("dm ioctl DM_DEV_CREATE", unix.EPERM)
		fake.install(t)
		(&fakeKeyring{}).install(t)
		_, err := activateTarget(context.Background(), "denied", "CRYPT-LUKS2-abc-denied", testTarget(), testKey(t, make([]byte, 32)))
		want(t, "the create", err, unix.EPERM)
	})
	t.Run("load", func(t *testing.T) {
		fake := newFakeDeviceMapper()
		fake.loadErr = os.NewSyscallError("dm ioctl DM_TABLE_LOAD", unix.EACCES)
		fake.install(t)
		(&fakeKeyring{}).install(t)
		recordRetryWaits(t)
		_, err := activateTarget(context.Background(), "denied", "CRYPT-LUKS2-abc-denied", testTarget(), testKey(t, make([]byte, 32)))
		want(t, "the table load", err, unix.EACCES)
		assertRolledBack(t, fake, "denied", err)
	})
	t.Run("node", func(t *testing.T) {
		withFakeNodes(t)
		previous := sys.makeBlockNode
		t.Cleanup(func() { sys.makeBlockNode = previous })
		sys.makeBlockNode = func(string, uint64) error { return os.NewSyscallError("mknod", unix.EPERM) }
		info := &devmapper.DeviceInfo{Name: "denied", DevNo: unix.Mkdev(253, 21)}
		want(t, "the device node", ensureDeviceNode(context.Background(), "denied", info), unix.EPERM)
	})
}

// --- Activate: branches reachable without a real Volume/Target ---

func TestActivateRefusesAnInvalidName(t *testing.T) {
	newFakeDeviceMapper().install(t)

	if _, err := Activate(context.Background(), nil, nil, "../escape"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Activate(../escape) = %v, want ErrInvalidName", err)
	}
}

// A nil Volume or Key is refused before the device-mapper is consulted: the
// name below is taken, so a guard that came after that lookup would report
// ErrActive instead, and on a real host the outcome would turn on privilege.
func TestActivateRefusesANilVolumeOrKey(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["taken"] = "CRYPT-LUKS2-someone-elses-volume"
	fake.install(t)
	v, key := formattedVolume(t)

	for _, tc := range []struct {
		name string
		v    *luks2.Volume
		key  *luks2.Key
	}{
		{"nil volume", nil, key},
		{"nil key", v, nil},
		{"both nil", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Activate(context.Background(), tc.v, tc.key, "taken")
			if !errors.Is(err, luks2.ErrInvalidArgument) || m != nil {
				t.Fatalf("Activate(%s) = %v, %v, want nil, ErrInvalidArgument", tc.name, m, err)
			}
		})
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

// TestDeactivateBusyMessageNamesTheHolderHints pins the ErrBusy message the
// user sees on close: the target, the attempt count and budget, the commands
// that find the holder and the deferred removal (user.md and cli.md, close).
func TestDeactivateBusyMessageNamesTheHolderHints(t *testing.T) {
	const name = "held-hint"
	fake := newFakeDeviceMapper()
	fake.targets[name] = "CRYPT-LUKS2-hint"
	fake.install(t)
	removeCalls := 0
	previous := sys.remove
	t.Cleanup(func() { sys.remove = previous })
	sys.remove = func(string) error {
		removeCalls++
		return os.NewSyscallError("dm ioctl", unix.EBUSY)
	}
	recordRetryWaits(t)

	err := Deactivate(context.Background(), name)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("Deactivate = %v, want ErrBusy", err)
	}
	msg := err.Error()
	for _, want := range []string{
		"device-mapper target is held open",
		fmt.Sprintf("after %d attempts over %v", removeCalls, dmpkg.RemoveRetryBudget),
		"lsof /dev/mapper/" + name,
		"mount | grep " + name,
		"dmsetup info -c " + name,
		"dmsetup remove --deferred " + name,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("ErrBusy message lacks %q:\n%s", want, msg)
		}
	}
	if removeCalls < 2 {
		t.Fatalf("remove was issued %d times; a held target must be retried", removeCalls)
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

func TestDeactivateReturnsNilWhenTheTargetVanishesDuringTheWait(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["vanishing"] = "CRYPT-LUKS2-vanishing"
	fake.install(t)
	recordRetryWaits(t)

	// Held on the first attempt, and closed by another actor during the
	// backoff.
	sys.remove = func(name string) error {
		fake.removed = append(fake.removed, name)
		delete(fake.targets, name)
		return os.NewSyscallError("dm ioctl", unix.EBUSY)
	}

	if err := Deactivate(context.Background(), "vanishing"); err != nil {
		t.Fatalf("Deactivate = %v, want nil for a target removed during the wait", err)
	}
	if len(fake.removed) != 1 {
		t.Fatalf("Deactivate tried to remove %d times, want 1: the name was gone after the first", len(fake.removed))
	}
}

func TestDeactivateTouchesNoKeyringState(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["closing"] = "CRYPT-LUKS2-closing"
	fake.install(t)
	ring := &fakeKeyring{ringErr: unix.ENOSYS, addErr: unix.ENOSYS, searchErr: unix.ENOSYS, revokeErr: unix.ENOSYS, unlinkErr: unix.ENOSYS}
	ring.install(t)

	if err := Deactivate(context.Background(), "closing"); err != nil {
		t.Fatalf("Deactivate = %v: it reached a keyring that refuses every call", err)
	}
	if len(ring.added) != 0 || len(ring.revoked) != 0 {
		t.Fatalf("Deactivate touched the keyring: added=%v revoked=%v", ring.added, ring.revoked)
	}
}

func TestActivateRefusesANameInUseBeforeTouchingTheKey(t *testing.T) {
	fake := newFakeDeviceMapper()
	fake.targets["in-use"] = "CRYPT-LUKS2-someone-elses"
	fake.install(t)
	ring := &fakeKeyring{}
	ring.install(t)
	v, key := formattedVolume(t)

	_, err := Activate(context.Background(), v, key, "in-use")
	if !errors.Is(err, ErrActive) {
		t.Fatalf("Activate = %v, want ErrActive for a name already in use", err)
	}
	if len(fake.created) != 0 || len(fake.removed) != 0 || len(ring.added) != 0 {
		t.Fatalf("Activate acted on a name in use: created=%v removed=%v keyring adds=%v", fake.created, fake.removed, ring.added)
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
