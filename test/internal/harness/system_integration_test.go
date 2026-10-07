// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package harness

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anatol/devmapper.go"
)

// The reaper's host primitives against the REAL kernel, in the devcontainer.
//
// Every other test of SystemRemover runs without privilege and so can only
// reach its refusals. These are the calls that actually remove host state --
// and the reaper is the one component whose failure is silent: a mapping it
// cannot identify is "already gone", a removal it cannot confirm is a clean
// host. So the identity reads and the removals are exercised on a mapping and
// a loop device this test creates, by the same suite discipline the rest of
// the integration tier follows: each is RECORDED before it exists, so a run
// that dies mid-test leaves a ledger the next run's reaper acts on.

var integrationSuite *Suite

func TestMain(m *testing.M) {
	suite, err := BeginSuite(os.Stderr)
	if err != nil {
		os.Stderr.WriteString("harness integration suite: " + err.Error() + "\n")
		os.Exit(1)
	}
	integrationSuite = suite
	os.Exit(suite.Finish(m.Run(), os.Stderr))
}

// loopBackingSize is the size of every backing file these tests attach.
const loopBackingSize = 1 << 20

// attachRecordedLoop records a backing file under the run root and attaches it
// to a free loop device, in that order, and returns the backing file and the
// device.
func attachRecordedLoop(t *testing.T, name string) (backing, device string) {
	t.Helper()
	backing = filepath.Join(integrationSuite.TempDir, name)
	if err := os.WriteFile(backing, make([]byte, loopBackingSize), 0o600); err != nil {
		t.Fatalf("creating the backing file: %v", err)
	}
	if err := integrationSuite.Ledger.Record(KindLoopBacking, backing, ""); err != nil {
		t.Fatalf("recording the loop device before creating it: %v", err)
	}
	out, err := exec.Command("losetup", "--find", "--show", backing).CombinedOutput() // #nosec G204 -- fixed argv; backing is under the recorded run root
	if err != nil {
		t.Fatalf("losetup: %v: %s", err, out)
	}
	return backing, strings.TrimSpace(string(out))
}

// detachOnCleanup releases a loop device this test attached, through the
// remover under test, once the test is done with it.
func detachOnCleanup(t *testing.T, backing string) {
	t.Helper()
	t.Cleanup(func() {
		devices, err := SystemRemover{}.LoopDevicesFor(backing)
		if err != nil {
			t.Errorf("finding the loop device backing %s to release it: %v", backing, err)
			return
		}
		for _, d := range devices {
			if err := (SystemRemover{}).DetachLoop(d); err != nil {
				t.Errorf("releasing %s: %v", d.Path, err)
			}
		}
	})
}

// TestSystemRemoverIdentifiesAndRemovesALiveMapping walks one dm target
// through every answer MappingIdentity and RemoveMapping give: present with
// its UUID, removed, then absent -- and a second removal of the absent name is
// an error, not a quiet success.
//
// The target is linear, over a loop device, because linear is part of
// device-mapper itself and needs no target module the runner's kernel might
// lack. devmapper takes table lengths in BYTES and loads sectors, so the
// length is the whole backing file -- a length under one sector is a zero-length
// table, which the kernel refuses with EINVAL.
func TestSystemRemoverIdentifiesAndRemovesALiveMapping(t *testing.T) {
	backing, loop := attachRecordedLoop(t, "harness-dm.img")
	detachOnCleanup(t, backing)

	name, err := integrationSuite.VolumeName("harness-dm")
	if err != nil {
		t.Fatalf("VolumeName: %v", err)
	}
	uuid := "GO-LUKS2-HARNESS-" + name
	if err := integrationSuite.Ledger.Record(KindMapping, name, uuid); err != nil {
		t.Fatalf("recording the mapping before creating it: %v", err)
	}
	if err := devmapper.CreateAndLoad(name, uuid, 0, devmapper.LinearTable{Length: loopBackingSize, BackendDevice: loop}); err != nil {
		t.Fatalf("creating the linear target over %s: %v", loop, err)
	}

	rm := SystemRemover{}
	got, present, err := rm.MappingIdentity(name)
	if err != nil || !present || got != uuid {
		t.Fatalf("MappingIdentity(live) = %q, %v, %v; want %q, true, nil", got, present, err, uuid)
	}
	if err := rm.RemoveMapping(name); err != nil {
		t.Fatalf("RemoveMapping: %v", err)
	}
	if got, present, err := rm.MappingIdentity(name); err != nil || present {
		t.Fatalf("MappingIdentity(removed) = %q, %v, %v; want absent and no error", got, present, err)
	}
	if err := rm.RemoveMapping(name); err == nil || !strings.Contains(err.Error(), name) {
		t.Fatalf("RemoveMapping of a name that no longer exists = %v, want an error naming it", err)
	}
}

// TestSystemRemoverFindsAndDetachesALiveLoopDevice: the enumeration finds the
// device backing a file with its kernel identity captured, DetachLoop
// releases it only after re-reading that identity, and the enumeration then
// finds nothing.
func TestSystemRemoverFindsAndDetachesALiveLoopDevice(t *testing.T) {
	backing, attached := attachRecordedLoop(t, "harness-loop.img")

	rm := SystemRemover{}
	devices, err := rm.LoopDevicesFor(backing)
	if err != nil || len(devices) != 1 || devices[0].Path != attached || !devices[0].IdentityKnown {
		t.Fatalf("LoopDevicesFor = %+v, %v; want %s with its identity captured", devices, err, attached)
	}
	under, err := rm.LoopDevicesUnder(integrationSuite.TempDir)
	if err != nil || len(under) != 1 || under[0].Path != attached {
		t.Fatalf("LoopDevicesUnder(run root) = %+v, %v; want %s", under, err, attached)
	}

	if err := rm.DetachLoop(devices[0]); err != nil {
		t.Fatalf("DetachLoop(%s): %v", attached, err)
	}
	if devices, err := rm.LoopDevicesFor(backing); err != nil || len(devices) != 0 {
		t.Fatalf("LoopDevicesFor after DetachLoop = %+v, %v; want none", devices, err)
	}
}

// TestSystemRemoverRefusesALoopNumberThatWasReused is the guard DetachLoop
// exists for, on the real ioctl path: an entry enumerated with one identity
// must not clear the device once the number backs something else.
func TestSystemRemoverRefusesALoopNumberThatWasReused(t *testing.T) {
	backing, _ := attachRecordedLoop(t, "harness-reused.img")
	detachOnCleanup(t, backing)

	rm := SystemRemover{}
	devices, err := rm.LoopDevicesFor(backing)
	if err != nil || len(devices) != 1 {
		t.Fatalf("LoopDevicesFor = %+v, %v; want one device", devices, err)
	}
	stale := devices[0]
	stale.Identity.inode++ // what the enumeration would have captured for a different file

	if err := rm.DetachLoop(stale); err == nil || !strings.Contains(err.Error(), "loop number was reused") {
		t.Fatalf("DetachLoop with a stale identity = %v, want the reuse refusal", err)
	}
	if still, err := rm.LoopDevicesFor(backing); err != nil || len(still) != 1 {
		t.Fatalf("after the refusal LoopDevicesFor = %+v, %v; want the device still attached", still, err)
	}
}

// TestMappingIdentityOnAnUnknownNameIsAbsentNotAnError pins the ordinary
// case: most ledger entries name a mapping a test already removed, and
// MappingIdentity must report that as "absent", not surface the kernel's
// not-found as a failure. It opens /dev/mapper/control, so it needs root.
func TestMappingIdentityOnAnUnknownNameIsAbsentNotAnError(t *testing.T) {
	uuid, present, err := SystemRemover{}.MappingIdentity(nonexistentMapping)
	if err != nil || present || uuid != "" {
		t.Errorf("MappingIdentity(%q) = %q, %v, %v, want \"\", false, nil", nonexistentMapping, uuid, present, err)
	}
}
