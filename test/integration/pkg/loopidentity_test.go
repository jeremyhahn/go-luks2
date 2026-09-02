// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package pkg_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/harness"
)

// The tests below drive harness.SystemRemover against REAL loop devices,
// because the decision they cover cannot be reached without one.
//
// A mutation sweep on the unit suite made that concrete: with
// SystemRemover.DetachLoop's identity comparison replaced by a constant
// `false` -- so a reassigned device is cleared without complaint, which is the
// whole reassignment defect restored -- `go test ./test/harness` stayed GREEN.
// Every reassignment test in that package drives fakeRemover, so they prove the
// fake refuses. Nothing reached the ioctl.
//
// They live in this package rather than in test/harness because of where the
// privileged legs actually run: the integration container's entrypoint invokes
// ./pkg/luks2, ./test/integration/pkg/... and ./test/integration/cli/... and
// NOT ./test/harness. An integration-tagged test in the harness package would
// build, would be reported by nothing, and would pass forever.

// systemRemover is the real remover under test. It is a value rather than a
// literal at each call site because `systemRemover.DetachLoop(x)` in
// an `if` header is a parse error -- Go cannot tell the composite literal from
// the start of the block.
var systemRemover harness.SystemRemover

// attachTestLoop attaches a loop device to a fresh backing file and returns
// both, registering a cleanup that detaches it.
//
// The backing file goes under t.TempDir(), which sits inside the run temp root
// the harness recorded before anything allocated there -- so if this test dies
// mid-way, the reaper finds the device by the same route it finds any other.
func attachTestLoop(t *testing.T, name string) (device, backing string) {
	t.Helper()

	backing = filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(backing, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatalf("creating the backing file: %v", err)
	}
	device, err := luks2.SetupLoopDevice(backing)
	if err != nil {
		t.Fatalf("attaching a loop device to %s: %v", backing, err)
	}
	t.Cleanup(func() {
		// Best effort: the test may already have detached it, and a detach of
		// something already gone is not a failure. What must not happen is
		// leaving it, which is what the ledger and the reaper are for.
		_ = luks2.DetachLoopDevice(device)
	})
	return device, backing
}

// enumerate finds the device among what the remover reports for a backing path,
// which is how a LoopDevice gets a captured identity -- the field cannot be
// built from outside the harness package, and building one by hand would be
// testing a value this code never produces.
func enumerate(t *testing.T, device, backing string) harness.LoopDevice {
	t.Helper()

	devices, err := systemRemover.LoopDevicesFor(backing)
	if err != nil {
		t.Fatalf("LoopDevicesFor(%s): %v", backing, err)
	}
	for _, d := range devices {
		if d.Path == device {
			if !d.IdentityKnown {
				t.Fatalf("the enumeration could not capture %s's identity: %v -- every device this suite "+
					"creates must be identifiable, or the detach refuses all of them and the runner latches",
					device, d.IdentityErr)
			}
			return d
		}
	}
	t.Fatalf("LoopDevicesFor(%s) = %v, which does not include %s", backing, devices, device)
	return harness.LoopDevice{}
}

// TestDetachLoopRefusesADeviceCarryingADifferentBinding is the reassignment
// guard, exercised through the ioctl rather than through a fake.
//
// The staging is deliberate. The obvious version -- detach a device and
// re-attach it, hoping the kernel hands back the same number -- makes the test
// depend on an allocation policy it does not control, and its failure mode is a
// skip. So the mismatch is built directly instead: enumerate two real devices,
// then ask the remover to detach the first while carrying the SECOND's
// identity. That is precisely the state a reassignment produces -- a device
// number whose current binding is not the one that was observed -- and it
// happens on demand.
func TestDetachLoopRefusesADeviceCarryingADifferentBinding(t *testing.T) {
	ourDevice, ourBacking := attachTestLoop(t, "ours.img")
	strangerDevice, strangerBacking := attachTestLoop(t, "stranger.img")

	ours := enumerate(t, ourDevice, ourBacking)
	stranger := enumerate(t, strangerDevice, strangerBacking)

	if ours.Identity == stranger.Identity {
		t.Fatalf("two devices backed by different files share an identity (%v); the comparison cannot "+
			"detect a reassignment at all", ours.Identity)
	}

	// Same device, somebody else's binding: what the caller holds no longer
	// describes what the kernel has.
	stale := ours
	stale.Identity = stranger.Identity

	err := systemRemover.DetachLoop(stale)
	if err == nil {
		t.Fatal("DetachLoop cleared a device whose current binding was not the one that was enumerated -- " +
			"a reused loop number would be detached out from under its new owner")
	}
	if !strings.Contains(err.Error(), "reused") {
		t.Errorf("error = %v, want it to say the loop number was reused", err)
	}

	// The damage plane, which is the assertion that matters.
	devices, err := systemRemover.LoopDevicesFor(ourBacking)
	if err != nil {
		t.Fatalf("LoopDevicesFor(%s): %v", ourBacking, err)
	}
	if len(devices) == 0 {
		t.Fatalf("%s was detached despite the refusal", ourDevice)
	}
}

// TestDetachLoopClearsTheDeviceItEnumerated is the control, and it is not
// optional: a refusal test alone passes just as well against a DetachLoop that
// refuses everything, which would latch every runner in the pool.
//
// It also pins the property the whole identity change rests on -- that a device
// created by this library, whose lo_file_name the kernel reports as EMPTY
// because pkg/luks2/loopdev.go binds with LOOP_SET_FD alone and never sets a
// name, is nonetheless identifiable and therefore detachable. Under the
// previous name-based check this was the "unverifiable" case, i.e. every device
// the suite makes.
func TestDetachLoopClearsTheDeviceItEnumerated(t *testing.T) {
	device, backing := attachTestLoop(t, "ours.img")
	enumerated := enumerate(t, device, backing)

	if err := systemRemover.DetachLoop(enumerated); err != nil {
		t.Fatalf("DetachLoop refused a device it had just enumerated: %v -- if this is the empty-lo_file_name "+
			"case, the reaper cannot clean up after ANY run and every host latches", err)
	}

	devices, err := systemRemover.LoopDevicesFor(backing)
	if err != nil {
		t.Fatalf("LoopDevicesFor(%s): %v", backing, err)
	}
	if len(devices) != 0 {
		t.Fatalf("%s still backs %v after DetachLoop reported success", backing, devices)
	}
}

// TestDetachLoopAcceptsADeviceThatIsAlreadyFree keeps the third answer distinct
// from the other two. An unbound device reports ENXIO, there is nothing to
// detach, and that is a SUCCESS -- not an error, and not something to retry.
// Reading it as a failure once made a clean run fail; reading an empty backing
// NAME as this state once skipped the detach entirely.
func TestDetachLoopAcceptsADeviceThatIsAlreadyFree(t *testing.T) {
	device, backing := attachTestLoop(t, "ours.img")
	enumerated := enumerate(t, device, backing)

	if err := luks2.DetachLoopDevice(device); err != nil {
		t.Fatalf("detaching %s: %v", device, err)
	}
	if err := systemRemover.DetachLoop(enumerated); err != nil {
		t.Fatalf("DetachLoop = %v for a device that was already free, want nil", err)
	}
}
