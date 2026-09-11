// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSystemRemoverRefusesADeviceItCouldNotIdentify tests the REAL remover, not
// the fake, and that distinction is the point.
//
// Every other test of this behavior in this package drives fakeRemover. A fake
// that refuses proves the fake refuses. The finding on 974bf2de was against
// SystemRemover.DetachLoop specifically -- it reached LOOP_CLR_FD on a device it
// had just declared it could not identify -- so the guard has to be asserted
// against the code that issues the ioctl.
//
// It needs no privilege and no loop device, because of WHERE the refusal sits:
// before the open. The device path below does not exist, and that is the
// assertion. If the refusal were moved after the open -- the natural place to
// put it, and where the previous version's equivalent check lived -- this test
// would report "no such file or directory" instead, and fail. So it pins the
// ORDER, which is the property that makes the guard unconditional rather than
// dependent on the device still being there.
func TestSystemRemoverRefusesADeviceItCouldNotIdentify(t *testing.T) {
	capture := errors.New("input/output error")

	err := SystemRemover{}.DetachLoop(LoopDevice{
		Path:          "/dev/loop-does-not-exist",
		Backing:       "/tmp/go-luks2-run-abc/x.img",
		IdentityKnown: false,
		IdentityErr:   capture,
	})
	if err == nil {
		t.Fatal("DetachLoop = nil -- the real remover cleared a device whose identity it never captured")
	}
	if !errors.Is(err, capture) {
		t.Errorf("error = %v, want it to carry why the capture failed", err)
	}
	if strings.Contains(err.Error(), "no such file") {
		t.Errorf("error = %v -- the refusal ran AFTER opening the device, so it is conditional on the "+
			"device still existing rather than on the identity being unknown", err)
	}
	if !strings.Contains(err.Error(), "/dev/loop-does-not-exist") {
		t.Errorf("error = %v, want it to name the device it refused", err)
	}
}

// TestSystemRemoverRefusesADeviceCarryingNoIdentityAtAll covers the same branch
// reached with no reason attached.
//
// IdentityKnown false with a nil IdentityErr is not a state the enumeration
// produces -- but it IS the zero value of LoopDevice, so it is what any future
// caller that builds one by hand will hand over. The dangerous version of this
// code is the one where a zero-valued device is the permissive case.
func TestSystemRemoverRefusesADeviceCarryingNoIdentityAtAll(t *testing.T) {
	err := SystemRemover{}.DetachLoop(LoopDevice{Path: "/dev/loop-does-not-exist"})
	if err == nil {
		t.Fatal("DetachLoop = nil for a zero-valued LoopDevice -- an unidentified device was cleared")
	}
	if strings.Contains(err.Error(), "no such file") {
		t.Errorf("error = %v -- the refusal ran after the open", err)
	}
}

// TestLoopIdentityIsReportedReadably keeps the refusal message useful: it names
// two identities, and "{66307 12345}" in a CI log tells nobody anything.
func TestLoopIdentityIsReportedReadably(t *testing.T) {
	got := loopIdentity{dev: 66307, inode: 16515163}.String()
	for _, want := range []string{"66307", "16515163", "dev", "inode"} {
		if !strings.Contains(got, want) {
			t.Errorf("loopIdentity.String() = %q, want it to contain %q", got, want)
		}
	}
}

// sysfsTree builds a stand-in for /sys/block so the release wait can be
// exercised with no loop device, no root and no real timeout. The layout
// mirrors /sys/block/loop<N>/loop/backing_file exactly.
func sysfsTree(t *testing.T, entries map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for dev, backing := range entries {
		dir := filepath.Join(root, dev, "loop")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "backing_file"), []byte(backing+"\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	return root
}

// TestWaitForLoopReleaseAcceptsADeviceThatIsGone is the ordinary path: the
// deferred release completed, the device no longer backs the file.
func TestWaitForLoopReleaseAcceptsADeviceThatIsGone(t *testing.T) {
	root := sysfsTree(t, map[string]string{"loop1": "/tmp/other.img"})
	dev := LoopDevice{Path: "/dev/loop0", Backing: "/tmp/ours.img", Identity: fakeIdentityOf("/tmp/ours.img"), IdentityKnown: true}

	// Same capturer as the still-bound case, so this test differs from it ONLY
	// in whether the device is present for this backing file -- otherwise
	// "released" could be an artifact of an identity that never matches.
	ours := func(string) (loopIdentity, bool, error) {
		return fakeIdentityOf("/tmp/ours.img"), true, nil
	}
	if err := waitForLoopRelease(root, dev, time.Second, time.Millisecond, ours); err != nil {
		t.Fatalf("waitForLoopRelease() on a released device = %v, want nil", err)
	}
}

// TestWaitForLoopReleaseRefusesADeviceStillBound is the case the whole change
// exists for, and it is the one the old code could not express: LOOP_CLR_FD
// reported success, the release was DEFERRED because something still held the
// device open, and the device still backs the file. Reporting that as success
// is what made TestDetachLoopClearsTheDeviceItEnumerated fail intermittently
// in the integration tier -- the caller was racing a promise it could not see.
func TestWaitForLoopReleaseRefusesADeviceStillBound(t *testing.T) {
	root := sysfsTree(t, map[string]string{"loop0": "/tmp/ours.img"})
	dev := LoopDevice{Path: "/dev/loop0", Backing: "/tmp/ours.img", Identity: fakeIdentityOf("/tmp/ours.img"), IdentityKnown: true}

	// The capturer must report OUR identity, or the device reads as a reused
	// number and the wait returns nil for the wrong reason. stubBoundIdentity
	// hashes the DEVICE path, not the backing file, so it never matches -- and
	// this test passed vacuously against it before that was noticed.
	ours := func(string) (loopIdentity, bool, error) {
		return fakeIdentityOf("/tmp/ours.img"), true, nil
	}

	const budget = 40 * time.Millisecond
	started := time.Now()
	err := waitForLoopRelease(root, dev, budget, time.Millisecond, ours)
	if err == nil {
		t.Fatal("waitForLoopRelease() on a device that never releases = nil, want an error")
	}
	if !strings.Contains(err.Error(), "/dev/loop0") {
		t.Errorf("error %q does not name the device an operator has to go and find", err)
	}
	if !strings.Contains(err.Error(), "deferred") {
		t.Errorf("error %q does not say the release was deferred, which is the whole diagnosis", err)
	}
	// A bound that is not honored is an unbounded wait wearing a timeout.
	if waited := time.Since(started); waited > budget+2*time.Second {
		t.Errorf("waited %s against a %s budget", waited, budget)
	}
}

// TestWaitForLoopReleaseAcceptsAReusedLoopNumber keeps the third answer
// distinct. The loop number being present is not the question -- the number is
// host-global and reusable, so a device bound to a DIFFERENT identity means
// ours was released and the number handed to someone else. Treating that as
// "still held" would make a successful detach fail whenever the host was busy,
// which is exactly when the suite runs.
func TestWaitForLoopReleaseAcceptsAReusedLoopNumber(t *testing.T) {
	// Same path, same backing string, but the capturer reports the identity of
	// a different file -- the shape of a number freed and reassigned.
	root := sysfsTree(t, map[string]string{"loop0": "/tmp/ours.img"})
	dev := LoopDevice{Path: "/dev/loop0", Backing: "/tmp/ours.img", Identity: fakeIdentityOf("/tmp/ours.img"), IdentityKnown: true}

	reused := func(device string) (loopIdentity, bool, error) {
		return fakeIdentityOf("/tmp/somebody-elses.img"), true, nil
	}
	if err := waitForLoopRelease(root, dev, time.Second, time.Millisecond, reused); err != nil {
		t.Fatalf("waitForLoopRelease() on a reused loop number = %v, want nil -- ours was released", err)
	}
}

// TestWaitForLoopReleaseFailsWhenTheScanFails keeps "could not find out" from
// becoming "it is fine", which is the rule this package is built on.
func TestWaitForLoopReleaseFailsWhenTheScanFails(t *testing.T) {
	dev := LoopDevice{Path: "/dev/loop0", Backing: "", Identity: fakeIdentityOf("x"), IdentityKnown: true}
	// An empty backing path is refused by the enumeration itself.
	if err := waitForLoopRelease(t.TempDir(), dev, time.Second, time.Millisecond, stubBoundIdentity); err == nil {
		t.Fatal("waitForLoopRelease() with an unusable backing path = nil, want the scan failure surfaced")
	}
}
