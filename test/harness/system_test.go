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

	"golang.org/x/sys/unix"
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

// TestSystemRemoverRemoveDirRemovesOnlyARunRoot drives the real remover: a
// directory named like a run root goes, contents and all; one that is not is
// refused and left exactly where it was.
func TestSystemRemoverRemoveDirRemovesOnlyARunRoot(t *testing.T) {
	parent := t.TempDir()
	runRoot := filepath.Join(parent, runRootPrefix+"abc")
	if err := os.MkdirAll(filepath.Join(runRoot, "nested"), 0o700); err != nil {
		t.Fatalf("creating the run root: %v", err)
	}
	if err := (SystemRemover{}).RemoveDir(runRoot); err != nil {
		t.Fatalf("RemoveDir(run root) = %v", err)
	}
	if _, err := os.Stat(runRoot); !os.IsNotExist(err) {
		t.Fatalf("the run root is still there after RemoveDir: %v", err)
	}

	stranger := filepath.Join(parent, "somebody-elses")
	if err := os.Mkdir(stranger, 0o700); err != nil {
		t.Fatalf("creating the stranger's directory: %v", err)
	}
	if err := (SystemRemover{}).RemoveDir(stranger); err == nil {
		t.Fatal("RemoveDir removed a directory not named like a run root")
	}
	if _, err := os.Stat(stranger); err != nil {
		t.Fatalf("the refused directory is gone: %v", err)
	}
}

// TestSystemRemoverDetachLoopRefusesWhatIsNotALoopDevice: an identified entry
// whose path is now gone, or now names something that is not a loop device,
// fails at the status read -- before LOOP_CLR_FD could be issued at anything.
func TestSystemRemoverDetachLoopRefusesWhatIsNotALoopDevice(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "not-a-loop")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatalf("creating the regular file: %v", err)
	}
	for _, tc := range []struct{ path, want string }{
		{filepath.Join(t.TempDir(), "loop-gone"), "opening"},
		{regular, "reading the status of"},
	} {
		err := SystemRemover{}.DetachLoop(LoopDevice{Path: tc.path, Backing: "/tmp/x.img", IdentityKnown: true})
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.path) {
			t.Errorf("DetachLoop(%s) = %v, want a refusal %q naming the device", tc.path, err, tc.want)
		}
	}
}

// TestCaptureLoopIdentityRefusesWhatIsNotALoopDevice: an identity that cannot
// be read is an error, never a zero identity that a later comparison could
// match.
func TestCaptureLoopIdentityRefusesWhatIsNotALoopDevice(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "not-a-loop")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatalf("creating the regular file: %v", err)
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "absent"), regular} {
		if id, bound, err := captureLoopIdentity(path); err == nil || bound {
			t.Errorf("captureLoopIdentity(%s) = %v, %v, %v; want an error", path, id, bound, err)
		}
	}
}

// TestSystemRemoverFindsNoLoopDeviceForAFileNothingBacks reads the host's real
// /sys/block: a file this test just created backs no loop device, whatever else
// the host has attached.
func TestSystemRemoverFindsNoLoopDeviceForAFileNothingBacks(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "unattached.img")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("creating the file: %v", err)
	}
	if devices, err := (SystemRemover{}).LoopDevicesFor(file); err != nil || len(devices) != 0 {
		t.Errorf("LoopDevicesFor = %v, %v; want none", devices, err)
	}
	if devices, err := (SystemRemover{}).LoopDevicesUnder(dir); err != nil || len(devices) != 0 {
		t.Errorf("LoopDevicesUnder = %v, %v; want none", devices, err)
	}
}

// withSysfsAnswer makes reads of path fail with err, as a given kernel would,
// and reads of anything else go to the real file. Sequential callers only:
// it replaces a package variable.
func withSysfsAnswer(t *testing.T, path string, err error) {
	t.Helper()
	previous := readSysfsAttr
	t.Cleanup(func() { readSysfsAttr = previous })
	readSysfsAttr = func(name string) ([]byte, error) {
		if name == path {
			return nil, &os.PathError{Op: "read", Path: name, Err: err}
		}
		return os.ReadFile(name) // #nosec G304 -- a fixture path under t.TempDir()
	}
}

// TestReadBackingFileTreatsEveryReleasedAnswerAsAbsent pins the kernel
// answers that mean "bound to nothing" -- ENOENT, and the ENODEV the CI
// runner's kernel gives for a detached device (#141, run 22538) -- against the
// ones that mean "could not tell", which must stay errors.
func TestReadBackingFileTreatsEveryReleasedAnswerAsAbsent(t *testing.T) {
	root := sysfsTree(t, map[string]string{"loop1": "/tmp/ours.img"})
	attr := filepath.Join(root, "loop1", "loop", "backing_file")
	for _, tc := range []struct {
		errno    error
		released bool
	}{
		{unix.ENOENT, true},
		{unix.ENODEV, true},
		{unix.ENXIO, true},
		{unix.EIO, false},
		{unix.EACCES, false},
	} {
		t.Run(tc.errno.Error(), func(t *testing.T) {
			withSysfsAnswer(t, attr, tc.errno)
			backing, present, err := readBackingFile(filepath.Join(root, "loop1"))
			if tc.released {
				if err != nil || present || backing != "" {
					t.Fatalf("readBackingFile = %q, %v, %v; want released (absent, no error)", backing, present, err)
				}
				return
			}
			if err == nil || !errors.Is(err, tc.errno) {
				t.Fatalf("readBackingFile = %q, %v, %v; want an error carrying %v", backing, present, err, tc.errno)
			}
		})
	}
}

// TestWaitForLoopReleaseAcceptsAnAttributeThatReportsNoDevice is the CI
// failure, end to end through the confirmation and without the host kernel:
// after LOOP_CLR_FD the device's backing_file read fails with ENODEV, and that
// is the release being confirmed, not a failure to confirm it.
func TestWaitForLoopReleaseAcceptsAnAttributeThatReportsNoDevice(t *testing.T) {
	root := sysfsTree(t, map[string]string{"loop1": "/tmp/ours.img"})
	dev := LoopDevice{Path: "/dev/loop1", Backing: "/tmp/ours.img", Identity: fakeIdentityOf("/tmp/ours.img"), IdentityKnown: true}
	ours := func(string) (loopIdentity, bool, error) { return fakeIdentityOf("/tmp/ours.img"), true, nil }

	withSysfsAnswer(t, filepath.Join(root, "loop1", "loop", "backing_file"), unix.ENODEV)
	if err := waitForLoopRelease(root, dev, time.Second, time.Millisecond, ours); err != nil {
		t.Fatalf("waitForLoopRelease with backing_file reporting ENODEV = %v, want nil", err)
	}

	withSysfsAnswer(t, filepath.Join(root, "loop1", "loop", "backing_file"), unix.EIO)
	if err := waitForLoopRelease(root, dev, time.Second, time.Millisecond, ours); err == nil {
		t.Fatal("waitForLoopRelease with an unreadable backing_file = nil, want the read failure")
	}
}
