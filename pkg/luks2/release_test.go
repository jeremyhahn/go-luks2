// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	devmapper "github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"
)

// This file is UNTAGGED on purpose, so it is compiled in both build
// configurations: releaseVolumeErr is the decision the integration suite's
// teardown depends on, and the property it guarantees has to be tested
// somewhere that can actually reproduce the failure. Running the integration
// suite cannot: a mapping that refuses to release is precisely the state
// nobody can produce on demand, which is why the defect survived so long.
// Driving the injectable device-mapper seam produces it exactly, in
// milliseconds, without root.

// volumeReleaseTimeout bounds the wait for a transient EBUSY to clear. Long
// enough for udev to settle after a mkfs, short enough that a genuine failure
// to release is reported within the run that caused it rather than discovered
// by the next job.
// A var, not a const, solely so the give-up cases below can shorten it. The
// reporting path they exercise is unchanged by that.
var volumeReleaseTimeout = 10 * time.Second

// releaseVolumePoll is the gap between attempts. A poll-until-condition on
// external state, which is the sanctioned use; it is not a fixed sleep standing
// in for synchronization.
var releaseVolumePoll = 100 * time.Millisecond

// releaseVolumeErr closes name and returns a diagnostic error if a
// device-mapper mapping is still present afterwards.
//
// It reports on the END STATE, not on what Lock returned, and the difference is
// the whole point:
//
//   - Lock returns ErrVolumeNotUnlocked when there is nothing to close. That is
//     the desired outcome, so a bare error check would fail every test that had
//     already closed explicitly.
//   - A Lock that returns nil while the mapping survives would satisfy a call
//     check and still leave the host dirty.
//
// The retry absorbs the transient EBUSY that mkfs, and the udev/blkid activity
// it triggers, produce for a moment after the filesystem is created. Exhausting
// the deadline is an ERROR, never a quiet return: a retry that gives up
// silently is the same defect wearing a delay.
func releaseVolumeErr(name string) error {
	var last error
	deadline := time.Now().Add(volumeReleaseTimeout)
	for {
		// A filesystem still mounted FROM THIS VOLUME holds the mapping open,
		// and no amount of retrying will free it. Unmount it first.
		//
		// This is scoped, not a sweep: it unmounts only what is mounted from
		// this volume's own device, discovered from /proc/self/mountinfo. That
		// distinction is the whole difference between this and the
		// `losetup -D` class of teardown that #17 removed -- a test may undo
		// what it created and nothing else.
		//
		// It lives here rather than as a deferred unmount at each of the ~19
		// mount sites because one mechanism that covers every site, including
		// sites not written yet, beats nineteen that each have to be
		// remembered. The defect being fixed IS a teardown someone forgot.
		releaseUnmount(name)

		if err := Lock(name); err != nil && !errors.Is(err, ErrVolumeNotUnlocked) {
			last = err
		}
		if mappingGone(name) {
			return nil
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(releaseVolumePoll)
	}
	return fmt.Errorf("device-mapper mapping %q is STILL PRESENT after %s, so "+
		"this run is leaving it on the host for the next job, which will "+
		"refuse to start. Last error from Lock: %v",
		name, volumeReleaseTimeout, last)
}

// mappingGone reports whether the mapping is CONFIRMED absent.
//
// It deliberately does NOT use IsUnlocked, which treats every infoByName error
// as absence unless a device node happens to stat. That is too loose for a
// teardown assertion: a transient dm-control failure, or an environment with no
// /dev/mapper node, would make "the mapping is gone" true on precisely the
// evidence that nothing can be known about it -- a silent instrument read as a
// clean result, which is the defect class this whole change is about.
//
// The strict reading already exists in this package: removeCreatedMapping
// treats only ENXIO/ENODEV as absence, and isNoSuchDevice documents why ENOENT
// is excluded (it comes from opening /dev/mapper/control, so it means dm cannot
// be QUERIED while any target it holds stays live). This reuses that predicate
// rather than inventing a second answer to the same question.
//
// Anything unclassifiable therefore counts as PRESENT, which keeps the retry
// running and, if it never clears, produces a reported failure instead of a
// quiet nil.
func mappingGone(name string) bool {
	if _, err := dm.infoByName(name); err == nil {
		return false // it answered: the mapping exists
	} else if !isNoSuchDevice(err) {
		return false // unclassifiable: not evidence of absence
	}
	// dm says absent. A live device node would still mean present -- a stale
	// symlink is why IsUnlocked looks here too.
	if fi, err := os.Stat(mapperNodePath(name)); err == nil && fi.Mode()&os.ModeDevice != 0 {
		return false
	}
	return true
}

// releaseUnmount is the unmount step, behind a seam.
//
// THIS IS NOT A CONVENIENCE. releaseVolumeErr is compiled into the DEFAULT
// build tier so its decision can be unit-tested, which means `go test
// ./pkg/luks2` executes it -- and the unit tests drive it with ordinary names
// like "clean" and "stuck". Calling the real unmount from there would read the
// host's actual /proc/self/mountinfo and run a real `umount` on any mount whose
// source happened to match /dev/mapper/clean.
//
// That is a test destroying state it does not own, on a developer's machine, in
// the untagged tier -- the same class of defect as the `losetup -D` teardown
// #17 removed, reintroduced by me while fixing its sibling. Review caught it.
//
// THE DEFAULT IS THE NO-OP, and that direction is the whole point. Making the
// real unmount the default and asking every unit test to stub it out is a fix
// that N people have to remember -- which is the same bug with more steps, and
// is exactly what this issue is about. Here the untagged tier physically cannot
// unmount: only the integration build turns it on (release_integration_test.go),
// so a unit test added later is safe without its author knowing this exists.
var releaseUnmount = func(string) {}

// unmountVolume unmounts everything mounted from this volume's own device.
// Best-effort by design: if nothing is mounted there is nothing to do, and if
// an unmount fails the caller's next Lock will fail too and be REPORTED, so a
// failure here is never the thing that goes unnoticed.
func unmountVolume(name string) {
	for _, mp := range mountPointsOfVolume(name) {
		_ = exec.Command("umount", mp).Run()
	}
}

// OWNERSHIP, stated because review asked and the answer is a boundary rather
// than a guarantee: this is NAME-scoped, not identity-scoped. It unmounts and
// closes whatever currently answers to `name`, without checking a dm UUID, so
// if a foreign mapping had taken that name it would be removed.
//
// Three things bound that, and none of them is "it cannot happen":
//
//   - It is not a regression. The teardown this replaces was `Lock(name)`,
//     which removes by name with no ownership check either, and the suite's
//     pre-clean `_ = Lock(volumeName)` does the same before each test.
//   - Inside the container the suite runs in, a foreign mapping cannot be
//     present: the entrypoint refuses to start when the host device-mapper is
//     visible with any mapping the suite did not create.
//   - The unmount is narrower than the close it enables: it touches only mount
//     points whose SOURCE is this volume's own device, never a sweep of
//     everything mounted.
//
// Identity-scoped teardown -- carrying the dm UUID from unlock to release, the
// way removeCreatedMapping does in production -- is the right end state and is
// a larger change than this issue. Recorded here so a green suite is not read
// as proving ownership was checked.
//
// mountPointsOfVolume returns the mount points currently mounted from the
// device-mapper device backing name.
func mountPointsOfVolume(name string) []string {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	devices := []string{"/dev/mapper/" + name}
	// The kernel usually records the resolved /dev/dm-N rather than the
	// /dev/mapper symlink, so match both.
	if resolved, err := filepath.EvalSymlinks("/dev/mapper/" + name); err == nil {
		devices = append(devices, resolved)
	}
	return parseMountinfoFor(f, devices)
}

// parseMountinfoFor is split out with an io.Reader so it can be tested against
// a fixture: the parsing is the part that can be wrong, and it needs neither
// root nor a real mount to exercise.
func parseMountinfoFor(r io.Reader, devices []string) []string {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// mountinfo: <id> <parent> <maj:min> <root> <mountpoint> <opts>
		// [optional fields] - <fstype> <source> <superopts>
		line := sc.Text()
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		left := strings.Fields(line[:sep])
		right := strings.Fields(line[sep+3:])
		if len(left) < 5 || len(right) < 2 {
			continue
		}
		source := right[1]
		for _, d := range devices {
			if source == d {
				// Mount points are octal-escaped for spaces and friends.
				out = append(out, unescapeMountPoint(left[4]))
				break
			}
		}
	}
	return out
}

// unescapeMountPoint decodes the \OOO octal escapes the kernel writes for
// space, tab, newline and backslash in a mount point.
func unescapeMountPoint(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// fakeDM installs a device-mapper whose behavior the test controls, and
// shortens the deadline so a "never releases" case does not take ten seconds.
//
// present is consulted by infoByName: while it returns true the mapping exists.
// removeErr is what remove returns. Both are closures so a case can change its
// mind partway through, which is what a transient EBUSY looks like.
func fakeDM(t *testing.T, present func() bool, removeErr func() error) {
	t.Helper()
	previous := dm
	t.Cleanup(func() { dm = previous })
	dm = deviceMapper{
		infoByName: func(string) (*devmapper.DeviceInfo, error) {
			if present() {
				return &devmapper.DeviceInfo{}, nil
			}
			return nil, unix.ENXIO // the kernel's answer for an unknown dm device
		},
		remove:     func(string) error { return removeErr() },
		ensureNode: func(string) error { return nil },
		waitReady:  func(string) error { return nil },
	}
}

func TestReleaseVolumeErr_MappingGone(t *testing.T) {
	fakeDM(t, func() bool { return false }, func() error { return nil })
	if err := releaseVolumeErr("gone"); err != nil {
		t.Fatalf("a volume with no mapping is the desired end state, not a "+
			"failure, but got: %v", err)
	}
}

func TestReleaseVolumeErr_ReleasesOnFirstAttempt(t *testing.T) {
	removed := false
	fakeDM(t, func() bool { return !removed }, func() error { removed = true; return nil })
	if err := releaseVolumeErr("clean"); err != nil {
		t.Fatalf("a mapping that releases normally must not be reported: %v", err)
	}
}

// The healthy-path leak this whole change is about: mkfs and udev hold the
// device for a moment, remove fails with EBUSY, and a later attempt succeeds.
func TestReleaseVolumeErr_RetriesThroughTransientBusy(t *testing.T) {
	attempts := 0
	removed := false
	fakeDM(t,
		func() bool { return !removed },
		func() error {
			attempts++
			if attempts < 3 {
				return errors.New("device or resource busy")
			}
			removed = true
			return nil
		})

	start := time.Now()
	if err := releaseVolumeErr("busy-then-free"); err != nil {
		t.Fatalf("a transient busy must be retried through, not reported: %v", err)
	}
	if attempts < 3 {
		t.Fatalf("expected the release to be retried; it was attempted %d time(s)", attempts)
	}
	if elapsed := time.Since(start); elapsed >= volumeReleaseTimeout {
		t.Fatalf("retry took %s, which means it waited out the deadline rather "+
			"than succeeding on a later attempt", elapsed)
	}
}

// The half that must never be traded away for the retry: giving up has to be
// LOUD. A retry that eventually returns nil is the original defect with a
// delay in front of it.
func TestReleaseVolumeErr_ReportsAMappingItCannotRelease(t *testing.T) {
	withShortDeadline(t)

	attempts := 0
	fakeDM(t,
		func() bool { return true }, // never goes away
		func() error { attempts++; return errors.New("device or resource busy") })

	err := releaseVolumeErr("stuck")
	if err == nil {
		t.Fatal("a mapping that never releases was NOT reported -- this is the " +
			"exact silence #100 is about: the run would pass and the next job " +
			"on this runner would refuse to start")
	}
	if !strings.Contains(err.Error(), "stuck") {
		t.Errorf("the failure must name the mapping left behind, got: %v", err)
	}
	if !strings.Contains(err.Error(), "busy") {
		t.Errorf("the failure must carry the last error from Lock, got: %v", err)
	}
	if attempts < 2 {
		t.Errorf("expected repeated attempts before giving up, got %d", attempts)
	}
}

// A Lock that reports success while the mapping survives must still fail. This
// is why the helper asserts the end state rather than the call's error.
func TestReleaseVolumeErr_ReportsWhenRemoveLiesAboutSuccess(t *testing.T) {
	withShortDeadline(t)
	fakeDM(t,
		func() bool { return true }, // mapping never disappears
		func() error { return nil }) // ...but remove claims it worked

	if err := releaseVolumeErr("lying"); err == nil {
		t.Fatal("remove returned nil while the mapping survived, and that was " +
			"accepted -- an error check on Lock alone would pass here and leak")
	}
}

// withShortDeadline makes the give-up cases finish quickly without weakening
// what they assert. The deadline is the only thing shortened; the reporting
// path under test is unchanged.
func withShortDeadline(t *testing.T) {
	t.Helper()
	prevTimeout, prevPoll := volumeReleaseTimeout, releaseVolumePoll
	t.Cleanup(func() { volumeReleaseTimeout, releaseVolumePoll = prevTimeout, prevPoll })
	volumeReleaseTimeout = 300 * time.Millisecond
	releaseVolumePoll = 10 * time.Millisecond
}

// The mountinfo parser is the part of the scoped unmount that can be wrong,
// and it needs neither root nor a real mount to exercise. A fixture is the
// honest way to test it: reading /proc on the dev box would test whatever
// happens to be mounted there.
func TestParseMountinfoFor(t *testing.T) {
	const fixture = `25 30 0:23 / /sys rw,nosuid shared:7 - sysfs sysfs rw
41 30 253:0 / /mnt/plain rw,relatime shared:1 - ext4 /dev/mapper/test-vol rw
42 30 253:0 / /mnt/resolved rw,relatime shared:2 - ext4 /dev/dm-0 rw
43 30 253:1 / /mnt/other rw,relatime shared:3 - ext4 /dev/mapper/someone-else rw
44 30 253:0 / /mnt/with\040space rw,relatime shared:4 - ext4 /dev/mapper/test-vol rw
45 30 8:1 / /boot rw,relatime - ext4 /dev/sda1 rw
`
	got := parseMountinfoFor(strings.NewReader(fixture),
		[]string{"/dev/mapper/test-vol", "/dev/dm-0"})

	want := []string{"/mnt/plain", "/mnt/resolved", "/mnt/with space"}
	if len(got) != len(want) {
		t.Fatalf("got %d mount points %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mount point %d = %q, want %q", i, got[i], want[i])
		}
	}

	// The negative is what keeps this scoped rather than a sweep: another
	// volume's mount must never be returned, because unmounting it would be
	// the ownership-blind teardown #17 removed.
	for _, mp := range got {
		if mp == "/mnt/other" {
			t.Fatal("returned a mount point belonging to a DIFFERENT volume; " +
				"unmounting that is exactly the ownership-blind teardown this " +
				"suite is not allowed to perform")
		}
	}
}

func TestParseMountinfoFor_NoMatch(t *testing.T) {
	const fixture = `41 30 253:0 / /mnt/x rw shared:1 - ext4 /dev/mapper/other rw
`
	if got := parseMountinfoFor(strings.NewReader(fixture), []string{"/dev/mapper/mine"}); len(got) != 0 {
		t.Fatalf("expected no mount points, got %v", got)
	}
}

// A malformed line must be skipped rather than panicking or being misread as a
// match: /proc content is not something this code gets to assume the shape of.
func TestParseMountinfoFor_MalformedLinesAreSkipped(t *testing.T) {
	const fixture = `garbage with no separator
41 30 253:0 / - ext4
42 30 253:0 / /mnt/good rw shared:1 - ext4 /dev/mapper/mine rw
`
	got := parseMountinfoFor(strings.NewReader(fixture), []string{"/dev/mapper/mine"})
	if len(got) != 1 || got[0] != "/mnt/good" {
		t.Fatalf("got %v, want exactly [/mnt/good]", got)
	}
}

// An inspection that fails for a reason other than "no such device" is not
// evidence that the mapping is gone. Reading it as absence is how a teardown
// reports clean on the evidence that nothing can be known -- the exact shape
// this change exists to remove, so it gets its own case.
func TestReleaseVolumeErr_UnclassifiableDMErrorIsNotAbsence(t *testing.T) {
	withShortDeadline(t)

	previous := dm
	t.Cleanup(func() { dm = previous })
	dm = deviceMapper{
		// Neither "it exists" nor ENXIO/ENODEV: dm simply cannot answer.
		infoByName: func(string) (*devmapper.DeviceInfo, error) {
			return nil, errors.New("device-mapper control could not be opened")
		},
		remove:     func(string) error { return errors.New("device or resource busy") },
		ensureNode: func(string) error { return nil },
		waitReady:  func(string) error { return nil },
	}

	if err := releaseVolumeErr("unknowable"); err == nil {
		t.Fatal("an unclassifiable device-mapper error was read as absence, so " +
			"teardown reported success without knowing whether a mapping was " +
			"left on the host")
	}
}
