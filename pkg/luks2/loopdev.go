// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package luks2

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// SetupLoopDevice creates a loop device for a file
func SetupLoopDevice(file string) (string, error) {
	// Open the backing file read-write
	backingFile, err := os.OpenFile(file, os.O_RDWR, 0) // #nosec G304 -- user-provided file path for disk image
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = backingFile.Close() }()

	// Open loop control to get free device
	loopControl, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("failed to open loop-control: %w", err)
	}
	defer func() { _ = loopControl.Close() }()

	// Get free loop device number
	devNum, _, errno := unix.Syscall(unix.SYS_IOCTL, loopControl.Fd(), unix.LOOP_CTL_GET_FREE, 0)
	if errno != 0 {
		return "", fmt.Errorf("LOOP_CTL_GET_FREE failed: %v", errno)
	}

	loopDevice := fmt.Sprintf("/dev/loop%d", devNum)

	// THE NUMBER IS NOT THE NODE. LOOP_CTL_GET_FREE allocated the minor above
	// and returned it; it does NOT create /dev/loop<N>. Creating the node
	// belongs to devtmpfs or to udev, and this code has no ordering guarantee
	// against either -- in a container the node appears only if devtmpfs
	// propagates it, or if udev is running and wins the race.
	//
	// The assumption held for the PRE-CREATED range, typically loop0-loop7,
	// which exists from boot. Past it the open failed outright, which is why
	// this presented as "works for the first N, fails past them" with N set by
	// how many loop devices the host was already using -- and why nothing
	// exercised it until something else consumed the low minors.
	//
	// Measured, PR #89 job 34083: four devices created fine and the fifth died
	// on `open /dev/loop8: no such file or directory`.
	if err := waitForLoopNode(loopDevice, loopNodeTimeout, loopNodePollInterval); err != nil {
		return "", err
	}

	// Open loop device
	loopFile, err := os.OpenFile(loopDevice, os.O_RDWR, 0) // #nosec G304 -- loop device path constructed from kernel
	if err != nil {
		return "", &DeviceError{Device: loopDevice, Op: "open the allocated loop device", Err: err}
	}
	defer func() { _ = loopFile.Close() }()

	// Attach backing file to loop device
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, loopFile.Fd(), unix.LOOP_SET_FD, backingFile.Fd())
	if errno != 0 {
		return "", fmt.Errorf("LOOP_SET_FD failed: %v", errno)
	}

	return loopDevice, nil
}

// detachSettleTimeout bounds how long DetachLoopDevice waits for the kernel to
// finish releasing a device. Release happens in microseconds on an idle host;
// the bound is generous because CI runners are not idle. Reaching it therefore
// means the device is still held by something, not that the host is slow.
//
// So this is NOT a guess at how long the kernel needs — do not tune it as one.
// Measured on a loaded CI runner (#24), the kernel completes the release ~0.5ms
// after the last holder closes. The only thing that can exhaust this bound is a
// HOLDER'S LIFETIME, and no value here shortens that: raising it just makes a
// caller wait longer for someone else before getting the same deferred answer.
// Read it as a ceiling on how long we are willing to wait on a third party.
//
// If a test or caller is timing out against this, the question to ask is what
// still holds the device, not what this number should be.
const detachSettleTimeout = 2 * time.Second

// detachPollInterval is how often the release is re-checked while waiting.
//
// This is a BACKOFF, not synchronization: correctness does not depend on the
// duration. sysfs exposes no readiness signal to select on, so there is nothing
// to wait on; a shorter interval only spends more CPU reaching the same answer,
// and a longer one only reaches it later. The bound above is what makes the
// failure case terminate.
const detachPollInterval = 500 * time.Microsecond

// loopNodeTimeout bounds the wait for a newly allocated loop device's node to
// appear under /dev.
//
// Read it, like detachSettleTimeout above, as a ceiling on how long we are
// willing to wait on a THIRD PARTY -- here udev or devtmpfs rather than
// whatever holds a device. Two seconds is the same order for the same reason:
// long enough to absorb a loaded machine's udev queue, short enough that a
// host where nothing will ever create the node fails with a diagnosis instead
// of hanging.
const loopNodeTimeout = 2 * time.Second

// loopNodePollInterval is how often the node is re-checked while waiting.
//
// A BACKOFF, not synchronization, exactly as detachPollInterval is: there is no
// readiness signal to select on, so a shorter interval only spends more CPU
// reaching the same answer and a longer one only reaches it later. The bound
// above is what makes the failure case terminate.
const loopNodePollInterval = 500 * time.Microsecond

// waitForLoopNode waits for the device node of a freshly allocated loop device
// to appear, and reports a TYPED refusal if it does not.
//
// The node is stat'ed rather than opened. An open can fail for reasons that
// have nothing to do with the node existing -- EACCES, EBUSY -- and retrying
// those for the whole budget would report a permission problem as a missing
// node. Existence is the one question this answers; the open that follows
// keeps its own error.
func waitForLoopNode(device string, timeout, poll time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := os.Stat(device)
		if err == nil {
			return nil
		}
		// Anything other than "not there yet" is not a race, and waiting will
		// not improve it.
		if !os.IsNotExist(err) {
			return &DeviceError{Device: device, Op: "wait for the loop device node", Err: err}
		}
		if time.Now().After(deadline) {
			return &DeviceError{Device: device, Op: "wait for the loop device node", Err: ErrLoopNodeAbsent}
		}
		time.Sleep(poll)
	}
}

// DetachState says what became of a detach request. Both values mean the
// kernel accepted it; they differ in whether the release has happened yet.
type DetachState int

const (
	// DetachReleased means the release was OBSERVED: the device is no longer
	// backed by the file it held.
	DetachReleased DetachState = iota

	// DetachDeferred means the kernel accepted the request and postponed it
	// because something else still has the device open — a mounted
	// filesystem, or a dm-crypt mapping built on it. The device carries the
	// autoclear flag and will be released when the last user goes away.
	//
	// This is a SUCCESS. It is what `losetup -d` does on a busy device, and
	// reporting it as a failure would tell a caller their detach did not work
	// when in fact it did and is simply pending.
	DetachDeferred
)

// DetachLoopDevice detaches a loop device and waits until the release is
// OBSERVED before returning.
//
// That is the promise callers have always read into it, and it holds in every
// case but one. If something else still holds the device when the wait's bound
// expires — a mounted filesystem, a dm-crypt mapping — the kernel has accepted
// the request and will complete it when the last user goes away, and this
// returns nil with the device still attached. That case is a success: it is
// what `losetup -d` reports for a busy device, and failing it would break
// callers detaching something legitimately still in use.
//
// [DetachLoopDeviceState] distinguishes the two. A caller that must know the
// device is free right now should use it and check for [DetachReleased].
//
// A deferred release is not an early exit. The wait keeps looking, because a
// holder is usually momentary — a neighboring process, a udev settle, a dm
// teardown in progress — and waiting turns most deferred cases into observed
// releases. The cost is that a genuinely long-held device pays the full bound
// before returning; that is bounded, and it buys a nil that means what callers
// take it to mean.
//
// The wait is the point. LOOP_CLR_FD does not necessarily tear the association
// down before it returns: while any descriptor for the device is still open the
// kernel marks it autoclear and defers the release until the last reference is
// dropped. So the ioctl reports success, this function used to return, and a
// caller that immediately asked [FindLoopDevice] whether the file was still
// attached could be told that it was — intermittently, depending on whether the
// kernel had got there yet.
//
// That is not a test artifact. Any caller that detaches and then acts on the
// device's state is exposed to it, and the failure is a race, so it appears and
// disappears without the code changing.
//
// A deferred release is NOT an error; see [DetachState]. Use
// [DetachLoopDeviceState] to tell the two successes apart.
func DetachLoopDevice(device string) error {
	_, err := DetachLoopDeviceState(device)
	return err
}

// DetachLoopDeviceState is [DetachLoopDevice] with the outcome reported rather
// than discarded, for callers that need to know whether the device is free NOW
// or merely promised.
func DetachLoopDeviceState(device string) (DetachState, error) {
	return detachLoopDevice(device, detachSettleTimeout, detachPollInterval, readLoopState)
}

// detachLoopDevice carries the bound, the poll interval and the reader as
// parameters so the waiting logic can be exercised without a loop device and
// without waiting out a real timeout. The kernel-facing path is covered
// separately, by the integration tests that drive a real device.
func detachLoopDevice(device string, timeout, poll time.Duration, read loopStateReader) (DetachState, error) {
	// Recorded BEFORE the detach so the wait can tell "our association is gone"
	// apart from "this device has since been attached to something else". The
	// loop-device namespace is host-global, so a freed device can be claimed by
	// another process between the ioctl and the first poll; waiting for the
	// backing file to merely become unreadable would then time out on a detach
	// that had in fact succeeded.
	before, beforeErr := read(device)

	loopFile, err := os.OpenFile(device, os.O_RDWR, 0) // #nosec G304 -- loop device path from SetupLoopDevice
	if err != nil {
		return DetachReleased, fmt.Errorf("failed to open %s: %w", device, err)
	}

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, loopFile.Fd(), unix.LOOP_CLR_FD, 0)

	// Closed explicitly rather than deferred, because the close has to happen
	// BEFORE the wait below rather than after the function returns: this
	// descriptor is a reference, and the release cannot complete while it is
	// held. A deferred close would make the wait wait for itself.
	closeErr := loopFile.Close()

	if errno != 0 {
		return DetachReleased, fmt.Errorf("LOOP_CLR_FD failed: %v", errno)
	}

	// A failed close does NOT skip the wait. The detach itself succeeded, the
	// descriptor is out of our hands either way, and returning here would both
	// abandon the observation this function exists to make and hand back an
	// error a caller cannot classify. It is reported alongside whatever the
	// wait concludes.
	state, waitErr := waitForDetach(device, before, beforeErr == nil, timeout, poll, read)
	if closeErr != nil {
		return state, errors.Join(&DeviceError{Device: device, Op: "close loop device after detach", Err: closeErr}, waitErr)
	}
	return state, waitErr
}

// waitForDetach blocks until the device is released, until the kernel says the
// release is deferred, or until timeout expires.
//
// before is the state observed before the detach; knownBefore says whether that
// observation succeeded. Without it there is no baseline to compare against, so
// the wait requires the authoritative not-attached state instead — a stronger
// condition, which is the right trade when already operating blind.
//
// The contract, and it is one sentence: NO PATH RETURNS SUCCESS WITHOUT AN
// AUTHORITATIVE OBSERVATION. An unreadable state is retried, never concluded
// from; if it never clears, the bound reports that the state could not be read.
func waitForDetach(device string, before loopState, knownBefore bool, timeout, poll time.Duration, read loopStateReader) (DetachState, error) {
	// Nothing was attached, and we KNOW that — the only case that needs no
	// wait. An unreadable pre-detach observation is not this case, however
	// similar an empty backing file looks.
	if knownBefore && before.backing == "" {
		return DetachReleased, nil
	}

	deadline := time.Now().Add(timeout)

	// Counted rather than remembered. Classifying on the LAST reading inverts
	// the report in both directions: a wait that was blind almost throughout
	// but read cleanly on its final poll would blame a holder that does not
	// exist, and a genuinely held device whose last poll happened to error
	// would send an operator to fix a healthy host. The two causes exist
	// precisely to route an operator differently, so the classification uses
	// what dominated the wait rather than what happened to come last.
	var unreadable, held int
	var lastErr error
	sawAutoclear := false

	for {
		current, err := read(device)
		switch {
		case err != nil:
			unreadable++
			lastErr = err

		case released(current, before, knownBefore):
			return DetachReleased, nil

		case current.autoclear:
			// The kernel took the request and postponed it. That is an
			// authoritative observation, and it is remembered — but it is NOT
			// an exit.
			//
			// Exiting here is what an earlier version did, and it made `nil`
			// mean "released, or maybe still attached", which is not what a
			// caller detaching a device takes it to mean. A holder is very
			// often momentary — a neighboring process, a udev settle, a dm
			// teardown that has not finished — so waiting usually turns the
			// deferred case into an observed release, at no cost beyond a few
			// more polls.
			sawAutoclear = true
			held++

		default:
			held++
		}

		if time.Now().After(deadline) {
			if sawAutoclear {
				// Still held at the bound, but the kernel has accepted the
				// request and will complete it when the last user goes away.
				// That is a success: a persistently-held device is exactly
				// what `losetup -d` reports success for, and failing here
				// would break callers that detach a device something else is
				// legitimately still using.
				return DetachDeferred, nil
			}

			return DetachReleased, &DeviceError{
				Device: device,
				Op:     "detach loop device",
				Err:    detachTimeoutCause(before, knownBefore, timeout, unreadable, held, lastErr),
			}
		}

		time.Sleep(poll)
	}
}

// released reports whether an observation shows our association gone.
func released(current, before loopState, knownBefore bool) bool {
	if knownBefore {
		// Gone, or claimed by someone else: either way it is no longer ours.
		return current.backing != before.backing
	}
	// No baseline, so only the authoritative not-attached state will do.
	return current.backing == ""
}

// detachTimeoutCause explains WHY the wait gave up, because the two reasons
// send an operator to different places: a device still held by something else
// is a process to find, and a sysfs we cannot read is a host to fix.
func detachTimeoutCause(before loopState, knownBefore bool, timeout time.Duration, unreadable, held int, lastErr error) error {
	if unreadable > held {
		return fmt.Errorf("%w: the device's state was unreadable for %d of %d checks over %s: %w",
			ErrDetachIncomplete, unreadable, unreadable+held, timeout, lastErr)
	}
	if knownBefore {
		return fmt.Errorf("%w: still backed by %s after %s; something else still holds the device open",
			ErrDetachIncomplete, before.backing, timeout)
	}
	return fmt.Errorf("%w: still attached after %s, and its state before the detach could not be read",
		ErrDetachIncomplete, timeout)
}

// loopState is one observation of a loop device's attributes.
type loopState struct {
	// backing is the file the device is attached to, or "" when it is
	// attached to nothing. It is only meaningful alongside a nil error: the
	// zero value is what an unreadable device gives too.
	backing string

	// autoclear reports the kernel's deferred-release flag.
	autoclear bool
}

// loopStateReader observes a loop device. An error means the state could not be
// determined — which is NOT the same as the device being free, and the
// difference is the whole contract of the wait above.
type loopStateReader func(device string) (loopState, error)

// sysBlockRoot is where the kernel exposes block-device attributes. It is a
// parameter of readLoopStateIn rather than a constant inside it so the reader's
// own failure branches can be exercised: every path under the real /sys/block
// either exists or does not, so an error that is NOT "absent" — the one this
// reader must never mistake for "detached" — is unreachable from a real device
// name and would otherwise go untested.
const sysBlockRoot = "/sys/block"

// readLoopState observes a loop device through the real sysfs.
func readLoopState(device string) (loopState, error) {
	return readLoopStateIn(sysBlockRoot, device)
}

// readLoopStateIn is [readLoopState] against a given sysfs root.
//
// The distinction it exists to make is between two ways of finding nothing:
//
//   - the BLOCK DEVICE is there and its loop attributes are gone — the device
//     exists and is attached to nothing, which is a positive answer;
//   - the block device is not there at all — which says nothing about any loop
//     association, because we are not looking at a loop device we can observe.
//
// Collapsing the second into the first is a fail-open, and a subtle one: a
// device whose basename is not a top-level /sys/block entry — a udev symlink,
// /dev/block/7:0, or a PARTITION such as /dev/loop0p1, which lives at
// /sys/block/loop0/loop0p1 — would otherwise report "not attached" and let a
// caller conclude a release it never observed.
func readLoopStateIn(root, device string) (loopState, error) {
	name := filepath.Base(device)
	blockDir := filepath.Join(root, name)

	if _, err := os.Stat(blockDir); err != nil {
		return loopState{}, fmt.Errorf("cannot observe block device %s: %w", name, err)
	}

	data, err := os.ReadFile(filepath.Join(blockDir, "loop", "backing_file")) // #nosec G304 -- sysfs path built from the device's base name
	switch {
	case loopAttributeSaysUnbound(err):
		// The block device is there and its loop attributes are not, so it is
		// attached to nothing. This is the authoritative negative.
		return loopState{}, nil
	case err != nil:
		return loopState{}, err
	}

	backing := strings.TrimRight(string(data), "\n")
	if backing == "" {
		return loopState{}, nil
	}

	abs, err := filepath.Abs(backing)
	if err != nil {
		return loopState{}, fmt.Errorf("unreadable backing file %q for %s: %w", backing, device, err)
	}

	return loopState{backing: abs, autoclear: readLoopFlag(blockDir, "autoclear")}, nil
}

// readLoopFlag reads a boolean loop attribute. It is best-effort by design: the
// flags are diagnostic, and a missing or unreadable one must not turn into a
// claim about the association itself — that is what [readLoopStateIn]'s error
// is for.
// loopAttributeSaysUnbound reports whether a failed read of a loop device's
// sysfs backing_file means the device is attached to nothing.
//
// Kernels say it differently: some remove the loop attributes (ENOENT), others
// keep them and fail the read with ENODEV once the device is released --
// measured on a CI runner, where the test harness's own release confirmation
// failed on exactly that (go-luks2 #141). ENXIO is the loop driver's "not
// bound" answer. Every other failure means the state could not be read, and
// stays an error.
func loopAttributeSaysUnbound(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENXIO)
}

func readLoopFlag(blockDir, name string) bool {
	data, err := os.ReadFile(filepath.Join(blockDir, "loop", name)) // #nosec G304 -- sysfs path built from the device's base name
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

// FindLoopDevice finds the loop device for a given file by reading /sys
func FindLoopDevice(file string) (string, error) {
	absFile, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}

	// Read /sys/block to find loop devices
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return "", err
	}

	// Counted rather than remembered, in the same idiom as waitForDetach.
	var unreadable int
	var lastErr error

	for _, entry := range entries {
		name := entry.Name()
		if len(name) < 4 || name[:4] != "loop" {
			continue
		}

		// One reader for sysfs, shared with the detach wait: two copies of this
		// parsing would be two places for "what counts as attached" to drift,
		// and the wait's correctness depends on answering it the same way
		// FindLoopDevice does.
		st, err := readLoopState(name)
		if err != nil {
			// Cannot tell for THIS device; it is not evidence about any other,
			// so the scan continues -- but it is counted, because it is
			// evidence about the ANSWER. See below.
			unreadable++
			lastErr = err
			continue
		}
		if st.backing != "" && absFile == st.backing {
			return "/dev/" + name, nil
		}
	}

	// "NOT ATTACHED" AND "COULD NOT TELL" ARE DIFFERENT ANSWERS, and only the
	// first may be acted on. Per-candidate the skip above is right; in the
	// AGGREGATE it used to erase the distinction, because every unreadable
	// candidate still ended here as a flat "no loop device found".
	//
	// waitForDetach in this same file is scrupulous about exactly this -- it
	// counts unreadable separately from held and never reports success from an
	// unreadable observation. This function did not, and the caller it misleads
	// is the one asking whether a file is ALREADY attached before attaching it:
	// told "no" when the truth was "the one device backing it could not be
	// inspected", it creates a SECOND loop device for the same backing file,
	// giving the kernel two independent writers of one LUKS container.
	if unreadable > 0 {
		return "", &DeviceError{
			Device: file,
			Op:     fmt.Sprintf("find the loop device backing this file (%d of %d candidates could not be inspected, so absence cannot be concluded)", unreadable, len(entries)),
			Err:    lastErr,
		}
	}

	return "", fmt.Errorf("no loop device found for %s", file)
}
