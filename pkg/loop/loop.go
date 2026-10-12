// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package loop attaches and detaches Linux loop devices and finds the one
// backing a given file. It is root-only: LOOP_SET_FD and LOOP_CLR_FD require
// CAP_SYS_ADMIN (or, with LOOP_SET_FD, ownership-equivalent privilege on most
// kernels), and /sys/block is readable but the device nodes under /dev
// generally are not, to an unprivileged caller.
package loop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// loopAttachAttempts bounds how often [Attach] asks for another free device
// after losing one to a concurrent attach.
const loopAttachAttempts = 16

// defaultNodeTimeout bounds the wait for a newly allocated loop device's node
// to appear under /dev.
//
// Read it as a ceiling on how long we are willing to wait on a THIRD PARTY --
// here udev or devtmpfs. Two seconds is long enough to absorb a loaded
// machine's udev queue, short enough that a host where nothing will ever
// create the node fails with a diagnosis instead of hanging.
const defaultNodeTimeout = 2 * time.Second

// defaultNodePoll is how often the node is re-checked while waiting.
//
// A BACKOFF, not synchronization: there is no readiness signal to select on,
// so a shorter interval only spends more CPU reaching the same answer and a
// longer one only reaches it later. The bound above is what makes the
// failure case terminate.
const defaultNodePoll = 500 * time.Microsecond

// defaultDetachTimeout bounds how long [Device.Detach] waits for the kernel
// to finish releasing a device. Release happens in microseconds on an idle
// host; the bound is generous because CI runners are not idle. Reaching it
// therefore means the device is still held by something, not that the host
// is slow.
//
// Measured on a loaded CI runner (go-luks2 #24), the kernel completes the
// release ~0.5ms after the last holder closes. The only thing that can
// exhaust this bound is a HOLDER'S LIFETIME, and no value here shortens
// that: raising it just makes a caller wait longer for someone else before
// getting the same deferred answer.
const defaultDetachTimeout = 2 * time.Second

// defaultDetachPoll is how often the release is re-checked while waiting. A
// BACKOFF, for the same reason as defaultNodePoll.
const defaultDetachPoll = 500 * time.Microsecond

// sys holds loop's seams: the clock, the sysfs root, the device directory
// and the OS-facing functions a test substitutes. Every field is set once,
// in [defaultSys], and read -- never reassigned -- by [Attach], [Find] and
// [Lookup], which hand it to the [Device] they return. There is no
// package-level mutable var of func or interface type.
type sys struct {
	clk clock.Clock

	// sysBlockRoot is where the kernel exposes block-device attributes.
	sysBlockRoot string

	// devDir is the directory holding device nodes.
	devDir string

	// openFile opens a file or device node.
	openFile func(name string, flag int, perm os.FileMode) (*os.File, error)

	// readDir lists a directory's entries, for the scan over candidate loop
	// devices in Find.
	readDir func(name string) ([]os.DirEntry, error)

	// loopBackingIdentity reports the device and inode a loop device at path
	// is backed by, as the loop driver itself records them.
	loopBackingIdentity func(path string) (dev, ino uint64, err error)

	// fdBackingIdentity is loopBackingIdentity for a loop device already
	// open as f, so [Device.Detach] checks the descriptor it then clears.
	fdBackingIdentity func(f *os.File) (dev, ino uint64, err error)

	// clearFD sends LOOP_CLR_FD on the loop device open as f.
	clearFD func(f *os.File) error

	// getFree sends LOOP_CTL_GET_FREE on loop-control and returns the minor
	// it names.
	getFree func(loopControl *os.File) (uintptr, error)

	// setFD sends LOOP_SET_FD, binding backing to the loop device open as
	// loopFile.
	setFD func(loopFile, backing *os.File) error

	attachAttempts int
	nodeTimeout    time.Duration
	nodePoll       time.Duration
	detachTimeout  time.Duration
	detachPoll     time.Duration
}

// defaultSys returns the seams [Attach], [Find] and [Lookup] use in
// production.
func defaultSys() sys {
	return sys{
		clk:                 clock.System{},
		sysBlockRoot:        defaultSysBlockRoot,
		devDir:              "/dev",
		openFile:            os.OpenFile,
		readDir:             os.ReadDir,
		loopBackingIdentity: loopBackingIdentityIoctl,
		fdBackingIdentity:   fdBackingIdentityIoctl,
		clearFD:             clearFDIoctl,
		getFree:             getFreeIoctl,
		setFD:               setFDIoctl,
		attachAttempts:      loopAttachAttempts,
		nodeTimeout:         defaultNodeTimeout,
		nodePoll:            defaultNodePoll,
		detachTimeout:       defaultDetachTimeout,
		detachPoll:          defaultDetachPoll,
	}
}

// readState observes device through s's sysfs root.
func (s sys) readState(device string) (loopState, error) {
	return readLoopStateIn(s.sysBlockRoot, device)
}

// Device is a handle to a Linux loop device, obtained from [Attach], [Find]
// or [Lookup].
type Device struct {
	path    string
	backing string
	ident   backingIdentity
	sys     sys
}

// backingIdentity is the device and inode of the file a [Device] was backed
// by when it was obtained, as LOOP_GET_STATUS64 reports them. known is false
// for a [Device] that [Lookup] found with nothing attached.
//
// It is what [Device.Detach] checks before LOOP_CLR_FD. The loop-device
// namespace is host-global and a device number is reused as soon as it is
// free, so the node this Device names may since have been released and
// attached to someone else's file; detaching that would pull a device out
// from under a caller that never handed it to us.
type backingIdentity struct {
	dev, ino uint64
	known    bool
}

// Path returns the device's node, such as "/dev/loop0".
func (d *Device) Path() string { return d.path }

// BackingFile returns the absolute path of the file the device is attached
// to, or "" if it is not currently attached to one (possible only for a
// [Device] obtained from [Lookup]).
func (d *Device) BackingFile() string { return d.backing }

// Attach creates a loop device backed by file and waits for its device node
// to appear.
func Attach(ctx context.Context, file string) (*Device, error) {
	d, err := attach(ctx, file, defaultSys())
	return d, errs.At("loop", "Attach", file, err)
}

func attach(ctx context.Context, file string, s sys) (*Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, &errs.Error{Kind: err}
	}

	// Open the backing file read-write.
	backingFile, err := s.openFile(file, os.O_RDWR, 0) // #nosec G304 -- user-provided file path for disk image
	if err != nil {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to open file", Err: err}
	}
	defer func() { _ = backingFile.Close() }()

	// Open loop control to get a free device.
	loopControl, err := s.openFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "failed to open loop-control", Err: err}
	}
	defer func() { _ = loopControl.Close() }()

	abs, err := filepath.Abs(file)
	if err != nil {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: fmt.Sprintf("resolve backing file path %q", file), Err: err}
	}

	// The descriptor LOOP_SET_FD hands the kernel, so this is the identity
	// LOOP_GET_STATUS64 will report for the device.
	var st unix.Stat_t
	if err := unix.Fstat(int(backingFile.Fd()), &st); err != nil {
		return nil, &errs.Error{Kind: errs.ErrIO, Detail: "identify the backing file " + file, Err: err}
	}
	ident := backingIdentity{dev: uint64(st.Dev), ino: st.Ino, known: true} //nolint:unconvert // Dev is not uint64 on every GOARCH

	// LOOP_CTL_GET_FREE names a free device without reserving it, so two
	// callers can be handed the same one and the second LOOP_SET_FD fails
	// with EBUSY. That is not a failure of this call, and losetup's answer
	// is the one taken here: ask again for another free device.
	var lastErr error
	for range s.attachAttempts {
		path, err := attachFreeLoopDevice(ctx, loopControl, backingFile, s)
		if err == nil {
			return &Device{path: path, backing: abs, ident: ident, sys: s}, nil
		}
		if !errors.Is(err, unix.EBUSY) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// attachFreeLoopDevice attaches backingFile to the device LOOP_CTL_GET_FREE
// names.
func attachFreeLoopDevice(ctx context.Context, loopControl, backingFile *os.File, s sys) (string, error) {
	// Get a free loop device number.
	devNum, err := s.getFree(loopControl)
	if err != nil {
		return "", &errs.Error{Kind: errs.ErrIO, Detail: fmt.Sprintf("LOOP_CTL_GET_FREE failed: %v", err)}
	}

	loopDevice := fmt.Sprintf("%s/loop%d", s.devDir, devNum)

	// THE NUMBER IS NOT THE NODE. LOOP_CTL_GET_FREE allocated the minor
	// above and returned it; it does NOT create /dev/loop<N>. Creating the
	// node belongs to devtmpfs or to udev, and this code has no ordering
	// guarantee against either -- in a container the node appears only if
	// devtmpfs propagates it, or if udev is running and wins the race.
	//
	// The assumption held for the PRE-CREATED range, typically loop0-loop7,
	// which exists from boot. Past it the open failed outright, which is
	// why this presented as "works for the first N, fails past them" with N
	// set by how many loop devices the host was already using -- and why
	// nothing exercised it until something else consumed the low minors.
	//
	// Measured, go-luks2 PR #89 job 34083: four devices created fine and the
	// fifth died on `open /dev/loop8: no such file or directory`.
	if err := waitForLoopNode(ctx, loopDevice, s.nodeTimeout, s.nodePoll, s.clk); err != nil {
		return "", err
	}

	// Open the loop device.
	loopFile, err := s.openFile(loopDevice, os.O_RDWR, 0) // #nosec G304 -- loop device path constructed from kernel
	if err != nil {
		return "", &errs.Error{Kind: errs.ErrIO, Detail: "open the allocated loop device " + loopDevice, Err: err}
	}
	defer func() { _ = loopFile.Close() }()

	// Attach the backing file to the loop device.
	if err := s.setFD(loopFile, backingFile); err != nil {
		return "", &errs.Error{Kind: errs.ErrIO, Detail: "LOOP_SET_FD failed", Err: err}
	}

	return loopDevice, nil
}

// getFreeIoctl is the production [sys.getFree].
func getFreeIoctl(loopControl *os.File) (uintptr, error) {
	devNum, _, errno := unix.Syscall(unix.SYS_IOCTL, loopControl.Fd(), unix.LOOP_CTL_GET_FREE, 0)
	if errno != 0 {
		return 0, errno
	}
	return devNum, nil
}

// setFDIoctl is the production [sys.setFD].
func setFDIoctl(loopFile, backing *os.File) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, loopFile.Fd(), unix.LOOP_SET_FD, backing.Fd()); errno != 0 {
		return errno
	}
	return nil
}

// waitForLoopNode waits for the device node of a freshly allocated loop
// device to appear, and reports a TYPED refusal if it does not.
//
// The node is stat'ed rather than opened. An open can fail for reasons that
// have nothing to do with the node existing -- EACCES, EBUSY -- and
// retrying those for the whole budget would report a permission problem as
// a missing node. Existence is the one question this answers; the open that
// follows keeps its own error.
func waitForLoopNode(ctx context.Context, nodePath string, timeout, poll time.Duration, clk clock.Clock) error {
	deadline := clk.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return &errs.Error{Kind: err}
		}

		_, err := os.Stat(nodePath)
		if err == nil {
			return nil
		}
		// Anything other than "not there yet" is not a race, and waiting
		// will not improve it.
		if !os.IsNotExist(err) {
			return &errs.Error{Kind: errs.ErrIO, Detail: "wait for the loop device node " + nodePath, Err: err}
		}
		if clk.Now().After(deadline) {
			return &errs.Error{Kind: ErrNodeAbsent, Detail: "wait for the loop device node " + nodePath}
		}

		select {
		case <-ctx.Done():
			return &errs.Error{Kind: ctx.Err()}
		case <-clk.NewTimer(poll).C():
		}
	}
}
