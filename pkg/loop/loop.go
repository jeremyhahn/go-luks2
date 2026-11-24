// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package loop attaches and detaches Linux loop devices and finds the one backing a file; root only.
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

// defaultNodeTimeout bounds the wait for udev or devtmpfs to create a new loop node.
const defaultNodeTimeout = 2 * time.Second

// defaultNodePoll is the re-check interval while waiting for the node.
const defaultNodePoll = 500 * time.Microsecond

// defaultDetachTimeout bounds [Device.Detach]'s wait; reaching it means something still holds the device.
const defaultDetachTimeout = 2 * time.Second

// defaultDetachPoll is the re-check interval while waiting for release.
const defaultDetachPoll = 500 * time.Microsecond

// sys holds loop's seams, set once in [defaultSys] and never reassigned.
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

// backingIdentity is the device and inode a [Device] was backed by when obtained; known is false when nothing was attached.
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

	// LOOP_CTL_GET_FREE does not reserve the device, so EBUSY means ask for another, as losetup does.
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

	// LOOP_CTL_GET_FREE does not create /dev/loop<N>; wait for udev or devtmpfs to make it.
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

// waitForLoopNode waits for a new loop device's node to exist (stat, not open), returning ErrNodeAbsent if it does not.
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
