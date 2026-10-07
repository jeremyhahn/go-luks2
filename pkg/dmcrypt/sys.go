// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package dmcrypt

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	dmpkg "github.com/jeremyhahn/go-luks2/internal/dm"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	keyringpkg "github.com/jeremyhahn/go-luks2/internal/keyring"
)

// seams is this package's one unexported struct of substitutable state
// (DESIGN.md §E): the device-mapper and kernel-keyring mechanism, the
// directory device nodes are made under, the stat used to identify a node,
// and the clock every wait runs on. Every consumer of this library wants
// the real kernel; only this package's own tests want anything else, so the
// seam is a package-level value rather than a parameter threaded through
// every call -- the same idiom pkg/luks2's transitional dm/keyring vars
// used before this package existed.
type seams struct {
	create     func(ctx context.Context, name, uuid string) (uint64, error)
	load       func(name string, table devmapper.Table) error
	resume     func(name string) error
	infoByName func(name string) (*devmapper.DeviceInfo, error)
	remove     func(name string) error
	ensureNode func(ctx context.Context, name string, info *devmapper.DeviceInfo) error
	waitReady  func(ctx context.Context, name string, info *devmapper.DeviceInfo) error

	keyring       keyringpkg.Syscalls
	devDir        string
	blockNodeRdev func(path string) (uint64, error)
	makeBlockNode func(path string, devNo uint64) error
	clock         clock.Clock
}

// sys is the live seam. Tests substitute it (or one of its fields) for the
// duration of one test and restore it with t.Cleanup.
//
// It is set in init, not in its own var initializer: liveSeams stores
// ensureDeviceNode and waitForDeviceReady, whose bodies read sys.devDir and
// sys.blockNodeRdev, and a var initializer that calls a function reading
// the variable it is initializing is an initialization cycle as far as the
// compiler's static check is concerned -- even though nothing actually
// runs ensureDeviceNode until long after sys exists. init runs after every
// package-level var has its declared zero value, so the assignment here is
// ordinary imperative code rather than an initializer expression, and the
// cycle check does not apply to it.
var sys seams

func init() {
	sys = liveSeams()
}

func liveSeams() seams {
	return seams{
		create:        createTarget,
		load:          func(name string, table devmapper.Table) error { return devmapper.Load(name, 0, table) },
		resume:        devmapper.Resume,
		infoByName:    devmapper.InfoByName,
		remove:        devmapper.Remove,
		ensureNode:    ensureDeviceNode,
		waitReady:     waitForDeviceReady,
		keyring:       keyringpkg.Live(),
		devDir:        "/dev",
		blockNodeRdev: statBlockRdev,
		makeBlockNode: makeBlockNodeDefault,
		clock:         clock.System{},
	}
}

// createTarget issues DM_DEV_CREATE and returns the device number from the
// kernel's reply. The ioctl itself lives in internal/dm; this is the
// pkg/dmcrypt-level translation of its one distinguished failure (a name or
// UUID that does not fit the ioctl) onto ErrInvalidName, which is also what
// ValidateName reports for the same condition.
func createTarget(ctx context.Context, name, uuid string) (uint64, error) {
	devNo, err := dmpkg.CreateTarget(ctx, name, uuid)
	if errors.Is(err, dmpkg.ErrNameTooLong) {
		return 0, &errs.Error{Kind: ErrInvalidName,
			Detail: "the device-mapper name or UUID does not fit the create ioctl without being cut"}
	}
	return devNo, err
}

// statBlockRdev stats path and returns its raw device number, refusing
// anything that is not a block device. isOurNode uses it to identify
// device-mapper nodes.
func statBlockRdev(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return 0, &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "not a block device: " + path}
	}
	return uint64(st.Rdev), nil //nolint:unconvert // Rdev is not uint64 on every GOARCH
}

// dmNodePath, mapperNodePath and mapperDir build the paths every node
// placement and lookup goes through, so the places that build them cannot
// drift from each other.
func dmNodePath(minor uint32) string    { return dmpkg.NodePath(sys.devDir, minor) }
func mapperNodePath(name string) string { return dmpkg.MapperPath(sys.devDir, name) }
func mapperDir() string                 { return dmpkg.MapperDir(sys.devDir) }

// isOurNode reports whether the node at path is the device info describes.
func isOurNode(path string, info *devmapper.DeviceInfo) bool {
	return dmpkg.IsOurNode(sys.blockNodeRdev, path, info)
}

// pollUntil checks done until it reports true or timeout has passed on
// sys.clock, and reports whether done ever did.
// pollUntil checks done until it reports true or timeout has passed on
// sys.clock, and reports whether done ever did, or ctx ended the wait first.
func pollUntil(ctx context.Context, timeout, interval time.Duration, done func() bool) (bool, error) {
	return dmpkg.PollUntil(ctx, sys.clock, timeout, interval, done)
}

// retryWhileBusy runs attempt until it stops reporting EBUSY or the budget
// is spent on sys.clock, and reports how many times it ran.
// retryWhileBusy runs attempt until it stops reporting EBUSY or the budget
// is spent on sys.clock, and reports how many times it ran.
func retryWhileBusy(ctx context.Context, attempt func() error) (attempts int, err error) {
	return dmpkg.RetryWhileBusy(ctx, sys.clock, attempt)
}

// makeBlockNodeDefault creates a block-device node. It is sys.makeBlockNode's
// default: mknod needs CAP_MKNOD, which an unprivileged unit-test account
// does not have, so tests substitute sys.makeBlockNode instead.
func makeBlockNodeDefault(path string, devNo uint64) error {
	mkdev := unix.Mkdev(unix.Major(devNo), unix.Minor(devNo))
	if mkdev > math.MaxInt {
		return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: fmt.Sprintf("device number %d does not fit a native int", mkdev)}
	}
	return unix.Mknod(path, unix.S_IFBLK|0o660, int(mkdev)) // #nosec G115 -- bounded just above
}

// placeNode puts a new directory entry at path, made by create, REPLACING
// whatever is there. The replace-by-rename mechanism lives in internal/dm;
// this is the pkg/dmcrypt-level translation of its one distinguished
// refusal (an existing entry that is not a safe candidate to replace) onto
// ErrNodeUnverified.
func placeNode(ctx context.Context, path string, create func(tmp string) error) error {
	if err := dmpkg.PlaceNode(ctx, path, create); err != nil {
		if errors.Is(err, dmpkg.ErrNodeUnverified) {
			return &errs.Error{Kind: ErrNodeUnverified, Detail: "replace the device node " + path}
		}
		return err
	}
	return nil
}

// ensureDeviceNode makes /dev/dm-<minor> the block node of the device info
// describes. It is needed where udev and devtmpfs do not provide it, which
// is the case in a container with its own /dev.
//
// A node that is already there is used ONLY if it carries this device's
// number, never merely because something exists at the path: dm minors are
// recycled, so a stale node left by an earlier mapping must not be adopted.
func ensureDeviceNode(ctx context.Context, _ string, info *devmapper.DeviceInfo) error {
	_, minor := unix.Major(info.DevNo), unix.Minor(info.DevNo)
	dmPath := dmNodePath(minor)
	if isOurNode(dmPath, info) {
		return nil
	}
	if err := placeNode(ctx, dmPath, func(tmp string) error { return sys.makeBlockNode(tmp, info.DevNo) }); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "create the device node " + dmPath, Err: err}
	}
	return nil
}

// waitForDeviceReady waits for /dev/mapper/<name> to name the device info
// describes, and makes that entry itself when udev does not.
//
// "Ready" is decided by identity, not existence: a stale entry from an
// earlier mapping must not pass for the new one.
func waitForDeviceReady(ctx context.Context, name string, info *devmapper.DeviceInfo) error {
	mapperPath := mapperNodePath(name)
	met, err := pollUntil(ctx, dmpkg.DeviceReadyTimeout, dmpkg.DeviceReadyPollInterval, func() bool { return isOurNode(mapperPath, info) })
	if err != nil {
		return err
	}
	if met {
		return nil
	}

	// udev has not made it, or made it and it was replaced. Make it here,
	// pointing at a /dev/dm-N that has itself been verified.
	if err := ensureDeviceNode(ctx, name, info); err != nil {
		return err
	}
	_, minor := unix.Major(info.DevNo), unix.Minor(info.DevNo)
	dmPath := dmNodePath(minor)
	if err := os.MkdirAll(mapperDir(), 0o750); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "create the directory " + mapperDir(), Err: err}
	}
	if err := placeNode(ctx, mapperPath, func(tmp string) error { return os.Symlink(dmPath, tmp) }); err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "create the device-mapper symlink " + mapperPath, Err: err}
	}
	if !isOurNode(mapperPath, info) {
		return &errs.Error{Kind: ErrNodeUnverified, Detail: "verify the device-mapper symlink " + mapperPath}
	}
	return nil
}

// removeMappingNodes deletes the device nodes a mapping left behind, and
// ONLY those that are still that mapping's. The identity-checked removal
// mechanism lives in internal/dm; see dmpkg.RemoveMappingNodes.
// removeMappingNodes deletes the device nodes a mapping left behind, and
// ONLY those that are still that mapping's. The identity-checked removal
// mechanism lives in internal/dm; see dmpkg.RemoveMappingNodes.
func removeMappingNodes(ctx context.Context, name string, info *devmapper.DeviceInfo) {
	dmpkg.RemoveMappingNodes(ctx, sys.devDir, sys.blockNodeRdev, name, info)
}
