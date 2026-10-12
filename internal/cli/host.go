// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"

	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/loop"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// mapping is the host's view of one active dm-crypt mapping: enough to
// build its device-mapper path and to check whether a filesystem on it is
// mounted. pkg/dmcrypt.Mapping carries Name, UUID, Major
// and Minor; this carries only the fields open.go, close.go and mount.go
// actually use today.
type mapping struct {
	name         string
	major, minor uint32
}

// path is the device-mapper node for the mapping, exactly as
// pkg/dmcrypt.Mapping.Path will report it.
func (m mapping) path() string { return "/dev/mapper/" + m.name }

// activator is the dm-crypt boundary (pkg/dmcrypt): activate a volume
// key as a named mapping, tear one down, and resolve a mapping name back to
// its device number. Every method mirrors a pkg/dmcrypt function 1:1.
// realActivator, below, is the production implementation; open, close,
// mount and unmount are also unit-tested against a fake one.
type activator interface {
	activate(ctx context.Context, v *luks2.Volume, key *luks2.Key, name string) (mapping, error)
	deactivate(ctx context.Context, name string) error
	lookup(ctx context.Context, name string) (mapping, error)
}

// mounter is the filesystem boundary (pkg/filesystem),
// kept behind an interface so a unit test never touches the real mount
// table.
type mounter interface {
	mount(ctx context.Context, p filesystem.MountParams) error
	unmount(ctx context.Context, target string, flags filesystem.UnmountFlags) error
	isMounted(ctx context.Context, target string) (bool, error)
	deviceMounted(ctx context.Context, major, minor uint32) (bool, error)
	detect(ctx context.Context, device string) (filesystem.Type, error)
	make(ctx context.Context, device string, t filesystem.Type, p filesystem.MakeParams) error
}

// loopDevice is the host's view of an attached loop device: enough to open
// it (its path) and to detach it again.
type loopDevice struct {
	devPath string

	// dev is the device Attach returned, which detach must use: it holds
	// the backing file's identity, and Detach refuses a device no longer
	// backed by that file. A device rebuilt from devPath by Lookup would
	// take whatever the number is attached to at that later moment.
	dev *loop.Device
}

func (d loopDevice) path() string { return d.devPath }

// looper is the loop-device boundary (pkg/loop): attach a
// file as a loop device, and detach one again. create's file-volume flow is
// the only user: it formats a regular file directly, then needs a block
// device to activate a dm-crypt mapping on.
type looper interface {
	attach(ctx context.Context, file string) (loopDevice, error)
	detach(ctx context.Context, d loopDevice) (loop.DetachState, error)
}

// realLooper is the production looper: pkg/loop, unmodified.
type realLooper struct{}

func (realLooper) attach(ctx context.Context, file string) (loopDevice, error) {
	d, err := loop.Attach(ctx, file)
	if err != nil {
		return loopDevice{}, err
	}
	return loopDevice{devPath: d.Path(), dev: d}, nil
}

func (realLooper) detach(ctx context.Context, d loopDevice) (loop.DetachState, error) {
	dev := d.dev
	if dev == nil {
		var err error
		if dev, err = loop.Lookup(ctx, d.devPath); err != nil {
			return 0, err
		}
	}
	return dev.Detach(ctx)
}

// realActivator is the production activator: pkg/dmcrypt, unmodified.
type realActivator struct{}

func (realActivator) activate(ctx context.Context, v *luks2.Volume, key *luks2.Key, name string) (mapping, error) {
	m, err := dmcrypt.Activate(ctx, v, key, name)
	if err != nil {
		return mapping{}, err
	}
	return mapping{name: m.Name, major: m.Major, minor: m.Minor}, nil
}

func (realActivator) deactivate(ctx context.Context, name string) error {
	return dmcrypt.Deactivate(ctx, name)
}

func (realActivator) lookup(ctx context.Context, name string) (mapping, error) {
	m, err := dmcrypt.Lookup(ctx, name)
	if err != nil {
		return mapping{}, err
	}
	return mapping{name: m.Name, major: m.Major, minor: m.Minor}, nil
}

// realMounter is the production mounter: pkg/filesystem, unmodified.
type realMounter struct{}

func (realMounter) mount(ctx context.Context, p filesystem.MountParams) error {
	return filesystem.Mount(ctx, p)
}

func (realMounter) unmount(ctx context.Context, target string, flags filesystem.UnmountFlags) error {
	return filesystem.Unmount(ctx, target, flags)
}

func (realMounter) isMounted(ctx context.Context, target string) (bool, error) {
	return filesystem.IsMounted(ctx, target)
}

func (realMounter) deviceMounted(ctx context.Context, major, minor uint32) (bool, error) {
	return filesystem.DeviceMounted(ctx, major, minor)
}

func (realMounter) detect(ctx context.Context, device string) (filesystem.Type, error) {
	return filesystem.Detect(ctx, device)
}

func (realMounter) make(ctx context.Context, device string, t filesystem.Type, p filesystem.MakeParams) error {
	return filesystem.Make(ctx, device, t, p)
}

// host groups the root-only boundaries every command reaches through
// rather than calling a root-sensitive package directly.
type host struct {
	activator activator
	looper    looper
	mounter   mounter
}
