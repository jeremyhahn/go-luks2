// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/pkg/dmcrypt"
	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
)

// MountOptions is the pre-redesign library's luks2.MountOptions shape.
type MountOptions struct {
	Device     string
	MountPoint string
	FSType     string
	Flags      uintptr
	Data       string
}

// Mount mounts an unlocked LUKS volume named by its device-mapper mapping,
// the way the pre-redesign library's luks2.Mount did before B.6 moved
// mounting to pkg/filesystem, which takes a device path rather than a
// mapping name.
func Mount(opts MountOptions) error {
	ctx := context.Background()
	m, err := dmcrypt.Lookup(ctx, opts.Device)
	if err != nil {
		return err
	}
	return filesystem.Mount(ctx, filesystem.MountParams{
		Source: m.Path(),
		Target: opts.MountPoint,
		Type:   filesystem.Type(opts.FSType),
		Flags:  opts.Flags,
		Data:   opts.Data,
	})
}

// Unmount unmounts mountPoint, the way the pre-redesign library's
// luks2.Unmount did, translating raw umount2(2) flags the same way it did.
func Unmount(mountPoint string, flags int) error {
	var uf filesystem.UnmountFlags
	if flags&unix.MNT_FORCE != 0 {
		uf |= filesystem.Force
	}
	if flags&unix.MNT_DETACH != 0 {
		uf |= filesystem.Detach
	}
	if flags&unix.MNT_EXPIRE != 0 {
		uf |= filesystem.Expire
	}
	return filesystem.Unmount(context.Background(), mountPoint, uf)
}

// IsMounted reports whether path is a mount point, the way the pre-redesign
// library's luks2.IsMounted did.
func IsMounted(mountPoint string) (bool, error) {
	return filesystem.IsMounted(context.Background(), mountPoint)
}

// IsMappingMounted reports whether a filesystem on the device-mapper mapping
// name is mounted, the way the pre-redesign library's luks2.IsMappingMounted
// did before the API redesign retired it in favor of this exact composition:
// dmcrypt.Lookup to resolve the mapping's device number, then
// filesystem.DeviceMounted to match it against /proc/self/mountinfo.
func IsMappingMounted(name string) (bool, error) {
	m, err := dmcrypt.Lookup(context.Background(), name)
	if err != nil {
		if errors.Is(err, dmcrypt.ErrNotActive) {
			return false, nil
		}
		return false, err
	}
	return filesystem.DeviceMounted(context.Background(), m.Major, m.Minor)
}
