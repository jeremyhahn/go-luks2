// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"io"
	"os"
	"strconv"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
)

// keyslotDevice is how a keyslot operation reaches its device: pinned, every read, write, sync and wipe goes through the locked descriptor.
type keyslotDevice struct {
	path   string
	file   *os.File       // the locked descriptor; the lock owns it
	locked *device.Locked // the same lock, for Claim (wipe.go)
	sys    volumeSys      // this operation's seams (see volumeSys)

	// leveled is set once readHeader has brought the header copies level,
	// or by an operation that reconciles them under its own policy
	// (MigrateToFIPS); readHeader repairs only while it is unset.
	leveled bool
}

// pinnedKeyslotDevice wraps the descriptor a FileLock holds. The lock still
// owns it: releasing the lock closes it, and nothing here does.
func pinnedKeyslotDevice(lock *deviceLock, path string, sys volumeSys) (*keyslotDevice, error) {
	file := lock.locked.File()
	if err := requireLockableDevice(file, path); err != nil {
		return nil, err
	}
	return &keyslotDevice{path: path, file: file, locked: lock.locked, sys: sys}, nil
}

// keyslotLockWait is how long a keyslot operation waits for the device locks; a variable for tests.
var keyslotLockWait = DefaultLockWait

// lockKeyslotDevice validates the path, opens and locks it once, and returns the
// lock together with the device pinned to the locked descriptor. The caller
// releases the lock.
func lockKeyslotDevice(ctx context.Context, device string, sys volumeSys) (*deviceLock, *keyslotDevice, error) {
	lock, err := acquireFileLock(ctx, device, keyslotLockWait, clock.System{}, sys)
	if err != nil {
		return nil, nil, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to acquire lock", Err: err}
	}
	dev, err := pinnedKeyslotDevice(lock, device, sys)
	if err != nil {
		_ = lock.Release()
		return nil, nil, err
	}
	return lock, dev, nil
}

// requireLockableDevice checks the descriptor is a regular file or block device.
func requireLockableDevice(f *os.File, path string) error {
	info, err := f.Stat()
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "stat the locked descriptor " + path, Err: err}
	}
	mode := info.Mode()
	if !mode.IsRegular() && mode&os.ModeDevice == 0 {
		return &errs.Error{Kind: ErrInvalidArgument, Detail: path + " is neither a regular file nor a block device"}
	}
	return nil
}

// reader is what every read of the operation goes through: the locked
// descriptor, via pinnedDeviceReader.
func (d *keyslotDevice) reader() io.ReaderAt {
	return d.sys.pinnedDeviceReader(d.file)
}

// mediumPath is the pinned descriptor's /proc/self/fd entry, for reopening the same inode with other flags.
func (d *keyslotDevice) mediumPath() string {
	return "/proc/self/fd/" + strconv.Itoa(int(d.file.Fd())) // #nosec G115 -- a descriptor number fits an int
}

// readHeader reads the current header copy; the first read of an operation also repairs the other copy (repairHeaderCopies).
func (d *keyslotDevice) readHeader() (*header.BinaryHeader, *header.Metadata, error) {
	cur, err := readCurrentHeader(d.reader())
	if err != nil {
		return nil, nil, err
	}
	if cur.Stale && !d.leveled {
		if err := repairHeaderCopies(d, cur); err != nil {
			return nil, nil, err
		}
	}
	d.leveled = true
	return cur.Header, cur.Metadata, nil
}

// readPrimaryHeader reads and validates the primary copy alone and repairs nothing; MigrateToFIPS uses it.
func (d *keyslotDevice) readPrimaryHeader() (*header.BinaryHeader, *header.Metadata, error) {
	return readHeaderCopyFrom(d.reader(), header.PrimaryHeaderOffset)
}

// writeHeader writes both header copies; the caller holds the lock.
func (d *keyslotDevice) writeHeader(ctx context.Context, hdr *header.BinaryHeader, metadata *header.Metadata) error {
	if err := d.sys.keyslotWriteStep(ctx, d, "write the LUKS2 header"); err != nil {
		return err
	}
	return writeHeaderTo(d.file, hdr, metadata, d.sys.syncDevice)
}

// writeArea writes data at offset, zero-fills the rest of a size-byte area, and syncs it.
func (d *keyslotDevice) writeArea(ctx context.Context, op string, offset int64, data []byte, size int64) error {
	if err := d.sys.keyslotWriteStep(ctx, d, op); err != nil {
		return err
	}
	f := d.file
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to seek to keyslot area", Err: err}
	}
	if _, err := f.Write(data); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to write key material", Err: err}
	}
	if pad := size - int64(len(data)); pad > 0 {
		if err := writeZeros(f, pad); err != nil {
			return &errs.Error{Kind: errs.ErrIO, Detail: "failed to write padding", Err: err}
		}
	}
	if err := d.sys.syncKeyslotArea(f); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: "failed to sync", Err: err}
	}
	return nil
}
