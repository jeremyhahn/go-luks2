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

// keyslotDevice is how a keyslot operation reaches the device it is changing.
//
// # One descriptor for the whole operation (#249, A10)
//
// Every keyslot operation used to resolve the device PATH again at each step:
// once to lock it, once to read the header, once to measure it, once to write
// the key material, once to write the header and once more to wipe. ChangeKey's
// material write did not even go through openDevice. A path is a name, not a
// device: between two of those steps a udev rule, an attacker who controls a
// parent directory, or an operator re-pointing a /dev/disk/by-* link can make it
// name something else, and the lock -- taken on the FIRST descriptor -- protects
// nothing the later ones reach. Authentication and the header read then happen
// against volume A while the new key material, the header and the wipe land on
// device B.
//
// A pinned keyslotDevice holds the descriptor the lock was taken on and does
// every read, size measurement, write, sync and wipe through it, so the
// operation acts on exactly the inode it locked. What that descriptor IS is
// checked on the descriptor itself (requireLockableDevice), not on the path.
//
// O_NOFOLLOW is deliberately not used. The paths operators pass are very often
// symlinks -- /dev/disk/by-uuid, /dev/mapper -- and refusing them would refuse
// the ordinary case. Following the link ONCE is safe; following it six times
// was the defect.
//
// MigrateToFIPS is pinned the same way (#255): it was the last keyslot writer
// that reached the device by path, kept so because its crash suite counted
// path opens as write steps. That suite now observes the steps on the pinned
// descriptor itself, through keyslotWriteStep.
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

// keyslotLockWait is how long a keyslot operation waits for the device's
// locks: DefaultLockWait, as acquireDeviceLock waits. A variable so a test
// process can observe the bounded refusal without spending the whole budget;
// nothing else changes it.
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

// requireLockableDevice checks, on the DESCRIPTOR, what ValidateDevicePath
// checked on the path: a regular file or a block device. The path check came
// first and is a different moment; this is the one that describes what the
// operation will actually write to.
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

// mediumPath names the pinned descriptor's file for an operation that must
// open it again with other flags -- an O_DIRECT read past the page cache. It is
// the descriptor's /proc/self/fd entry, which reopens the inode the lock was
// taken on rather than resolving the operator's path a second time.
func (d *keyslotDevice) mediumPath() string {
	return "/proc/self/fd/" + strconv.Itoa(int(d.file.Fd())) // #nosec G115 -- a descriptor number fits an int
}

// readHeader reads the current header copy (readCurrentHeader). The first read
// of an operation -- the one its read-modify-write starts from, under the
// exclusive lock -- also rewrites the other copy from it when that copy is
// invalid or older (repairHeaderCopies), so the write starts from the copy
// cryptsetup would use with both copies level. Later reads, such as the
// verification after the operation's own writes, report what is on the medium
// and repair nothing: rewriting there would hide a copy damaged by the write.
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

// readPrimaryHeader reads and validates the primary header copy alone, and
// repairs nothing. MigrateToFIPS alone uses it: its design ("Both header
// copies", fipsmigrate.go) holds the primary authoritative, reconciles the
// secondary to it as a reported stage of its own, refuses a torn primary
// before writing, and re-reads after its writes to catch a copy damaged since
// -- which a read that repaired would hide.
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

// writeArea writes data at offset, fills the rest of an area of size bytes with
// zeros, and makes it durable. Nothing here decides WHERE: the caller has
// already placed the area inside the keyslots area.
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
