// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"io"
	"os"
	"strconv"
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
	path string
	file *os.File // the locked descriptor; the lock owns it
}

// pinnedKeyslotDevice wraps the descriptor a FileLock holds. The lock still
// owns it: releasing the lock closes it, and nothing here does.
func pinnedKeyslotDevice(lock *FileLock, path string) (*keyslotDevice, error) {
	if err := requireLockableDevice(lock.file, path); err != nil {
		return nil, err
	}
	return &keyslotDevice{path: path, file: lock.file}, nil
}

// lockKeyslotDevice validates the path, opens and locks it once, and returns the
// lock together with the device pinned to the locked descriptor. The caller
// releases the lock.
func lockKeyslotDevice(device string) (*FileLock, *keyslotDevice, error) {
	lock, err := AcquireFileLock(device)
	if err != nil {
		return nil, nil, &detailError{Detail: "failed to acquire lock", Err: err}
	}
	dev, err := pinnedKeyslotDevice(lock, device)
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
		return &DeviceError{Device: path, Op: "stat the locked descriptor", Err: err}
	}
	mode := info.Mode()
	if !mode.IsRegular() && mode&os.ModeDevice == 0 {
		return &detailError{Kind: ErrInvalidPath, Detail: path + " is neither a regular file nor a block device"}
	}
	return nil
}

// reader is what every read of the operation goes through: the locked
// descriptor, via pinnedDeviceReader.
func (d *keyslotDevice) reader() io.ReaderAt {
	return pinnedDeviceReader(d.file)
}

// pinnedDeviceReader is the read side of a pinned descriptor. A seam for the
// reason readDeviceDirect is one: a page cache that disagrees with the medium
// cannot be produced from a test without a failing device, and MigrateToFIPS's
// cache-model tests substitute it to serve the operation's reads from a stale
// cached view until the cache is dropped. Unexported, substituted only by this
// package's tests.
var pinnedDeviceReader = func(f *os.File) io.ReaderAt { return f }

// keyslotWriteStep runs at the start of every write step a keyslot operation
// makes on its pinned descriptor -- keyslot material, a header (both copies),
// a secondary-header repair, a wipe -- before a byte of it is written. It is
// the boundary MigrateToFIPS's crash suite enumerates: the suite snapshots the
// device at each step and fails a chosen one, which is how it reaches every
// state an interrupted migration can leave now that there is one open, not one
// per step. A no-op in production. Unexported, substituted only by this
// package's tests.
var keyslotWriteStep = func(*keyslotDevice, string) error { return nil }

// mediumPath names the pinned descriptor's file for an operation that must
// open it again with other flags -- an O_DIRECT read past the page cache. It is
// the descriptor's /proc/self/fd entry, which reopens the inode the lock was
// taken on rather than resolving the operator's path a second time.
func (d *keyslotDevice) mediumPath() string {
	return "/proc/self/fd/" + strconv.Itoa(int(d.file.Fd())) // #nosec G115 -- a descriptor number fits an int
}

// readHeader reads and validates the primary header copy.
func (d *keyslotDevice) readHeader() (*LUKS2BinaryHeader, *LUKS2Metadata, error) {
	return readHeaderCopyFrom(d.reader(), LUKS2PrimaryHeaderOffset)
}

// writeHeader writes both header copies; the caller holds the lock.
func (d *keyslotDevice) writeHeader(hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) error {
	if err := keyslotWriteStep(d, "write the LUKS2 header"); err != nil {
		return err
	}
	return writeHeaderTo(d.file, hdr, metadata)
}

// writeArea writes data at offset, fills the rest of an area of size bytes with
// zeros, and makes it durable. Nothing here decides WHERE: the caller has
// already placed the area inside the keyslots area.
func (d *keyslotDevice) writeArea(op string, offset int64, data []byte, size int64) error {
	if err := keyslotWriteStep(d, op); err != nil {
		return err
	}
	f := d.file
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return &detailError{Detail: "failed to seek to keyslot area", Err: err}
	}
	if _, err := f.Write(data); err != nil {
		return &detailError{Detail: "failed to write key material", Err: err}
	}
	if pad := size - int64(len(data)); pad > 0 {
		if err := writeZeros(f, pad); err != nil {
			return &detailError{Detail: "failed to write padding", Err: err}
		}
	}
	if err := syncKeyslotArea(f); err != nil {
		return &detailError{Detail: "failed to sync", Err: err}
	}
	return nil
}

// syncKeyslotArea makes a written keyslot area durable. A seam for the reason
// syncDevice is one: what reaches the medium cannot be made to differ from what
// was written without a failing device, and the read-back that guards against
// exactly that (verifyWrittenKeyslot) needs a test that makes it differ.
// Unexported, substituted only by this package's tests.
var syncKeyslotArea = (*os.File).Sync
