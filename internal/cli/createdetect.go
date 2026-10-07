// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// pathKind is what is at the path create was given.
type pathKind int

const (
	pathAbsent pathKind = iota
	pathRegular
	pathBlockDevice
	pathOther
)

// createPathKind stats path, following symlinks: /dev/disk/by-id names are
// links to the device.
func createPathKind(path string) (pathKind, error) {
	st, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return pathAbsent, nil
	case err != nil:
		return pathOther, err
	case st.Mode().IsRegular():
		return pathRegular, nil
	case st.Mode()&os.ModeDevice != 0 && st.Mode()&os.ModeCharDevice == 0:
		return pathBlockDevice, nil
	}
	return pathOther, nil
}

// claimDevice opens the block device at path read-only and EXCLUSIVELY,
// and names the first LUKS header, filesystem or partition-table signature
// it finds, or "" when there is none. A device the kernel reports in use
// is luks2.ErrDeviceInUse. The exclusive claim is held until release is
// called, so nothing can mount or map the device while the operator is
// asked to confirm and to choose a passphrase.
func claimDevice(path string) (string, func(), error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_EXCL|unix.O_CLOEXEC, 0) // #nosec G304 -- the operator's own device argument
	if errors.Is(err, unix.EBUSY) {
		return "", nil, &errs.Error{Kind: luks2.ErrDeviceInUse, Detail: fmt.Sprintf("%s is in use", path)}
	}
	if err != nil {
		return "", nil, err
	}
	found, err := findSignature(f)
	if err != nil {
		_ = f.Close()
		return "", nil, err
	}
	return found, func() { _ = f.Close() }, nil
}

// signature is one recognizable on-disk magic.
type signature struct {
	name   string
	offset int64
	magic  []byte
}

// knownSignatures are what create refuses to format over without --force:
// a LUKS header, a filesystem, a RAID or LVM member, a partition table.
// The offsets and magics are those blkid's probes use.
var knownSignatures = []signature{
	{"a LUKS header", 0, []byte("LUKS\xba\xbe")},
	{"an ext2/3/4 filesystem", 1080, []byte{0x53, 0xEF}},
	{"an XFS filesystem", 0, []byte("XFSB")},
	{"a btrfs filesystem", 65600, []byte("_BHRfS_M")},
	{"swap space", 4086, []byte("SWAPSPACE2")},
	{"swap space", 4086, []byte("SWAP-SPACE")},
	{"an NTFS filesystem", 3, []byte("NTFS    ")},
	{"an exFAT filesystem", 3, []byte("EXFAT   ")},
	{"a BitLocker volume", 3, []byte("-FVE-FS-")},
	{"a FAT filesystem", 54, []byte("FAT1")},
	{"a FAT filesystem", 82, []byte("FAT32")},
	{"an ISO 9660 filesystem", 32769, []byte("CD001")},
	{"a squashfs filesystem", 0, []byte("hsqs")},
	{"an F2FS filesystem", 1024, []byte{0x10, 0x20, 0xF5, 0xF2}},
	{"an LVM2 physical volume", 512, []byte("LABELONE")},
	{"an LVM2 physical volume", 536, []byte("LVM2 001")},
	{"an md RAID member", 4096, []byte{0xFC, 0x4E, 0x2B, 0xA9}},
	{"an md RAID member", 0, []byte{0xFC, 0x4E, 0x2B, 0xA9}},
	{"a ZFS pool member", 128 << 10, []byte{0x0C, 0xB1, 0xBA, 0x00}},
	{"a ZFS pool member", 128 << 10, []byte{0x00, 0xBA, 0xB1, 0x0C}},
	{"a GPT partition table", 512, []byte("EFI PART")},
	{"a DOS partition table", 510, []byte{0x55, 0xAA}},
}

// signatureScanSize is how much of the device findSignature reads: past
// the furthest offset in knownSignatures.
const signatureScanSize = 136 << 10

// findSignature names the first known signature in r, then any LUKS2
// secondary header copy -- what is left of a container whose primary was
// damaged or wiped -- or "".
func findSignature(r io.ReaderAt) (string, error) {
	head := make([]byte, signatureScanSize)
	n, err := r.ReadAt(head, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	head = head[:n]
	for _, s := range knownSignatures {
		end := s.offset + int64(len(s.magic))
		if end <= int64(len(head)) && bytes.Equal(head[s.offset:end], s.magic) {
			return s.name, nil
		}
	}

	magic := make([]byte, 6)
	for off := int64(16 << 10); off <= 4<<20; off *= 2 {
		if n, _ := r.ReadAt(magic, off); n == len(magic) && bytes.Equal(magic, []byte("SKUL\xba\xbe")) {
			return "a LUKS2 secondary header", nil
		}
	}
	return "", nil
}

// removeCreatedFile removes path only if it is the file this run created
// and still holds open as created.
//
// Checking and then removing by name would race: the path could be
// replaced between the check and the unlink. So the path is first moved
// aside with an atomic rename to a name of this process's own, the file
// now at that name is compared with the held descriptor, and only a match
// is unlinked. Anything else is renamed back -- RENAME_NOREPLACE, so
// nothing that has since appeared at the path is overwritten -- and the
// cleanup is refused.
func removeCreatedFile(path string, created *os.File) error {
	aside := path + ".luks2-cleanup-" + strconv.Itoa(os.Getpid())
	if err := unix.Renameat2(unix.AT_FDCWD, path, unix.AT_FDCWD, aside, unix.RENAME_NOREPLACE); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: fmt.Sprintf("move %s aside for removal", path), Err: err}
	}
	if stillCreatedFile(aside, created) {
		return os.Remove(aside)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, aside, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return &errs.Error{Kind: errs.ErrIO, Detail: fmt.Sprintf("put back a file this run did not create (it was moved aside from %s)", path), Err: err}
	}
	return &errs.Error{Kind: os.ErrNotExist, Detail: path}
}

// stillCreatedFile reports whether path still names the regular file this
// run created and still holds open as created, so cleanup removes that
// file and never one put in its place. The descriptor is what makes the
// comparison sound: an inode number is reused as soon as its file is gone,
// but not while a descriptor keeps it alive.
func stillCreatedFile(path string, created *os.File) bool {
	if created == nil {
		return false
	}
	held, err := created.Stat()
	if err != nil {
		return false
	}
	now, err := os.Lstat(path)
	return err == nil && now.Mode().IsRegular() && os.SameFile(now, held)
}
