// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// Destructive operations: formatting a block device, wiping a volume, and
// overwriting a header copy.
//
// They follow cryptsetup's model, with one difference. cryptsetup asks for a
// literal YES and accepts --batch-mode instead; it also proceeds WITHOUT asking
// whenever standard input is not a terminal. This tool always asks unless
// --batch-mode (or --yes) is given, so a script that pipes something else into
// it is refused rather than obeyed. Anything but YES -- including end of input
// and a read error -- cancels the operation and exits non-zero: a script
// checking the exit status must never read a canceled wipe as a finished one.
//
// Formatting a block device also refuses a device that already carries a LUKS
// header or a filesystem signature unless --force is given, and a device the
// kernel reports in use (mounted, mapped, held) always.

// maxConfirmationLine bounds how much of standard input one confirmation
// reads. YES is three bytes; a longer line is not YES.
const maxConfirmationLine = 64

// batchFlags declares --batch-mode and its alias --yes, and reports whether
// either was given.
func batchFlags(o *options) func() bool {
	batch := o.Bool("batch-mode")
	yes := o.Bool("yes")
	return func() bool { return *batch || *yes }
}

// batchFlagsHelp describes the flags batchFlags declares.
const batchFlagsHelp = `  --batch-mode, --yes  Do not ask for confirmation. For scripts.
`

// confirmDestructive asks for a literal YES on standard input, unless batch is
// set. It returns nil only for YES; any other answer is ErrNotConfirmed, and
// end of input or a read error is a ConfirmationError wrapping it.
func (c *CLI) confirmDestructive(prompt string, batch bool) error {
	if batch {
		return nil
	}
	_, _ = fmt.Fprint(c.Stdout, prompt)

	answer, err := readConfirmation(c.Stdin)
	_, _ = fmt.Fprintln(c.Stdout)
	switch {
	case err != nil:
		return &ConfirmationError{Err: err}
	case answer != "YES":
		return &ConfirmationError{Err: ErrNotConfirmed}
	}
	return nil
}

// readConfirmation reads one line, one byte at a time so nothing after it is
// consumed. A line ended by end of input counts; no line at all is
// io.ErrUnexpectedEOF.
func readConfirmation(r io.Reader) (string, error) {
	var (
		line []byte
		one  = make([]byte, 1)
	)
	for len(line) <= maxConfirmationLine {
		n, err := r.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return strings.TrimSuffix(string(line), "\r"), nil
			}
			line = append(line, one[0])
		}
		if errors.Is(err, io.EOF) {
			if len(line) == 0 {
				return "", io.ErrUnexpectedEOF
			}
			return string(line), nil
		}
		if err != nil {
			return "", err
		}
	}
	return string(line), nil
}

// refuseUnconfirmed reports a canceled destructive operation and returns its
// exit status.
func (c *CLI) refuseUnconfirmed(what string, err error) int {
	_, _ = fmt.Fprintf(c.Stderr, "%s canceled: %v\n", what, err)
	return 1
}

// absPath resolves an operator's path argument against the working directory.
// The library takes absolute paths only, and the documentation shows relative
// ones, so the tool resolves them -- once, here, rather than in every command.
func absPath(command, arg string) (string, error) {
	if arg == "" {
		return "", &UsageError{Command: command, Detail: "an empty path"}
	}
	abs, err := filepath.Abs(arg)
	if err != nil {
		return "", &UsageError{Command: command, Detail: fmt.Sprintf("cannot resolve %q: %v", arg, err)}
	}
	return abs, nil
}

// pathKind is what is at a path create was given.
type pathKind int

const (
	pathAbsent pathKind = iota
	pathRegular
	pathBlockDevice
	pathOther
)

// DeviceProber is how create inspects a path before it formats anything.
type DeviceProber interface {
	// Kind reports what is at path, following symlinks: /dev/disk/by-id
	// names are links to the device.
	Kind(path string) (pathKind, error)

	// Claim opens the block device at path read-only and EXCLUSIVELY, and
	// names the first LUKS header, filesystem or partition-table signature it
	// finds, or "" when there is none. A device the kernel reports in use is
	// luks2.ErrDeviceInUse. The exclusive claim is held until release is
	// called, so nothing can mount or map the device while the operator is
	// asked to confirm and to choose a passphrase.
	Claim(path string) (found string, release func(), err error)
}

// DefaultDeviceProber is the DeviceProber on the real system.
type DefaultDeviceProber struct{}

// Kind stats path.
func (DefaultDeviceProber) Kind(path string) (pathKind, error) {
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

// Claim reads the start of the device, opened with O_EXCL so that a mounted,
// mapped or otherwise held device is refused before anything else, and keeps
// it open -- and so claimed -- until release.
func (DefaultDeviceProber) Claim(path string) (string, func(), error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_EXCL|unix.O_CLOEXEC, 0) // #nosec G304 -- the operator's device argument
	if errors.Is(err, unix.EBUSY) {
		return "", nil, &DevicePathError{Path: path, Op: "open", Err: luks2.ErrDeviceInUse}
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

// knownSignatures are what create refuses to format over without --force: a
// LUKS header, a filesystem, a RAID or LVM member, a partition table. The
// offsets and magics are those blkid's probes use.
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

// signatureScanSize is how much of the device findSignature reads: past the
// furthest offset in knownSignatures.
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

// removeCreated removes path only if it is the file this run created and
// still holds open as created.
//
// Checking and then removing by name would race: the path could be replaced
// between the check and the unlink. So the path is first moved aside with an
// atomic rename to a name of this process's own, the file now at that name is
// compared with the held descriptor, and only a match is unlinked. Anything
// else is renamed back -- RENAME_NOREPLACE, so nothing that has since
// appeared at the path is overwritten -- and the cleanup is refused.
func removeCreated(path string, created *os.File) error {
	aside := path + ".luks2-cleanup-" + strconv.Itoa(os.Getpid())
	if err := unix.Renameat2(unix.AT_FDCWD, path, unix.AT_FDCWD, aside, unix.RENAME_NOREPLACE); err != nil {
		return &DevicePathError{Path: path, Op: "move aside for removal", Err: err}
	}
	if stillCreated(aside, created) {
		return os.Remove(aside)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, aside, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return &DevicePathError{Path: aside, Op: "put back a file this run did not create (it was moved aside from " + path + ")", Err: err}
	}
	return &DevicePathError{Path: path, Op: "remove", Err: os.ErrNotExist}
}

// stillCreated reports whether path still names the regular file this run
// created and still holds open as created, so cleanup removes that file and
// never one put in its place. The descriptor is what makes the comparison
// sound: an inode number is reused as soon as its file is gone, but not while
// a descriptor keeps it alive.
func stillCreated(path string, created *os.File) bool {
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
