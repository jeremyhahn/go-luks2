// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"golang.org/x/sys/unix"
)

// MountOptions contains options for mounting
type MountOptions struct {
	Device     string  // Device mapper name (e.g., "my-volume")
	MountPoint string  // Where to mount (e.g., "/mnt/encrypted")
	FSType     string  // Filesystem type (e.g., "ext4", "xfs"); empty detects it (DetectFilesystem)
	Flags      uintptr // Mount flags (unix.MS_RDONLY, etc.)
	Data       string  // Mount data/options
}

// Mount mounts an unlocked LUKS volume using syscall.
//
// An empty opts.FSType mounts the filesystem DetectFilesystem finds on the
// mapping, and refuses with ErrFilesystemNotDetected when it finds none.
//
// There is deliberately no already-mounted refusal, and no ErrAlreadyMounted
// sentinel for one to return (#70). Linux permits STACKING a mount over an
// existing mount point, so "already mounted" is a legal state rather than an
// error condition, and a pre-check that refused it would remove a capability
// the kernel offers. A caller that wants to know asks IsMounted, which is
// exported and answers exactly that question.
func Mount(opts MountOptions) error {
	// opts.Device is a MAPPING NAME, resolved only through device-mapper: the
	// name is validated, and the node mounted must carry the target's device
	// number. A name that merely stat'd as a block device under /dev/mapper
	// used to be enough, so "../sdb" mounted /dev/sdb and a stale mapper entry
	// mounted whatever it pointed at (#250, C3 and C5). See mappedDevicePath.
	devicePath, _, err := mappedDevicePath(opts.Device)
	if err != nil {
		return err
	}

	// Check if mount point exists
	if _, err := os.Stat(opts.MountPoint); os.IsNotExist(err) {
		return &errs.Error{Detail: "mount point " + opts.MountPoint + " does not exist", Err: err}
	}

	// No type named means the type ON THE DEVICE, as blkid identifies it --
	// never an assumed one. Mounting under the wrong type fails at best, and
	// a caller that hard-codes ext4 cannot mount the xfs volume create made.
	fsType := opts.FSType
	if fsType == "" {
		detected, err := probeFilesystem(probeOutput, devicePath)
		if err != nil {
			return err
		}
		fsType = string(detected)
	}

	if err := unix.Mount(devicePath, opts.MountPoint, fsType, opts.Flags, opts.Data); err != nil {
		return &errs.Error{Detail: "mount syscall failed (" + fsType + ")", Err: err}
	}

	return nil
}

// mountInfoPath is the mount table IsMappingMounted reads. A variable so the
// unit tests can hand it a table they wrote.
var mountInfoPath = "/proc/self/mountinfo"

// IsMappingMounted reports whether a filesystem on the device-mapper mapping
// name is mounted, in this process's mount namespace.
//
// It matches the mounted DEVICE, by number, and not a path. /proc/self/mountinfo
// records each mount's st_dev as major:minor, and that is compared with the
// mapping's dm DevNo. IsMounted answers a different question -- whether a PATH
// is a mount point -- and the CLI's close used to ask it about
// "/dev/mapper/<name>", which is never a mount point, so the still-mounted
// refusal could not fire (#250, C10). Matching a source path instead would
// still miss a filesystem mounted through /dev/dm-N or a udev alias.
//
// A mapping that does not exist is not mounted: false, nil. A name that is not
// a valid mapping name is refused with ErrInvalidMappingName, and a mount table
// that cannot be read is an error rather than "not mounted".
//
// A filesystem whose st_dev is not the block device's own -- a ZFS pool on the
// mapping, for example -- is not seen here; device-mapper still refuses to
// remove a mapping that is held open, so Lock fails on it with ErrMappingBusy.
func IsMappingMounted(name string) (bool, error) {
	if err := ValidateMappingName(name); err != nil {
		return false, err
	}
	info, err := dm.infoByName(name)
	if err != nil {
		if isNoSuchDevice(err) {
			return false, nil
		}
		return false, &VolumeError{Volume: name, Op: "inspect the device-mapper target of", Err: err}
	}

	f, err := os.Open(mountInfoPath)
	if err != nil {
		return false, &errs.Error{Detail: "failed to open " + mountInfoPath, Err: err}
	}
	defer func() { _ = f.Close() }()

	major, minor := decodeDevNo(info.DevNo)
	return deviceListedInMountInfo(f, major, minor)
}

// deviceListedInMountInfo reports whether any mount in a mountinfo-formatted
// stream is of the device major:minor. The third field of every mountinfo line
// is that device number (proc(5)).
func deviceListedInMountInfo(r io.Reader, major, minor uint32) (bool, error) {
	want := strconv.FormatUint(uint64(major), 10) + ":" + strconv.FormatUint(uint64(minor), 10)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == want {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, &errs.Error{Detail: "error reading " + mountInfoPath, Err: err}
	}
	return false, nil
}

// umountFlags is every flag umount2(2) defines, as one mask.
//
// It exists so Unmount can refuse a flags argument the kernel does not
// recognize. That refusal is not tidiness -- it is what makes the EINVAL
// classification in Unmount mean exactly one thing.
const umountFlags = unix.MNT_FORCE | unix.MNT_DETACH | unix.MNT_EXPIRE | unix.UMOUNT_NOFOLLOW

// unmountFunc is the syscall seam Unmount goes through, in the same idiom as
// the dm value in devicemapper.go and openFileFunc in security.go.
//
// It exists because the property this function has to hold -- that the KERNEL
// decides whether a path is a mount point, and that it is asked -- cannot be
// observed from the return value alone: "not a mount point" and "refused before
// asking" are the same error to a caller. A test can only tell them apart by
// watching whether the syscall happened.
var unmountFunc = unix.Unmount

// Unmount unmounts a LUKS volume using syscall.
//
// # The kernel decides whether this is a mount point, not us
//
// This used to consult IsMounted first and return ErrNotMounted without calling
// the syscall. That was a REGRESSION, found by review on the change that
// introduced it (#70), and the bug is instructive: /proc/mounts ESCAPES its
// fields, so a real mount at "/mnt/my disk" appears there as
// "/mnt/my\040disk". The string comparison missed it, and Unmount refused a
// mount point the kernel would have unmounted quite happily -- a false negative
// for any path containing a space, tab, newline or backslash.
//
// The general shape is worth keeping: a pre-check that duplicates a decision
// the kernel already makes is a second source of truth, and it can only ever
// drift away from the first. So the kernel is asked, and its answer is
// classified.
//
// # Why an EINVAL from the kernel can be read as "not a mount point"
//
// That reading is only sound because of the flag check above it. umount2(2)
// documents exactly three causes for EINVAL: the target is not a mount point;
// MNT_EXPIRE was combined with MNT_FORCE or MNT_DETACH; and flags contains a
// value it does not define. The second and third are properties of the
// CALLER'S OWN ARGUMENT -- not of the system, and not subject to drift -- so
// refusing them here leaves the first as the only remaining reading. Remove the
// flag validation and the classification silently becomes a guess again.
func Unmount(mountPoint string, flags int) error {
	if unknown := flags &^ umountFlags; unknown != 0 {
		return &errs.Error{
			Detail: fmt.Sprintf("invalid unmount flags: 0x%x is not among MNT_FORCE, MNT_DETACH, MNT_EXPIRE and UMOUNT_NOFOLLOW",
				unknown),
		}
	}
	if flags&unix.MNT_EXPIRE != 0 && flags&(unix.MNT_FORCE|unix.MNT_DETACH) != 0 {
		return &errs.Error{
			Detail: "invalid unmount flags: MNT_EXPIRE cannot be combined with MNT_FORCE or MNT_DETACH",
		}
	}

	if err := unmountFunc(mountPoint, flags); err != nil {
		if errors.Is(err, unix.EINVAL) {
			return &errs.Error{
				Kind:   ErrNotMounted,
				Detail: fmt.Sprintf("%s is not a mount point", mountPoint),
			}
		}
		return &errs.Error{Detail: "unmount syscall failed", Err: err}
	}
	return nil
}

// IsMounted reports whether a path is a mount point, by reading /proc/mounts.
func IsMounted(mountPoint string) (bool, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return false, &errs.Error{Detail: "failed to open /proc/mounts", Err: err}
	}
	defer func() { _ = file.Close() }()

	return mountPointListed(file, mountPoint)
}

// mountPointListed reports whether mountPoint appears as the target of any line
// in a /proc/mounts-formatted stream.
//
// It is separate from IsMounted so the parsing can be tested against a table
// the test writes, rather than against whatever the host happens to have
// mounted -- which is the only way to exercise an escaped path at all.
func mountPointListed(r io.Reader, mountPoint string) (bool, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && unescapeMountField(fields[1]) == mountPoint {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, &errs.Error{Detail: "error reading /proc/mounts", Err: err}
	}

	return false, nil
}

// unescapeMountField decodes the octal escapes the kernel writes into
// /proc/mounts.
//
// The fields there are SPACE-DELIMITED, so the four bytes that would break that
// grammar are mangled on the way out: space, tab, newline and backslash become
// \040, \011, \012 and \134 (fs/proc_namespace.c, seq_escape with " \t\n\\").
// Comparing a caller's path against the raw field therefore fails for every
// mount point containing one of them -- which is exactly how Unmount came to
// refuse a mount it should have unmounted (#70, caught in review of #87).
//
// Any three-digit octal escape is decoded, not just those four. A literal
// backslash is itself escaped as \134, so a backslash followed by three digits
// cannot occur in the output except as an escape, and decoding generally cannot
// misread a path the kernel wrote.
func unescapeMountField(field string) string {
	if !strings.Contains(field, "\\") {
		return field
	}

	var out strings.Builder
	out.Grow(len(field))
	for i := 0; i < len(field); {
		if field[i] == '\\' && i+3 < len(field) {
			if value, err := strconv.ParseUint(field[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(value))
				i += 4
				continue
			}
		}
		out.WriteByte(field[i])
		i++
	}
	return out.String()
}
