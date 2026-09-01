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

	"golang.org/x/sys/unix"
)

// MountOptions contains options for mounting
type MountOptions struct {
	Device     string  // Device mapper name (e.g., "my-volume")
	MountPoint string  // Where to mount (e.g., "/mnt/encrypted")
	FSType     string  // Filesystem type (e.g., "ext4", "xfs")
	Flags      uintptr // Mount flags (unix.MS_RDONLY, etc.)
	Data       string  // Mount data/options
}

// Mount mounts an unlocked LUKS volume using syscall.
//
// There is deliberately no already-mounted refusal, and no ErrAlreadyMounted
// sentinel for one to return (#70). Linux permits STACKING a mount over an
// existing mount point, so "already mounted" is a legal state rather than an
// error condition, and a pre-check that refused it would remove a capability
// the kernel offers. A caller that wants to know asks IsMounted, which is
// exported and answers exactly that question.
func Mount(opts MountOptions) error {
	// Get the device path (handles both udev and non-udev environments)
	devicePath, err := GetMappedDevicePath(opts.Device)
	if err != nil {
		return fmt.Errorf("%w: no mapping named %q was found, so there is nothing to mount", ErrVolumeNotUnlocked, opts.Device)
	}

	// Check if device exists
	if _, err := os.Stat(devicePath); err != nil {
		return fmt.Errorf("%w: the mapping named %q resolves to %s, which is not there", ErrVolumeNotUnlocked, opts.Device, devicePath)
	}

	// Check if mount point exists
	if _, err := os.Stat(opts.MountPoint); os.IsNotExist(err) {
		return fmt.Errorf("mount point %s does not exist", opts.MountPoint)
	}

	// Use syscall to mount
	err = unix.Mount(devicePath, opts.MountPoint, opts.FSType, opts.Flags, opts.Data)
	if err != nil {
		return fmt.Errorf("mount syscall failed: %w", err)
	}

	return nil
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
		return fmt.Errorf("invalid unmount flags: 0x%x is not among MNT_FORCE, MNT_DETACH, MNT_EXPIRE and UMOUNT_NOFOLLOW", unknown)
	}
	if flags&unix.MNT_EXPIRE != 0 && flags&(unix.MNT_FORCE|unix.MNT_DETACH) != 0 {
		return fmt.Errorf("invalid unmount flags: MNT_EXPIRE cannot be combined with MNT_FORCE or MNT_DETACH")
	}

	if err := unmountFunc(mountPoint, flags); err != nil {
		if errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("%w: %s is not a mount point", ErrNotMounted, mountPoint)
		}
		return fmt.Errorf("unmount syscall failed: %w", err)
	}
	return nil
}

// IsMounted reports whether a path is a mount point, by reading /proc/mounts.
func IsMounted(mountPoint string) (bool, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return false, fmt.Errorf("failed to open /proc/mounts: %w", err)
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
		return false, fmt.Errorf("error reading /proc/mounts: %w", err)
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
