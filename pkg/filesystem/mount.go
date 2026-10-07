// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package filesystem

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"golang.org/x/sys/unix"
)

// MountParams contains the parameters for Mount.
type MountParams struct {
	// Source is the device path to mount (not a device-mapper mapping
	// name).
	Source string

	// Target is where to mount it (e.g., "/mnt/encrypted").
	Target string

	// Type is the filesystem type; empty detects it with Detect.
	Type Type

	// Flags are the mount(2) flags (unix.MS_RDONLY, etc.).
	Flags uintptr

	// Data is the mount(2) data/options string.
	Data string
}

// Mount mounts the filesystem on p.Source at p.Target using the mount(2)
// syscall.
//
// An empty p.Type mounts the filesystem Detect finds on p.Source, and
// refuses with ErrNotDetected when it finds none.
//
// There is deliberately no already-mounted refusal, and no ErrAlreadyMounted
// sentinel for one to return (#70). Linux permits STACKING a mount over an
// existing mount point, so "already mounted" is a legal state rather than an
// error condition, and a pre-check that refused it would remove a capability
// the kernel offers. A caller that wants to know asks IsMounted, which
// answers exactly that question.
func Mount(ctx context.Context, p MountParams) (err error) {
	defer func() { err = errs.At("filesystem", "Mount", p.Source, err) }()
	if err := ctx.Err(); err != nil {
		return &Error{Kind: err}
	}

	if _, err := os.Stat(p.Target); os.IsNotExist(err) {
		return &Error{Kind: ErrInvalidArgument, Detail: "mount point " + p.Target + " does not exist", Err: err}
	}

	// No type named means the type ON THE DEVICE, as blkid identifies it --
	// never an assumed one. Mounting under the wrong type fails at best, and
	// a caller that hard-codes ext4 cannot mount the xfs volume Make made.
	fsType := p.Type
	if fsType == "" {
		detected, err := probeFilesystem(ctx, probeOutputRunner, p.Source)
		if err != nil {
			return err
		}
		fsType = detected
	}

	if err := sys.mount(p.Source, p.Target, string(fsType), p.Flags, p.Data); err != nil {
		return &Error{Kind: errs.ErrIO, Detail: "mount syscall failed (" + string(fsType) + ")", Err: err}
	}

	return nil
}

// deviceListedInMountInfo reports whether any mount in a mountinfo-formatted
// stream is of the device major:minor. The third field of every mountinfo
// line is that device number (proc(5)).
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
		return false, &Error{Kind: errs.ErrIO, Detail: "error reading the mount table", Err: err}
	}
	return false, nil
}

// DeviceMounted reports whether a filesystem on the device numbered
// major:minor is mounted, in this process's mount namespace.
//
// It matches the mounted DEVICE, by number, and not a path: a filesystem
// mounted through a different path to the same device (/dev/dm-N or a udev
// alias, for example) is still seen. A caller that has a device-mapper
// mapping name resolves it to its device number first; dmcrypt.Lookup does
// that.
func DeviceMounted(ctx context.Context, major, minor uint32) (mounted bool, err error) {
	defer func() { err = errs.At("filesystem", "DeviceMounted", "", err) }()
	if err := ctx.Err(); err != nil {
		return false, &Error{Kind: err}
	}

	f, err := os.Open(sys.mountInfoPath)
	if err != nil {
		return false, &Error{Kind: errs.ErrIO, Detail: "failed to open " + sys.mountInfoPath, Err: err}
	}
	defer func() { _ = f.Close() }()

	return deviceListedInMountInfo(f, major, minor)
}

// UnmountFlags selects behavior for Unmount, mirroring a subset of
// umount2(2)'s flags. The zero value asks for an ordinary unmount.
type UnmountFlags int

const (
	// Force asks for a forced unmount, even if the filesystem is busy (NFS
	// only; on other filesystems its effect is undefined -- umount2(2)).
	Force UnmountFlags = 1 << iota

	// Detach unmounts the mount point immediately but defers releasing the
	// underlying filesystem until it is no longer busy (MNT_DETACH, "lazy").
	Detach

	// Expire marks a mount point that is not currently busy as expired,
	// rather than unmounting it; a SECOND call with Expire on a mount point
	// that is still not busy then unmounts it. It cannot be combined with
	// Force or Detach.
	Expire
)

// knownUnmountFlags is every flag Unmount accepts, as one mask, so it can
// refuse a flags argument it does not recognize.
const knownUnmountFlags = Force | Detach | Expire

// toUnix translates f to the umount2(2) flags it names.
func (f UnmountFlags) toUnix() int {
	var out int
	if f&Force != 0 {
		out |= unix.MNT_FORCE
	}
	if f&Detach != 0 {
		out |= unix.MNT_DETACH
	}
	if f&Expire != 0 {
		out |= unix.MNT_EXPIRE
	}
	return out
}

// Unmount unmounts target using the umount2(2) syscall.
//
// # The kernel decides whether this is a mount point, not us
//
// A pre-check with IsMounted would duplicate a decision the kernel already
// makes, and /proc/mounts ESCAPES its fields, so a real mount at "/mnt/my
// disk" appears there as "/mnt/my\040disk" -- a string comparison against the
// raw field would refuse a mount point the kernel would unmount quite
// happily (#70, caught in review of #87). So the kernel is asked, and its
// answer is classified.
//
// # Why an EINVAL from the kernel can be read as "not a mount point"
//
// That reading is only sound because of the flag check below it. umount2(2)
// documents exactly three causes for EINVAL: the target is not a mount
// point; Expire was combined with Force or Detach; and flags contains a
// value it does not define. The second and third are properties of the
// CALLER'S OWN ARGUMENT -- not of the system, and not subject to drift -- so
// refusing them here leaves the first as the only remaining reading.
func Unmount(ctx context.Context, target string, flags UnmountFlags) (err error) {
	defer func() { err = errs.At("filesystem", "Unmount", target, err) }()
	if err := ctx.Err(); err != nil {
		return &Error{Kind: err}
	}

	if unknown := flags &^ knownUnmountFlags; unknown != 0 {
		return &Error{Kind: ErrInvalidArgument, Detail: fmt.Sprintf("invalid unmount flags: 0x%x is not among Force, Detach and Expire", int(unknown))}
	}
	if flags&Expire != 0 && flags&(Force|Detach) != 0 {
		return &Error{Kind: ErrInvalidArgument, Detail: "invalid unmount flags: Expire cannot be combined with Force or Detach"}
	}

	if err := sys.unmount(target, flags.toUnix()); err != nil {
		if errors.Is(err, unix.EINVAL) {
			return &Error{Kind: ErrNotMounted, Detail: fmt.Sprintf("%s is not a mount point", target)}
		}
		return &Error{Kind: errs.ErrIO, Detail: "unmount syscall failed", Err: err}
	}
	return nil
}

// IsMounted reports whether target is a mount point, by reading
// /proc/mounts.
func IsMounted(ctx context.Context, target string) (mounted bool, err error) {
	defer func() { err = errs.At("filesystem", "IsMounted", target, err) }()
	if err := ctx.Err(); err != nil {
		return false, &Error{Kind: err}
	}

	file, err := os.Open(sys.procMountsPath)
	if err != nil {
		return false, &Error{Kind: errs.ErrIO, Detail: "failed to open " + sys.procMountsPath, Err: err}
	}
	defer func() { _ = file.Close() }()

	return mountPointListed(file, target)
}

// mountPointListed reports whether target appears as the target of any line
// in a /proc/mounts-formatted stream.
//
// It is separate from IsMounted so the parsing can be tested against a table
// the test writes, rather than against whatever the host happens to have
// mounted -- which is the only way to exercise an escaped path at all.
func mountPointListed(r io.Reader, target string) (bool, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && unescapeMountField(fields[1]) == target {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, &Error{Kind: errs.ErrIO, Detail: "error reading " + sys.procMountsPath, Err: err}
	}

	return false, nil
}

// unescapeMountField decodes the octal escapes the kernel writes into
// /proc/mounts.
//
// The fields there are SPACE-DELIMITED, so the four bytes that would break
// that grammar are mangled on the way out: space, tab, newline and backslash
// become \040, \011, \012 and \134 (fs/proc_namespace.c, seq_escape with "
// \t\n\\"). Comparing a caller's path against the raw field therefore fails
// for every mount point containing one of them -- which is exactly how
// Unmount came to refuse a mount it should have unmounted (#70, caught in
// review of #87).
//
// Any three-digit octal escape is decoded, not just those four. A literal
// backslash is itself escaped as \134, so a backslash followed by three
// digits cannot occur in the output except as an escape, and decoding
// generally cannot misread a path the kernel wrote.
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
