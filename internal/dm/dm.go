// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package dm provides the device-mapper mechanism a LUKS2 activation needs:
// the DM_DEV_CREATE ioctl, busy-retry around a removal, and the node
// placement and readiness wait that stand in for udev when it is absent.
//
// Every seam this package needs -- the clock, the device directory, and the
// node-identity check -- is a parameter, never a package-level variable: the
// caller (today, pkg/luks2's transitional deviceMapper seam) owns the state
// and this package stays reference-transparent.
package dm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// ControlPath is the device-mapper control node every dm ioctl is issued on.
const ControlPath = "/dev/mapper/control"

// RemoveRetryBudget and RemoveRetryInitialDelay bound RetryWhileBusy's
// backoff: a hold on a dm target clears within a few seconds or it does not
// clear, and retrying past that budget would turn a genuine failure into a
// hang (#122 -- see RetryWhileBusy).
const (
	RemoveRetryBudget       = 3 * time.Second
	RemoveRetryInitialDelay = 20 * time.Millisecond
)

// DeviceReadyTimeout and DeviceReadyPollInterval bound WaitForDeviceReady's
// wait for udev; MappedNodeTimeout bounds MappedDevicePath's wait for a
// verified node. Both are unchanged from the budgets this package replaces.
const (
	DeviceReadyTimeout      = 3 * time.Second
	DeviceReadyPollInterval = 100 * time.Millisecond
	MappedNodeTimeout       = 5 * time.Second
)

// CreateTarget issues DM_DEV_CREATE and returns the device number from the
// kernel's reply.
//
// devmapper.Create performs the same ioctl and discards the reply, so the only
// way to learn the new target's DevNo through it is a second lookup by name --
// and between the two another process can remove the target and create its
// own under the same name. The reply is the one answer that cannot belong to
// anyone else, so the ioctl is issued here directly.
func CreateTarget(ctx context.Context, name, uuid string) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var req unix.DmIoctl
	// The kernel would silently cut either string, and every identity check
	// after this compares against what it stored. Refused rather than cut, so
	// a caller that skipped its own name validation fails here.
	if len(name) >= len(req.Name) || len(uuid) >= len(req.Uuid) ||
		strings.IndexByte(name, 0) >= 0 || strings.IndexByte(uuid, 0) >= 0 {
		return 0, ErrNameTooLong
	}
	req.Version = [3]uint32{4, 0, 0}
	req.Data_size = unix.SizeofDmIoctl
	req.Data_start = unix.SizeofDmIoctl
	copy(req.Name[:len(req.Name)-1], name)
	copy(req.Uuid[:len(req.Uuid)-1], uuid)

	control, err := os.Open(ControlPath)
	if err != nil {
		return 0, err
	}
	defer func() { _ = control.Close() }()

	// #nosec G103 -- the dm ioctl ABI takes a pointer to struct dm_ioctl, and
	// req is exactly that struct (Data_size covers it and no more).
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, control.Fd(), unix.DM_DEV_CREATE, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return 0, os.NewSyscallError("dm ioctl DM_DEV_CREATE", errno)
	}
	return req.Dev, nil
}

// RetryWhileBusy runs attempt until it stops reporting EBUSY or the budget is
// spent, and reports how many times it ran.
//
// # The ATTEMPT is the caller's whole unit of work, not just the removal
//
// That is the point of the signature: whatever a caller must be sure of
// before removing has to be inside the thing being retried, so that a
// concurrent actor recreating the target mid-backoff is caught by every
// attempt rather than only the first (#122).
//
// It reports the LAST error and leaves the meaning to the caller, because
// different callers face the same errno and owe the operator different
// answers.
func RetryWhileBusy(ctx context.Context, clk clock.Clock, attempt func() error) (attempts int, err error) {
	deadline := clk.Now().Add(RemoveRetryBudget)
	delay := RemoveRetryInitialDelay

	for {
		attempts++
		err = attempt()
		if err == nil || !errors.Is(err, unix.EBUSY) {
			return attempts, err
		}
		remaining := deadline.Sub(clk.Now())
		if remaining <= 0 {
			return attempts, err
		}
		// The LAST wait is clipped to whatever is left, rather than the loop
		// giving up as soon as the next doubling would overshoot (#122).
		t := clk.NewTimer(min(delay, remaining))
		select {
		case <-ctx.Done():
		case <-t.C():
		}
		t.Stop()
		if err := ctx.Err(); err != nil {
			return attempts, err
		}
		delay *= 2
	}
}

// PollUntil checks done until it reports true or timeout has passed on clk,
// sleeping interval between checks (the last sleep clipped to the deadline),
// and reports whether done ever did. It always checks at least once and
// checks once more at the deadline. A canceled ctx stops the wait and
// returns ctx.Err(); the met bool is meaningless when err is non-nil.
func PollUntil(ctx context.Context, clk clock.Clock, timeout, interval time.Duration, done func() bool) (met bool, err error) {
	deadline := clk.Now().Add(timeout)
	for {
		if done() {
			return true, nil
		}
		remaining := deadline.Sub(clk.Now())
		if remaining <= 0 {
			return false, nil
		}
		t := clk.NewTimer(min(interval, remaining))
		select {
		case <-ctx.Done():
		case <-t.C():
		}
		t.Stop()
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}
}

// NodePath is the /dev/dm-N path for a minor, and MapperPath the
// /dev/mapper/<name> entry. Every caller goes through these rather than
// formatting the path itself, so the places that build them cannot drift.
func NodePath(devDir string, minor uint32) string { return fmt.Sprintf("%s/dm-%d", devDir, minor) }
func MapperPath(devDir, name string) string       { return fmt.Sprintf("%s/mapper/%s", devDir, name) }
func MapperDir(devDir string) string              { return devDir + "/mapper" }

// decodeDevNo splits a device-mapper device number into its major and minor,
// the exact inverse of the unix.Mkdev the caller uses to create nodes.
func decodeDevNo(devNo uint64) (major, minor uint32) {
	return unix.Major(devNo), unix.Minor(devNo)
}

// IsOurNode reports whether the node at path is the device info describes.
//
// A path that cannot be stat'd is NOT ours as far as this is concerned: the
// answer is unknown, and unlinking or trusting on an unknown is the failure
// mode being avoided. blockNodeRdev is the caller's seam for stat'ing a block
// node's device number.
func IsOurNode(blockNodeRdev func(path string) (uint64, error), path string, info *devmapper.DeviceInfo) bool {
	if info == nil {
		return false
	}
	rdev, err := blockNodeRdev(path)
	if err != nil {
		return false
	}
	major, minor := decodeDevNo(info.DevNo)
	return rdev == unix.Mkdev(major, minor)
}

// IsDanglingSymlink reports whether path is a symlink whose target does not
// resolve. Lstat sees the link itself; Stat follows it and fails when the
// target is gone.
func IsDanglingSymlink(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return false
	}
	_, err = os.Stat(path)
	return err != nil
}

// IsNoSuchDevice reports whether err is the kernel saying a dm target does
// not exist, as opposed to any other reason an inspection can fail.
//
// The distinction decides whether a caller reports a possible live plaintext
// mapping, so it is drawn on the ERRNO rather than on the message: a
// permission failure, a missing /dev/mapper/control or an interrupted syscall
// all leave the target's existence unknown and must not be read as absence.
// devmapper wraps its errno in *os.SyscallError, which errors.Is unwraps.
//
// ENOENT is deliberately NOT in this set: here it would come from opening
// /dev/mapper/control, not from the kernel's answer about the target. The
// kernel's answer for an unknown dm device is ENXIO.
func IsNoSuchDevice(err error) bool {
	return errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ENODEV)
}

// RemoveMappingNodes deletes the device nodes a mapping left behind, and ONLY
// those that are still that mapping's.
//
// # Why each node is identified before it is unlinked
//
// A path is not an identity. The minor is decoded from a device number, so a
// decoding bug aims the unlink at some other device's node; and dm minors are
// RECYCLED, so a node may belong to a device created after this one went
// away. So each node is stat'd and its rdev compared with the DeviceInfo
// captured before the target was removed; only a match is unlinked.
//
// The one deliberate exception is a DANGLING /dev/mapper/<name> symlink: it
// cannot be stat'd, so it cannot be identified that way, but it names this
// mapping and points at nothing. A dangling symlink also cannot be mistaken
// for another live device, which is what makes the exception safe.
//
// Errors from the unlinks themselves stay ignored on purpose: a node may never
// have existed or may already have been reaped by udev, and neither changes
// the outcome the caller cares about, which is whether the dm target is gone.
func RemoveMappingNodes(ctx context.Context, devDir string, blockNodeRdev func(path string) (uint64, error), name string, info *devmapper.DeviceInfo) {
	if ctx.Err() != nil {
		return
	}
	// The mapper entry goes FIRST, while its target still resolves. Removing
	// the dm node first would turn this symlink into a dangling one and force
	// it down the exception path for no reason.
	mapperPath := MapperPath(devDir, name)
	if IsOurNode(blockNodeRdev, mapperPath, info) || IsDanglingSymlink(mapperPath) {
		_ = os.Remove(mapperPath)
	}

	if info == nil {
		return
	}
	_, minor := decodeDevNo(info.DevNo)
	dmPath := NodePath(devDir, minor)
	if IsOurNode(blockNodeRdev, dmPath, info) {
		_ = os.Remove(dmPath)
	}
}

// PlaceNode puts a new directory entry at path, made by create, REPLACING
// whatever is there.
//
// The entry is made under a temporary name in the same directory and renamed
// over path, so a reader sees the old entry or the new one and never a gap.
// It replaces rather than refuses because the only callers reach here after
// confirming the existing entry does NOT name the device dm reports: it is
// stale, and leaving it is how a mapping name comes to resolve to some other
// device (#250, C5).
func PlaceNode(ctx context.Context, path string, create func(tmp string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Only an entry that could be a stale device-mapper node is replaced: a
	// symlink, or a block device. A character device -- /dev/mapper/control
	// above all -- a directory, a regular file or anything else is somebody
	// else's, and is refused rather than renamed over.
	if fi, err := os.Lstat(path); err == nil {
		mode := fi.Mode()
		staleCandidate := mode&os.ModeSymlink != 0 || (mode&os.ModeDevice != 0 && mode&os.ModeCharDevice == 0)
		if !staleCandidate {
			return &errs.Error{Kind: ErrNodeUnverified, Detail: "not a stale symlink or block device"}
		}
	}
	suffix, err := randomSuffix(8)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".luks2-"+suffix)
	if err := create(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// randomSuffix returns n random bytes hex-encoded, for PlaceNode's temporary
// name. It is not a secret -- it only has to be unique for the instant the
// rename needs -- so it draws directly on crypto/rand rather than through any
// caller-supplied seam.
func randomSuffix(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", &errs.Error{Kind: errs.ErrIO, Detail: "failed to generate a random suffix", Err: err}
	}
	return hex.EncodeToString(b), nil
}
