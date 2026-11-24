// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package dm provides DM_DEV_CREATE, busy-retry around removal, and node placement for when udev is absent; every seam is a parameter.
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

// RemoveRetryBudget and RemoveRetryInitialDelay bound RetryWhileBusy's backoff.
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

// CreateTarget issues DM_DEV_CREATE and returns the device number from the kernel's reply, not a racy lookup by name.
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

// RetryWhileBusy reruns the caller's whole attempt until it stops reporting EBUSY or the budget is spent, returning the count and last error.
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
		// Clip the last wait to the remaining budget.
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

// PollUntil checks done every interval until true or timeout on clk, checking at least once and at the deadline; a canceled ctx returns ctx.Err().
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

// IsOurNode reports whether the node at path is the device info describes; an unstat-able path is not ours.
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

// IsNoSuchDevice reports whether err is the kernel's ENXIO for a missing dm target; other errors leave existence unknown.
func IsNoSuchDevice(err error) bool {
	return errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ENODEV)
}

// RemoveMappingNodes unlinks only the nodes whose rdev still matches info, plus a dangling /dev/mapper/<name> symlink; unlink errors are ignored.
func RemoveMappingNodes(ctx context.Context, devDir string, blockNodeRdev func(path string) (uint64, error), name string, info *devmapper.DeviceInfo) {
	if ctx.Err() != nil {
		return
	}
	// Remove the mapper entry first, while its target still resolves.
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

// PlaceNode atomically replaces the entry at path with one made by create, via a temporary name and rename.
func PlaceNode(ctx context.Context, path string, create func(tmp string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Replace only a symlink or block device; anything else is refused.
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

// randomSuffix returns n random bytes hex-encoded for PlaceNode's temporary name.
func randomSuffix(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", &errs.Error{Kind: errs.ErrIO, Detail: "failed to generate a random suffix", Err: err}
	}
	return hex.EncodeToString(b), nil
}
