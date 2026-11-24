// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// DetachState says what became of a detach request. Both values mean the
// kernel accepted it; they differ in whether the release has happened yet.
type DetachState int

const (
	// Released means the device was observed no longer backed by its file.
	Released DetachState = iota

	// Deferred means the kernel accepted the request but another holder keeps the device open; autoclear releases it later. A success, as for losetup -d.
	Deferred
)

// Detach detaches the device and waits until the release is observed, returning [Deferred] if still held at the bound; refuses with [ErrDeviceReassigned] a device no longer backed by its original file.
func (d *Device) Detach(ctx context.Context) (DetachState, error) {
	state, err := detachDevice(ctx, d.path, d.ident, d.sys, d.sys.readState)
	return state, errs.At("loop", "Device.Detach", d.path, err)
}

// detachDevice takes its seams and reader as parameters so the identity check and wait are testable without a loop device.
func detachDevice(ctx context.Context, path string, want backingIdentity, s sys, read loopStateReader) (DetachState, error) {
	if err := ctx.Err(); err != nil {
		return Released, &errs.Error{Kind: err}
	}

	// Record the state before the detach, so the wait can tell our release from a reattachment by someone else.
	before, beforeErr := read(path)

	loopFile, err := s.openFile(path, os.O_RDWR, 0) // #nosec G304 -- loop device path from Attach or Lookup
	if err != nil {
		return Released, &errs.Error{Kind: errs.ErrIO, Detail: fmt.Sprintf("failed to open %s", path), Err: err}
	}

	if err := checkBackingIdentity(path, loopFile, want, s); err != nil {
		_ = loopFile.Close()
		return Released, err
	}

	clearErr := s.clearFD(loopFile)

	// Close before the wait: this descriptor would hold the release.
	closeErr := loopFile.Close()

	if clearErr != nil {
		return Released, &errs.Error{Kind: errs.ErrIO, Detail: fmt.Sprintf("LOOP_CLR_FD failed: %v", clearErr)}
	}

	// A failed close still waits; it is reported with the wait's result.
	state, waitErr := waitForDetach(ctx, path, before, beforeErr == nil, s.detachTimeout, s.detachPoll, read, s.clk)
	if closeErr != nil {
		closeFailed := errs.At("loop", "Device.Detach", path,
			&errs.Error{Kind: errs.ErrIO, Detail: "close loop device " + path + " after detach", Err: closeErr})
		return state, errors.Join(closeFailed, waitErr)
	}
	return state, waitErr
}

// checkBackingIdentity errors unless the device open as f is still backed by the file want records.
func checkBackingIdentity(path string, f *os.File, want backingIdentity, s sys) error {
	dev, ino, err := s.fdBackingIdentity(f)
	switch {
	case errors.Is(err, unix.ENXIO):
		// The loop driver's "not bound": there is nothing to detach, and
		// clearing would race whoever attaches the device next.
		return &errs.Error{Kind: errs.ErrIO, Detail: path + " is not attached to a file", Err: err}
	case err != nil:
		return &errs.Error{Kind: errs.ErrIO, Detail: "identify the file backing " + path + " before detaching it", Err: err}
	case !want.known:
		return &errs.Error{Kind: ErrDeviceReassigned,
			Detail: path + " had nothing attached when it was looked up and is now attached to a file"}
	case dev != want.dev || ino != want.ino:
		return &errs.Error{Kind: ErrDeviceReassigned,
			Detail: fmt.Sprintf("%s is now backed by device %d inode %d, not device %d inode %d", path, dev, ino, want.dev, want.ino)}
	}
	return nil
}

// clearFDIoctl sends LOOP_CLR_FD on the loop device open as f.
func clearFDIoctl(f *os.File) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.LOOP_CLR_FD, 0); errno != 0 {
		return errno
	}
	return nil
}

// waitForDetach blocks until release, a deferred release at the bound, or timeout; success always needs an authoritative observation.
func waitForDetach(ctx context.Context, path string, before loopState, knownBefore bool, timeout, poll time.Duration, read loopStateReader, clk clock.Clock) (DetachState, error) {
	// Known to be attached to nothing: no wait needed.
	if knownBefore && before.backing == "" {
		return Released, nil
	}

	deadline := clk.Now().Add(timeout)

	// Classify a timeout by the dominant observation, not the last one.
	var unreadable, held int
	var lastErr error
	sawAutoclear := false

	for {
		if err := ctx.Err(); err != nil {
			return Released, &errs.Error{Kind: err}
		}

		current, err := read(path)
		switch {
		case err != nil:
			unreadable++
			lastErr = err

		case released(current, before, knownBefore):
			return Released, nil

		case current.autoclear:
			// Deferred is remembered but not an exit: keep waiting for an observed release.
			sawAutoclear = true
			held++

		default:
			held++
		}

		if clk.Now().After(deadline) {
			if sawAutoclear {
				// Still held at the bound, but accepted: deferred success.
				return Deferred, nil
			}

			cause := detachTimeoutCause(before, knownBefore, timeout, unreadable, held, lastErr)
			return Released, &errs.Error{
				Kind:   errs.KindOf(cause, ErrDetachIncomplete),
				Detail: "detach loop device " + path,
				Err:    cause,
			}
		}

		select {
		case <-ctx.Done():
			return Released, &errs.Error{Kind: ctx.Err()}
		case <-clk.NewTimer(poll).C():
		}
	}
}

// released reports whether an observation shows our association gone.
func released(current, before loopState, knownBefore bool) bool {
	if knownBefore {
		// Gone or reattached: either way no longer ours.
		return current.backing != before.backing
	}
	// No baseline, so only the authoritative not-attached state will do.
	return current.backing == ""
}

// detachTimeoutCause explains WHY the wait gave up, because the two reasons
// send an operator to different places: a device still held by something
// else is a process to find, and a sysfs we cannot read is a host to fix.
func detachTimeoutCause(before loopState, knownBefore bool, timeout time.Duration, unreadable, held int, lastErr error) error {
	if unreadable > held {
		return &errs.Error{
			Kind: ErrDetachIncomplete,
			Detail: fmt.Sprintf("the device's state was unreadable for %d of %d checks over %s",
				unreadable, unreadable+held, timeout),
			Err: lastErr,
		}
	}
	if knownBefore {
		return &errs.Error{
			Kind: ErrDetachIncomplete,
			Detail: fmt.Sprintf("still backed by %s after %s; something else still holds the device open",
				before.backing, timeout),
		}
	}
	return &errs.Error{
		Kind: ErrDetachIncomplete,
		Detail: fmt.Sprintf("still attached after %s, and its state before the detach could not be read",
			timeout),
	}
}
