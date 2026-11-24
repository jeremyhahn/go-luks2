// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"os"

	"github.com/jeremyhahn/go-luks2/internal/device"
)

// Erase crypto-erases the volume: every header copy and
// the keyslot area are overwritten, destroying every key the volume key
// could be recovered through. The data segment's ciphertext is left in
// place -- undecodable without a key, but not itself erased.
//
// This is the exclusive-lock half of the old Wipe(WipeOptions{HeaderOnly:
// true}), through v's own pinned descriptor and lock rather than reopening
// the path a second time; wipeHeaders is the shared core.
func (v *Volume) Erase(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.checkOpen("Volume.Erase"); err != nil {
		return err
	}
	if err := v.checkWritable("Volume.Erase"); err != nil {
		return err
	}

	const op = "Volume.Erase"
	locked, err := v.lockFor(ctx, device.LockExclusive)
	if err != nil {
		return errAt(op, v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	claimed, err := locked.Claim(ctx, "erase the volume", os.O_RDWR|os.O_EXCL, v.sys.openFile)
	if err != nil {
		return errAt(op, v.path, err)
	}
	defer func() { _ = claimed.Close() }()

	if err := wipeHeaders(ctx, claimed.File()); err != nil {
		return errAt(op, v.path, err)
	}
	return nil
}
