// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"os"

	"github.com/jeremyhahn/go-luks2/internal/device"
)

// Erase crypto-erases the volume: every header copy and the keyslot area are overwritten; the data ciphertext stays.
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
