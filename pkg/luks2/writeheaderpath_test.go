// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// No build constraint: both tiers write fixtures through it.

package luks2

import (
	"context"
	"os"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/header"
)

// writeHeaderInternal writes a validated header to device by path without a lock; a test fixture writer only.
func writeHeaderInternal(device string, hdr *header.BinaryHeader, metadata *header.Metadata) error {
	return writeHeaderInternalWithSys(device, hdr, metadata, testVolumeSys())
}

// writeHeaderInternalWithSys is writeHeaderInternal, parameterized by sys so
// a test can inject a failing or observing syncDevice.
func writeHeaderInternalWithSys(device string, hdr *header.BinaryHeader, metadata *header.Metadata, sys volumeSys) error {
	f, err := openDevice("write the LUKS2 header", device, os.O_RDWR, sys)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	return writeHeaderTo(f, hdr, metadata, sys.syncDevice)
}

// restorePrimaryHeaderForTest and replacePrimaryHeaderForTest open device, call the Volume method once and close it; options apply to the Volume.
func restorePrimaryHeaderForTest(device string, opts ...Option) error {
	v, err := Open(context.Background(), device, cheapOpts(opts)...)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()
	return v.RestorePrimaryHeader(context.Background())
}

func replacePrimaryHeaderForTest(device string, opts ...Option) error {
	v, err := Open(context.Background(), device, cheapOpts(opts)...)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()
	return v.ReplacePrimaryHeader(context.Background())
}

// removeKeyForTest unlocks slot with passphrase and removes it, the way
// the pre-redesign library's RemoveKey did before B.6 deleted it:
// credential checks are CLI policy now (Unlock/UnlockKeyslot, then
// RemoveKeyslot), not the library's. No build constraint: both tiers use
// it.
func removeKeyForTest(device string, passphrase []byte, slot int, opts ...Option) error {
	ctx := context.Background()
	v, err := Open(ctx, device, cheapOpts(opts)...)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryCopy(passphrase)
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()
	key, err := v.UnlockKeyslot(ctx, slot, pass)
	if err != nil {
		return err
	}
	key.Destroy()

	return v.RemoveKeyslot(ctx, slot)
}

// killSlotForTest authenticates with passphrase against ANY bound keyslot
// and then removes targetSlot regardless of which slot verified it, the
// way the pre-redesign library's KillSlot did before B.6 deleted it:
// credential checks are CLI policy now (Unlock, then RemoveKeyslot). No
// build constraint: both tiers use it.
func killSlotForTest(device string, passphrase []byte, targetSlot int, opts ...Option) error {
	ctx := context.Background()
	v, err := Open(ctx, device, cheapOpts(opts)...)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryCopy(passphrase)
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()
	key, err := v.Unlock(ctx, pass)
	if err != nil {
		return err
	}
	key.Destroy()

	return v.RemoveKeyslot(ctx, targetSlot)
}
