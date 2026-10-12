// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bytes"
	"context"
	"os"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/pkg/loop"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// ReadHeader reads and validates the PRIMARY LUKS2 header from a device, the
// way the pre-redesign library's own luks2.ReadHeader did before B.6 renamed
// it away in favor of (*luks2.Volume).Header, which returns a read-only view
// rather than the raw on-disk BinaryHeader and Metadata these integration
// tests assert on directly.
func ReadHeader(device string) (*header.BinaryHeader, *header.Metadata, error) {
	f, err := os.Open(device) // #nosec G304 -- the test's own fixture path
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	return header.ReadHeaderCopyFrom(f, header.PrimaryHeaderOffset)
}

// ReadCurrentHeader reads the header copy cryptsetup would use: the valid
// copy with the higher sequence id, the primary on a tie. A test that kills
// cryptsetup mid-operation reads through this, because the kill can land
// while the primary is being rewritten, leaving it torn and the secondary
// current.
func ReadCurrentHeader(device string) (*header.BinaryHeader, *header.Metadata, error) {
	f, err := os.Open(device) // #nosec G304 -- the test's own fixture path
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	cur, err := header.ReadCurrentHeader(f)
	if err != nil {
		return nil, nil, err
	}
	return cur.Header, cur.Metadata, nil
}

// ReadSecondaryHeader reads and validates the SECOND LUKS2 header copy, the
// one carrying the SKUL magic. See ReadHeader.
func ReadSecondaryHeader(device string) (*header.BinaryHeader, *header.Metadata, error) {
	f, err := os.Open(device) // #nosec G304 -- the test's own fixture path
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	return header.ReadSecondaryHeaderFrom(f)
}

// IsLUKS reports whether device carries the LUKS magic at offset 0, LUKS1 or
// LUKS2. IsLUKS2 narrows that to the version this library reads.
func IsLUKS(device string) (bool, error) {
	f, err := os.Open(device) // #nosec G304 -- the test's own fixture path
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	magic := make([]byte, len(header.Magic))
	n, err := f.ReadAt(magic, 0)
	if err != nil && n < len(magic) {
		return false, nil // too small to be LUKS
	}
	return bytes.Equal(magic, []byte(header.Magic)), nil
}

// IsLUKS2 reports whether device opens as a LUKS2 container this library can
// read: the public replacement for a boolean probe is
// (*luks2.Volume).Header's ErrNotLUKS2, which this wraps back into a bool for
// integration tests that only ever checked the yes/no answer.
func IsLUKS2(device string) (bool, error) {
	v, err := luks2.Open(context.Background(), device, luks2.WithReadOnly())
	if err != nil {
		return false, err
	}
	defer func() { _ = v.Close() }()

	if _, err := v.Header(context.Background()); err != nil {
		return false, nil //nolint:nilerr // "not LUKS2" is the answer, not a probe failure
	}
	return true, nil
}

// TestKey reports whether passphrase opens device, the way the pre-redesign
// library's luks2.TestKey did before B.6 deleted it in favor of
// (*luks2.Volume).Unlock followed by (*luks2.Key).Destroy.
func TestKey(device string, passphrase []byte) error {
	v, err := luks2.Open(context.Background(), device, luks2.WithReadOnly())
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryCopy(passphrase)
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()

	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		return err
	}
	key.Destroy()
	return nil
}

// ListKeyslots returns device's keyslots, the way the pre-redesign library's
// luks2.ListKeyslots did before B.6 renamed it to (*luks2.Header).Keyslots.
func ListKeyslots(device string) ([]luks2.KeyslotInfo, error) {
	v, err := luks2.Open(context.Background(), device, luks2.WithReadOnly())
	if err != nil {
		return nil, err
	}
	defer func() { _ = v.Close() }()

	h, err := v.Header(context.Background())
	if err != nil {
		return nil, err
	}
	return h.Keyslots(), nil
}

// WipeKeyslot removes slot unconditionally, the way the pre-redesign
// library's luks2.WipeKeyslot did before B.6 retired it: the same operation
// as (*luks2.Volume).RemoveKeyslot, which always destroys the area.
func WipeKeyslot(device string, slot int) error {
	v, err := luks2.Open(context.Background(), device)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()
	return v.RemoveKeyslot(context.Background(), slot)
}

// VolumeInfo is luks2's pre-redesign VolumeInfo shape, which GetVolumeInfo
// (DELETE, B.6) returned and which (*luks2.Header)'s accessors replace.
type VolumeInfo struct {
	UUID           string
	Label          string
	Subsystem      string
	Version        int
	Cipher         string
	KeySize        int
	SectorSize     int
	ActiveKeyslots []int
	Metadata       *header.Metadata
}

// GetVolumeInfo reports on device's header through the new (*luks2.Volume)
// API, in the old VolumeInfo shape these integration tests still assert on.
func GetVolumeInfo(device string) (*VolumeInfo, error) {
	v, err := luks2.Open(context.Background(), device, luks2.WithReadOnly())
	if err != nil {
		return nil, err
	}
	defer func() { _ = v.Close() }()

	h, err := v.Header(context.Background())
	if err != nil {
		return nil, err
	}

	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return nil, err
	}

	info := &VolumeInfo{
		UUID:      h.UUID(),
		Label:     h.Label(),
		Subsystem: h.Subsystem(),
		Version:   int(hdr.Version),
		Metadata:  metadata,
	}

	for _, seg := range h.Segments() {
		info.Cipher = seg.Encryption
		info.SectorSize = seg.SectorSize
		break
	}
	for _, slot := range h.Keyslots() {
		info.ActiveKeyslots = append(info.ActiveKeyslots, slot.ID)
		if info.KeySize == 0 {
			info.KeySize = slot.KeySize * 8
		}
	}

	return info, nil
}

// SetupLoopDevice creates a loop device for file, the way the pre-redesign
// library's luks2.SetupLoopDevice did before B.6 renamed it away in favor of
// pkg/loop.Attach, which returns a *loop.Device rather than a bare path.
//
// It refuses a file that is not below the run root BeginSuite recorded (#348):
// that record, made before any test runs, is what lets a later run's reaper
// find and detach the device by its backing file if this run dies first.
func SetupLoopDevice(file string) (string, error) {
	if err := checkBackedUnderRunRoot(file); err != nil {
		return "", err
	}
	d, err := loop.Attach(context.Background(), file)
	if err != nil {
		return "", err
	}
	return d.Path(), nil
}

// DetachLoopDevice detaches the loop device at path and waits until the
// release is observed before returning, discarding the
// Deferred/Released distinction the way luks2.DetachLoopDevice did.
func DetachLoopDevice(path string) error {
	d, err := loop.Lookup(context.Background(), path)
	if err != nil {
		return err
	}
	_, err = d.Detach(context.Background())
	return err
}

// FindLoopDevice finds the loop device backing file, the way the
// pre-redesign library's luks2.FindLoopDevice did.
func FindLoopDevice(file string) (string, error) {
	d, err := loop.Find(context.Background(), file)
	if err != nil {
		return "", err
	}
	return d.Path(), nil
}
