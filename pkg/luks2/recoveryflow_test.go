// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// End-to-end tests for the documented recovery flow.
//
// The defect these exist for was not in what ReadSecondaryHeader RETURNS -- the
// returned values were correct and the tests that inspected them passed -- but
// in what happens when a caller does the thing the documentation tells them to
// do with those values. Writing the returned header back put SKUL and
// hdr_offset 0x4000 at offset ZERO, leaving a container with two secondary
// copies, no primary, and no way to open it:
//
//	bytes now at offset 0:      "SKUL\xba\xbe"
//	bytes now at offset 0x4000: "SKUL\xba\xbe"
//	primary still unreadable after recovery: invalid LUKS magic at offset 0
//	volume does not open: failed to read header: invalid LUKS magic at offset 0
//
// Recovery made the container worse than the damage it was repairing.
//
// So these tests DRIVE THE FLOW and assert on the end state: the container
// afterwards, opened by this package and validated by cryptsetup. Inspecting
// the intermediate header is exactly the check that already passed while the
// flow was broken.

// destroyPrimaryHeader zeroes the primary header copy of a container whose
// header area is areaSize bytes.
func destroyPrimaryHeader(t *testing.T, device string, areaSize int64) {
	t.Helper()

	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the volume: %v", err)
	}
	if _, err := f.WriteAt(make([]byte, areaSize), 0); err != nil {
		_ = f.Close()
		t.Fatalf("failed to destroy the primary header: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the volume: %v", err)
	}

	if _, _, err := ReadHeader(device); err == nil {
		t.Fatal("the primary header still reads after being zeroed; the fixture is not testing recovery")
	}
}

// assertHeaderCopiesAreDistinct checks that the two copies on disk carry the
// identities their positions require -- the thing the broken flow destroyed.
func assertHeaderCopiesAreDistinct(t *testing.T, device string, areaSize int64) {
	t.Helper()

	f, err := os.Open(device) // #nosec G304 -- device is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the volume: %v", err)
	}
	defer func() { _ = f.Close() }()

	for _, tc := range []struct {
		name   string
		offset int64
		magic  string
	}{
		{"primary", LUKS2PrimaryHeaderOffset, LUKS2Magic},
		{"secondary", areaSize, LUKS2SecondaryMagic},
	} {
		magic := make([]byte, LUKS2MagicLen)
		if _, err := f.ReadAt(magic, tc.offset); err != nil {
			t.Fatalf("failed to read the %s magic: %v", tc.name, err)
		}
		if !bytes.Equal(magic, []byte(tc.magic)) {
			t.Errorf("%s copy at offset %d carries magic %q, want %q",
				tc.name, tc.offset, magic, tc.magic)
		}
	}

	primary, _, err := ReadHeader(device)
	if err != nil {
		t.Fatalf("the primary header does not read back: %v", err)
	}
	if primary.HeaderOffset != uint64(LUKS2PrimaryHeaderOffset) { // #nosec G115 -- zero
		t.Errorf("restored primary records hdr_offset %d, want 0", primary.HeaderOffset)
	}

	secondary, _, err := ReadSecondaryHeader(device)
	if err != nil {
		t.Fatalf("the secondary header does not read back: %v", err)
	}
	if secondary.HeaderOffset != uint64(areaSize) { // #nosec G115 -- a legal area size
		t.Errorf("secondary records hdr_offset %d, want %d", secondary.HeaderOffset, areaSize)
	}
}

// TestRecoveryFlow_RestorePrimaryHeader drives the documented repair through
// the public API and checks the container that comes out the other side.
func TestRecoveryFlow_RestorePrimaryHeader(t *testing.T) {
	t.Parallel()

	device, passphrase := headerSizeVolume(t)

	destroyPrimaryHeader(t, device, LUKS2SecondaryHeaderOffset)

	if err := RestorePrimaryHeader(device); err != nil {
		t.Fatalf("RestorePrimaryHeader failed: %v", err)
	}

	assertHeaderCopiesAreDistinct(t, device, LUKS2SecondaryHeaderOffset)

	// The end state that matters: the volume opens again.
	if err := TestKey(device, passphrase); err != nil {
		t.Fatalf("the volume does not open after recovery: %v", err)
	}
}

// TestRecoveryFlow_WriteBackTheSecondaryHeader drives the same repair the long
// way -- ReadSecondaryHeader followed by WriteHeader -- because that sequence is
// what a caller reading the documentation would assemble, and it is the exact
// sequence that used to destroy the container.
func TestRecoveryFlow_WriteBackTheSecondaryHeader(t *testing.T) {
	t.Parallel()

	device, passphrase := headerSizeVolume(t)

	destroyPrimaryHeader(t, device, LUKS2SecondaryHeaderOffset)

	hdr, metadata, err := ReadSecondaryHeader(device)
	if err != nil {
		t.Fatalf("ReadSecondaryHeader failed: %v", err)
	}

	// The returned header IS a secondary header -- that is what was asked for,
	// and asserting it here pins the precondition the write path has to cope
	// with rather than assuming it away.
	if !bytes.Equal(hdr.Magic[:], []byte(LUKS2SecondaryMagic)) {
		t.Fatalf("ReadSecondaryHeader returned magic %q, want %q", hdr.Magic[:], LUKS2SecondaryMagic)
	}
	if hdr.HeaderOffset != uint64(LUKS2SecondaryHeaderOffset) { // #nosec G115 -- a legal area size
		t.Fatalf("ReadSecondaryHeader returned hdr_offset %d, want %d",
			hdr.HeaderOffset, LUKS2SecondaryHeaderOffset)
	}

	if err := WriteHeader(device, hdr, metadata); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	assertHeaderCopiesAreDistinct(t, device, LUKS2SecondaryHeaderOffset)

	// The caller's header must also have been normalized to describe what was
	// actually written, the way HeaderSize already is.
	if !bytes.Equal(hdr.Magic[:], []byte(LUKS2Magic)) {
		t.Errorf("after WriteHeader the caller's header carries magic %q, want %q",
			hdr.Magic[:], LUKS2Magic)
	}
	if hdr.HeaderOffset != uint64(LUKS2PrimaryHeaderOffset) { // #nosec G115 -- zero
		t.Errorf("after WriteHeader the caller's header records hdr_offset %d, want 0", hdr.HeaderOffset)
	}

	if err := TestKey(device, passphrase); err != nil {
		t.Fatalf("the volume does not open after recovery: %v", err)
	}
}

// TestRecoveryFlow_RefusesWhenBothCopiesAreGone checks the failure direction:
// a container with no usable secondary is left alone rather than half-written.
func TestRecoveryFlow_RefusesWhenBothCopiesAreGone(t *testing.T) {
	t.Parallel()

	device, _ := headerSizeVolume(t)

	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device is under t.TempDir()
	if err != nil {
		t.Fatalf("failed to open the volume: %v", err)
	}
	if _, err := f.WriteAt(make([]byte, 2*LUKS2SecondaryHeaderOffset), 0); err != nil {
		_ = f.Close()
		t.Fatalf("failed to destroy the headers: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close the volume: %v", err)
	}

	before := deviceHead(t, device, 2*LUKS2HeaderMinSize)

	err = RestorePrimaryHeader(device)
	if err == nil {
		t.Fatal("RestorePrimaryHeader reported success with no secondary header to restore from")
	}
	if !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("error = %v, want it to wrap ErrInvalidHeader", err)
	}

	if after := deviceHead(t, device, 2*LUKS2HeaderMinSize); !bytes.Equal(before, after) {
		t.Fatal("a failed recovery still modified the device")
	}
}

// TestConformance_RecoveredContainerIsAcceptedByCryptsetup checks that the
// repair produces a container other implementations accept.
//
// IT DOES NOT, ON ITS OWN, CATCH THE DEFECT THIS FILE EXISTS FOR, and saying so
// is the point. MEASURED against the broken flow: with SKUL written at offset 0
// and at 0x4000, `cryptsetup isLuks` still exits 0 and --debug reports neither
// copy as requiring recovery. cryptsetup finds the primary unreadable, silently
// falls back to the intact secondary, and never complains.
//
// So the corruption was ASYMMETRIC. cryptsetup shrugged it off; this package,
// whose ReadHeader looks only at offset 0, could not open the volume at all.
// The assertions that catch it are the raw magic bytes and this package's own
// read path, which is why they are made here too rather than trusting the
// third party to notice.
func TestConformance_RecoveredContainerIsAcceptedByCryptsetup(t *testing.T) {
	t.Parallel()

	requireCryptsetup(t)

	path := newImage(t, "recovered.img")
	formatWithLibrary(t, path)

	destroyPrimaryHeader(t, path, LUKS2SecondaryHeaderOffset)

	if err := RestorePrimaryHeader(path); err != nil {
		t.Fatalf("RestorePrimaryHeader failed: %v", err)
	}

	assertHeaderCopiesAreDistinct(t, path, LUKS2SecondaryHeaderOffset)
	if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("this package cannot open the container it just recovered: %v", err)
	}

	if code, out := runCryptsetup(t, "", "isLuks", path); code != 0 {
		t.Fatalf("after recovery, cryptsetup isLuks exited %d, want 0\n%s", code, out)
	}
	code, out := runCryptsetup(t, "", "luksDump", path)
	if code != 0 {
		t.Fatalf("after recovery, cryptsetup luksDump exited %d, want 0\n%s", code, out)
	}
	for _, want := range []string{
		"Metadata area: \t16384 [bytes]",
		"Keyslots area: \t16744448 [bytes]",
		"cipher: aes-xts-plain64",
	} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("after recovery, luksDump is missing %q\n%s", want, out)
		}
	}

	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path); code != 0 {
		t.Fatalf("after recovery, cryptsetup rejected the correct passphrase (exit %d)\n%s", code, out)
	}
	if code, _ := runCryptsetup(t, conformanceWrongPassphrase, "luksOpen", "--test-passphrase", path); code == 0 {
		t.Fatal("after recovery, cryptsetup accepted a WRONG passphrase")
	}
}

// TestConformance_RecoverForeignGeometryContainer is the same end-to-end repair
// on a cryptsetup-written container with a 32 KiB metadata area, where the
// secondary copy is at 0x8000 rather than 0x4000. It ties the recovery flow to
// the offset-probing fix: nothing in the repair may assume the default layout.
func TestConformance_RecoverForeignGeometryContainer(t *testing.T) {
	t.Parallel()

	requireCryptsetup(t)

	const areaSize = 0x8000

	path := newForeignContainer(t, "recover-foreign.img", foreignGeometry{
		metadataSize:     "32k",
		keyslotsSize:     "1m",
		wantArea:         areaSize,
		wantKeyslotsSize: 1 << 20,
	})

	destroyPrimaryHeader(t, path, areaSize)

	if err := RestorePrimaryHeader(path); err != nil {
		t.Fatalf("RestorePrimaryHeader failed on a 32 KiB-metadata container: %v", err)
	}

	assertHeaderCopiesAreDistinct(t, path, areaSize)

	// The area size must survive the repair; restoring at the default geometry
	// would move the second copy onto the keyslots.
	hdr, _, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader failed after recovery: %v", err)
	}
	if hdr.HeaderSize != areaSize {
		t.Errorf("restored header area = %d, want %d", hdr.HeaderSize, areaSize)
	}

	if code, out := runCryptsetup(t, "", "luksDump", path); code != 0 {
		t.Fatalf("after recovery, cryptsetup luksDump exited %d, want 0\n%s", code, out)
	}
	if code, out := runCryptsetup(t, conformancePassphrase, "luksOpen", "--test-passphrase", path); code != 0 {
		t.Fatalf("after recovery, cryptsetup rejected the correct passphrase (exit %d)\n%s", code, out)
	}
	if err := TestKey(path, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("this package cannot open the recovered container: %v", err)
	}
}
