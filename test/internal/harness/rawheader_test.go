// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

const rawHeaderTestPassphrase = "harness-rawheader-pass"

// formatRawHeaderFixture creates a minimal, fast PBKDF2 LUKS2 container at a
// fresh temp path. None of the functions in rawheader.go touch a kernel
// primitive -- they open a path with os.Open or pkg/luks2.Open and read or
// write bytes -- so every one of them is exercisable here without root,
// against a real formatted file rather than a fake.
func formatRawHeaderFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rawheader.img")
	f, err := os.Create(path) // #nosec G304 -- a path under t.TempDir()
	if err != nil {
		t.Fatalf("creating the fixture file: %v", err)
	}
	if err := f.Truncate(32 * 1024 * 1024); err != nil {
		t.Fatalf("sizing the fixture file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing the fixture file: %v", err)
	}

	ctx := context.Background()
	v, err := luks2.Open(ctx, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryEnclaveCopy([]byte(rawHeaderTestPassphrase))
	if err != nil {
		t.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	if err := v.Format(ctx, pass, luks2.FormatParams{
		KDF: luks2.KDFParams{Type: luks2.KDFPBKDF2, IterTime: 50 * time.Millisecond},
	}); err != nil {
		t.Fatalf("Format: %v", err)
	}
	return path
}

func TestReadHeaderReadsAFormattedContainer(t *testing.T) {
	path := formatRawHeaderFixture(t)
	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader(%q) = %v", path, err)
	}
	if hdr == nil || metadata == nil {
		t.Fatalf("ReadHeader(%q) = %v, %v, want both populated", path, hdr, metadata)
	}
}

func TestReadHeaderOnAMissingFileFails(t *testing.T) {
	if _, _, err := ReadHeader(filepath.Join(t.TempDir(), "absent.img")); err == nil {
		t.Fatal("ReadHeader on a missing file = nil, want the open error")
	}
}

func TestReadSecondaryHeaderReadsAFormattedContainer(t *testing.T) {
	path := formatRawHeaderFixture(t)
	hdr, metadata, err := ReadSecondaryHeader(path)
	if err != nil {
		t.Fatalf("ReadSecondaryHeader(%q) = %v", path, err)
	}
	if hdr == nil || metadata == nil {
		t.Fatalf("ReadSecondaryHeader(%q) = %v, %v, want both populated", path, hdr, metadata)
	}
}

func TestReadSecondaryHeaderOnAMissingFileFails(t *testing.T) {
	if _, _, err := ReadSecondaryHeader(filepath.Join(t.TempDir(), "absent.img")); err == nil {
		t.Fatal("ReadSecondaryHeader on a missing file = nil, want the open error")
	}
}

func TestIsLUKSRecognizesTheMagicItsAbsenceAndATooSmallFile(t *testing.T) {
	path := formatRawHeaderFixture(t)
	if ok, err := IsLUKS(path); err != nil || !ok {
		t.Errorf("IsLUKS(%q) = %v, %v, want true, nil", path, ok, err)
	}

	notLUKS := filepath.Join(t.TempDir(), "plain.img")
	if err := os.WriteFile(notLUKS, []byte("not a luks container, but long enough to read"), 0o600); err != nil {
		t.Fatalf("writing the plain file: %v", err)
	}
	if ok, err := IsLUKS(notLUKS); err != nil || ok {
		t.Errorf("IsLUKS(%q) = %v, %v, want false, nil", notLUKS, ok, err)
	}

	tooSmall := filepath.Join(t.TempDir(), "tiny.img")
	if err := os.WriteFile(tooSmall, []byte{0x01}, 0o600); err != nil {
		t.Fatalf("writing the tiny file: %v", err)
	}
	if ok, err := IsLUKS(tooSmall); err != nil || ok {
		t.Errorf("IsLUKS(%q) = %v, %v, want false, nil -- too small to carry the magic, not a read failure", tooSmall, ok, err)
	}
}

func TestIsLUKSOnAMissingFileFails(t *testing.T) {
	if _, err := IsLUKS(filepath.Join(t.TempDir(), "absent.img")); err == nil {
		t.Fatal("IsLUKS on a missing file = nil, want the open error")
	}
}

func TestIsLUKS2DistinguishesARealContainerFromNoise(t *testing.T) {
	path := formatRawHeaderFixture(t)
	if ok, err := IsLUKS2(path); err != nil || !ok {
		t.Errorf("IsLUKS2(%q) = %v, %v, want true, nil", path, ok, err)
	}

	notLUKS2 := filepath.Join(t.TempDir(), "plain.img")
	if err := os.WriteFile(notLUKS2, make([]byte, 2*1024*1024), 0o600); err != nil {
		t.Fatalf("writing the plain file: %v", err)
	}
	if ok, err := IsLUKS2(notLUKS2); err != nil || ok {
		t.Errorf("IsLUKS2(%q) = %v, %v, want false, nil -- not LUKS2 is the answer, not a probe failure", notLUKS2, ok, err)
	}
}

func TestIsLUKS2OnAMissingFileFails(t *testing.T) {
	if _, err := IsLUKS2(filepath.Join(t.TempDir(), "absent.img")); err == nil {
		t.Fatal("IsLUKS2 on a missing file = nil, want the open error")
	}
}

func TestTestKeyAcceptsTheRightPassphraseAndRejectsTheWrongOne(t *testing.T) {
	path := formatRawHeaderFixture(t)
	if err := TestKey(path, []byte(rawHeaderTestPassphrase)); err != nil {
		t.Errorf("TestKey with the formatting passphrase = %v, want nil", err)
	}
	if err := TestKey(path, []byte("definitely-the-wrong-passphrase")); err == nil {
		t.Error("TestKey with the wrong passphrase = nil, want an error")
	}
}

func TestTestKeyOnAMissingFileFails(t *testing.T) {
	if err := TestKey(filepath.Join(t.TempDir(), "absent.img"), []byte("x")); err == nil {
		t.Fatal("TestKey on a missing file = nil, want the open error")
	}
}

func TestListKeyslotsReportsTheFormattingKeyslot(t *testing.T) {
	path := formatRawHeaderFixture(t)
	slots, err := ListKeyslots(path)
	if err != nil {
		t.Fatalf("ListKeyslots(%q) = %v", path, err)
	}
	if len(slots) == 0 {
		t.Fatalf("ListKeyslots(%q) = empty, want the formatting keyslot", path)
	}
}

func TestListKeyslotsOnAMissingFileFails(t *testing.T) {
	if _, err := ListKeyslots(filepath.Join(t.TempDir(), "absent.img")); err == nil {
		t.Fatal("ListKeyslots on a missing file = nil, want the open error")
	}
}

// TestWipeKeyslotRefusesTheOnlyKeyslot exercises WipeKeyslot's real
// pass-through to (*luks2.Volume).RemoveKeyslot, which refuses to strip a
// container's last keyslot -- so this is WipeKeyslot's genuine error-return
// path, not a not-found stand-in for it.
func TestWipeKeyslotRefusesTheOnlyKeyslot(t *testing.T) {
	path := formatRawHeaderFixture(t)
	if err := WipeKeyslot(path, 0); err == nil {
		t.Error("WipeKeyslot(slot 0) on a single-keyslot container = nil, want RemoveKeyslot's last-keyslot refusal")
	}
}

func TestWipeKeyslotOnAMissingFileFails(t *testing.T) {
	if err := WipeKeyslot(filepath.Join(t.TempDir(), "absent.img"), 0); err == nil {
		t.Fatal("WipeKeyslot on a missing file = nil, want the open error")
	}
}

func TestGetVolumeInfoReportsTheFormattedContainer(t *testing.T) {
	path := formatRawHeaderFixture(t)
	info, err := GetVolumeInfo(path)
	if err != nil {
		t.Fatalf("GetVolumeInfo(%q) = %v", path, err)
	}
	if info.UUID == "" {
		t.Error("GetVolumeInfo().UUID is empty")
	}
	if info.Version != 2 {
		t.Errorf("GetVolumeInfo().Version = %d, want 2", info.Version)
	}
	if info.Cipher == "" {
		t.Error("GetVolumeInfo().Cipher is empty")
	}
	if len(info.ActiveKeyslots) == 0 {
		t.Error("GetVolumeInfo().ActiveKeyslots is empty, want the formatting keyslot")
	}
	if info.Metadata == nil {
		t.Error("GetVolumeInfo().Metadata is nil")
	}
}

func TestGetVolumeInfoOnAMissingFileFails(t *testing.T) {
	if _, err := GetVolumeInfo(filepath.Join(t.TempDir(), "absent.img")); err == nil {
		t.Fatal("GetVolumeInfo on a missing file = nil, want the open error")
	}
}

// TestSetupLoopDeviceOnAMissingFileFails, TestDetachLoopDeviceOnAMissingDeviceFails
// and TestFindLoopDeviceForAFileNothingBacksFails are the only branches of
// their functions reachable without root: pkg/loop fails each of them before
// it ever reaches a privileged ioctl -- Attach at the backing file's os.Open,
// Lookup/Detach and Find at a plain sysfs read that finds nothing. The
// success paths need a real loop device and stay for the integration tier.
func TestSetupLoopDeviceOnAMissingFileFails(t *testing.T) {
	if _, err := SetupLoopDevice(filepath.Join(t.TempDir(), "absent.img")); err == nil {
		t.Fatal("SetupLoopDevice on a missing backing file = nil, want the open error")
	}
}

func TestDetachLoopDeviceOnAMissingDeviceFails(t *testing.T) {
	if err := DetachLoopDevice("/dev/loop-does-not-exist-9999"); err == nil {
		t.Fatal("DetachLoopDevice on a device that was never attached = nil, want an error")
	}
}

func TestFindLoopDeviceForAFileNothingBacksFails(t *testing.T) {
	if _, err := FindLoopDevice(filepath.Join(t.TempDir(), "unattached.img")); err == nil {
		t.Fatal("FindLoopDevice for a file no loop device backs = nil, want an error")
	}
}
