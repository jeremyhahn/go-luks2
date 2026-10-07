// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"testing"
)

// A detached header -- cryptsetup luksFormat --header -- puts its data
// segment at offset 0 of ANOTHER device. Every keyslot check that kept a
// keyslot area clear of the data segment read that offset as "the data starts
// at 0 of this file", so every keyslot of every detached header overlapped it:
// the header's keyslots could not be opened, added, changed or removed here,
// while cryptsetup manages them. Activation is still refused
// (TestADetachedHeaderIsNeverActivated); keyslot management is not.
func TestDetachedHeaderKeyslotsAreManageable(t *testing.T) {
	defer parallel(t)()
	requireCryptsetup(t)

	data := newImage(t, "detached-data.img")
	header := newImage(t, "detached.hdr")
	if code, out := runCryptsetup(t, conformancePassphrase, "luksFormat", "--type", "luks2", "--batch-mode",
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--header", header, data); code != 0 {
		t.Fatalf("cryptsetup luksFormat --header exited %d\n%s", code, out)
	}
	opensWith := func(passphrase string) bool {
		code, _ := runCryptsetup(t, passphrase, "open", "--test-passphrase", "--header", header, data)
		return code == 0
	}

	if err := testKeyForTest(header, []byte(conformancePassphrase)); err != nil {
		t.Fatalf("TestKey on cryptsetup's detached header: %v", err)
	}
	const second, third = "detached-second-passphrase", "detached-third-passphrase"
	slot, err := addKeyForTest(header, []byte(conformancePassphrase), []byte(second), &addKeyOptionsForTest{KDFType: kdfTypePBKDF2, PBKDFIterTime: 1})
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if !opensWith(second) {
		t.Fatal("cryptsetup does not open the data with the keyslot AddKey wrote to its detached header")
	}
	if err := changeKeyForTest(header, []byte(second), []byte(third), slot); err != nil {
		t.Fatalf("ChangeKey: %v", err)
	}
	if !opensWith(third) || opensWith(second) {
		t.Fatal("cryptsetup does not see ChangeKey's passphrase change")
	}
	if err := killSlotForTest(header, []byte(conformancePassphrase), slot); err != nil {
		t.Fatalf("KillSlot: %v", err)
	}
	if opensWith(third) || !opensWith(conformancePassphrase) {
		t.Fatal("cryptsetup does not see KillSlot's removal")
	}
	if err := killKeyslotForTest(header, 0); !errors.Is(err, ErrLastKeyslot) {
		t.Fatalf("KillKeyslot of the last keyslot = %v, want ErrLastKeyslot", err)
	}
}

func TestDataOnAnotherDevice(t *testing.T) {
	if !dataOnAnotherDevice(0) || dataOnAnotherDevice(16<<20) {
		t.Fatal("only a data segment at offset 0 is a detached header's")
	}
}
