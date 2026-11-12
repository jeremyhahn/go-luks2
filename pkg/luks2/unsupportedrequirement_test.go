//go:build !integration

// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"errors"
	"testing"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
)

// A caller of this package matches the refusal of a container with an
// unsupported mandatory requirement by its exported type and learns which
// requirement was refused, for unlock and for a header write alike
// (docs/header/architecture.md).
func TestUnsupportedRequirementErrorIsExportedForUnlockAndWrites(t *testing.T) {
	device, passphrase := unlockableVolume(t)

	pass, err := enclave.NewMemoryCopy(passphrase)
	if err != nil {
		t.Fatalf("could not build the test passphrase enclave: %v", err)
	}
	defer func() { _ = pass.Destroy() }()

	// The volume key is recovered before the requirement is written, so the
	// write below is refused for the requirement and not for want of a key.
	v, err := Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	key, err := v.Unlock(context.Background(), pass)
	if err != nil {
		t.Fatalf("Unlock before the requirement failed: %v", err)
	}
	defer key.Destroy()
	_ = v.Close()

	writeRequirement(t, device, "inline-hw-tags")

	v, err = Open(context.Background(), device, withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = v.Close() }()

	newPass := newPassphraseEnclave(t, "never written")
	defer func() { _ = newPass.Destroy() }()

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Unlock", func() error {
			_, err := v.Unlock(context.Background(), pass)
			return err
		}},
		{"AddKeyslot", func() error {
			_, err := v.AddKeyslot(context.Background(), key, newPass, KeyslotParams{
				KDF: KDFParams{Type: KDFPBKDF2, IterTime: time.Millisecond},
			})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if !errors.Is(err, ErrUnsupportedRequirement) {
				t.Fatalf("%s = %v, want ErrUnsupportedRequirement", tc.name, err)
			}
			var target *UnsupportedRequirementError
			if !errors.As(err, &target) {
				t.Fatalf("%s = %v, want a *luks2.UnsupportedRequirementError", tc.name, err)
			}
			if target.Requirement != "inline-hw-tags" {
				t.Errorf("%s refused requirement %q, want inline-hw-tags", tc.name, target.Requirement)
			}
		})
	}
}
