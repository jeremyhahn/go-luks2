// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// recordingProvider is a working KeyProvider that records whether it was
// consulted, so a test can tell a refusal that came before the provider
// from one that came after it.
type recordingProvider struct {
	t                     *testing.T
	tokenCalls, passCalls int
}

func (p *recordingProvider) Token() Token {
	p.tokenCalls++
	return Token{}
}

func (p *recordingProvider) Passphrase(context.Context) (enclave.ByteAccess, error) {
	p.passCalls++
	return newTestPassphrase(p.t), nil
}

func openNilKeyVolume(t *testing.T, name string) *Volume {
	t.Helper()
	v, err := Open(context.Background(), formattedVolumeImage(t, name, "", ""), withTestSys(testVolumeSys()))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

// A nil Key is refused up front, before the lock is taken: the context is
// already canceled, so a refusal that came only after the lock would report
// context.Canceled, and ChangeKeyslot would panic reading the key's slot.
// Every other argument is valid, so nothing else can refuse the call.
func TestVolumeKeyTakingMethodsRefuseANilKeyUpFront(t *testing.T) {
	v := openNilKeyVolume(t, "nilkey.img")
	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	params := KeyslotParams{KDF: argon2TestKDF()}
	for name, call := range map[string]func() error{
		"AddKeyslot": func() error {
			_, err := v.AddKeyslot(ctx, nil, pass, params)
			return err
		},
		"ChangeKeyslot": func() error {
			_, err := v.ChangeKeyslot(ctx, nil, pass, params)
			return err
		},
		"AddRecoveryKey": func() error {
			_, err := v.AddRecoveryKey(ctx, nil, rk, params)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("%s(nil key) = %v, want ErrInvalidArgument", name, err)
			}
		})
	}
}

// Enroll refuses a nil Key before it asks the provider for anything: a
// provider can block on a hardware touch, and must not be run for a call
// that cannot succeed.
func TestVolumeEnrollRefusesANilKeyBeforeConsultingTheProvider(t *testing.T) {
	v := openNilKeyVolume(t, "nilkeyenroll.img")
	p := &recordingProvider{t: t}

	_, err := v.Enroll(context.Background(), nil, p, KeyslotParams{KDF: argon2TestKDF()})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Enroll(nil key) = %v, want ErrInvalidArgument", err)
	}
	if p.tokenCalls != 0 || p.passCalls != 0 {
		t.Fatalf("Enroll(nil key) consulted the provider: Token %d, Passphrase %d calls, want none", p.tokenCalls, p.passCalls)
	}
}

// A zero Key{} is not nil, so it passes the nil checks and reaches the point
// where the key is borrowed; that borrow refuses a Key with no enclave rather
// than dereferencing it. Every other argument is valid and the context is
// live, so the borrow is the only thing that can refuse these calls.
func TestVolumeKeyTakingMethodsRefuseAKeyWithNoEnclave(t *testing.T) {
	v := openNilKeyVolume(t, "emptykey.img")
	pass := newTestPassphrase(t)
	defer func() { _ = pass.Destroy() }()
	rk, err := NewRecoveryKey()
	if err != nil {
		t.Fatalf("NewRecoveryKey failed: %v", err)
	}
	defer rk.Destroy()

	ctx := context.Background()
	params := KeyslotParams{KDF: argon2TestKDF()}
	for name, call := range map[string]func() error{
		"AddKeyslot": func() error {
			_, err := v.AddKeyslot(ctx, &Key{}, pass, params)
			return err
		},
		"ChangeKeyslot": func() error {
			_, err := v.ChangeKeyslot(ctx, &Key{}, pass, params)
			return err
		},
		"Enroll": func() error {
			_, err := v.Enroll(ctx, &Key{}, &recordingProvider{t: t}, params)
			return err
		},
		"AddRecoveryKey": func() error {
			_, err := v.AddRecoveryKey(ctx, &Key{}, rk, params)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("%s(Key{}) = %v, want ErrInvalidArgument", name, err)
			}
		})
	}
}

// Target verifies the key against the header before it reads its size, and
// that check refuses a nil Key and a Key with no enclave alike.
func TestVolumeTargetRefusesANilOrEmptyKey(t *testing.T) {
	v := openNilKeyVolume(t, "nilkeytarget.img")
	for _, key := range []*Key{nil, {}} {
		if _, err := v.Target(context.Background(), key); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("Target(%v) = %v, want ErrInvalidArgument", key, err)
		}
	}
}
